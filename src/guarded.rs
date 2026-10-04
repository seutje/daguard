//! Direct guarded process execution with private, bounded output capture.

use std::io::{self, Read, Write};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
#[cfg(unix)]
use std::sync::atomic::{AtomicI32, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use crate::model::{ResultEffect, SensitivityCategory};
use crate::scanner::{MAX_SCAN_BYTES, ScanConfig};
use crate::sensitivity::SourceClassification;

pub(crate) const BLOCKED_EXIT_CODE: i32 = 125;
pub(crate) const TIMEOUT_EXIT_CODE: i32 = 124;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
#[cfg(unix)]
const SIGNAL_GRACE: Duration = Duration::from_secs(1);

pub(crate) struct ExecutionOptions<'a> {
    pub(crate) program: &'a str,
    pub(crate) arguments: &'a [String],
    pub(crate) cwd: &'a Path,
    pub(crate) timeout: Duration,
    pub(crate) config: &'a ScanConfig,
    pub(crate) protect_stdout: bool,
}

pub(crate) struct ExecutionResult {
    pub(crate) exit_code: i32,
    pub(crate) classifications: Vec<SourceClassification>,
    pub(crate) effect: ResultEffect,
    stdout: Option<String>,
    stderr: Option<String>,
}

impl ExecutionResult {
    /// Release only the already-inspected bodies. Callers persist required
    /// taint/audit metadata before invoking this method.
    pub(crate) fn release(self) -> io::Result<i32> {
        if let Some(content) = self.stdout {
            io::stdout().lock().write_all(content.as_bytes())?;
        }
        if let Some(content) = self.stderr {
            io::stderr().lock().write_all(content.as_bytes())?;
        }
        Ok(self.exit_code)
    }
}

pub(crate) fn execute(options: &ExecutionOptions<'_>) -> io::Result<ExecutionResult> {
    #[cfg(unix)]
    let _signals = SignalForwarder::install()?;
    let mut command = Command::new(options.program);
    command
        .args(options.arguments)
        .current_dir(options.cwd)
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    #[cfg(unix)]
    let mut child = ChildGuard::in_process_group(command.spawn()?);
    #[cfg(not(unix))]
    let mut child = ChildGuard::new(command.spawn()?);
    let stdout = child
        .child_mut()
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("could not capture child stdout"))?;
    let stderr = child
        .child_mut()
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("could not capture child stderr"))?;
    let deadline = Instant::now() + options.timeout;
    let stdout_reader = spawn_capture(stdout, deadline);
    let stderr_reader = spawn_capture(stderr, deadline);
    let (status, termination) = wait_for_child(&mut child, deadline)?;
    let stdout = join_capture(&stdout_reader, deadline)?;
    let stderr = join_capture(&stderr_reader, deadline)?;
    if matches!(termination, Termination::TimedOut) || stdout.timed_out || stderr.timed_out {
        synthetic_block(
            "result.timeout",
            "Guarded command timed out; output was discarded.",
        )?;
        return Ok(blocked_execution(TIMEOUT_EXIT_CODE, "result.timeout"));
    }
    if stdout.oversized || stderr.oversized {
        synthetic_block(
            "result.scan_limit",
            "Guarded command output exceeded the complete-scan limit and was discarded.",
        )?;
        return Ok(blocked_execution(BLOCKED_EXIT_CODE, "result.scan_limit"));
    }

    let stdout_decision = if options.protect_stdout {
        crate::scanner::inspect_sensitive_source(&stdout.bytes, options.config)
    } else {
        crate::scanner::inspect(&stdout.bytes, options.config)
    };
    let stderr_decision = crate::scanner::inspect(&stderr.bytes, options.config);
    if Instant::now() >= deadline {
        synthetic_block(
            "result.timeout",
            "Guarded output inspection exceeded the execution deadline.",
        )?;
        return Ok(blocked_execution(TIMEOUT_EXIT_CODE, "result.timeout"));
    }
    let mut classifications = decision_classifications(&stdout_decision);
    classifications.extend(decision_classifications(&stderr_decision));
    if matches!(stdout_decision.decision, ResultEffect::Block)
        || matches!(stderr_decision.decision, ResultEffect::Block)
    {
        synthetic_block(
            "result.inspection_failed",
            "Guarded command output could not be inspected safely and was discarded.",
        )?;
        return Ok(ExecutionResult {
            exit_code: BLOCKED_EXIT_CODE,
            classifications,
            effect: ResultEffect::Block,
            stdout: None,
            stderr: None,
        });
    }
    let effect = if classifications.is_empty() {
        ResultEffect::Allow
    } else {
        ResultEffect::Sanitize
    };
    Ok(ExecutionResult {
        exit_code: match termination {
            #[cfg(unix)]
            Termination::Signaled(signal) => 128 + signal,
            Termination::Exited | Termination::TimedOut => status_code(status),
        },
        classifications,
        effect,
        stdout: stdout_decision.content,
        stderr: stderr_decision.content,
    })
}

fn wait_for_child(
    child: &mut ChildGuard,
    deadline: Instant,
) -> io::Result<(ExitStatus, Termination)> {
    loop {
        if let Some(status) = child.try_wait()? {
            child.terminate_group(libc_signal_kill())?;
            return Ok((status, Termination::Exited));
        }
        #[cfg(unix)]
        if let Some(signal) = pending_signal() {
            return Ok((
                forward_signal_and_wait(child, signal)?,
                Termination::Signaled(signal),
            ));
        }
        if Instant::now() >= deadline {
            child.terminate_group(libc_signal_kill())?;
            return Ok((child.wait()?, Termination::TimedOut));
        }
        thread::sleep(POLL_INTERVAL);
    }
}

#[cfg(unix)]
fn forward_signal_and_wait(child: &mut ChildGuard, signal: i32) -> io::Result<ExitStatus> {
    child.terminate_group(signal)?;
    let deadline = Instant::now() + SIGNAL_GRACE;
    loop {
        if let Some(status) = child.try_wait()? {
            child.terminate_group(libc_signal_kill())?;
            return Ok(status);
        }
        if Instant::now() >= deadline {
            child.terminate_group(libc_signal_kill())?;
            return child.wait();
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn blocked_execution(exit_code: i32, rule_id: &str) -> ExecutionResult {
    ExecutionResult {
        exit_code,
        classifications: vec![dynamic_classification(
            rule_id,
            [SensitivityCategory::UnknownSensitive],
        )],
        effect: ResultEffect::Block,
        stdout: None,
        stderr: None,
    }
}

#[derive(Clone, Copy)]
enum Termination {
    Exited,
    #[cfg(unix)]
    Signaled(i32),
    TimedOut,
}

pub(crate) struct ChildGuard {
    child: Child,
    reaped: bool,
    #[cfg(unix)]
    process_group: bool,
}

impl ChildGuard {
    pub(crate) const fn new(child: Child) -> Self {
        Self {
            child,
            reaped: false,
            #[cfg(unix)]
            process_group: false,
        }
    }

    #[cfg(unix)]
    pub(crate) const fn in_process_group(child: Child) -> Self {
        Self {
            child,
            reaped: false,
            process_group: true,
        }
    }

    pub(crate) fn child_mut(&mut self) -> &mut Child {
        &mut self.child
    }

    pub(crate) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        let status = self.child.try_wait()?;
        self.reaped |= status.is_some();
        Ok(status)
    }

    pub(crate) fn kill(&mut self) -> io::Result<()> {
        self.child.kill()
    }

    fn terminate_group(&mut self, signal: i32) -> io::Result<()> {
        #[cfg(not(unix))]
        let _ = signal;
        #[cfg(unix)]
        if self.process_group {
            let process_group = i32::try_from(self.child.id())
                .map_err(|_| io::Error::other("child process identifier is out of range"))?;
            // SAFETY: `kill` receives a valid negative child process-group ID
            // and an OS signal number. It does not access Rust memory.
            let result = unsafe { libc::kill(-process_group, signal) };
            if result == 0 {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                return Ok(());
            }
            return Err(error);
        }
        if self.reaped { Ok(()) } else { self.kill() }
    }

    pub(crate) fn wait(&mut self) -> io::Result<ExitStatus> {
        let status = self.child.wait()?;
        self.reaped = true;
        Ok(status)
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.terminate_group(libc_signal_kill());
            let _ = self.child.wait();
        }
    }
}

struct Capture {
    bytes: Vec<u8>,
    oversized: bool,
    timed_out: bool,
}

#[cfg(unix)]
fn spawn_capture(
    reader: impl Read + std::os::fd::AsRawFd + Send + 'static,
    deadline: Instant,
) -> std::sync::mpsc::Receiver<io::Result<Capture>> {
    let (sender, receiver) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let fd = reader.as_raw_fd();
        let _ = sender.send(capture(reader, || {
            crate::platform::read_ready(fd, deadline)
        }));
    });
    receiver
}

#[cfg(not(unix))]
fn spawn_capture(
    reader: impl Read + Send + 'static,
    _deadline: Instant,
) -> std::sync::mpsc::Receiver<io::Result<Capture>> {
    let (sender, receiver) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let _ = sender.send(capture(reader, || Ok(())));
    });
    receiver
}

fn capture(
    mut reader: impl Read,
    mut ready: impl FnMut() -> io::Result<()>,
) -> io::Result<Capture> {
    let mut bytes = Vec::with_capacity(16 * 1024);
    let mut oversized = false;
    let mut buffer = [0_u8; 8192];
    loop {
        if let Err(error) = ready() {
            if error.kind() == io::ErrorKind::TimedOut {
                return Ok(Capture {
                    bytes: Vec::new(),
                    oversized,
                    timed_out: true,
                });
            }
            return Err(error);
        }
        let count = match reader.read(&mut buffer) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if count == 0 {
            break;
        }
        let remaining = MAX_SCAN_BYTES.saturating_sub(bytes.len());
        if count > remaining {
            bytes.extend_from_slice(&buffer[..remaining]);
            oversized = true;
        } else if !oversized {
            bytes.extend_from_slice(&buffer[..count]);
        }
        if oversized {
            break;
        } // Do not drain unlimited producer output.
    }
    Ok(Capture {
        bytes,
        oversized,
        timed_out: false,
    })
}

fn join_capture(
    receiver: &std::sync::mpsc::Receiver<io::Result<Capture>>,
    deadline: Instant,
) -> io::Result<Capture> {
    match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Ok(capture) => capture,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Ok(Capture {
            bytes: Vec::new(),
            oversized: false,
            timed_out: true,
        }),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            Err(io::Error::other("guarded output capture failed"))
        }
    }
}

fn synthetic_block(rule_id: &str, message: &str) -> io::Result<()> {
    writeln!(
        io::stderr().lock(),
        "daguard blocked result [{rule_id}]: {message}"
    )
}

fn dynamic_classification(
    detector_id: &str,
    categories: impl IntoIterator<Item = SensitivityCategory>,
) -> SourceClassification {
    SourceClassification::dynamic(detector_id, categories)
}

fn decision_classifications(decision: &crate::result::ResultDecision) -> Vec<SourceClassification> {
    let mut sources = std::collections::BTreeMap::new();
    for finding in &decision.findings {
        sources
            .entry(finding.detector_id)
            .or_insert_with(std::collections::BTreeSet::new)
            .insert(finding.category);
    }
    if sources.is_empty() && !decision.categories.is_empty() {
        sources.insert(decision.rule_id, decision.categories.clone());
    }
    sources
        .into_iter()
        .map(|(detector_id, categories)| dynamic_classification(detector_id, categories))
        .collect()
}

#[cfg(unix)]
static PENDING_SIGNAL: AtomicI32 = AtomicI32::new(0);

#[cfg(unix)]
extern "C" fn record_signal(signal: libc::c_int) {
    PENDING_SIGNAL.store(signal, Ordering::Relaxed);
}

#[cfg(unix)]
struct SignalForwarder {
    previous: [(libc::c_int, libc::sigaction); 3],
}

#[cfg(unix)]
impl SignalForwarder {
    fn install() -> io::Result<Self> {
        PENDING_SIGNAL.store(0, Ordering::Relaxed);
        let mut previous = Vec::with_capacity(3);
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            // SAFETY: zeroed `sigaction` is immediately initialized with an
            // empty signal mask, a function pointer, and valid flags.
            let mut action = unsafe { std::mem::zeroed::<libc::sigaction>() };
            action.sa_sigaction = record_signal as *const () as usize;
            action.sa_flags = libc::SA_RESTART;
            // SAFETY: `action.sa_mask` points to initialized writable storage.
            if unsafe { libc::sigemptyset(&raw mut action.sa_mask) } != 0 {
                restore_signal_actions(&previous);
                return Err(io::Error::last_os_error());
            }
            let mut old = std::mem::MaybeUninit::<libc::sigaction>::uninit();
            // SAFETY: the signal number and action pointer are valid, and the
            // OS initializes `old` on success.
            if unsafe { libc::sigaction(signal, &raw const action, old.as_mut_ptr()) } != 0 {
                restore_signal_actions(&previous);
                return Err(io::Error::last_os_error());
            }
            // SAFETY: successful `sigaction` initialized `old`.
            previous.push((signal, unsafe { old.assume_init() }));
        }
        let previous = previous
            .try_into()
            .map_err(|_| io::Error::other("signal handler initialization failed"))?;
        Ok(Self { previous })
    }
}

#[cfg(unix)]
impl Drop for SignalForwarder {
    fn drop(&mut self) {
        restore_signal_actions(&self.previous);
        PENDING_SIGNAL.store(0, Ordering::Relaxed);
    }
}

#[cfg(unix)]
fn restore_signal_actions(previous: &[(libc::c_int, libc::sigaction)]) {
    for (signal, action) in previous {
        // SAFETY: these actions were returned by successful `sigaction`
        // calls for the same valid signal numbers.
        let _ = unsafe { libc::sigaction(*signal, action, std::ptr::null_mut()) };
    }
}

#[cfg(unix)]
fn pending_signal() -> Option<i32> {
    let signal = PENDING_SIGNAL.swap(0, Ordering::Relaxed);
    (signal != 0).then_some(signal)
}

#[cfg(unix)]
const fn libc_signal_kill() -> i32 {
    libc::SIGKILL
}

#[cfg(not(unix))]
const fn libc_signal_kill() -> i32 {
    0
}

#[cfg(unix)]
fn status_code(status: ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt as _;
    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(1))
}

#[cfg(not(unix))]
fn status_code(status: ExitStatus) -> i32 {
    status.code().unwrap_or(1)
}
