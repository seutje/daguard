//! Supervised, bounded MCP stdio transport with request/response correlation.
use crate::mcp::{self, Authorization, MAX_MCP_MESSAGE_BYTES, ProxyOptions};
use crate::model::ResultEffect;
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::process::{Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc::{self, Receiver, SyncSender},
};
use std::thread;
use std::time::{Duration, Instant};

const MAX_PENDING: usize = 64;
const POLL: Duration = Duration::from_millis(50);
#[derive(Clone, Copy)]
enum Stream {
    Client,
    Server,
    Diagnostic,
}
enum Event {
    Message(Stream, Vec<u8>),
    End(Stream),
    Failure,
}
struct Stop(Arc<AtomicBool>);
impl Drop for Stop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}
struct Pending {
    method: String,
    sources: Vec<crate::sensitivity::SourceClassification>,
    sent: Instant,
}
struct Session {
    pending: BTreeMap<String, Pending>,
    server_requests: BTreeMap<String, Instant>,
    cancelled: BTreeMap<String, Instant>,
    diagnostics: Vec<u8>,
    client_end: Option<Instant>,
    server_end: bool,
    diagnostic_end: bool,
}

pub(crate) fn proxy(
    options: &ProxyOptions<'_>,
    mut authorize: impl FnMut(&Value) -> io::Result<Authorization>,
) -> io::Result<i32> {
    let mut command = Command::new(&options.command[0]);
    command
        .args(&options.command[1..])
        .current_dir(options.cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    #[cfg(unix)]
    let mut child = crate::guarded::ChildGuard::in_process_group(command.spawn()?);
    #[cfg(not(unix))]
    let mut child = crate::guarded::ChildGuard::new(command.spawn()?);
    let mut input = Some(child.child_mut().stdin.take().ok_or_else(invalid)?);
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd as _;
        crate::platform::nonblocking(input.as_ref().ok_or_else(invalid)?.as_raw_fd())?;
    }
    let output = child.child_mut().stdout.take().ok_or_else(invalid)?;
    let error = child.child_mut().stderr.take().ok_or_else(invalid)?;
    let (sender, receiver) = mpsc::sync_channel(4);
    let stop = Stop(Arc::new(AtomicBool::new(false)));
    start_reader(
        io::stdin(),
        Stream::Client,
        sender.clone(),
        Arc::clone(&stop.0),
        options.timeout,
    );
    start_reader(
        output,
        Stream::Server,
        sender.clone(),
        Arc::clone(&stop.0),
        options.timeout,
    );
    start_reader(
        error,
        Stream::Diagnostic,
        sender,
        Arc::clone(&stop.0),
        options.timeout,
    );
    let mut session = Session {
        pending: BTreeMap::new(),
        server_requests: BTreeMap::new(),
        cancelled: BTreeMap::new(),
        diagnostics: Vec::new(),
        client_end: None,
        server_end: false,
        diagnostic_end: false,
    };
    supervise(options, &receiver, &mut session, &mut input, &mut authorize)?;
    let diagnostic = crate::scanner::inspect(&session.diagnostics, options.config);
    persist(&diagnostic, options, &[])?;
    if diagnostic.decision == ResultEffect::Block {
        return Err(invalid());
    }
    if let Some(content) = diagnostic.content {
        io::stderr().lock().write_all(content.as_bytes())?;
    }
    let deadline = Instant::now() + options.timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status.code().unwrap_or(1));
        }
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        thread::sleep(POLL);
    }
}

fn supervise(
    options: &ProxyOptions<'_>,
    receiver: &Receiver<Event>,
    session: &mut Session,
    input: &mut Option<std::process::ChildStdin>,
    authorize: &mut impl FnMut(&Value) -> io::Result<Authorization>,
) -> io::Result<()> {
    loop {
        session
            .cancelled
            .retain(|_, sent| sent.elapsed() < options.timeout);
        let timed_out = session
            .pending
            .values()
            .any(|pending| pending.sent.elapsed() >= options.timeout)
            || session
                .server_requests
                .values()
                .any(|sent| sent.elapsed() >= options.timeout)
            || session
                .client_end
                .is_some_and(|ended| ended.elapsed() >= options.timeout);
        if timed_out {
            return Err(io::ErrorKind::TimedOut.into());
        }
        if session.server_end && session.diagnostic_end {
            if !session.pending.is_empty() || !session.server_requests.is_empty() {
                return Err(invalid());
            }
            return Ok(());
        }
        let event = match receiver.recv_timeout(POLL) {
            Ok(event) => event,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => return Err(invalid()),
        };
        match event {
            Event::Failure => return Err(invalid()),
            Event::End(Stream::Client) => {
                session.client_end = Some(Instant::now());
                input.take();
            }
            Event::End(Stream::Server) => {
                session.server_end = true;
                session.client_end.get_or_insert_with(Instant::now);
                input.take();
            }
            Event::End(Stream::Diagnostic) => session.diagnostic_end = true,
            Event::Message(Stream::Diagnostic, bytes) => {
                if session.diagnostics.len() + bytes.len() > MAX_MCP_MESSAGE_BYTES {
                    return Err(invalid());
                }
                session.diagnostics.extend_from_slice(&bytes);
            }
            Event::Message(stream, bytes) => {
                let value = frame(&bytes)?;
                match stream {
                    Stream::Client => {
                        client_message(&value, &bytes, options, session, input, authorize)?;
                    }
                    Stream::Server => server_message(&value, &bytes, options, session, input)?,
                    Stream::Diagnostic => unreachable!(),
                }
            }
        }
    }
}

fn client_message(
    value: &Value,
    bytes: &[u8],
    options: &ProxyOptions<'_>,
    session: &mut Session,
    input: &mut Option<std::process::ChildStdin>,
    authorize: &mut impl FnMut(&Value) -> io::Result<Authorization>,
) -> io::Result<()> {
    if let Some(id) = value.get("id") {
        id_key(id, options)?;
    }
    let Some(method) = value.get("method").and_then(Value::as_str) else {
        let key = id_key(value.get("id").ok_or_else(invalid)?, options)?;
        if session.server_requests.remove(&key).is_none() || !is_response(value) {
            return Err(invalid());
        }
        return forward(input, bytes, options.timeout);
    };
    validate_params(value, method)?;
    let data_method = matches!(
        method,
        "tools/call" | "resources/read" | "prompts/get" | "completion/complete"
    );
    let notification = matches!(
        method,
        "notifications/initialized" | "notifications/cancelled"
    );
    let supported = data_method
        || notification
        || matches!(
            method,
            "initialize"
                | "ping"
                | "tools/list"
                | "resources/list"
                | "resources/templates/list"
                | "prompts/list"
                | "logging/setLevel"
        );
    if !supported {
        return deny(value, "mcp.method.unsupported");
    }
    if notification != value.get("id").is_none() {
        return Err(invalid());
    }
    let key = value.get("id").map(|id| id_key(id, options)).transpose()?;
    if let Some(key) = &key
        && (session.pending.contains_key(key)
            || session.cancelled.contains_key(key)
            || session.pending.len() + session.cancelled.len() >= MAX_PENDING)
    {
        return Err(invalid());
    }
    let authorization = if data_method {
        authorize(value)?
    } else {
        if mcp::inspect_metadata(bytes, options.config)
            .map_err(|()| invalid())?
            .decision
            != ResultEffect::Allow
        {
            return deny(value, "mcp.metadata_sensitive");
        }
        Authorization {
            rule_id: None,
            sources: Vec::new(),
        }
    };
    if let Some(rule) = authorization.rule_id {
        return deny(value, &rule);
    }
    if let Some(key) = key {
        session.pending.insert(
            key,
            Pending {
                method: method.to_owned(),
                sources: authorization.sources,
                sent: Instant::now(),
            },
        );
    }
    if method == "notifications/cancelled" {
        let id = value.pointer("/params/requestId").ok_or_else(invalid)?;
        let key = id_key(id, options)?;
        if session.pending.remove(&key).is_none() {
            return Err(invalid());
        }
        session.cancelled.insert(key, Instant::now());
    }
    forward(input, bytes, options.timeout)
}

fn validate_params(value: &Value, method: &str) -> io::Result<()> {
    if matches!(method, "tools/call" | "prompts/get")
        && !value
            .pointer("/params/name")
            .and_then(Value::as_str)
            .is_some_and(|name| !name.is_empty() && name.len() <= 128)
    {
        return Err(invalid());
    }
    if method == "resources/read"
        && !value
            .pointer("/params/uri")
            .and_then(Value::as_str)
            .is_some_and(|uri| !uri.is_empty() && uri.len() <= 4096)
    {
        return Err(invalid());
    }
    if value
        .pointer("/params/arguments")
        .is_some_and(|arguments| !arguments.is_object())
    {
        return Err(invalid());
    }
    Ok(())
}

fn server_message(
    value: &Value,
    bytes: &[u8],
    options: &ProxyOptions<'_>,
    session: &mut Session,
    input: &mut Option<std::process::ChildStdin>,
) -> io::Result<()> {
    if let Some(method) = value.get("method").and_then(Value::as_str) {
        if let Some(id) = value.get("id") {
            let key = id_key(id, options)?;
            if method != "ping" {
                return forward(
                    input,
                    &serde_json::to_vec(&mcp::blocked_response(
                        id,
                        "mcp.server_request.unsupported",
                    ))
                    .map_err(io::Error::other)?,
                    options.timeout,
                );
            }
            if session.server_requests.len() >= MAX_PENDING
                || session
                    .server_requests
                    .insert(key, Instant::now())
                    .is_some()
            {
                return Err(invalid());
            }
        } else if !matches!(
            method,
            "notifications/progress"
                | "notifications/message"
                | "notifications/tools/list_changed"
                | "notifications/resources/list_changed"
                | "notifications/prompts/list_changed"
        ) {
            return Err(invalid());
        }
        let decision = mcp::inspect_metadata(bytes, options.config).map_err(|()| invalid())?;
        persist(&decision, options, &[])?;
        if decision.decision != ResultEffect::Allow {
            return Err(invalid());
        }
        return output(value);
    }
    if !is_response(value) {
        return Err(invalid());
    }
    let key = id_key(value.get("id").ok_or_else(invalid)?, options)?;
    if session.cancelled.remove(&key).is_some() {
        return Ok(());
    }
    let pending = session.pending.remove(&key).ok_or_else(invalid)?;
    let decision = inspect_reply(bytes, &pending, options.config)?;
    persist(&decision, options, &pending.sources)?;
    if decision.decision == ResultEffect::Block {
        output(&mcp::blocked_response(&value["id"], decision.rule_id))
    } else {
        let safe: Value = serde_json::from_str(decision.content.as_deref().ok_or_else(invalid)?)
            .map_err(|_| invalid())?;
        if safe["id"] != value["id"] {
            return Err(invalid());
        }
        output(&safe)
    }
}

fn inspect_reply(
    bytes: &[u8],
    pending: &Pending,
    config: &crate::scanner::ScanConfig,
) -> io::Result<crate::result::ResultDecision> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    let data = matches!(
        pending.method.as_str(),
        "tools/call" | "resources/read" | "prompts/get" | "completion/complete"
    );
    let decision = if !pending.sources.is_empty() {
        crate::result::ResultDecision::block(
            "result.sensitive_source",
            "Known sensitive-source MCP results cannot be released safely.",
        )
    } else if data || value.get("error").is_some() {
        mcp::inspect_response(bytes, config).map_err(|()| invalid())?
    } else {
        mcp::inspect_metadata(bytes, config).map_err(|()| invalid())?
    };
    Ok(decision)
}

fn frame(bytes: &[u8]) -> io::Result<Value> {
    crate::json::preflight(bytes, MAX_MCP_MESSAGE_BYTES).map_err(|_| invalid())?;
    let value: Value = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    if !value.is_object() || value["jsonrpc"] != "2.0" {
        return Err(invalid());
    }
    if let Some(method) = value.get("method") {
        if !method
            .as_str()
            .is_some_and(|method| !method.is_empty() && method.len() <= 128)
            || value.get("result").is_some()
            || value.get("error").is_some()
        {
            return Err(invalid());
        }
        if value
            .get("params")
            .is_some_and(|params| !params.is_object())
        {
            return Err(invalid());
        }
    } else if !is_response(&value) {
        return Err(invalid());
    }
    Ok(value)
}
fn is_response(value: &Value) -> bool {
    value.get("result").is_some() != value.get("error").is_some()
        && value.get("id").is_some()
        && value.get("error").is_none_or(|error| {
            error.is_object() && error["code"].as_i64().is_some() && error["message"].is_string()
        })
}
fn id_key(id: &Value, options: &ProxyOptions<'_>) -> io::Result<String> {
    if !(id.as_i64().is_some()
        || id.as_u64().is_some()
        || id
            .as_str()
            .is_some_and(|id| !id.is_empty() && id.len() <= 256))
    {
        return Err(invalid());
    }
    let bytes = serde_json::to_vec(id).map_err(io::Error::other)?;
    if mcp::inspect_metadata(&bytes, options.config)
        .map_err(|()| invalid())?
        .decision
        != ResultEffect::Allow
    {
        return Err(invalid());
    }
    String::from_utf8(bytes).map_err(|_| invalid())
}
fn persist(
    decision: &crate::result::ResultDecision,
    options: &ProxyOptions<'_>,
    sources: &[crate::sensitivity::SourceClassification],
) -> io::Result<()> {
    mcp::persist_result_metadata(
        decision,
        options.agent,
        options.state_dir,
        options.session_id,
        options.audit_log,
        sources,
    )
}
fn deny(value: &Value, rule: &str) -> io::Result<()> {
    if let Some(id) = value.get("id") {
        output(&mcp::blocked_response(id, rule))
    } else {
        Err(invalid())
    }
}
fn output(value: &Value) -> io::Result<()> {
    let mut writer = io::stdout().lock();
    serde_json::to_writer(&mut writer, value).map_err(io::Error::other)?;
    writeln!(writer)?;
    writer.flush()
}
fn forward(
    input: &mut Option<std::process::ChildStdin>,
    bytes: &[u8],
    timeout: Duration,
) -> io::Result<()> {
    let writer = input.as_mut().ok_or_else(invalid)?;
    let deadline = Instant::now() + timeout;
    let mut framed = bytes.to_vec();
    framed.push(b'\n');
    let mut offset = 0;
    while offset < framed.len() {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        match writer.write(&framed[offset..]) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(count) => offset += count,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::sleep(POLL),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    writer.flush()
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "MCP transport or protocol could not be handled safely",
    )
}

#[cfg(unix)]
fn start_reader(
    reader: impl Read + std::os::fd::AsRawFd + Send + 'static,
    stream: Stream,
    sender: SyncSender<Event>,
    stop: Arc<AtomicBool>,
    timeout: Duration,
) {
    let fd = reader.as_raw_fd();
    thread::spawn(move || {
        read_stream(reader, stream, &sender, &stop, timeout, || {
            crate::platform::read_ready(fd, Instant::now() + POLL)
        });
    });
}
#[cfg(not(unix))]
fn start_reader(
    reader: impl Read + Send + 'static,
    stream: Stream,
    sender: SyncSender<Event>,
    stop: Arc<AtomicBool>,
    timeout: Duration,
) {
    thread::spawn(move || read_stream(reader, stream, &sender, &stop, timeout, || Ok(())));
}
fn read_stream(
    mut reader: impl Read,
    stream: Stream,
    sender: &SyncSender<Event>,
    stop: &AtomicBool,
    timeout: Duration,
    mut ready: impl FnMut() -> io::Result<()>,
) {
    let mut pending = Vec::new();
    let mut began = Instant::now();
    let mut chunk = [0_u8; 8192];
    while !stop.load(Ordering::Relaxed) {
        if !pending.is_empty() && began.elapsed() >= timeout {
            let _ = sender.send(Event::Failure);
            return;
        }
        match ready() {
            Err(error) if error.kind() == io::ErrorKind::TimedOut => continue,
            Err(_) => {
                let _ = sender.send(Event::Failure);
                return;
            }
            Ok(()) => {}
        }
        let count = match reader.read(&mut chunk) {
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => {
                let _ = sender.send(Event::Failure);
                return;
            }
        };
        if count == 0 {
            if pending.is_empty() {
                let _ = sender.send(Event::End(stream));
            } else {
                let _ = sender.send(Event::Failure);
            }
            return;
        }
        if matches!(stream, Stream::Diagnostic) {
            if sender
                .send(Event::Message(stream, chunk[..count].to_vec()))
                .is_err()
            {
                return;
            }
            continue;
        }
        for byte in &chunk[..count] {
            if pending.is_empty() {
                began = Instant::now();
            }
            if *byte == b'\n' {
                if pending.last() == Some(&b'\r') {
                    pending.pop();
                }
                if pending.is_empty()
                    || sender
                        .send(Event::Message(stream, std::mem::take(&mut pending)))
                        .is_err()
                {
                    return;
                }
            } else {
                pending.push(*byte);
                if pending.len() > MAX_MCP_MESSAGE_BYTES {
                    let _ = sender.send(Event::Failure);
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a18_known_sources_block_opaque_reply_values() {
        let pending = super::Pending {
            method: "tools/call".to_owned(),
            sources: vec![crate::sensitivity::SourceClassification::dynamic(
                "synthetic.source",
                [crate::model::SensitivityCategory::UnknownSensitive],
            )],
            sent: std::time::Instant::now(),
        };
        let decision = super::inspect_reply(br#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"SYNTHETIC_OPAQUE_SOURCE_VALUE"}]}}"#, &pending, &crate::scanner::ScanConfig::default()).unwrap();
        assert_eq!(decision.decision, crate::model::ResultEffect::Block);
        assert!(
            !serde_json::to_string(&decision)
                .unwrap()
                .contains("SYNTHETIC_OPAQUE_SOURCE_VALUE")
        );
    }
}
