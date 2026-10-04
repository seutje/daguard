//! Explicit operand effects for supported mutation and download commands.
#[derive(Clone, Copy)]
pub(crate) enum Effect<'a> {
    Read(&'a str),
    Write(&'a str),
    TreeWrite(&'a str),
}

pub(crate) fn effects<'a>(program: &str, args: &[&'a str]) -> Result<Vec<Effect<'a>>, ()> {
    if matches!(program, "curl" | "wget") {
        return downloads(program, args);
    }
    if !matches!(program, "cp" | "mv" | "install" | "rm") {
        return Ok(Vec::new());
    }
    let mut operands = Vec::new();
    let mut directory = None;
    let mut positional = false;
    let mut index = 0;
    while let Some(arg) = args.get(index) {
        if !positional && *arg == "--" {
            positional = true;
        } else if !positional && matches!(*arg, "-t" | "--target-directory") {
            directory = Some(*args.get(index + 1).ok_or(())?);
            index += 1;
        } else if !positional && arg.starts_with("-t") && arg.len() > 2 {
            directory = arg.get(2..);
        } else if !positional && arg.starts_with("--target-directory=") {
            directory = arg.strip_prefix("--target-directory=");
        } else if !positional
            && matches!(
                *arg,
                "-m" | "--mode" | "-o" | "--owner" | "-g" | "--group" | "--suffix"
            )
        {
            if program != "install" && *arg != "--suffix" {
                return Err(());
            }
            if args.get(index + 1).is_none() {
                return Err(());
            }
            index += 1;
        } else if positional || !arg.starts_with('-') {
            operands.push(*arg);
        } else if arg.starts_with("--")
            && !matches!(
                *arg,
                "--recursive"
                    | "--force"
                    | "--preserve"
                    | "--no-preserve"
                    | "--verbose"
                    | "--no-target-directory"
            )
            && ![
                "--mode=",
                "--owner=",
                "--group=",
                "--suffix=",
                "--preserve=",
                "--no-preserve=",
            ]
            .iter()
            .any(|flag| arg.starts_with(flag))
        {
            return Err(());
        }
        index += 1;
    }
    if program == "rm" {
        return Ok(operands.into_iter().map(Effect::TreeWrite).collect());
    }
    let target = directory.or_else(|| operands.pop()).ok_or(())?;
    if args.iter().any(|arg| {
        arg.starts_with('-')
            && !arg.starts_with("--")
            && arg.contains('t')
            && !arg.starts_with("-t")
    }) {
        return Err(());
    }
    let recursive = args.iter().any(|arg| {
        *arg == "--recursive"
            || (arg.starts_with('-') && !arg.starts_with("--") && arg.contains(['r', 'R', 'a']))
    });
    let mut effects = vec![if recursive {
        Effect::TreeWrite(target)
    } else {
        Effect::Write(target)
    }];
    for source in operands {
        effects.push(Effect::Read(source));
        if program == "mv" {
            effects.push(Effect::TreeWrite(source));
        }
    }
    Ok(effects)
}

fn downloads<'a>(program: &str, args: &[&'a str]) -> Result<Vec<Effect<'a>>, ()> {
    let mut effects = Vec::new();
    let flags = if program == "curl" {
        &["-o", "--output", "--output-dir"][..]
    } else {
        &["-O", "--output-document", "-P", "--directory-prefix"][..]
    };
    for (index, arg) in args.iter().enumerate() {
        if flags.contains(arg) {
            effects.push(Effect::Write(args.get(index + 1).ok_or(())?));
        } else if let Some((flag, value)) = arg.split_once('=') {
            if flags.contains(&flag) {
                effects.push(Effect::Write(value));
            }
        } else if let Some(flag) = flags
            .iter()
            .find(|flag| flag.len() == 2 && arg.starts_with(**flag) && arg.len() > 2)
        {
            effects.push(Effect::Write(&arg[flag.len()..]));
        }
        if program == "curl"
            && matches!(
                *arg,
                "-O" | "--remote-name" | "--remote-name-all" | "-J" | "--remote-header-name"
            )
        {
            return Err(());
        }
    }
    // Wget's implicit remote filenames cannot be established from the argv alone.
    if program == "wget" && effects.is_empty() {
        return Err(());
    }
    Ok(effects)
}
