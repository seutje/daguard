//! Protected-file arguments of supported network transfer commands.

/// This protects explicit file references, not arbitrary data or every network
/// sink. Host allowlists and session taint remain separate future work.
pub(crate) fn protected_file_candidates<'a>(
    program: &str,
    args: &[&'a str],
) -> Option<Vec<&'a str>> {
    match program {
        "curl" => Some(
            args.iter()
                .enumerate()
                .filter_map(|(index, arg)| {
                    let (flag, value) = if matches!(
                        *arg,
                        "-d" | "--data"
                            | "--data-binary"
                            | "--data-ascii"
                            | "--data-urlencode"
                            | "-F"
                            | "--form"
                            | "-T"
                            | "--upload-file"
                            | "--config"
                            | "-K"
                    ) {
                        (*arg, args.get(index + 1).copied()?)
                    } else if arg.starts_with("--") {
                        arg.split_once('=')?
                    } else if arg.starts_with("-d")
                        || arg.starts_with("-F")
                        || arg.starts_with("-T")
                        || arg.starts_with("-K")
                    {
                        (arg.get(..2)?, arg.get(2..)?)
                    } else {
                        return None;
                    };
                    let file = match flag {
                        "-d" | "--data" | "--data-binary" | "--data-ascii" => {
                            value.strip_prefix('@')
                        }
                        "--data-urlencode" => value.split_once('@').map(|(_, file)| file),
                        "-F" | "--form" => value.split_once('=').and_then(|(_, value)| {
                            value.strip_prefix('@').or_else(|| value.strip_prefix('<'))
                        }),
                        "-T" | "--upload-file" | "-K" | "--config" => Some(value),
                        _ => None,
                    }?;
                    Some(file.split(';').next().unwrap_or(file))
                })
                .collect(),
        ),
        "scp" | "sftp" | "rsync" => Some(
            args.iter()
                .copied()
                .filter(|arg| !arg.starts_with('-') && !arg.contains(':'))
                .collect(),
        ),
        "wget" => Some(
            args.iter()
                .enumerate()
                .filter_map(|(index, arg)| {
                    if matches!(*arg, "--post-file" | "--body-file" | "--input-file" | "-i") {
                        args.get(index + 1).copied()
                    } else {
                        arg.split_once('=').and_then(|(flag, value)| {
                            matches!(flag, "--post-file" | "--body-file" | "--input-file")
                                .then_some(value)
                        })
                    }
                })
                .collect(),
        ),
        _ => None,
    }
}
