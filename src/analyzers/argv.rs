//! Bounded value-taking global option normalization.
pub(crate) fn command<'a>(
    args: &'a [&'a str],
    flags: &[&str],
    values: &[&str],
) -> Result<&'a [&'a str], ()> {
    let mut index = 0;
    while let Some(arg) = args.get(index) {
        if *arg == "--" {
            return Ok(&args[index + 1..]);
        }
        if !arg.starts_with('-') {
            return Ok(&args[index..]);
        }
        if flags.contains(arg) {
            index += 1;
        } else if values.contains(arg) && args.get(index + 1).is_some() {
            index += 2;
        } else if values.iter().any(|flag| {
            arg.starts_with(&format!("{flag}="))
                || (flag.len() == 2 && arg.starts_with(flag) && arg.len() > 2)
        }) {
            index += 1;
        } else {
            return Err(());
        }
    }
    Ok(&[])
}
