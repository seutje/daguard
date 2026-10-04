//! Bounded deterministic result scanning and structured sanitization.
//!
//! The detectors intentionally use finite byte scans rather than backtracking
//! regular expressions. Raw matches never leave this module.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::model::SensitivityCategory;
use crate::result::{Confidence, Finding, ResultDecision, placeholder};

pub(crate) const MAX_SCAN_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_FINDINGS: usize = 256;
pub(crate) const MAX_SCAN_DURATION: Duration = Duration::from_secs(1);

#[derive(Clone, Debug, Default)]
pub(crate) struct ScanConfig {
    pub(crate) secret_prefixes: Vec<String>,
    pub(crate) sensitive_fields: BTreeMap<String, SensitivityCategory>,
    pub(crate) ip_addresses_are_personal: bool,
}

#[derive(Clone, Debug)]
struct Range {
    start: usize,
    end: usize,
    detector_id: &'static str,
    category: SensitivityCategory,
    confidence: Confidence,
}

pub(crate) fn inspect(bytes: &[u8], config: &ScanConfig) -> ResultDecision {
    let started = Instant::now();
    if bytes.len() > MAX_SCAN_BYTES {
        return ResultDecision::block(
            "result.scan_limit",
            "The protected result exceeded the maximum complete-scan size.",
        );
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return ResultDecision::block(
            "result.unsupported_encoding",
            "The protected result was not valid UTF-8 and could not be inspected safely.",
        );
    };
    if text
        .bytes()
        .filter(|byte| *byte == b'\n')
        .take(16_385)
        .count()
        > 16_384
        || text.lines().any(|line| {
            line.bytes()
                .filter(|byte| matches!(byte, b'|' | b'\t'))
                .take(4097)
                .count()
                > 4096
        })
    {
        return ResultDecision::block(
            "result.structure_limit",
            "The protected result exceeded structural work limits.",
        );
    }
    if looks_like_json(text) {
        match sanitize_json(text, config, started) {
            Ok(Some((sanitized, findings))) => {
                return within_budget(started, ResultDecision::sanitize(sanitized, findings));
            }
            Ok(None) => return within_budget(started, ResultDecision::allow(text.to_owned())),
            Err(()) => {
                return ResultDecision::block(
                    "result.sanitization_error",
                    "The structured protected result could not be sanitized safely.",
                );
            }
        }
    }
    let ranges = detect(text, config, started);
    if finding_limit_exceeded(&ranges) {
        return ResultDecision::block(
            ranges
                .first()
                .map_or("result.finding_limit", |range| range.detector_id),
            "The protected result exceeded scanner work limits.",
        );
    }
    if ranges.is_empty() {
        within_budget(started, ResultDecision::allow(text.to_owned()))
    } else {
        let merged = merge_ranges(ranges);
        let findings = public_findings(&merged);
        within_budget(
            started,
            ResultDecision::sanitize(redact(text, &merged), findings),
        )
    }
}

/// Inspect output from a source already classified as sensitive. Structured
/// values are comprehensively redacted; unstructured output is blocked because
/// ordinary pattern matching cannot prove full coverage.
pub(crate) fn inspect_sensitive_source(bytes: &[u8], config: &ScanConfig) -> ResultDecision {
    let started = Instant::now();
    if bytes.len() > MAX_SCAN_BYTES {
        return ResultDecision::block(
            "result.scan_limit",
            "The protected result exceeded the maximum complete-scan size.",
        );
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return ResultDecision::block(
            "result.unsupported_encoding",
            "The protected result was not valid UTF-8 and could not be inspected safely.",
        );
    };
    if text
        .bytes()
        .filter(|byte| *byte == b'\n')
        .take(16_385)
        .count()
        > 16_384
        || text.lines().any(|line| {
            line.bytes()
                .filter(|byte| matches!(byte, b'|' | b'\t'))
                .take(4097)
                .count()
                > 4096
        })
    {
        return ResultDecision::block(
            "result.structure_limit",
            "The protected result exceeded structural work limits.",
        );
    }
    if text.trim().is_empty() {
        return ResultDecision::allow(text.to_owned());
    }
    let result = if looks_like_json(text) {
        sanitize_sensitive_json(text, config, started)
    } else {
        sanitize_sensitive_table(text, config, started)
    };
    match result {
        Ok(Some((content, findings))) => {
            within_budget(started, ResultDecision::sanitize(content, findings))
        }
        Ok(None) => ResultDecision::allow(text.to_owned()),
        Err(()) => ResultDecision::block(
            "result.unstructured_sensitive_source",
            "Output from the sensitive source could not be sanitized with complete coverage.",
        ),
    }
}

fn sanitize_sensitive_json(
    text: &str,
    config: &ScanConfig,
    started: Instant,
) -> Result<Option<(String, Vec<Finding>)>, ()> {
    crate::json::preflight(text.as_bytes(), MAX_SCAN_BYTES).map_err(|_| ())?;
    let mut value: Value = serde_json::from_str(text).map_err(|_| ())?;
    let mut findings = Vec::new();
    sanitize_value(&mut value, None, config, &mut findings, started)?;
    sanitize_all_values(&mut value, &mut findings, started)?;
    if findings.is_empty() {
        return Ok(None);
    }
    Ok(Some((
        serde_json::to_string(&value).map_err(|_| ())?,
        findings,
    )))
}

fn sanitize_all_values(
    value: &mut Value,
    findings: &mut Vec<Finding>,
    started: Instant,
) -> Result<(), ()> {
    sanitize_classified_value(
        value,
        SensitivityCategory::UnknownSensitive,
        "source.sensitive_value",
        findings,
        started,
    )
}

fn sanitize_sensitive_table(
    text: &str,
    config: &ScanConfig,
    started: Instant,
) -> Result<Option<(String, Vec<Finding>)>, ()> {
    let lines = lines_with_offsets(text);
    let Some((header_index, delimiter)) =
        lines.iter().enumerate().find_map(|(index, (_, line))| {
            if line.contains('|') {
                Some((index, b'|'))
            } else if line.contains('\t') {
                Some((index, b'\t'))
            } else {
                None
            }
        })
    else {
        return Err(());
    };
    let has_header_separator = lines
        .iter()
        .skip(header_index + 1)
        .find(|(_, line)| !line.trim().is_empty())
        .is_some_and(|(_, line)| table_separator(line));
    if !has_header_separator {
        return Err(());
    }
    let mut ranges = detect(text, config, started);
    for (index, (offset, line)) in lines.iter().copied().enumerate() {
        if index == header_index || line.trim().is_empty() || table_separator(line) {
            continue;
        }
        if line.as_bytes().contains(&delimiter) {
            for (start, end, value) in delimited_cells(offset, line, delimiter) {
                let leading = value.len() - value.trim_start().len();
                let trailing = value.trim_end().len();
                push_range(
                    &mut ranges,
                    start + leading,
                    start + trailing.min(end - start),
                    "source.sensitive_value",
                    SensitivityCategory::UnknownSensitive,
                    Confidence::High,
                );
            }
        } else {
            let leading = line.len() - line.trim_start().len();
            let trailing = line.trim_end().len();
            push_range(
                &mut ranges,
                offset + leading,
                offset + trailing,
                "source.sensitive_value",
                SensitivityCategory::UnknownSensitive,
                Confidence::High,
            );
        }
    }
    if ranges.len() > MAX_FINDINGS || finding_limit_exceeded(&ranges) {
        return Err(());
    }
    let ranges = merge_ranges(ranges);
    if ranges.is_empty() {
        return Ok(None);
    }
    Ok(Some((redact(text, &ranges), public_findings(&ranges))))
}

fn within_budget(started: Instant, decision: ResultDecision) -> ResultDecision {
    if started.elapsed() > MAX_SCAN_DURATION {
        ResultDecision::block(
            "result.scan_timeout",
            "The protected result exceeded the scanner time budget.",
        )
    } else {
        decision
    }
}

fn looks_like_json(text: &str) -> bool {
    matches!(text.trim_start().as_bytes().first(), Some(b'{' | b'['))
}

fn sanitize_json(
    text: &str,
    config: &ScanConfig,
    started: Instant,
) -> Result<Option<(String, Vec<Finding>)>, ()> {
    crate::json::preflight(text.as_bytes(), MAX_SCAN_BYTES).map_err(|_| ())?;
    let mut value: Value = serde_json::from_str(text).map_err(|_| ())?;
    let mut findings = Vec::new();
    sanitize_value(&mut value, None, config, &mut findings, started)?;
    if findings.is_empty() {
        return Ok(None);
    }
    let encoded = serde_json::to_string(&value).map_err(|_| ())?;
    Ok(Some((encoded, findings)))
}

fn sanitize_value(
    value: &mut Value,
    key: Option<&str>,
    config: &ScanConfig,
    findings: &mut Vec<Finding>,
    started: Instant,
) -> Result<(), ()> {
    if findings.len() > MAX_FINDINGS || started.elapsed() > MAX_SCAN_DURATION {
        return Err(());
    }
    if let Some((category, detector_id)) = key.and_then(|key| field_category(key, config)) {
        return sanitize_classified_value(value, category, detector_id, findings, started);
    }
    match value {
        Value::String(text) => {
            let ranges = merge_ranges(detect(text, config, started));
            if finding_limit_exceeded(&ranges) {
                return Err(());
            }
            if !ranges.is_empty() {
                findings.extend(public_findings(&ranges));
                if findings.len() > MAX_FINDINGS {
                    return Err(());
                }
                *text = redact(text, &ranges);
            }
        }
        Value::Array(values) => {
            for value in values {
                sanitize_value(value, key, config, findings, started)?;
            }
        }
        Value::Object(values) => {
            let original = std::mem::take(values);
            for (key, mut value) in original {
                let key_ranges = merge_ranges(detect(&key, config, started));
                if finding_limit_exceeded(&key_ranges) {
                    return Err(());
                }
                findings.extend(public_findings(&key_ranges));
                if findings.len() > MAX_FINDINGS {
                    return Err(());
                }
                let safe_key = redact(&key, &key_ranges);
                sanitize_value(&mut value, Some(&key), config, findings, started)?;
                if values.insert(safe_key, value).is_some() {
                    return Err(());
                }
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    Ok(())
}

fn sanitize_classified_value(
    value: &mut Value,
    category: SensitivityCategory,
    detector_id: &'static str,
    findings: &mut Vec<Finding>,
    started: Instant,
) -> Result<(), ()> {
    if started.elapsed() > MAX_SCAN_DURATION {
        return Err(());
    }
    match value {
        Value::Array(values) => {
            for value in values {
                sanitize_classified_value(value, category, detector_id, findings, started)?;
            }
        }
        Value::Object(values) => {
            let original = std::mem::take(values);
            for (index, (key, mut value)) in original.into_iter().enumerate() {
                if findings.len() >= MAX_FINDINGS {
                    return Err(());
                }
                findings.push(Finding {
                    detector_id,
                    category,
                    start: 0,
                    end: key.len(),
                    confidence: Confidence::High,
                });
                let safe_key = format!("{}:key{index}", placeholder(category));
                sanitize_classified_value(&mut value, category, detector_id, findings, started)?;
                if values.insert(safe_key, value).is_some() {
                    return Err(());
                }
            }
        }
        Value::Null => {}
        Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            if findings.len() >= MAX_FINDINGS {
                return Err(());
            }
            findings.push(Finding {
                detector_id,
                category,
                start: 0,
                end: value_length(value),
                confidence: Confidence::High,
            });
            *value = Value::String(placeholder(category).to_owned());
        }
    }
    Ok(())
}

fn finding_limit_exceeded(ranges: &[Range]) -> bool {
    ranges
        .iter()
        .any(|range| range.detector_id.starts_with("result."))
}

fn value_length(value: &Value) -> usize {
    match value {
        Value::String(value) => value.len(),
        _ => 0,
    }
}

pub(crate) fn field_category(
    key: &str,
    config: &ScanConfig,
) -> Option<(SensitivityCategory, &'static str)> {
    let normalized = normalize_field(key);
    let value = normalized.as_str();
    if contains_word(
        value,
        &["password", "passwd", "secret", "api_key", "private_key"],
    ) || matches!(
        value,
        "pass"
            | "token"
            | "access_token"
            | "refresh_token"
            | "accountkey"
            | "access_key_id"
            | "secret_access_key"
    ) {
        return Some((
            SensitivityCategory::Credential,
            "structured.credential_field",
        ));
    }
    if contains_word(
        value,
        &["authorization", "cookie", "session", "session_id", "hash"],
    ) {
        return Some((
            SensitivityCategory::Authentication,
            "structured.authentication_field",
        ));
    }
    if contains_word(
        value,
        &["card_number", "iban", "bank_account", "payment_method"],
    ) {
        return Some((
            SensitivityCategory::FinancialData,
            "structured.financial_field",
        ));
    }
    if contains_word(
        value,
        &[
            "billing_address",
            "shipping_address",
            "customer_profile",
            "webform_submission",
            "comment_author",
        ],
    ) {
        return Some((
            SensitivityCategory::CustomerData,
            "structured.customer_field",
        ));
    }
    if contains_word(
        value,
        &[
            "email",
            "mail",
            "phone",
            "telephone",
            "address",
            "postal_code",
            "birth_date",
            "date_of_birth",
        ],
    ) {
        return Some((
            SensitivityCategory::PersonalData,
            "structured.personal_field",
        ));
    }
    config
        .sensitive_fields
        .get(&normalized)
        .map(|category| (*category, "configured.sensitive_field"))
}

fn normalize_field(field: &str) -> String {
    field
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() {
                byte.to_ascii_lowercase() as char
            } else {
                '_'
            }
        })
        .collect()
}

fn contains_word(value: &str, words: &[&str]) -> bool {
    words.iter().any(|word| {
        value == *word
            || value
                .strip_suffix(word)
                .is_some_and(|prefix| prefix.ends_with('_'))
    })
}

fn detect(text: &str, config: &ScanConfig, started: Instant) -> Vec<Range> {
    let (plain, offsets) = without_ansi(text);
    let mut ranges = Vec::new();
    detect_private_keys(&plain, &mut ranges);
    if finding_limit_exceeded(&ranges) || scan_stopped(&mut ranges, started, text.len()) {
        return ranges;
    }
    detect_assignments(&plain, config, &mut ranges);
    if finding_limit_exceeded(&ranges) || scan_stopped(&mut ranges, started, text.len()) {
        return ranges;
    }
    detect_tables(&plain, config, &mut ranges, started);
    if finding_limit_exceeded(&ranges) || scan_stopped(&mut ranges, started, text.len()) {
        return ranges;
    }
    detect_authorization(&plain, &mut ranges);
    if finding_limit_exceeded(&ranges) || scan_stopped(&mut ranges, started, text.len()) {
        return ranges;
    }
    detect_database_urls(&plain, &mut ranges);
    if finding_limit_exceeded(&ranges) || scan_stopped(&mut ranges, started, text.len()) {
        return ranges;
    }
    detect_prefixed_tokens(&plain, config, &mut ranges, started);
    if finding_limit_exceeded(&ranges) || scan_stopped(&mut ranges, started, text.len()) {
        return ranges;
    }
    detect_jwts(&plain, &mut ranges);
    if finding_limit_exceeded(&ranges) || scan_stopped(&mut ranges, started, text.len()) {
        return ranges;
    }
    detect_emails(&plain, &mut ranges);
    if finding_limit_exceeded(&ranges) || scan_stopped(&mut ranges, started, text.len()) {
        return ranges;
    }
    detect_context_values(&plain, &mut ranges);
    if finding_limit_exceeded(&ranges) || scan_stopped(&mut ranges, started, text.len()) {
        return ranges;
    }
    detect_cards_and_ibans(&plain, &mut ranges, started);
    if finding_limit_exceeded(&ranges) || scan_stopped(&mut ranges, started, text.len()) {
        return ranges;
    }
    if config.ip_addresses_are_personal {
        detect_ip_addresses(&plain, &mut ranges);
        if finding_limit_exceeded(&ranges) || scan_stopped(&mut ranges, started, text.len()) {
            return ranges;
        }
    }
    ranges.truncate(MAX_FINDINGS + 1);
    if ranges.len() > MAX_FINDINGS {
        return vec![Range {
            start: 0,
            end: text.len(),
            detector_id: "result.finding_limit",
            category: SensitivityCategory::UnknownSensitive,
            confidence: Confidence::High,
        }];
    }
    if offsets.is_empty() {
        return ranges;
    }
    for range in &mut ranges {
        range.start = offsets.get(range.start).copied().unwrap_or(range.start);
        range.end = if range.end == 0 {
            0
        } else {
            offsets
                .get(range.end.saturating_sub(1))
                .map_or(text.len(), |offset| next_char_boundary(text, *offset))
        };
    }
    ranges
}

fn without_ansi(text: &str) -> (String, Vec<usize>) {
    if !text.contains('\u{1b}') {
        return (text.to_owned(), Vec::new());
    }
    let bytes = text.as_bytes();
    let mut plain = Vec::with_capacity(bytes.len());
    let mut offsets = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == 0x1b && bytes.get(index + 1) == Some(&b'[') {
            index += 2;
            while index < bytes.len() {
                let byte = bytes[index];
                index += 1;
                if (0x40..=0x7e).contains(&byte) {
                    break;
                }
            }
            continue;
        }
        plain.push(bytes[index]);
        offsets.push(index);
        index += 1;
    }
    // Removing complete byte-oriented ANSI sequences preserves UTF-8.
    (String::from_utf8(plain).unwrap_or_default(), offsets)
}

fn next_char_boundary(text: &str, offset: usize) -> usize {
    let mut end = (offset + 1).min(text.len());
    while end < text.len() && !text.is_char_boundary(end) {
        end += 1;
    }
    end
}

fn detect_private_keys(text: &str, ranges: &mut Vec<Range>) {
    let mut from = 0;
    while let Some(relative) = text[from..].find("-----BEGIN ") {
        let start = from + relative;
        let header_end = text[start..]
            .find('\n')
            .map_or(text.len(), |value| start + value + 1);
        let header = &text[start..header_end];
        if header.contains("PRIVATE KEY") {
            let label = header
                .trim()
                .strip_prefix("-----BEGIN ")
                .and_then(|value| value.strip_suffix("-----"));
            let end = label
                .and_then(|label| {
                    let footer = format!("-----END {label}-----");
                    text[header_end..]
                        .find(&footer)
                        .map(|offset| header_end + offset + footer.len())
                })
                .unwrap_or(text.len());
            push_range(
                ranges,
                start,
                end,
                "secret.pem_private_key",
                SensitivityCategory::Credential,
                Confidence::High,
            );
            from = end;
        } else {
            from = header_end;
        }
    }
}

fn detect_assignments(text: &str, config: &ScanConfig, ranges: &mut Vec<Range>) {
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_start();
        let leading = line.len() - trimmed.len();
        if let Some(separator) = trimmed.find(['=', ':']) {
            let key = normalize_field(trimmed[..separator].trim());
            if let Some((category, detector_id)) = field_category(&key, config) {
                let value_start = separator
                    + 1
                    + trimmed[separator + 1..]
                        .len()
                        .saturating_sub(trimmed[separator + 1..].trim_start().len());
                let value_end = trimmed.trim_end_matches(['\r', '\n']).len();
                let value = trimmed[separator + 1..].trim();
                if assignment_continues(value) {
                    push_range(
                        ranges,
                        offset + leading + separator + 1,
                        text.len(),
                        detector_id,
                        category,
                        Confidence::High,
                    );
                    return; // Remaining continuation content has no proven safe boundary.
                }
                if value_start < value_end {
                    push_range(
                        ranges,
                        offset + leading + value_start,
                        offset + leading + value_end,
                        detector_id,
                        category,
                        Confidence::High,
                    );
                }
            }
        }
        offset += line.len();
    }
}

fn assignment_continues(value: &str) -> bool {
    value.is_empty()
        || matches!(value, "|" | ">" | "|-" | ">-" | "|+" | ">+")
        || value.ends_with('\\')
        || ((value.starts_with('"') || value.starts_with('\''))
            && (value.len() < 2 || !value.ends_with(value.chars().next().unwrap_or('"'))))
}

/// Only metadata escapes this helper. An open envelope can continue in another
/// captured stream; independently redacting its current bytes is insufficient.
pub(crate) fn has_open_sensitive_context(bytes: &[u8], config: &ScanConfig) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return true;
    };
    if bytes.len() > MAX_SCAN_BYTES {
        return true;
    }
    if looks_like_json(text) {
        return false;
    } // Structured scanning owns its boundaries.
    let (plain, _) = without_ansi(text);
    if plain.lines().any(|line| {
        line.trim_start()
            .split_once(['=', ':'])
            .is_some_and(|(key, value)| {
                field_category(key.trim(), config).is_some() && assignment_continues(value.trim())
            })
    }) {
        return true;
    }
    let mut keys = Vec::new();
    detect_private_keys(&plain, &mut keys);
    if finding_limit_exceeded(&keys) {
        return true;
    }
    keys.iter().any(|range| {
        let body = &plain[range.start..range.end];
        let header = body.lines().next().unwrap_or("").trim();
        let label = header
            .strip_prefix("-----BEGIN ")
            .and_then(|label| label.strip_suffix("-----"));
        label.is_none_or(|label| !body.contains(&format!("-----END {label}-----")))
    })
}

fn detect_tables(text: &str, config: &ScanConfig, ranges: &mut Vec<Range>, started: Instant) {
    let lines = lines_with_offsets(text);
    let mut index = 0;
    while index < lines.len() {
        if scan_stopped(ranges, started, text.len()) {
            return;
        }
        let (offset, header) = lines[index];
        index += 1;
        let delimiter = if header.contains('|') {
            b'|'
        } else if header.contains('\t') {
            b'\t'
        } else {
            continue;
        };
        let headers = delimited_cells(offset, header, delimiter);
        if headers.len() < 2 {
            continue;
        }
        let sensitive = headers
            .iter()
            .map(|(_, _, header)| field_category(header.trim(), config))
            .collect::<Vec<_>>();
        if sensitive.iter().all(Option::is_none) {
            continue;
        }
        while index < lines.len() {
            if scan_stopped(ranges, started, text.len()) {
                return;
            }
            let (row_offset, row) = lines[index];
            if table_separator(row) {
                index += 1;
                continue;
            }
            if !row.as_bytes().contains(&delimiter) {
                break;
            }
            let values = delimited_cells(row_offset, row, delimiter);
            if headers.len() != values.len() {
                break;
            }
            index += 1;
            for ((start, end, value), classification) in values.into_iter().zip(&sensitive) {
                if let Some((category, detector_id)) = classification {
                    let leading = value.len() - value.trim_start().len();
                    let trailing = value.trim_end().len();
                    push_range(
                        ranges,
                        start + leading,
                        start + trailing.min(end - start),
                        detector_id,
                        *category,
                        Confidence::High,
                    );
                }
            }
        }
    }
}

fn scan_stopped(ranges: &mut Vec<Range>, started: Instant, length: usize) -> bool {
    let rule = if ranges.len() > MAX_FINDINGS {
        "result.finding_limit"
    } else if started.elapsed() > MAX_SCAN_DURATION {
        "result.scan_timeout"
    } else {
        return false;
    };
    ranges.clear();
    ranges.push(Range {
        start: 0,
        end: length,
        detector_id: rule,
        category: SensitivityCategory::UnknownSensitive,
        confidence: Confidence::High,
    });
    true
}

fn table_separator(line: &str) -> bool {
    !line.trim().is_empty()
        && line.bytes().all(|byte| {
            byte.is_ascii_whitespace() || matches!(byte, b'|' | b'+' | b'-' | b'=' | b':')
        })
}

fn lines_with_offsets(text: &str) -> Vec<(usize, &str)> {
    let mut lines = Vec::new();
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        lines.push((offset, line.trim_end_matches(['\r', '\n'])));
        offset += line.len();
    }
    if text.is_empty() {
        lines.push((0, ""));
    }
    lines
}

fn delimited_cells(offset: usize, line: &str, delimiter: u8) -> Vec<(usize, usize, &str)> {
    let mut cells = Vec::new();
    let mut start = 0;
    for (index, byte) in line.bytes().enumerate() {
        if byte == delimiter {
            cells.push((offset + start, offset + index, &line[start..index]));
            start = index + 1;
        }
    }
    cells.push((offset + start, offset + line.len(), &line[start..]));
    cells
}

fn detect_authorization(text: &str, ranges: &mut Vec<Range>) {
    for (start, end) in case_insensitive_values(text, &["authorization", "bearer"]) {
        push_range(
            ranges,
            start,
            end,
            "secret.authorization",
            SensitivityCategory::Authentication,
            Confidence::High,
        );
    }
}

fn case_insensitive_values(text: &str, keys: &[&str]) -> Vec<(usize, usize)> {
    let lower = text.to_ascii_lowercase();
    let mut values = Vec::new();
    for key in keys {
        let mut from = 0;
        while let Some(relative) = lower[from..].find(key) {
            let key_start = from + relative;
            let mut start = key_start + key.len();
            while text
                .as_bytes()
                .get(start)
                .is_some_and(|byte| byte.is_ascii_whitespace() || matches!(*byte, b':' | b'='))
            {
                start += 1;
            }
            let end = consume_token(text, start);
            if end.saturating_sub(start) >= 8 {
                values.push((start, end));
                if values.len() > MAX_FINDINGS {
                    return values;
                }
            }
            from = end.max(key_start + key.len());
        }
    }
    values
}

fn detect_database_urls(text: &str, ranges: &mut Vec<Range>) {
    let lower = text.to_ascii_lowercase();
    for scheme in ["mysql://", "mariadb://", "postgres://", "postgresql://"] {
        let mut from = 0;
        while let Some(relative) = lower[from..].find(scheme) {
            let start = from + relative + scheme.len();
            let authority_end = text[start..]
                .find(['/', '?', '#', ' ', '\n', '\r'])
                .map_or(text.len(), |value| start + value);
            if let Some(at) = text[start..authority_end].rfind('@') {
                let at = start + at;
                if let Some(colon) = text[start..at].find(':') {
                    push_range(
                        ranges,
                        start + colon + 1,
                        at,
                        "secret.database_url",
                        SensitivityCategory::Credential,
                        Confidence::High,
                    );
                }
            }
            from = authority_end;
        }
    }
}

fn detect_prefixed_tokens(
    text: &str,
    config: &ScanConfig,
    ranges: &mut Vec<Range>,
    started: Instant,
) {
    let built_in = [
        ("ghp_", 36, "secret.github_token"),
        ("gho_", 36, "secret.github_token"),
        ("ghu_", 36, "secret.github_token"),
        ("ghs_", 36, "secret.github_token"),
        ("ghr_", 36, "secret.github_token"),
        ("github_pat_", 24, "secret.github_token"),
        ("glpat-", 20, "secret.gitlab_token"),
        ("AKIA", 20, "secret.aws_access_key"),
        ("ASIA", 20, "secret.aws_access_key"),
        ("AIza", 39, "secret.google_api_key"),
        ("sk_live_", 20, "secret.stripe_key"),
        ("rk_live_", 20, "secret.stripe_key"),
        ("sk_test_", 20, "secret.stripe_key"),
        ("rk_test_", 20, "secret.stripe_key"),
        ("xoxb-", 20, "secret.slack_token"),
        ("xoxp-", 20, "secret.slack_token"),
        ("xoxa-", 20, "secret.slack_token"),
        ("xoxr-", 20, "secret.slack_token"),
        ("ya29.", 20, "secret.oauth_token"),
    ];
    for (prefix, minimum, detector) in built_in {
        if scan_stopped(ranges, started, text.len()) {
            return;
        }
        find_prefixed(text, prefix, minimum, detector, ranges);
    }
    for prefix in &config.secret_prefixes {
        if scan_stopped(ranges, started, text.len()) {
            return;
        }
        find_prefixed(
            text,
            prefix,
            prefix.len() + 8,
            "configured.secret_prefix",
            ranges,
        );
    }
}

fn find_prefixed(
    text: &str,
    prefix: &str,
    minimum: usize,
    detector: &'static str,
    ranges: &mut Vec<Range>,
) {
    let mut from = 0;
    while let Some(relative) = text[from..].find(prefix) {
        let start = from + relative;
        let end = consume_token(text, start);
        if end.saturating_sub(start) >= minimum {
            push_range(
                ranges,
                start,
                end,
                detector,
                SensitivityCategory::Credential,
                Confidence::High,
            );
        }
        from = end.max(start + prefix.len());
    }
}

fn detect_jwts(text: &str, ranges: &mut Vec<Range>) {
    for (start, end) in tokens(text) {
        let token = &text[start..end];
        let mut parts = token.split('.');
        if parts.next().is_some_and(|part| part.len() >= 8)
            && parts.next().is_some_and(|part| part.len() >= 8)
            && parts.next().is_some_and(|part| part.len() >= 8)
            && parts.next().is_none()
            && token.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'=')
            })
        {
            push_range(
                ranges,
                start,
                end,
                "secret.jwt",
                SensitivityCategory::Authentication,
                Confidence::High,
            );
        }
    }
}

fn detect_emails(text: &str, ranges: &mut Vec<Range>) {
    for (start, end) in tokens(text) {
        let value = text[start..end].trim_matches(|character: char| {
            matches!(character, '<' | '>' | '(' | ')' | ',' | ';' | '"' | '\'')
        });
        let adjustment = text[start..end].find(value).unwrap_or(0);
        let Some((local, domain)) = value.split_once('@') else {
            continue;
        };
        if !local.is_empty()
            && domain.contains('.')
            && !domain.starts_with('.')
            && !domain.ends_with('.')
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'@' | b'.' | b'_' | b'-' | b'+')
            })
        {
            push_range(
                ranges,
                start + adjustment,
                start + adjustment + value.len(),
                "personal.email",
                SensitivityCategory::PersonalData,
                Confidence::Medium,
            );
        }
    }
}

fn detect_context_values(text: &str, ranges: &mut Vec<Range>) {
    let lower = text.to_ascii_lowercase();
    for (start, end) in case_insensitive_values(
        text,
        &[
            "phone",
            "telephone",
            "date_of_birth",
            "birth_date",
            "cookie",
            "session",
        ],
    ) {
        let before = lower[..start].trim_end_matches(|character: char| {
            character.is_ascii_whitespace() || matches!(character, ':' | '=')
        });
        let category = if before.ends_with("cookie") || before.ends_with("session") {
            SensitivityCategory::Authentication
        } else {
            SensitivityCategory::PersonalData
        };
        push_range(
            ranges,
            start,
            end,
            if category == SensitivityCategory::Authentication {
                "authentication.structured_value"
            } else {
                "personal.context_value"
            },
            category,
            Confidence::High,
        );
    }
}

fn detect_cards_and_ibans(text: &str, ranges: &mut Vec<Range>, started: Instant) {
    for (start, end) in span_tokens(text, |byte| {
        byte.is_ascii_digit() || matches!(byte, b' ' | b'-')
    }) {
        let value = &text[start..end];
        let compact = value
            .bytes()
            .filter(|byte| !matches!(byte, b' ' | b'-'))
            .collect::<Vec<_>>();
        if (13..=19).contains(&compact.len())
            && compact.iter().all(u8::is_ascii_digit)
            && luhn(&compact)
        {
            let leading = value.len() - value.trim_start().len();
            let trailing = value.trim_end().len();
            push_range(
                ranges,
                start + leading,
                start + trailing,
                "financial.payment_card",
                SensitivityCategory::FinancialData,
                Confidence::High,
            );
        }
    }
    let bytes = text.as_bytes();
    for start in 0..bytes.len().saturating_sub(3) {
        if start % 1024 == 0 && scan_stopped(ranges, started, text.len()) {
            return;
        }
        if start > 0 && bytes[start - 1].is_ascii_alphanumeric() {
            continue;
        }
        if !bytes[start].is_ascii_alphabetic()
            || !bytes[start + 1].is_ascii_alphabetic()
            || !bytes[start + 2].is_ascii_digit()
            || !bytes[start + 3].is_ascii_digit()
        {
            continue;
        }
        let mut compact = Vec::with_capacity(34);
        let mut end = start;
        let mut valid_end = None;
        while end < bytes.len() && compact.len() < 34 {
            let byte = bytes[end];
            if byte.is_ascii_alphanumeric() {
                compact.push(byte);
                if compact.len() >= 15 && valid_iban(&compact) {
                    valid_end = Some(end + 1);
                }
            } else if !matches!(byte, b' ' | b'-') {
                break;
            }
            end += 1;
        }
        if let Some(end) = valid_end {
            push_range(
                ranges,
                start,
                end,
                "financial.iban",
                SensitivityCategory::FinancialData,
                Confidence::High,
            );
        }
    }
}

fn luhn(digits: &[u8]) -> bool {
    let mut sum = 0_u32;
    let parity = digits.len() % 2;
    for (index, digit) in digits.iter().enumerate() {
        let mut value = u32::from(*digit - b'0');
        if index % 2 == parity {
            value *= 2;
            if value > 9 {
                value -= 9;
            }
        }
        sum += value;
    }
    sum.is_multiple_of(10)
}

fn valid_iban(compact: &[u8]) -> bool {
    let mut remainder = 0_u32;
    for byte in compact[4..].iter().chain(&compact[..4]) {
        if byte.is_ascii_digit() {
            remainder = (remainder * 10 + u32::from(*byte - b'0')) % 97;
        } else {
            let value = u32::from(byte.to_ascii_uppercase() - b'A') + 10;
            remainder = (remainder * 100 + value) % 97;
        }
    }
    remainder == 1
}

fn detect_ip_addresses(text: &str, ranges: &mut Vec<Range>) {
    for (start, end) in span_tokens(text, |byte| {
        byte.is_ascii_hexdigit() || matches!(byte, b'.' | b':')
    }) {
        let candidate = text[start..end].trim_matches('.');
        if candidate.parse::<std::net::IpAddr>().is_ok() {
            let adjustment = text[start..end].find(candidate).unwrap_or(0);
            push_range(
                ranges,
                start + adjustment,
                start + adjustment + candidate.len(),
                "personal.ip_address",
                SensitivityCategory::PersonalData,
                Confidence::Medium,
            );
        }
    }
}

fn tokens(text: &str) -> impl Iterator<Item = (usize, usize)> + '_ {
    span_tokens(text, |byte| {
        !byte.is_ascii_whitespace() && !matches!(byte, b'{' | b'}' | b'[' | b']' | b':' | b'=')
    })
}

fn span_tokens<'a>(
    text: &'a str,
    predicate: impl Fn(u8) -> bool + Copy + 'a,
) -> impl Iterator<Item = (usize, usize)> + 'a {
    let bytes = text.as_bytes();
    let mut index = 0;
    std::iter::from_fn(move || {
        while index < bytes.len() && !predicate(bytes[index]) {
            index += 1;
        }
        if index == bytes.len() {
            return None;
        }
        let start = index;
        while index < bytes.len() && predicate(bytes[index]) {
            index += 1;
        }
        Some((start, index))
    })
}

fn consume_token(text: &str, start: usize) -> usize {
    let bytes = text.as_bytes();
    let mut end = start;
    while end < bytes.len()
        && (bytes[end].is_ascii_alphanumeric()
            || matches!(bytes[end], b'_' | b'-' | b'.' | b'~' | b'+' | b'/' | b'='))
    {
        end += 1;
    }
    end
}

fn push_range(
    ranges: &mut Vec<Range>,
    start: usize,
    end: usize,
    detector_id: &'static str,
    category: SensitivityCategory,
    confidence: Confidence,
) {
    if start < end && ranges.len() <= MAX_FINDINGS {
        ranges.push(Range {
            start,
            end,
            detector_id,
            category,
            confidence,
        });
    }
}

fn merge_ranges(mut ranges: Vec<Range>) -> Vec<Range> {
    ranges.sort_by_key(|range| (range.start, range.end));
    let mut merged: Vec<Range> = Vec::new();
    for range in ranges {
        if let Some(previous) = merged.last_mut()
            && range.start <= previous.end
        {
            previous.end = previous.end.max(range.end);
            if category_rank(range.category) > category_rank(previous.category) {
                previous.category = range.category;
                previous.detector_id = range.detector_id;
                previous.confidence = range.confidence;
            }
            continue;
        }
        merged.push(range);
    }
    merged
}

const fn category_rank(category: SensitivityCategory) -> u8 {
    match category {
        SensitivityCategory::Credential => 8,
        SensitivityCategory::Authentication => 7,
        SensitivityCategory::FinancialData => 6,
        SensitivityCategory::CustomerData => 5,
        SensitivityCategory::PersonalData => 4,
        SensitivityCategory::PrivateContent => 3,
        SensitivityCategory::OperationalSensitive => 2,
        SensitivityCategory::UnknownSensitive => 1,
    }
}

fn public_findings(ranges: &[Range]) -> Vec<Finding> {
    ranges
        .iter()
        .map(|range| Finding {
            detector_id: range.detector_id,
            category: range.category,
            start: range.start,
            end: range.end,
            confidence: range.confidence,
        })
        .collect()
}

fn redact(text: &str, ranges: &[Range]) -> String {
    let mut output = String::with_capacity(text.len());
    let mut cursor = 0;
    for range in ranges {
        if range.start >= cursor && range.end <= text.len() {
            output.push_str(&text[cursor..range.start]);
            output.push_str(placeholder(range.category));
            cursor = range.end;
        }
    }
    output.push_str(&text[cursor..]);
    output
}

#[cfg(test)]
mod tests {
    use super::{ScanConfig, inspect, inspect_sensitive_source};
    use crate::model::ResultEffect;

    #[test]
    fn a16_deadline_and_structure_fail_closed() {
        let expired = std::time::Instant::now()
            .checked_sub(super::MAX_SCAN_DURATION + std::time::Duration::from_millis(1))
            .unwrap();
        assert!(
            super::sanitize_json(r#"{"safe":"ordinary"}"#, &ScanConfig::default(), expired)
                .is_err()
        );
        for input in [
            "safe\n".repeat(16_385),
            "|".repeat(4097),
            format!("[{}0]", "0,".repeat(8192)),
        ] {
            assert_eq!(
                inspect(input.as_bytes(), &ScanConfig::default()).decision,
                ResultEffect::Block
            );
        }
    }

    #[test]
    fn a16_repeated_sensitive_headers_have_bounded_work() {
        let input = "password|safe\n".repeat(15_000);
        let started = std::time::Instant::now();
        let decision = inspect(input.as_bytes(), &ScanConfig::default());
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        assert_eq!(decision.decision, ResultEffect::Block);
        assert!(decision.content.is_none());
    }

    #[test]
    fn a14_incomplete_envelopes_and_multiline_assignments() {
        for input in [
            "-----BEGIN PRIVATE KEY-----\nSYNTHETIC_AUDIT_KEY_BODY\n",
            "-----BEGIN OPENSSH PRIVATE KEY-----\nSYNTHETIC_AUDIT_KEY_BODY",
            "password=\nSYNTHETIC_AUDIT_KEY_BODY\n",
            "password: |\n  SYNTHETIC_AUDIT_KEY_BODY\n",
            "password=\\\nSYNTHETIC_AUDIT_KEY_BODY\n",
        ] {
            let decision = inspect(input.as_bytes(), &ScanConfig::default());
            assert!(
                !serde_json::to_string(&decision)
                    .unwrap()
                    .contains("SYNTHETIC_AUDIT_KEY_BODY")
            );
            let json = serde_json::json!({"message": input});
            let decision = inspect(&serde_json::to_vec(&json).unwrap(), &ScanConfig::default());
            assert!(
                !serde_json::to_string(&decision)
                    .unwrap()
                    .contains("SYNTHETIC_AUDIT_KEY_BODY")
            );
        }
        assert_eq!(
            inspect(b"title=\nordinary text\n", &ScanConfig::default()).decision,
            ResultEffect::Allow
        );
    }

    #[test]
    fn a13_classified_keys_and_forged_placeholders_do_not_leak() {
        let canary = "SYNTHETIC_AUDIT_SECRET";
        for input in [
            br#"{"password":{"SYNTHETIC_AUDIT_SECRET":null}}"#.as_slice(),
            br#"{"password":[{"SYNTHETIC_AUDIT_SECRET":"value"}]}"#.as_slice(),
        ] {
            let decision = inspect(input, &ScanConfig::default());
            assert!(!serde_json::to_string(&decision).unwrap().contains(canary));
        }
        let input = br#"{"SYNTHETIC_AUDIT_SECRET":"[REDACTED:SYNTHETIC_AUDIT_SECRET]"}"#;
        let decision = inspect_sensitive_source(input, &ScanConfig::default());
        assert!(!serde_json::to_string(&decision).unwrap().contains(canary));
    }

    #[test]
    fn sanitizes_secret_classes_without_echoing_canaries() {
        let canary = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
        let input = format!(
            "Authorization: Bearer synthetic-access-token-123456\nDATABASE_URL=mysql://user:synthetic-password@example.test/db\ntoken={canary}\n"
        );
        let result = inspect(input.as_bytes(), &ScanConfig::default());
        assert_eq!(result.decision, ResultEffect::Sanitize);
        let output = result.content.unwrap();
        assert!(!output.contains(canary));
        assert!(!output.contains("synthetic-password"));
        assert!(output.contains("[REDACTED:CREDENTIAL]"));
    }

    #[test]
    fn structured_json_stays_valid_and_redacts_nested_fields() {
        let input = br#"{"user":{"mail":"phase15@example.test","pass":"synthetic-hash"},"customer_profile":{"city":"Brussels","nested":{"reference":42}},"safe":7}"#;
        let result = inspect(input, &ScanConfig::default());
        assert_eq!(result.decision, ResultEffect::Sanitize);
        let output = result.content.unwrap();
        let value: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(value["safe"], 7);
        assert_eq!(value["user"]["mail"], "[REDACTED:PERSONAL_DATA]");
        assert_eq!(value["user"]["pass"], "[REDACTED:CREDENTIAL]");
        assert_eq!(
            value["customer_profile"]["[REDACTED:CUSTOMER_DATA]:key0"],
            "[REDACTED:CUSTOMER_DATA]"
        );
        assert_eq!(
            value["customer_profile"]["[REDACTED:CUSTOMER_DATA]:key1"]["[REDACTED:CUSTOMER_DATA]:key0"],
            "[REDACTED:CUSTOMER_DATA]"
        );
        assert!(!output.contains("phase15@example.test"));

        let escaped = inspect(
            br#"{"note":"phase15\u0040example.test"}"#,
            &ScanConfig::default(),
        );
        assert!(!escaped.content.unwrap().contains("example.test"));

        let mut config = ScanConfig::default();
        config.sensitive_fields.insert(
            "password".to_owned(),
            crate::model::SensitivityCategory::PersonalData,
        );
        let built_in = inspect(br#"{"password":"synthetic"}"#, &config);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&built_in.content.unwrap()).unwrap()["password"],
            "[REDACTED:CREDENTIAL]"
        );
    }

    #[test]
    fn recognizes_checksums_ansi_and_unicode() {
        let input = "name=Zoë\nmail=phase\u{1b}[31m15@example.test\u{1b}[0m\ncard=4242 4242 4242 4242\niban=GB82 WEST 1234 5698 7654 32";
        let result = inspect(input.as_bytes(), &ScanConfig::default());
        let output = result.content.unwrap();
        assert!(!output.contains("example.test"));
        assert!(!output.contains("4242 4242"));
        assert!(!output.contains("GB82 WEST"));
        assert!(output.contains("Zoë"));
    }

    #[test]
    fn blocks_invalid_utf8_and_oversized_results() {
        assert_eq!(
            inspect(&[0xff], &ScanConfig::default()).decision,
            ResultEffect::Block
        );
        assert_eq!(
            inspect(
                &vec![b'x'; super::MAX_SCAN_BYTES + 1],
                &ScanConfig::default()
            )
            .decision,
            ResultEffect::Block
        );
    }

    #[test]
    fn covers_bounded_secret_and_contextual_personal_detectors() {
        let input = concat!(
            "-----BEGIN PRIVATE KEY-----\nSYNTHETICKEYDATA\n-----END PRIVATE KEY-----\n",
            "jwt=eyJhbGciOiJIUzI1NiJ9.c3ludGhldGljLXBheWxvYWQ.c3ludGhldGljLXNpZ25hdHVyZQ\n",
            "aws=AKIAABCDEFGHIJKLMNOP\n",
            "gitlab=glpat-abcdefghijklmnopqrst\n",
            "stripe=sk_live_abcdefghijklmnopqrst\n",
            "slack=xoxb-1234567890-abcdefghijkl\n",
            "oauth=ya29.abcdefghijklmnopqrst\n",
            "phone=+32 470 00 00 00\n",
            "date_of_birth=2000-01-02\n",
            "billing_address=Example Street 1\n"
        );
        let result = inspect(input.as_bytes(), &ScanConfig::default());
        assert_eq!(result.decision, ResultEffect::Sanitize);
        let output = result.content.unwrap();
        for canary in [
            "SYNTHETICKEYDATA",
            "eyJhbGciOiJIUzI1NiJ9",
            "AKIAABCDEFGHIJKLMNOP",
            "glpat-abcdefghijklmnopqrst",
            "sk_live_abcdefghijklmnopqrst",
            "xoxb-1234567890-abcdefghijkl",
            "ya29.abcdefghijklmnopqrst",
            "+32 470 00 00 00",
            "2000-01-02",
            "Example Street 1",
        ] {
            assert!(!output.contains(canary), "leaked {canary}");
        }
    }

    #[test]
    fn malformed_json_fails_closed_instead_of_plain_text_fallback() {
        let result = inspect(br#"{"token":"synthetic"#, &ScanConfig::default());
        assert_eq!(result.decision, ResultEffect::Block);
        assert!(result.content.is_none());
    }

    #[test]
    fn sanitizes_sensitive_json_keys_and_blocks_redaction_collisions() {
        let result = inspect(
            br#"{"phase15-key@example.test":"safe"}"#,
            &ScanConfig::default(),
        );
        let output = result.content.unwrap();
        assert!(!output.contains("phase15-key@example.test"));
        assert!(output.contains("[REDACTED:PERSONAL_DATA]"));

        let collision = inspect(
            br#"{"first@example.test":1,"second@example.test":2}"#,
            &ScanConfig::default(),
        );
        assert_eq!(collision.decision, ResultEffect::Block);
        assert!(collision.content.is_none());
    }

    #[test]
    fn finding_overflow_fails_closed() {
        let input = (0..=super::MAX_FINDINGS)
            .map(|index| format!("canary-{index}@example.test"))
            .collect::<Vec<_>>()
            .join(" ");
        let result = inspect(input.as_bytes(), &ScanConfig::default());
        assert_eq!(result.decision, ResultEffect::Block);
        assert_eq!(result.rule_id, "result.finding_limit");
        assert!(result.content.is_none());
    }

    #[test]
    fn sensitive_source_requires_complete_structured_coverage() {
        let table = b"uid|name\n---|---\n1|alice\n2|bob\n";
        let result = inspect_sensitive_source(table, &ScanConfig::default());
        assert_eq!(result.decision, ResultEffect::Sanitize);
        let output = result.content.unwrap();
        assert!(output.contains("uid|name"));
        assert!(!output.contains("alice"));
        assert!(!output.contains("bob"));

        let json = br#"{"uid":1,"name":"alice","nested":{"reference":42}}"#;
        let result = inspect_sensitive_source(json, &ScanConfig::default());
        let output = result.content.unwrap();
        assert!(!output.contains("alice"));
        assert!(!output.contains("42"));
        serde_json::from_str::<serde_json::Value>(&output).unwrap();

        let unstructured = inspect_sensitive_source(b"alice\n", &ScanConfig::default());
        assert_eq!(unstructured.decision, ResultEffect::Block);
        assert!(unstructured.content.is_none());
    }
}
