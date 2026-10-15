pub fn redact_sensitive_str(input: &str) -> String {
    // Redact password patterns, tokens, and basic auth in URLs
    let mut result = input.to_string();

    // Redact URL credentials: http://user:pass@host -> http://user:[REDACTED]@host
    if let Some(start) = result.find("://") {
        if let Some(at) = result[start + 3..].find('@') {
            let userpass = &result[start + 3..start + 3 + at];
            if let Some(colon) = userpass.find(':') {
                let to_replace = &userpass[colon + 1..];
                result = result.replace(to_replace, "[REDACTED]");
            }
        }
    }

    result
}

pub fn mask_credential(cred: &str) -> String {
    if cred.len() <= 4 {
        "****".to_string()
    } else {
        format!("{}****", &cred[..2])
    }
}
