//! Device keys and vodozemac E2EE wrappers
//!
//! Part of the Thunderducks MVP (AIDLC Gate 4 construction).

/// Crate smoke marker used by CI.
pub fn crate_name() -> &'static str {
    env!("CARGO_PKG_NAME")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_name() {
        assert_eq!(crate_name(), "td-crypto");
    }
}
