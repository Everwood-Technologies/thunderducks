//! Optional untrusted store-and-forward assist relay

fn main() {
    println!("td-relay {}", env!("CARGO_PKG_VERSION"));
}

#[cfg(test)]
mod tests {
    #[test]
    fn smoke() {
        assert!(!env!("CARGO_PKG_VERSION").is_empty());
    }
}
