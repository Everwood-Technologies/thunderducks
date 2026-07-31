//! Thunderducks CLI client

fn main() {
    println!("tducks {}", env!("CARGO_PKG_VERSION"));
}

#[cfg(test)]
mod tests {
    #[test]
    fn smoke() {
        assert!(!env!("CARGO_PKG_VERSION").is_empty());
    }
}
