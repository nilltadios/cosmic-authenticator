//! Text that must not linger in memory or show up in logs: passwords typed
//! into the app. The buffer is wiped when dropped, and `Debug` never prints it,
//! because app messages derive `Debug`.

use zeroize::Zeroizing;

#[derive(Clone, Default, PartialEq)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<String> for Secret {
    fn from(text: String) -> Self {
        Secret(Zeroizing::new(text))
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(…)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_prints_its_text() {
        let secret = Secret::from(String::from("hunter2"));
        assert_eq!(format!("{secret:?}"), "Secret(…)");
        assert_eq!(secret.as_str(), "hunter2");
    }
}
