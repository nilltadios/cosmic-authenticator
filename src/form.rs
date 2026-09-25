//! The add and edit form. Entries are built and changed through Proton's
//! core. Proton's code generator falls back to a secret's raw bytes when it is
//! not Base32, so a mistyped key would silently make wrong codes; the form
//! therefore checks new and changed TOTP secrets itself.

use proton_authenticator::{
    Algorithm, AuthenticatorEntry, AuthenticatorEntryContent, AuthenticatorEntrySteamCreateParameters,
    AuthenticatorEntryTotpCreateParameters, AuthenticatorEntryType, AuthenticatorEntryUpdateContents,
};

pub const ALGORITHMS: [Algorithm; 3] = [Algorithm::SHA1, Algorithm::SHA256, Algorithm::SHA512];
pub const ALGORITHM_LABELS: [&str; 3] = ["SHA1", "SHA256", "SHA512"];
pub const TYPE_LABELS: [&str; 2] = ["TOTP", "Steam"];
const DEFAULT_DIGITS: u8 = 6;
const DEFAULT_PERIOD: u16 = 30;

#[derive(Debug, Clone)]
pub struct EntryForm {
    /// The id of the entry being edited, `None` when adding.
    pub editing: Option<String>,
    pub name: String,
    pub secret: String,
    pub issuer: String,
    pub steam: bool,
    pub digits: u8,
    pub period: String,
    pub algorithm: usize,
    pub note: Option<String>,
    pub show_advanced: bool,
    pub error: Option<String>,
}

impl Default for EntryForm {
    fn default() -> Self {
        EntryForm {
            editing: None,
            name: String::new(),
            secret: String::new(),
            issuer: String::new(),
            steam: false,
            digits: DEFAULT_DIGITS,
            period: DEFAULT_PERIOD.to_string(),
            algorithm: 0,
            note: None,
            show_advanced: false,
            error: None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Field {
    Name(String),
    Secret(String),
    Issuer(String),
    Steam(bool),
    Digits(usize),
    Period(String),
    Algorithm(usize),
    ShowAdvanced,
}

/// Secrets are often shown in spaced groups, such as `jbsw y3dp ehpk 3pxp`.
fn clean_secret(secret: &str) -> String {
    secret.chars().filter(|c| !c.is_whitespace() && *c != '-').collect::<String>().to_uppercase()
}

/// RFC 4648 Base32: letters, digits 2 to 7, and trailing `=` padding.
fn is_base32(secret: &str) -> bool {
    let data = secret.trim_end_matches('=');
    !data.is_empty() && data.chars().all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c))
}

impl EntryForm {
    pub fn edit(entry: &AuthenticatorEntry) -> Self {
        let mut form = EntryForm {
            editing: Some(entry.id.clone()),
            name: entry.name(),
            secret: entry.secret(),
            issuer: entry.issuer(),
            note: entry.note.clone(),
            ..EntryForm::default()
        };
        match &entry.content {
            AuthenticatorEntryContent::Totp(totp) => {
                form.digits = totp.get_digits();
                form.period = totp.get_period().to_string();
                form.algorithm = ALGORITHMS.iter().position(|a| *a == totp.get_algorithm()).unwrap_or(0);
                let non_default =
                    form.digits != DEFAULT_DIGITS || totp.get_period() != DEFAULT_PERIOD || form.algorithm != 0;
                form.show_advanced = non_default;
            }
            AuthenticatorEntryContent::Steam(_) => {
                form.steam = true;
                form.show_advanced = true;
            }
        }
        form
    }

    /// Choices for the digits dropdown: Proton's 6 to 8, plus whatever an
    /// imported entry already uses.
    pub fn digit_options(&self) -> Vec<u8> {
        let mut options = vec![6, 7, 8];
        if !options.contains(&self.digits) {
            options.push(self.digits);
            options.sort_unstable();
        }
        options
    }

    pub fn apply(&mut self, field: Field) {
        self.error = None;
        match field {
            Field::Name(name) => self.name = name,
            Field::Secret(secret) => {
                // A pasted link fills in the whole form.
                if secret.trim().starts_with("otpauth://")
                    && let Ok(entry) = AuthenticatorEntry::from_uri(secret.trim(), None)
                {
                    let editing = self.editing.take();
                    let note = self.note.take();
                    *self = EntryForm { editing, note, ..EntryForm::edit(&entry) };
                } else {
                    self.secret = secret;
                }
            }
            Field::Issuer(issuer) => self.issuer = issuer,
            Field::Steam(steam) => self.steam = steam,
            Field::Digits(index) => self.digits = self.digit_options()[index],
            Field::Period(period) => self.period = period.chars().filter(char::is_ascii_digit).collect(),
            Field::Algorithm(index) => self.algorithm = index,
            Field::ShowAdvanced => self.show_advanced = !self.show_advanced,
        }
    }

    fn period(&self) -> Result<u16, String> {
        match self.period.parse::<u16>() {
            Ok(period) if (1..=300).contains(&period) => Ok(period),
            _ => Err(String::from("The time interval must be between 1 and 300 seconds")),
        }
    }

    /// Builds the new entry, or applies the form to `existing` when editing.
    pub fn build(&self, existing: Option<&AuthenticatorEntry>) -> Result<AuthenticatorEntry, String> {
        let name = self.name.trim().to_string();
        let secret = clean_secret(&self.secret);
        let issuer = self.issuer.trim().to_string();
        if name.is_empty() && issuer.is_empty() {
            return Err(String::from("Enter a title or an issuer"));
        }
        if secret.is_empty() {
            return Err(String::from("Enter the secret key"));
        }
        // An unchanged secret is kept exactly as stored: for a secret that is
        // not Base32, the core hashes its raw bytes, so even its case matters.
        let secret = match existing {
            Some(entry) if clean_secret(&entry.secret()) == secret => entry.secret(),
            _ if !self.steam && !is_base32(&secret) => {
                return Err(String::from(
                    "The secret key is not valid. It uses the letters A to Z and the digits 2 to 7, \
                     such as JBSWY3DPEHPK3PXP.",
                ));
            }
            _ => secret,
        };
        // Proton's core requires a title, and many sites give only an issuer.
        let name = if name.is_empty() { issuer.clone() } else { name };

        match existing {
            Some(existing) => {
                let mut entry = existing.clone();
                entry
                    .update(AuthenticatorEntryUpdateContents {
                        name,
                        secret,
                        issuer,
                        period: if self.steam { 0 } else { self.period()? },
                        digits: self.digits,
                        algorithm: ALGORITHMS[self.algorithm],
                        note: self.note.clone(),
                        entry_type: if self.steam { AuthenticatorEntryType::Steam } else { AuthenticatorEntryType::Totp },
                    })
                    .map_err(|error| format!("Cannot save this code: {error:?}"))?;
                Ok(entry)
            }
            None if self.steam => AuthenticatorEntry::new_steam_entry_from_params(AuthenticatorEntrySteamCreateParameters {
                name,
                secret,
                note: self.note.clone(),
            })
            .map_err(|_| String::from("This is not a valid Steam secret")),
            None => AuthenticatorEntry::new_totp_entry_from_params(AuthenticatorEntryTotpCreateParameters {
                name,
                secret,
                issuer,
                period: Some(self.period()?),
                digits: Some(self.digits),
                algorithm: Some(ALGORITHMS[self.algorithm]),
                note: self.note.clone(),
            })
            .map_err(|error| format!("Cannot save this code: {error:?}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_a_totp_entry_from_a_spaced_lowercase_secret() {
        let form = EntryForm {
            name: String::from("me@example.com"),
            secret: String::from("jbsw y3dp ehpk 3pxp"),
            issuer: String::from("GitHub"),
            ..EntryForm::default()
        };
        let entry = form.build(None).unwrap();
        assert_eq!(entry.secret(), "JBSWY3DPEHPK3PXP");
        assert_eq!(entry.issuer(), "GitHub");
        assert_eq!(entry.period(), 30);
    }

    #[test]
    fn rejects_a_secret_that_is_not_base32() {
        for secret in ["not a secret!", "JBSWY3DPEHPK3PX0", "===="] {
            let form = EntryForm { name: String::from("x"), secret: String::from(secret), ..EntryForm::default() };
            assert!(form.build(None).is_err(), "{secret}");
        }
    }

    #[test]
    fn renaming_keeps_an_imported_secret_that_is_not_base32() {
        let original = AuthenticatorEntry::from_uri("otpauth://totp/me?secret=abc1&issuer=Old", None).unwrap();
        let mut form = EntryForm::edit(&original);
        form.apply(Field::Issuer(String::from("New")));
        let edited = form.build(Some(&original)).unwrap();
        assert_eq!(edited.issuer(), "New");
        assert_eq!(edited.secret(), "abc1");
    }

    #[test]
    fn uses_the_issuer_when_the_title_is_empty() {
        let form = EntryForm { issuer: String::from("ngrok"), secret: String::from("JBSWY3DPEHPK3PXP"), ..EntryForm::default() };
        assert_eq!(form.build(None).unwrap().name(), "ngrok");
    }

    #[test]
    fn editing_keeps_the_id_and_note() {
        let original = AuthenticatorEntry::from_uri(
            "otpauth://totp/me?secret=JBSWY3DPEHPK3PXP&issuer=Old&digits=8&period=60",
            Some(String::from("recovery codes in the safe")),
        )
        .unwrap();
        let mut form = EntryForm::edit(&original);
        assert!(form.show_advanced);
        assert_eq!(form.digits, 8);
        form.apply(Field::Issuer(String::from("New")));
        let edited = form.build(Some(&original)).unwrap();
        assert_eq!(edited.id, original.id);
        assert_eq!(edited.issuer(), "New");
        assert_eq!(edited.period(), 60);
        assert_eq!(edited.note.as_deref(), Some("recovery codes in the safe"));
    }

    #[test]
    fn a_pasted_link_fills_the_form() {
        let mut form = EntryForm::default();
        form.apply(Field::Secret(String::from(
            "otpauth://totp/Parsec:me@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Parsec&algorithm=SHA256",
        )));
        assert_eq!(form.issuer, "Parsec");
        assert_eq!(form.name, "me@example.com");
        assert_eq!(ALGORITHM_LABELS[form.algorithm], "SHA256");
    }
}
