//! Reads codes from other apps' exports, QR code images and `otpauth://` links.
//!
//! The format is detected from the content, so one "Import" action covers
//! every source Proton's core can parse: Proton Authenticator, Proton Pass,
//! Aegis, 2FAS, Bitwarden, Ente, LastPass and Google Authenticator.

use proton_authenticator::{
    AuthenticatorEntry, ImportResult, ThirdPartyImportError, parse_2fas_file, parse_aegis_json, parse_bitwarden_csv,
    parse_bitwarden_json, parse_ente_encrypted, parse_google_authenticator_totp, parse_lastpass_json,
    parse_pass_zip, parse_proton_authenticator_export, parse_proton_authenticator_export_with_password,
};

#[derive(Debug)]
pub struct Imported {
    pub entries: Vec<AuthenticatorEntry>,
    /// Entries the source held but that could not be read, such as HOTP codes.
    pub failed: usize,
}

impl From<ImportResult> for Imported {
    fn from(result: ImportResult) -> Self {
        Imported { failed: result.errors.len(), entries: result.entries }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportError {
    Unrecognized,
    NoQrCode,
    PasswordRequired,
    WrongPassword,
}

impl ImportError {
    pub fn message(self) -> &'static str {
        match self {
            ImportError::Unrecognized => "No codes found. The file is not an export this app can read.",
            ImportError::NoQrCode => "No QR code found in the image",
            ImportError::PasswordRequired => "This export needs a password",
            ImportError::WrongPassword => "Wrong password",
        }
    }
}

/// Imports a file's contents. Zip files are read as Proton Pass exports and
/// images are scanned for a QR code; anything else is read as text.
pub fn import_bytes(bytes: &[u8], password: Option<&str>) -> Result<Imported, ImportError> {
    if bytes.starts_with(b"PK\x03\x04") {
        return parse_pass_zip(bytes).map(Imported::from).map_err(|_| ImportError::Unrecognized);
    }
    if image::guess_format(bytes).is_ok() {
        let text = read_qr_code(bytes).ok_or(ImportError::NoQrCode)?;
        return import_text(&text, password);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ImportError::Unrecognized)?;
    import_text(text, password)
}

/// Returns the text of the first readable QR code in an image. Transparent
/// pixels count as white, as they do in Proton's reader, since QR codes saved
/// from web pages often have a transparent background.
fn read_qr_code(bytes: &[u8]) -> Option<String> {
    let image = image::load_from_memory(bytes).ok()?.into_rgba8();
    let luma = |x: usize, y: usize| {
        let [r, g, b, a] = image.get_pixel(x as u32, y as u32).0;
        let grey = (306 * u32::from(r) + 601 * u32::from(g) + 117 * u32::from(b) + 512) >> 10;
        let alpha = u32::from(a);
        ((grey * alpha + 255 * (255 - alpha)) / 255) as u8
    };
    let mut prepared = rqrr::PreparedImage::prepare_from_greyscale(image.width() as usize, image.height() as usize, luma);
    prepared.detect_grids().into_iter().find_map(|grid| grid.decode().ok().map(|(_, text)| text))
}

pub fn import_text(text: &str, password: Option<&str>) -> Result<Imported, ImportError> {
    let text = text.trim_start_matches('\u{feff}').trim();
    if text.starts_with("otpauth-migration://") {
        return from_lines(text, |line| {
            parse_google_authenticator_totp(line).map(|result| result.entries).map_err(|_| ())
        });
    }
    if text.starts_with("otpauth://") || text.starts_with("steam://") {
        return from_lines(text, |line| AuthenticatorEntry::from_uri(line, None).map(|entry| vec![entry]).map_err(|_| ()));
    }
    if text.starts_with('{') || text.starts_with('[') {
        return from_json(text, password);
    }
    match parse_bitwarden_csv(text) {
        Ok(result) if !result.entries.is_empty() => Ok(result.into()),
        _ => Err(ImportError::Unrecognized),
    }
}

/// One link per line, as Aegis and Ente plain-text exports and most
/// "copy link" buttons produce. Lines that fail count as failed entries.
fn from_lines(
    text: &str,
    parse: impl Fn(&str) -> Result<Vec<AuthenticatorEntry>, ()>,
) -> Result<Imported, ImportError> {
    let mut imported = Imported { entries: Vec::new(), failed: 0 };
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        match parse(line) {
            Ok(entries) => imported.entries.extend(entries),
            Err(()) => imported.failed += 1,
        }
    }
    if imported.entries.is_empty() { Err(ImportError::Unrecognized) } else { Ok(imported) }
}

fn is_ente_encrypted(text: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(text)
        .is_ok_and(|value| value.get("kdfParams").is_some() && value.get("encryptedData").is_some())
}

/// Tries each JSON format in turn. A parser can accept another app's file and
/// find nothing in it, so an empty result only wins when no parser finds codes
/// and none asks for a password.
fn from_json(text: &str, password: Option<&str>) -> Result<Imported, ImportError> {
    let owned_password = || password.map(String::from);
    let attempts: [&dyn Fn() -> Result<ImportResult, ThirdPartyImportError>; 6] = [
        &|| match password {
            Some(password) => parse_proton_authenticator_export_with_password(text, password),
            None => parse_proton_authenticator_export(text),
        },
        &|| parse_aegis_json(text, owned_password()).map_err(Into::into),
        &|| parse_2fas_file(text, owned_password()).map_err(Into::into),
        &|| parse_bitwarden_json(text).map_err(Into::into),
        &|| parse_lastpass_json(text).map_err(Into::into),
        &|| {
            if !is_ente_encrypted(text) {
                return Err(ThirdPartyImportError::BadContent);
            }
            match password {
                Some(password) => parse_ente_encrypted(text, password).map_err(Into::into),
                None => Err(ThirdPartyImportError::MissingPassword),
            }
        },
    ];

    let mut empty = None;
    let mut error = ImportError::Unrecognized;
    for attempt in attempts {
        match attempt() {
            Ok(result) if !result.entries.is_empty() => return Ok(result.into()),
            Ok(result) => empty = empty.or(Some(result)),
            Err(ThirdPartyImportError::BadPassword | ThirdPartyImportError::DecryptionFailed) => {
                error = ImportError::WrongPassword;
            }
            Err(ThirdPartyImportError::MissingPassword) if error != ImportError::WrongPassword => {
                error = ImportError::PasswordRequired;
            }
            Err(_) => {}
        }
    }
    match (error, empty) {
        (ImportError::Unrecognized, Some(result)) if !result.errors.is_empty() => Ok(result.into()),
        (error, _) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proton_authenticator::{AuthenticatorClient, AuthenticatorEntryTotpCreateParameters};

    fn sample() -> Vec<AuthenticatorEntry> {
        ["GitHub", "Proton"]
            .into_iter()
            .map(|issuer| {
                AuthenticatorEntry::new_totp_entry_from_params(AuthenticatorEntryTotpCreateParameters {
                    name: format!("someone@{issuer}"),
                    secret: String::from("JBSWY3DPEHPK3PXP"),
                    issuer: issuer.to_string(),
                    period: None,
                    digits: None,
                    algorithm: None,
                    note: None,
                })
                .unwrap()
            })
            .collect()
    }

    fn issuers(imported: &Imported) -> Vec<String> {
        imported.entries.iter().map(AuthenticatorEntry::issuer).collect()
    }

    #[test]
    fn reads_a_plain_proton_export() {
        let export = AuthenticatorClient::new().export_entries(sample()).unwrap();
        let imported = import_bytes(export.as_bytes(), None).unwrap();
        assert_eq!(issuers(&imported), ["GitHub", "Proton"]);
    }

    #[test]
    fn asks_for_and_checks_the_password_of_a_proton_export() {
        let export = AuthenticatorClient::new().export_entries_with_password(sample(), "hunter2").unwrap();
        assert_eq!(import_bytes(export.as_bytes(), None).unwrap_err(), ImportError::PasswordRequired);
        assert_eq!(import_bytes(export.as_bytes(), Some("wrong")).unwrap_err(), ImportError::WrongPassword);
        let imported = import_bytes(export.as_bytes(), Some("hunter2")).unwrap();
        assert_eq!(issuers(&imported), ["GitHub", "Proton"]);
    }

    #[test]
    fn reads_one_link_per_line_and_counts_bad_lines() {
        let text = "otpauth://totp/GitHub:me?secret=JBSWY3DPEHPK3PXP&issuer=GitHub\n\
                    otpauth://hotp/Old:me?secret=JBSWY3DPEHPK3PXP&counter=1\n\
                    otpauth://totp/Proton:me?secret=JBSWY3DPEHPK3PXP&issuer=Proton\n";
        let imported = import_text(text, None).unwrap();
        assert_eq!(issuers(&imported), ["GitHub", "Proton"]);
        assert_eq!(imported.failed, 1);
    }

    #[test]
    fn reads_the_demo_export() {
        let demo = include_str!("../demo/demo-export.json");
        assert_eq!(import_text(demo, None).unwrap().entries.len(), 11);
    }

    #[test]
    fn reads_a_qr_code_image() {
        // Made by demo/make-demo-qr.py.
        let imported = import_bytes(include_bytes!("../demo/demo-qr.png"), None).unwrap();
        assert_eq!(issuers(&imported), ["Demo"]);
        assert_eq!(imported.entries[0].name(), "demo@example.com");
    }

    #[test]
    fn rejects_unrelated_content() {
        assert_eq!(import_text("hello", None).unwrap_err(), ImportError::Unrecognized);
        assert_eq!(import_text("{\"a\": 1}", None).unwrap_err(), ImportError::Unrecognized);
        assert_eq!(import_bytes(&[0xff, 0xfe, 0x00], None).unwrap_err(), ImportError::Unrecognized);
    }
}
