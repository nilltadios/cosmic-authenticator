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
///
/// rqrr's own thresholding misses small, smoothed codes, such as a
/// screenshot of a web page where a module is about 4 px and not a whole
/// number of pixels. Those read after a global (Otsu) threshold or a smooth
/// 3x upscale, so both are tried when the image as it is gives nothing.
fn read_qr_code(bytes: &[u8]) -> Option<String> {
    let image = image::load_from_memory(bytes).ok()?.into_rgba8();
    let grey = image::GrayImage::from_fn(image.width(), image.height(), |x, y| {
        let [r, g, b, a] = image.get_pixel(x, y).0;
        let grey = (306 * u32::from(r) + 601 * u32::from(g) + 117 * u32::from(b) + 512) >> 10;
        let alpha = u32::from(a);
        image::Luma([((grey * alpha + 255 * (255 - alpha)) / 255) as u8])
    });
    decode_qr(&grey)
        .or_else(|| {
            let threshold = otsu_threshold(&grey);
            decode_qr(&image::GrayImage::from_fn(grey.width(), grey.height(), |x, y| {
                image::Luma([if grey.get_pixel(x, y).0[0] <= threshold { 0 } else { 255 }])
            }))
        })
        .or_else(|| {
            // Only small images: a 3x copy of a large photo costs a lot of
            // memory, and large images rarely have modules this small.
            (grey.width().max(grey.height()) <= 1200).then_some(())?;
            let filter = image::imageops::FilterType::Triangle;
            decode_qr(&image::imageops::resize(&grey, grey.width() * 3, grey.height() * 3, filter))
        })
}

fn decode_qr(grey: &image::GrayImage) -> Option<String> {
    let mut prepared = rqrr::PreparedImage::prepare_from_greyscale(grey.width() as usize, grey.height() as usize, |x, y| {
        grey.get_pixel(x as u32, y as u32).0[0]
    });
    prepared.detect_grids().into_iter().find_map(|grid| grid.decode().ok().map(|(_, text)| text))
}

/// The grey level that best splits the image into dark and light pixels
/// (Otsu's method: the largest variance between the two groups).
fn otsu_threshold(grey: &image::GrayImage) -> u8 {
    let mut histogram = [0u64; 256];
    for pixel in grey.pixels() {
        histogram[usize::from(pixel.0[0])] += 1;
    }
    let total: u64 = histogram.iter().sum();
    let sum: u64 = histogram.iter().enumerate().map(|(level, &count)| level as u64 * count).sum();
    let (mut dark_count, mut dark_sum) = (0u64, 0u64);
    let (mut best, mut best_variance) = (127u8, 0f64);
    for (level, &count) in histogram.iter().enumerate() {
        dark_count += count;
        dark_sum += level as u64 * count;
        let light_count = total - dark_count;
        if dark_count == 0 || light_count == 0 {
            continue;
        }
        let dark_mean = dark_sum as f64 / dark_count as f64;
        let light_mean = (sum - dark_sum) as f64 / light_count as f64;
        let variance = dark_count as f64 * light_count as f64 * (dark_mean - light_mean).powi(2);
        if variance > best_variance {
            (best, best_variance) = (level as u8, variance);
        }
    }
    best
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
    fn reads_a_small_qr_code_from_a_screenshot() {
        // Made by demo/make-small-qr.py: about 3 px per module, smoothed.
        let imported = import_bytes(include_bytes!("../demo/small-qr.png"), None).unwrap();
        assert_eq!(issuers(&imported), ["Example"]);
    }

    #[test]
    #[ignore = "run by demo/qr-sweep.sh"]
    fn reads_every_qr_code_in_qr_dir() {
        let mut missed = Vec::new();
        for entry in std::fs::read_dir(std::env::var("QR_DIR").unwrap()).unwrap() {
            let path = entry.unwrap().path();
            let bytes = std::fs::read(&path).unwrap();
            let read = read_qr_code(&bytes).is_some_and(|text| text.starts_with("otpauth"));
            // Whether rqrr alone, on the image as it is, would have read it.
            let plain = decode_qr(&image::load_from_memory(&bytes).unwrap().into_luma8()).is_some();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            eprintln!("{name}: {} (rqrr alone: {})", if read { "read" } else { "MISSED" }, if plain { "read" } else { "missed" });
            if !read {
                missed.push(path);
            }
        }
        assert!(missed.is_empty(), "missed {missed:?}");
    }

    #[test]
    fn rejects_unrelated_content() {
        assert_eq!(import_text("hello", None).unwrap_err(), ImportError::Unrecognized);
        assert_eq!(import_text("{\"a\": 1}", None).unwrap_err(), ImportError::Unrecognized);
        assert_eq!(import_bytes(&[0xff, 0xfe, 0x00], None).unwrap_err(), ImportError::Unrecognized);
    }
}
