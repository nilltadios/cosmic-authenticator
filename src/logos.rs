//! Service logos. Proton's issuer list maps an issuer name to a logo address,
//! usually the service's own site or Google's favicon service, the same source
//! Proton Authenticator loads from. Downloads are cached in
//! `$XDG_CACHE_HOME/cosmic-authenticator/logos`, so each logo is fetched once.

use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

use cosmic::widget::image::Handle;
use proton_authenticator::TOTPIssuerMapper;

use crate::store::xdg_dir;

/// Largest logo download accepted, far above any real favicon.
const MAX_BYTES: u64 = 1 << 20;
/// Pixels per side after decoding: the tile is 36 logical pixels, and this
/// keeps logos sharp at 2x scaling.
const SIZE: u32 = 72;

pub enum Logo {
    Loading,
    Ready(Handle),
    /// No logo is known, or it failed to load. The letter tile is shown instead.
    Missing,
}

pub struct Logos {
    mapper: TOTPIssuerMapper,
    by_issuer: HashMap<String, Logo>,
}

/// What the app needs to fetch: the issuer key and the logo address.
pub struct Fetch {
    pub key: String,
    pub url: String,
    pub cache: PathBuf,
}

pub fn key(issuer: &str) -> String {
    issuer.trim().to_lowercase()
}

fn cache_dir() -> PathBuf {
    xdg_dir("XDG_CACHE_HOME", ".cache").join("logos")
}

/// Domains come from Proton's list, but keep only filename-safe characters
/// before using one as a path.
fn cache_path(domain: &str) -> PathBuf {
    let name: String = domain
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c.to_ascii_lowercase() } else { '_' })
        .collect();
    cache_dir().join(format!("{name}.img"))
}

pub fn decode(bytes: &[u8]) -> Option<Handle> {
    let image = image::load_from_memory(bytes).ok()?;
    let image = image.resize(SIZE, SIZE, image::imageops::FilterType::Lanczos3).into_rgba8();
    Some(Handle::from_rgba(image.width(), image.height(), image.into_raw()))
}

impl Logos {
    pub fn new() -> Self {
        Logos { mapper: TOTPIssuerMapper::new(), by_issuer: HashMap::new() }
    }

    pub fn get(&self, issuer: &str) -> Option<&Handle> {
        match self.by_issuer.get(&key(issuer)) {
            Some(Logo::Ready(handle)) => Some(handle),
            _ => None,
        }
    }

    /// Loads cached logos for these issuers and returns the ones to download.
    pub fn request<'a>(&mut self, issuers: impl IntoIterator<Item = &'a str>) -> Vec<Fetch> {
        let mut fetches = Vec::new();
        for issuer in issuers {
            let key = key(issuer);
            if key.is_empty() || self.by_issuer.contains_key(&key) {
                continue;
            }
            let Some(info) = self.mapper.lookup(&key) else {
                self.by_issuer.insert(key, Logo::Missing);
                continue;
            };
            let cache = cache_path(&info.domain);
            if let Some(handle) = std::fs::read(&cache).ok().and_then(|bytes| decode(&bytes)) {
                self.by_issuer.insert(key, Logo::Ready(handle));
                continue;
            }
            self.by_issuer.insert(key.clone(), Logo::Loading);
            fetches.push(Fetch { key, url: info.icon_url, cache });
        }
        fetches
    }

    pub fn finish(&mut self, key: String, handle: Option<Handle>) {
        self.by_issuer.insert(key, handle.map_or(Logo::Missing, Logo::Ready));
    }
}

/// Downloads a logo and caches it. Blocking, so it runs on its own thread.
pub fn download(fetch: &Fetch) -> Option<Handle> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(15)))
        .user_agent(concat!("cosmic-authenticator/", env!("CARGO_PKG_VERSION")))
        .build()
        .into();
    let response = agent.get(&fetch.url).call().ok()?;
    let mut bytes = Vec::new();
    response.into_body().into_reader().take(MAX_BYTES).read_to_end(&mut bytes).ok()?;
    let handle = decode(&bytes)?;
    if let Some(dir) = fetch.cache.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(&fetch.cache, &bytes);
    Some(handle)
}
