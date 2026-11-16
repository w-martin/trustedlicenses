//! Pure-Rust core of `trustedlicenses`: license detection and policy evaluation.

pub mod config;
pub mod detection;
pub mod index;
pub mod index_discovery;
pub mod match_cache;
pub mod matcher;
pub mod policy;
pub mod sources;

pub use matcher::scan_license_text;
