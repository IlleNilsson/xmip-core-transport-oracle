//! What a Location of this technology is configured with: its declaration,
//! which its wire hands `transport::sql`'s `Configured`, built with the
//! crate's `declaration` feature alone and the code behind the default
//! (ADR-0064, amendments 2026-09-26, 2026-10-22 and 2026-11-26), for the
//! library the surfaces load to carry (open problem 48): what every SQL
//! Location declares (`transport::sql`), with Oracle's service in place of
//! a database.

use transport::sql::accept::ACCEPT;
use transport::sql::{COLUMN, ENCODING, QUERY, TIMEOUT, USER};
use xcore::settings::{Applies, Kind, Presence, Setting, Settings};

/// The setting that names the service a Location connects for.
pub const SERVICE: Setting = Setting {
    name: "service",
    kind: Kind::Text,
    presence: Presence::Required,
    meaning: "The service name a Location connects for and reads or inserts in.",
    applies: Applies::Both,
};

/// Every setting an Oracle Location takes beyond its address, the
/// listener's host and port.
pub const SETTINGS: &Settings = &Settings {
    technology: env!("CARGO_PKG_NAME"),
    settings: &[SERVICE, USER, QUERY, ACCEPT, COLUMN, ENCODING, TIMEOUT],
};

/// The schemes a Location's address is entered with to choose this technology.
pub const SCHEMES: &[&str] = &["oracle"];
