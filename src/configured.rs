//! What a Location declares for this technology (ADR-0064, amendment
//! 2026-09-26): what every SQL Location declares (`transport::sql`), with
//! Oracle's service in place of a database.

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
