//! This technology's declaration: the transport guide's "The declaration",
//! `module/core/capability/transport/doc/adding-a-transport.md`. Its wire
//! hands it to `transport::sql`'s `Configured`. What every SQL Location
//! declares stays `transport::sql`'s. Oracle's service takes the place of a
//! database.

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

/// This technology's schemes, as [`transport::Configured::SCHEMES`] defines
/// them.
pub const SCHEMES: &[&str] = &["oracle"];
