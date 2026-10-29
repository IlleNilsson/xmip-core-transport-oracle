//! What a Location declares for this technology, and the transport it builds
//! from it (ADR-0064, amendment 2026-09-26).

use transport::Configured;
use transport::error::Result;
use transport::sql::{COLUMN, Column, ENCODING, accept};
use xcore::settings::{Applies, Fixed, Kind, Presence, Read, Setting, Settings};

use crate::{DEFAULT_QUERY, OracleTransport, SCHEMES};

impl Configured for OracleTransport {
    /// The password the Location's secret holds, read at each login.
    fn secured_by(mut self, secret: transport::Secured) -> Result<Self> {
        self.secret = Some(secret);
        Ok(self)
    }

    /// The address is the listener's host and port: where a Location
    /// connects.
    const SETTINGS: &'static Settings = &Settings {
        technology: env!("CARGO_PKG_NAME"),
        settings: &[
            Setting {
                name: "service",
                kind: Kind::Text,
                presence: Presence::Required,
                meaning: "The service name a Location connects for and reads or inserts in.",
                applies: Applies::Both,
            },
            Setting {
                name: "user",
                kind: Kind::Text,
                presence: Presence::Required,
                meaning: "The user a Location logs in as.",
                applies: Applies::Both,
            },
            Setting {
                name: "query",
                kind: Kind::Text,
                presence: Presence::Default(Fixed::Text(DEFAULT_QUERY)),
                meaning: "The query a receive runs: the first column names the row, the last \
                          is the Stream.",
                applies: Applies::Receive,
            },
            accept::ACCEPT,
            COLUMN,
            ENCODING,
            Setting {
                name: "timeout",
                kind: Kind::Duration,
                presence: Presence::Optional,
                meaning: "How long a server that stops mid-packet is waited on; unbounded \
                          when left out.",
                applies: Applies::Both,
            },
        ],
    };

    /// The schemes a Location's address is entered with to choose this technology.
    const SCHEMES: &'static [&'static str] = SCHEMES;

    /// The password is the secret the Location names, never a
    /// setting.
    fn configured(address: &str, settings: &Read) -> Result<Self> {
        let mut transport = Self::new(address, settings.text("service"), settings.text("user"));
        if let Some(query) = settings.optional_text("query") {
            transport = transport.with_query(query);
        }
        if let Some(statement) = settings.optional_text(accept::ACCEPT.name) {
            transport = transport.with_accept(statement);
        }
        if let Some(timeout) = settings.optional_duration("timeout") {
            transport = transport.timing_out_after(timeout);
        }
        Ok(transport.holding(Column::configured(settings)?))
    }
}
