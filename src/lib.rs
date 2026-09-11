#![forbid(unsafe_code)]

//! Streams that arrive as rows. One row is one Stream: the last column of
//! a configured query is what Xmip carries, the first column is where it
//! came from.
//!
//! Oracle is the database under the enterprise's oldest systems, and a
//! table in one is an integration surface a partner already has: a
//! producer inserts, an integrator polls. A Receive Location runs its
//! query — `SELECT id, payload FROM inbox ORDER BY id` unless told
//! otherwise — and hands each row up; a Send Location inserts the Stream
//! as one bound RAW of one row, `INSERT INTO <table> (<column>) VALUES
//! (:1)`, so a byte is a byte both ways. What is spoken is Oracle Net
//! (TNS) on port 1521 — the connect and its accept (`tns.rs`) — with the
//! two-task common layer inside it (`ttc.rs`): a protocol and data-type
//! negotiation, the O5LOGON session key and authentication, then a
//! statement executed with a bind and its rows fetched, as
//! python-oracledb's thin mode speaks them. `client.rs` is Xmip's side;
//! `session.rs` is the listener a test or the loopback pair puts on the
//! far end.
//!
//! The O5LOGON verifier a real 11g or 12c server checks is an AES key
//! schedule over the password; that computation belongs to the identity
//! capability (ADR-0044), so this crate stands it in with a session-key
//! mix its own listener checks, the way TLS is deferred to the transport
//! capability (ADR-0033). A server that demands the real verifier or TLS
//! refuses the login, and this transport says so.
//!
//! Rows are artefacts and this transport claims none of them, per
//! ADR-0024: the atomic claim a database has, `SELECT ... FOR UPDATE SKIP
//! LOCKED`, holds only inside a transaction, and the flow here opens and
//! closes its connection inside one receive, so there is no transaction to
//! hold it across the Stream's lifetime. The query itself — a status
//! column, a `RETURNING` clause — is what keeps a row from arriving twice.
//!
//! The origin URI carries what the row knew: `oracle://server/service
//! ?row=41`. A send target is `oracle://host:1521/<service>/<table>
//! /<column>`, `host:1521/<service>/<table>/<column>`, or
//! `<table>/<column>` on the configured server and service.

pub mod client;
pub mod session;
pub mod tns;
pub mod ttc;

use std::net::TcpListener;
use std::time::Duration;

pub use client::{Client, Login, QueryResult, oracle_error};
pub use session::{Answer, Event, Session};
use transport::claim::{NoNativeClaim, ResourceClaim};
use transport::error::{Result, TransportError, protocol_error};
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
use transport::socket;
use transport::{Arrived, Directions, Transport};

/// What a Receive Location runs unless told otherwise.
pub const DEFAULT_QUERY: &str = "SELECT id, payload FROM inbox ORDER BY id";

/// What the loopback pair agrees on: one service, one user whose login the
/// far end takes as it comes, one table and column the payload is bound
/// into.
const LOOPBACK_SERVICE: &str = "XMIP";
const LOOPBACK_USER: &str = "xmip";
const LOOPBACK_TARGET: &str = "inbox/payload";

#[derive(Clone)]
pub struct OracleTransport {
    server: String,
    service: String,
    login: Login,
    query: String,
    timeout: Option<Duration>,
}

impl OracleTransport {
    /// Speak to the listener at `server`, for `service`, as `user` with no
    /// password until one is given.
    #[must_use]
    pub fn new(
        server: impl Into<String>,
        service: impl Into<String>,
        user: impl Into<String>,
    ) -> Self {
        Self {
            server: server.into(),
            service: service.into(),
            login: Login::new(user, ""),
            query: DEFAULT_QUERY.to_string(),
            timeout: None,
        }
    }

    /// The password the login answers the session key with.
    #[must_use]
    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.login.password = password.into();
        self
    }

    /// The query a receive runs: the first column is the row's name, the
    /// last is the Stream.
    #[must_use]
    pub fn with_query(mut self, query: impl Into<String>) -> Self {
        self.query = query.into();
        self
    }

    /// Give up on a server that stops mid-packet.
    #[must_use]
    pub const fn timing_out_after(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Connect and log in.
    ///
    /// # Errors
    /// Where the server could not be reached or refused the login.
    pub fn connect(&self) -> Result<Client> {
        self.connect_to(&self.server, &self.service)
    }

    fn connect_to(&self, server: &str, service: &str) -> Result<Client> {
        Client::connect(server, &connect_string(service), &self.login, self.timeout)
    }

    /// Bind as the listener clients connect to, and report the address.
    ///
    /// # Errors
    /// Where the address is taken, malformed, or not permitted.
    pub fn bind(&self) -> Result<(TcpListener, String)> {
        socket::bind_tcp(&self.server)
    }

    /// Accept one client on an already-bound listener, demanding this
    /// transport's login.
    ///
    /// # Errors
    /// Where the connection could not be accepted or the login failed.
    pub fn accept_one(&self, listener: &TcpListener) -> Result<Session> {
        Session::accept(listener, Some(&self.login), self.timeout)
    }

    /// Where a target names the server, service, table and column, or some
    /// suffix of them on what this transport is configured with.
    fn resolve<'a>(&'a self, target: &'a str) -> Result<(&'a str, &'a str, &'a str, &'a str)> {
        let (server, path) = socket::target("oracle", target)
            .or_else(|| match target.split_once('/') {
                Some((peer, path)) if peer.contains(':') => Some((peer, path)),
                _ => None,
            })
            .unwrap_or((&self.server, target));
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        match segments.as_slice() {
            [service, table, column] => Ok((server, service, table, column)),
            [table, column] => Ok((server, &self.service, table, column)),
            _ => Err(TransportError::permanent(format!(
                "{target:?} is not service/table/column or table/column"
            ))),
        }
    }
}

/// A connect string a listener reads a service out of.
fn connect_string(service: &str) -> String {
    format!("(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME={service})))")
}

impl Transport for OracleTransport {
    fn name(&self) -> &'static str {
        "oracle"
    }

    fn directions(&self) -> Directions {
        Directions::BOTH
    }

    /// Run the query; each row is a Stream.
    fn receive(&self) -> Result<Vec<Arrived>> {
        let mut client = self.connect()?;
        let result = client.query(&self.query, None)?;
        client.close()?;
        let mut arrived = Vec::with_capacity(result.rows.len());
        for (index, row) in result.rows.into_iter().enumerate() {
            let name = row.first().and_then(|value| value.as_ref()).map_or_else(
                || index.to_string(),
                |bytes| String::from_utf8_lossy(bytes).into_owned(),
            );
            let value = row.into_iter().next_back().flatten().unwrap_or_default();
            arrived.push(Arrived::new(
                format!("oracle://{}/{}?row={name}", self.server, self.service),
                value,
            ));
        }
        Ok(arrived)
    }

    /// Insert the bytes as one bound RAW of one row.
    fn send(&self, target: &str, bytes: &[u8]) -> Result<()> {
        let (server, service, table, column) = self.resolve(target)?;
        let mut client = self.connect_to(server, service)?;
        let sql = format!("INSERT INTO {table} ({column}) VALUES (:1)");
        client.execute(&sql, Some(bytes))?;
        client.close()
    }

    /// Rows are artefacts, and one receive holds no transaction to claim
    /// one in.
    fn claims(&self) -> Option<&dyn ResourceClaim> {
        Some(&NoNativeClaim)
    }
}

impl OracleTransport {
    /// Both ends on this machine: an ephemeral local port, a login with no
    /// password, the loopback timeout.
    #[must_use]
    pub fn loopback() -> Self {
        Self::new("127.0.0.1:0", LOOPBACK_SERVICE, LOOPBACK_USER).timing_out_after(LOOPBACK_TIMEOUT)
    }
}

/// A bound listener waiting for its one client: logged in, one INSERT
/// taken as the Stream, its logoff read.
struct Listening {
    transport: OracleTransport,
    listener: TcpListener,
    address: String,
}

impl FarEnd for Listening {
    fn address(&self) -> &str {
        &self.address
    }

    fn take_one(self: Box<Self>) -> Result<Arrived> {
        let mut session = self.transport.accept_one(&self.listener)?;
        let arrived = session
            .next_insert()?
            .ok_or_else(|| protocol_error("the client logged off without inserting"))?;
        // Read the logoff that follows, so the goodbye is taken rather
        // than written into a closed socket.
        session.next_insert()?;
        Ok(arrived)
    }
}

impl Loopback for OracleTransport {
    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        let (listener, address) = self.bind()?;
        Ok(Box::new(Listening {
            transport: self.clone(),
            listener,
            address,
        }))
    }

    /// INSERT the payload as one bound RAW from a fresh near end logging in
    /// to `address` as this transport does.
    fn send_to(&self, address: &str, payload: &[u8]) -> Result<()> {
        let near = Self {
            server: address.to_string(),
            ..self.clone()
        };
        near.send(LOOPBACK_TARGET, payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    /// The Playground's edge payloads, written here so the crate does not
    /// depend on it.
    fn edge_payloads() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("empty", Vec::new()),
            ("one byte", vec![0x2a]),
            ("every byte", (0..=255).collect()),
            ("nul run", vec![0; 512]),
            ("high bytes", vec![0xff; 512]),
            ("crlf storm", b"\r\n".repeat(400)),
        ]
    }

    #[test]
    fn the_loopback_inserts_bytes_through_its_own_listener() {
        let pair = OracleTransport::loopback();
        let arrived = pair.round(b"it's \\here").expect("round");
        assert_eq!(arrived.bytes, b"it's \\here");
        assert!(arrived.origin_uri.starts_with("oracle://127.0.0.1:"));
        assert!(arrived.origin_uri.ends_with("/inbox"));
        let binary = pair.round(&[0xff, 0xfe]).expect("bytes");
        assert_eq!(binary.bytes, [0xff, 0xfe]);
        assert_eq!(pair.name(), "oracle");
        assert_eq!(pair.directions(), Directions::BOTH);
        assert!(pair.claims().is_some(), "rows are artefacts");
        assert_eq!(pair.ceiling(), None);
    }

    #[test]
    fn the_loopback_returns_the_edge_payloads_whole() {
        let pair = OracleTransport::loopback();
        for (name, payload) in edge_payloads() {
            assert!(pair.refuses(&payload).is_none(), "{name}");
            let arrived = pair.round(&payload).expect(name);
            assert_eq!(arrived.bytes, payload, "{name}");
        }
    }

    #[test]
    fn a_receive_runs_the_query_and_each_row_is_a_stream() {
        let far_end = OracleTransport::new("127.0.0.1:0", "ORDERS", "xmip")
            .with_password("secret")
            .timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let receiver = std::thread::spawn(move || {
            OracleTransport::new(address, "ORDERS", "xmip")
                .with_password("secret")
                .with_query("SELECT id, kind, payload FROM inbox ORDER BY id")
                .timing_out_after(secs(2))
                .receive()
        });
        let mut session = far_end
            .accept_one(&listener)
            .expect("accepting")
            .with_table(
                &["id", "kind", "payload"],
                &[
                    &[Some(b"41"), Some(b"order"), Some(b"ISA*00*")],
                    &[Some(b"42"), None, Some(&[0xff, 0xfe])],
                    &[None, Some(b""), None],
                ],
            );
        assert_eq!(session.user(), "xmip");
        assert_eq!(session.service(), "ORDERS");
        let event = session.next_event().expect("query").expect("one");
        assert_eq!(
            event,
            Event::Selected("SELECT id, kind, payload FROM inbox ORDER BY id".into())
        );
        assert!(session.next_event().expect("logoff").is_none());
        let arrived = receiver.join().expect("thread").expect("receiving");
        assert_eq!(arrived.len(), 3);
        assert_eq!(arrived[0].bytes, b"ISA*00*");
        assert!(arrived[0].origin_uri.ends_with("/ORDERS?row=41"));
        assert_eq!(arrived[1].bytes, [0xff, 0xfe], "bytes are bytes");
        assert!(arrived[1].origin_uri.ends_with("?row=42"));
        assert!(arrived[2].bytes.is_empty(), "NULL is an empty Stream");
        assert!(arrived[2].origin_uri.ends_with("?row=2"));
    }

    #[test]
    fn a_send_inserts_the_stream_and_the_login_is_checked() {
        let far_end = OracleTransport::new("127.0.0.1:0", "ORDERS", "xmip")
            .with_password("secret")
            .timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let sender = std::thread::spawn(move || {
            let near = OracleTransport::new(address.clone(), "ORDERS", "xmip")
                .with_password("secret")
                .timing_out_after(secs(2));
            near.send(
                &format!("oracle://{address}/ORDERS/inbox/payload"),
                b"\0raw\xff",
            )?;
            let bad_target = near.send("oracle://host/only-one", b"x");
            let refused = OracleTransport::new(address.clone(), "ORDERS", "xmip")
                .with_password("wrong")
                .timing_out_after(secs(2))
                .send("inbox/payload", b"x");
            let nobody = OracleTransport::new(address, "ORDERS", "nobody")
                .timing_out_after(secs(2))
                .send("inbox/payload", b"x");
            Ok::<_, TransportError>((bad_target, refused, nobody))
        });
        let mut session = far_end.accept_one(&listener).expect("accepting");
        let first = session.next_insert().expect("insert").expect("one");
        assert_eq!(first.bytes, b"\0raw\xff");
        assert!(first.origin_uri.ends_with("/inbox"));
        assert!(session.next_insert().expect("logoff").is_none());
        let wrong = far_end.accept_one(&listener).err().expect("wrong password");
        assert!(wrong.message.contains("ORA-01017"), "{wrong}");
        let nobody = far_end.accept_one(&listener).err().expect("wrong user");
        assert!(nobody.message.contains("'nobody'"), "{nobody}");
        let (bad_target, refused, nobody) = sender.join().expect("thread").expect("sending");
        assert!(!bad_target.expect_err("not a column").retryable);
        assert!(
            refused
                .expect_err("wrong password")
                .message
                .contains("ORA-01017")
        );
        assert!(
            nobody
                .expect_err("wrong user")
                .message
                .contains("ORA-01017")
        );
    }

    #[test]
    fn a_statement_the_far_end_errors_is_the_error_and_a_bad_connect_is_refused() {
        let far_end =
            OracleTransport::new("127.0.0.1:0", "ORDERS", "xmip").timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let near = std::thread::spawn(move || {
            let near = OracleTransport::new(address, "ORDERS", "xmip").timing_out_after(secs(2));
            let failed = near.receive();
            let mut client = near.connect()?;
            let banner = client.server_banner().to_string();
            let deleted = client.execute("DELETE FROM inbox WHERE id = 41", None)?;
            client.close()?;
            Ok::<_, TransportError>((failed, banner, deleted))
        });
        let session = far_end
            .accept_one(&listener)
            .expect("accepting")
            .answering(|sql| {
                sql.starts_with("SELECT").then(|| Answer::Error {
                    code: 942,
                    message: "table or view does not exist".into(),
                })
            });
        assert_eq!(session.serve().expect("served").len(), 1);
        let session = far_end
            .accept_one(&listener)
            .expect("again")
            .answering(|sql| sql.starts_with("DELETE").then_some(Answer::Complete(3)));
        assert_eq!(
            session.serve().expect("served"),
            [Event::Executed("DELETE FROM inbox WHERE id = 41".into())]
        );
        let (failed, banner, deleted) = near.join().expect("thread").expect("near");
        let error = failed.expect_err("the table is missing");
        assert!(!error.retryable);
        assert!(error.message.contains("ORA-00942"), "{error}");
        assert_eq!(banner, session::SERVER_BANNER);
        assert_eq!(deleted, 3);
    }
}
