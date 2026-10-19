#![forbid(unsafe_code)]

//! Streams that arrive as rows. One row is one Stream: the last column of
//! a configured query is what Xmip carries, the first column is where it
//! came from.
//!
//! Oracle Database is the database under the enterprise's oldest systems,
//! and a table in one is an integration surface a Party already has: a
//! producer inserts, an integrator polls. A Receive Location runs its
//! query — `SELECT id, payload FROM inbox ORDER BY id` unless told
//! otherwise — and hands each row up; a Send Location inserts the Stream
//! as one column of one row. What the column holds is the Location's to
//! declare, never the bytes' (ADR-0038): `column = "binary"`, the default,
//! inserts every Stream as `HEXTORAW('…')` and reads a value back from the
//! bare hex `RAWTOHEX(…)` answers; `column = "text"` decodes the Stream
//! strictly in its `encoding` — `utf-8` unless another Unicode form is
//! named — inserts it as a string literal, and encodes a value read back
//! to that form. A Stream that is not its declared form is refused, never
//! repaired; so is a row value that is not UTF-8. The SQL is Oracle's as
//! `xmip-core-library-sql` writes it (`sql::ORACLE`).
//!
//! Oracle is a transport here and nothing more: no Storage server speaks
//! it (the owner, 2026-10-14).
//!
//! **The wire is this crate's own, not yet Oracle's.** A session goes as
//! Oracle Net goes — a TNS connect and its accept (`tns.rs`), then the
//! two-task layer's order inside data packets (`ttc.rs`): a protocol and a
//! data-type exchange, a challenge and its answer, a statement executed
//! and its rows fetched — but the bodies are not Oracle's: no TTC function
//! codes, no O5LOGON with the 11g or 12c verifier. A real Oracle listener
//! refuses this client, and this transport speaks only to the far end it
//! carries (`session.rs`), which the loopback pair and the tests drive.
//! TCPS is not spoken; where it is, it is `xmip-core-library-tls`'s
//! (ADR-0033).
//!
//! Rows are artefacts and this transport claims none of them, per
//! ADR-0024: the atomic claim a database has, `SELECT … FOR UPDATE SKIP
//! LOCKED`, holds only inside a transaction, and none is held across a
//! Stream's lifetime. The query itself — a status column — is what keeps a
//! row from arriving twice.
//!
//! **A row is consumed by the `accept` statement, after its cycle.** The
//! query only reads. Where the Location declares `accept` — `DELETE FROM
//! inbox WHERE id = :1` — it runs once a row's cycle accepted it, the
//! row's name bound in place of `:1` as Oracle's string literal
//! (`transport::sql::accept`), and is committed. A refused row is left
//! where it lies, and not received again while its body is unchanged. A
//! row whose cycle failed is left, and the next receive reads it again; so
//! is a row whose name is NULL, which no statement can name. Where
//! `accept` is left out a row's verdict tells the database nothing: every
//! row is read again unless the query keeps it from that.
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
use std::sync::Arc;
use std::time::Duration;

pub use client::{Client, QueryResult, oracle_error};
pub use session::{Answer, Event, Session};
use sql::ORACLE;
use transport::ArrivalIdentity;
use transport::claim::{NoNativeClaim, ResourceClaim};
use transport::error::{Result, protocol_error};
use transport::listening::{Accepting, Listening};
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
use transport::socket;
use transport::sql::{COLUMN, Column, ENCODING, accept, destination};
use transport::{Arrived, Configured, Directions, Login, Pool, Taken, Transport};
use xcore::settings::{Applies, Fixed, Kind, Presence, Read, Setting, Settings};

/// The schemes a send target may open with.
const SCHEMES: &[&str] = &["oracle"];

/// What a Receive Location runs unless told otherwise.
pub const DEFAULT_QUERY: &str = "SELECT id, payload FROM inbox ORDER BY id";

/// What runs after an INSERT or an `accept` statement: a session kept
/// between statements is not logged off, and Oracle commits nothing until
/// told.
const COMMIT: &str = "COMMIT";

/// What the loopback pair agrees on: one service, one user whose login the
/// far end demands and the near end gives, one table and column the
/// payload is inserted into.
const LOOPBACK_SERVICE: &str = "XMIP";
const LOOPBACK_USER: &str = "xmip";
const LOOPBACK_TARGET: &str = "inbox/payload";

#[derive(Clone)]
pub struct OracleTransport {
    server: String,
    service: String,
    login: Login,
    query: String,
    /// The statement run on a row's verdict, its name bound in.
    accept: Option<String>,
    /// The rows refused and left, not received again while unchanged.
    /// Cloned, the same memory.
    refused: accept::RefusedRows,
    column: Column,
    timeout: Option<Duration>,
    /// The sessions a send inserts on and a receive queries on, logged
    /// in once per server and service and kept.
    sessions: Pool<Client>,
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
            accept: None,
            refused: accept::RefusedRows::default(),
            column: Column::Binary,
            timeout: None,
            sessions: Pool::new(),
        }
    }

    /// The password the login answers the challenge with.
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

    /// The statement run once a row's cycle accepted it, the row's name in
    /// place of the dialect's first parameter (`transport::sql::accept`).
    #[must_use]
    pub fn with_accept(mut self, statement: impl Into<String>) -> Self {
        self.accept = Some(statement.into());
        self
    }

    /// What the payload column holds: bytes unless declared otherwise.
    #[must_use]
    pub const fn holding(mut self, column: Column) -> Self {
        self.column = column;
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
            .map(|session| session.holding(self.column))
    }

    /// Run `statement` and commit it, on the session kept for `server` and
    /// `service`, logged in on the first statement to them.
    fn committed(&self, server: &str, service: &str, statement: &str) -> Result<()> {
        self.sessions.exchange(
            &format!("{server}/{service}"),
            || self.connect_to(server, service),
            |client| {
                client.execute(statement)?;
                client.execute(COMMIT).map(|_| ())
            },
        )
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

    fn arrivals(&self) -> transport::Arrivals {
        transport::Arrivals::Ordered("a poll reads again what is not yet told")
    }

    fn waiting(&self) -> transport::Waiting {
        transport::Waiting::Polled("a receive runs the query and returns")
    }

    /// Run the query on the session kept for the server and service,
    /// logged in on the first receive; each row is a Stream, whole. Its
    /// verdict runs the `accept` statement where one is declared — on
    /// `Accepted`, never on `Refused` or `Failed` — and tells the database
    /// nothing where none is.
    fn receive_up_to(&self, most: usize) -> Result<Vec<Arrived>> {
        let result = self.sessions.exchange(
            &format!("{}/{}", self.server, self.service),
            || self.connect(),
            |client| client.query(&self.query),
        )?;
        let shared = Arc::new(self.clone());
        accept::arrivals(
            result.rows,
            most,
            &self.refused,
            |name| format!("oracle://{}/{}?row={name}", self.server, self.service),
            Clone::clone,
            |value| self.column.bytes(&value, &ORACLE),
            |name| {
                let transport = Arc::clone(&shared);
                accept::accepting(&ORACLE, self.accept.as_deref(), name, move |sql| {
                    transport.committed(&transport.server, &transport.service, sql)
                })
            },
        )
    }

    fn sending(&self) -> transport::Sending {
        transport::Sending::Gathered("an INSERT carries the body as one literal in its statement")
    }

    /// Insert the bytes as one column of one row — as `HEXTORAW('…')`, or
    /// as text where the column is declared to hold it — and commit it, on
    /// the session kept for the server and service.
    fn send_from(&self, target: &str, outgoing: transport::Outgoing<'_>) -> Result<()> {
        let bytes: &[u8] = &outgoing.gather()?;
        let to = destination(SCHEMES, target, &self.server, &self.service)?;
        let literal = self.column.literal(bytes, &ORACLE)?;
        let insert = ORACLE.insert(to.table, to.column, &literal);
        self.committed(to.server, to.database, &insert)
    }

    /// Rows are artefacts, and one receive holds no transaction to claim
    /// one in.
    fn claims(&self) -> Option<&dyn ResourceClaim> {
        Some(&NoNativeClaim)
    }
}

impl Configured for OracleTransport {
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

    /// The password comes through the Location's credentials, never a
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

impl OracleTransport {
    /// Both ends on this machine: an ephemeral local port, a login with no
    /// password, the loopback timeout.
    #[must_use]
    pub fn loopback() -> Self {
        Self::new("127.0.0.1:0", LOOPBACK_SERVICE, LOOPBACK_USER).timing_out_after(LOOPBACK_TIMEOUT)
    }
}

impl Accepting for OracleTransport {
    fn take_one(self, listener: &TcpListener) -> Result<Taken> {
        let mut session = self.accept_one(listener)?;
        let arrived = session
            .next_insert()?
            .ok_or_else(|| protocol_error("the client logged off without inserting"))?;
        // Answer the COMMIT that follows; the client keeps its session for
        // the next insert.
        session.next_event()?;
        Ok(arrived)
    }
}

impl Loopback for OracleTransport {
    fn arrival_identity(&self) -> ArrivalIdentity {
        ArrivalIdentity::Unnamed(
            "a row names no sender: the database it was read from is in its origin",
        )
    }

    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        Ok(Box::new(Listening::new(self.clone(), self.bind()?)))
    }

    /// INSERT the payload as one column of one row, as the column is
    /// declared to hold it, from a fresh near end logging in to `address`
    /// as this transport does.
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
    use codec::unicode::Form;
    use transport::error::TransportError;
    use transport::payload::{edge_payloads, sized_payloads};

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn oracle_declares_its_settings_and_reads_through_them() {
        use xcore::settings::Given;
        assert_eq!(OracleTransport::SETTINGS.problems(), Vec::<String>::new());
        let text = |name: &str, value: &str| (name.to_string(), Given::Text(value.to_string()));
        let given = [
            text("service", "ORDERS"),
            text("user", "xmip"),
            text("query", "SELECT id, body FROM outbox"),
            text("timeout", "2s"),
        ];
        let built = OracleTransport::open("db:1521", Applies::Receive, &given).expect("built");
        assert_eq!(built.server, "db:1521");
        assert_eq!(built.service, "ORDERS");
        assert_eq!(built.query, "SELECT id, body FROM outbox");
        assert_eq!(built.timeout, Some(secs(2)));
        assert_eq!(built.column, Column::Binary, "bytes unless declared");
        let texts = [
            text("service", "ORDERS"),
            text("user", "xmip"),
            text("column", "text"),
        ];
        let built = OracleTransport::open("db:1521", Applies::Send, &texts).expect("text");
        assert_eq!(built.column, Column::Text(Form::Utf8), "utf-8 unless named");
        let Err(refused) = OracleTransport::open("db:1521", Applies::Send, &given[..3]) else {
            panic!("query is a receive setting");
        };
        assert!(refused.message.contains("\"query\""), "{}", refused.message);
    }

    #[test]
    fn the_loopback_inserts_bytes_through_its_own_listener() {
        let pair = OracleTransport::loopback();
        let arrived = pair.round(b"it's \\here").expect("round");
        assert_eq!(arrived.bytes, b"it's \\here");
        assert!(arrived.origin_uri.starts_with("oracle://127.0.0.1:"));
        assert!(arrived.origin_uri.ends_with("/XMIP/inbox/payload"));
        let binary = pair.round(&[0xff, 0xfe]).expect("bytes");
        assert_eq!(binary.bytes, [0xff, 0xfe]);
        assert_eq!(pair.name(), "oracle");
        assert_eq!(pair.directions(), Directions::BOTH);
        assert!(pair.waiting().polled(), "a query returns at once");
        assert!(pair.claims().is_some(), "rows are artefacts");
        assert_eq!(pair.ceiling(), None);
    }

    #[test]
    fn the_loopback_returns_the_edge_and_sized_payloads_whole() {
        let pair = OracleTransport::loopback();
        for (name, payload) in edge_payloads().into_iter().chain(sized_payloads()) {
            assert!(pair.refuses(&payload).is_none(), "{name}");
            let arrived = pair.round(&payload).expect(name);
            assert_eq!(arrived.bytes, payload, "{name}");
        }
    }

    #[test]
    fn a_text_column_inserts_a_string_literal_and_refuses_what_is_not_its_form() {
        let pair = OracleTransport::loopback().holding(Column::Text(Form::Utf8));
        let arrived = pair.round("it's \u{e9}".as_bytes()).expect("text");
        assert_eq!(arrived.bytes, "it's \u{e9}".as_bytes());
        let refused = pair.send("inbox/payload", &[0xff]).expect_err("not UTF-8");
        assert!(refused.message.contains("utf-8"), "{refused}");
    }

    /// The first of `arrived` read and failed, the rest taken.
    fn verdicts(arrived: Vec<Arrived>) -> Result<Vec<Taken>> {
        let mut taken = Vec::new();
        for (index, one) in arrived.into_iter().enumerate() {
            assert!(one.defers());
            if index > 0 {
                taken.push(one.taken()?);
                continue;
            }
            let (origin, mut body, acknowledgement) = one.into_parts();
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(&mut body, &mut bytes).expect("reading");
            acknowledgement.acknowledge(transport::Verdict::Failed)?;
            taken.push(Taken::new(origin, bytes));
        }
        Ok(taken)
    }

    #[test]
    fn accept_consumes_an_accepted_row_and_a_refused_one_is_left_unreceived() {
        let far_end =
            OracleTransport::new("127.0.0.1:0", "ORDERS", "xmip").timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let receiver = std::thread::spawn(move || {
            let near = OracleTransport::new(address, "ORDERS", "xmip")
                .with_accept("DELETE FROM inbox WHERE id = :1")
                .timing_out_after(secs(2));
            let mut arrived = near.receive()?;
            assert_eq!(arrived.len(), 4);
            arrived.remove(0).taken()?;
            arrived
                .remove(0)
                .refused(transport::Refusal::Unacceptable)?;
            arrived.remove(0).failed()?;
            arrived.remove(0).taken()?;
            let again: Vec<_> = near.receive()?.into_iter().map(|a| a.origin_uri).collect();
            assert_eq!(
                again.len(),
                3,
                "the refused row is not received again: {again:?}"
            );
            assert!(
                again.iter().all(|row| !row.ends_with("?row=it's")),
                "{again:?}"
            );
            Ok::<_, TransportError>(())
        });
        let rows: [&[Option<&str>]; 4] = [
            &[Some("41"), Some("61")],
            &[Some("it's"), Some("62")],
            &[Some("43"), Some("63")],
            &[None, Some("64")],
        ];
        let mut session = far_end
            .accept_one(&listener)
            .expect("accepting")
            .with_table(&["id", "payload"], &rows)
            .answering(|sql| sql.starts_with("DELETE").then_some(Answer::Complete(1)));
        let mut events = Vec::new();
        while let Some(event) = session.next_event().expect("serving") {
            events.push(event);
        }
        receiver.join().expect("thread").expect("receiving");
        assert_eq!(
            events,
            [
                Event::Selected(DEFAULT_QUERY.into()),
                Event::Executed("DELETE FROM inbox WHERE id = '41'".into()),
                Event::Executed(COMMIT.into()),
                Event::Selected(DEFAULT_QUERY.into()),
            ],
            "the refused, the failed and the unnamed row are left"
        );
    }

    #[test]
    fn a_receive_runs_the_query_and_each_row_is_a_stream_in_its_column_form() {
        let far_end = OracleTransport::new("127.0.0.1:0", "ORDERS", "xmip")
            .with_password("secret")
            .timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let receiver = std::thread::spawn(move || {
            let near = OracleTransport::new(address, "ORDERS", "xmip")
                .with_password("secret")
                .with_query("SELECT id, kind, RAWTOHEX(payload) FROM inbox ORDER BY id")
                .timing_out_after(secs(2));
            let binary = verdicts(near.receive()?)?;
            let text = near.clone().holding(Column::Text(Form::Utf8)).receive()?;
            let refused = near.receive().map(|_| ());
            Ok::<_, TransportError>((binary, text.len(), refused))
        });
        let mut session = far_end
            .accept_one(&listener)
            .expect("accepting")
            .with_table(
                &["id", "kind", "payload"],
                &[
                    &[Some("41"), Some("order"), Some("49534123")],
                    &[Some("42"), None, Some("FFFE")],
                    &[None, Some(""), None],
                ],
            );
        assert_eq!(session.user(), "xmip");
        assert_eq!(session.service(), "ORDERS");
        let event = session.next_event().expect("query").expect("one");
        assert_eq!(
            event,
            Event::Selected("SELECT id, kind, RAWTOHEX(payload) FROM inbox ORDER BY id".into())
        );
        session.next_event().expect("as text").expect("one");
        let mut session = session.with_table(&["id", "payload"], &[&[Some("1"), Some("x")]]);
        session.next_event().expect("not hex").expect("one");
        let (arrived, text, refused) = receiver.join().expect("thread").expect("receiving");
        assert_eq!(arrived.len(), 3);
        assert_eq!(arrived[0].bytes, b"ISA#");
        assert!(arrived[0].origin_uri.ends_with("/ORDERS?row=41"));
        assert_eq!(arrived[1].bytes, [0xff, 0xfe], "bytes are bytes");
        assert!(arrived[1].origin_uri.ends_with("?row=42"));
        assert!(arrived[2].bytes.is_empty(), "NULL is an empty Stream");
        assert!(arrived[2].origin_uri.ends_with("?row=2"));
        assert_eq!(text, 3);
        let refused = refused.expect_err("a binary column's value that is not hex");
        assert!(refused.message.contains("column = \"text\""), "{refused}");
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
                &format!("oracle://{address}/ORDERS/INBOX/PAYLOAD"),
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
        assert!(first.origin_uri.ends_with("/ORDERS/INBOX/PAYLOAD"));
        assert_eq!(
            session.next_event().expect("commit"),
            Some(Event::Executed(COMMIT.into())),
            "committed, since the session is kept rather than logged off"
        );
        drop(session);
        let wrong = far_end.accept_one(&listener).err().expect("wrong password");
        assert!(wrong.message.contains("ORA-01017"), "{wrong}");
        let nobody = far_end.accept_one(&listener).err().expect("wrong user");
        assert!(nobody.message.contains("'nobody'"), "{nobody}");
        let (bad_target, refused, nobody) = sender.join().expect("thread").expect("sending");
        assert!(!bad_target.expect_err("not a column").retryable);
        let refused = refused.expect_err("wrong password");
        assert!(refused.message.contains("ORA-01017"), "{refused}");
        let nobody = nobody.expect_err("wrong user");
        assert!(nobody.message.contains("ORA-01017"), "{nobody}");
    }

    #[test]
    fn a_thousand_inserts_log_in_once_and_a_session_the_listener_closed_is_replaced() {
        const SENDS: usize = 1000;
        let far_end = OracleTransport::new("127.0.0.1:0", "ORDERS", "xmip")
            .with_password("secret")
            .timing_out_after(secs(5));
        let (listener, address) = far_end.bind().expect("binding");
        let near = OracleTransport::new(address, "ORDERS", "xmip")
            .with_password("secret")
            .timing_out_after(secs(5));
        let sending = near.clone();
        let sender = std::thread::spawn(move || {
            let began = std::time::Instant::now();
            for n in 0..SENDS {
                sending.send("inbox/payload", n.to_string().as_bytes())?;
            }
            let took = began.elapsed();
            // Generous for a debug build under load: a millisecond an insert.
            assert!(took < Duration::from_millis(SENDS as u64), "{took:?}");
            sending.send("inbox/payload", b"after the close")
        });
        // One connect and login for every insert: one session accepted.
        let mut session = far_end.accept_one(&listener).expect("accepting");
        for n in 0..SENDS {
            let inserted = session.next_insert().expect("insert").expect("one");
            assert_eq!(inserted.bytes, n.to_string().as_bytes());
        }
        session.next_event().expect("the last commit");
        drop(session);
        let mut again = far_end.accept_one(&listener).expect("a new login");
        let last = again.next_insert().expect("insert").expect("one");
        assert_eq!(last.bytes, b"after the close");
        again.next_event().expect("its commit");
        sender.join().expect("thread").expect("sending");
        assert_eq!(near.sessions.opened(), 2);
    }

    #[test]
    fn a_thousand_receives_log_in_once_and_a_connection_the_server_closed_is_replaced() {
        const RECEIVES: usize = 1000;
        let far_end = OracleTransport::new("127.0.0.1:0", "ORDERS", "xmip")
            .with_password("secret")
            .timing_out_after(secs(5));
        let (listener, address) = far_end.bind().expect("binding");
        let near = OracleTransport::new(address, "ORDERS", "xmip")
            .with_password("secret")
            .timing_out_after(secs(5));
        let receiving = near.clone();
        let receiver = std::thread::spawn(move || {
            let began = std::time::Instant::now();
            for _ in 0..RECEIVES {
                assert_eq!(receiving.receive()?.len(), 1);
            }
            let took = began.elapsed();
            // Generous for a debug build under load: a millisecond a query.
            assert!(took < Duration::from_millis(RECEIVES as u64), "{took:?}");
            receiving.receive()
        });
        let accept = || {
            far_end
                .accept_one(&listener)
                .expect("a login")
                .with_table(&["id", "payload"], &[&[Some("1"), None]])
        };
        // One login for every query: one session accepted.
        let mut session = accept();
        for _ in 0..RECEIVES {
            let event = session.next_event().expect("query");
            assert!(matches!(event, Some(Event::Selected(_))), "{event:?}");
        }
        drop(session);
        let mut again = accept();
        assert!(matches!(again.next_event(), Ok(Some(Event::Selected(_)))));
        assert_eq!(receiver.join().expect("thread").expect("after").len(), 1);
        assert_eq!(near.sessions.opened(), 2);
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
            let deleted = client.execute("DELETE FROM inbox WHERE id = 41")?;
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
