//! The server's side of one connection: what a test puts at the far end,
//! and what the loopback pair drives.
//!
//! Not a database, and not an Oracle listener: it speaks this crate's own
//! wire (`tns.rs`, `ttc.rs`). One session accepts one client's connect,
//! answers the protocol and data-type exchange, hands out a challenge and
//! checks the answer against the one login it expects — or takes any,
//! where none is — and answers each statement from a closure or from one
//! fixed table: any SELECT gets the table's rows, an INSERT of one column
//! is recorded as a Stream — a literal in Oracle's dialect, as the column
//! is declared to hold it — a COMMIT is done, anything else is refused
//! with `ORA-00900`. Planning, storage and SQL are a database's.

use std::io::BufReader;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use sql::{ORACLE, Verb};
use transport::error::{Result, TransportError, protocol_error};
use transport::sql::{Answering, Column, Inserted, Rows, next_insert, table};
use transport::{Login, Taken, socket};

use crate::tns;
use crate::ttc::{self, Message, Ttc, TtcWrite, tag, verifier};

/// The number Oracle answers a refused login with (`ORA-01017`).
const INVALID_CREDENTIAL: u32 = 1017;
/// The number it answers a statement it will not run (`ORA-00900`).
const INVALID_STATEMENT: u32 = 900;
/// What the far end names itself in the protocol exchange.
pub const SERVER_BANNER: &str = "Oracle Database (xmip)";

/// What the client did, as [`Session::next_event`] reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The client ran a SELECT; here it is.
    Selected(String),
    /// The client inserted one value; here is the Stream.
    Inserted(Taken),
    /// The client ran something else; here it is.
    Executed(String),
}

impl Inserted for Event {
    fn inserted(self) -> Option<Taken> {
        match self {
            Self::Inserted(arrived) => Some(arrived),
            Self::Selected(_) | Self::Executed(_) => None,
        }
    }
}

/// How a statement is answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer {
    Rows {
        columns: Vec<String>,
        rows: Vec<Vec<Option<String>>>,
    },
    /// Done, this many rows touched.
    Complete(u64),
    Error {
        code: u32,
        message: String,
    },
}

pub struct Session {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
    peer: SocketAddr,
    user: String,
    service: String,
    column: Column,
    columns: Vec<String>,
    rows: Rows<String>,
    answering: Option<Answering<Answer>>,
}

impl Session {
    /// Accept one client on `listener`, negotiate, and log it in: against
    /// `expected` where there is one, taking any login where there is not.
    ///
    /// # Errors
    /// Where the connection could not be accepted, the client did not open
    /// with a connect and a login, or gave the wrong answer — which is told
    /// to the client as `ORA-01017` before this returns.
    pub fn accept(
        listener: &TcpListener,
        expected: Option<&Login>,
        timeout: Option<Duration>,
    ) -> Result<Self> {
        let (stream, peer) = socket::accept_tcp(listener, timeout)?;
        let (reader, writer) = socket::split(stream)?;
        let mut session = Self {
            reader,
            writer,
            peer,
            user: String::new(),
            service: String::new(),
            column: Column::Binary,
            columns: Vec::new(),
            rows: Vec::new(),
            answering: None,
        };
        session.handshake()?;
        session.authenticate(expected)?;
        Ok(session)
    }

    fn handshake(&mut self) -> Result<()> {
        let connect = tns::Packet::expect(&mut self.reader)?;
        if connect.kind != tns::CONNECT {
            tns::refuse("ORA-12514: no service").write(&mut self.writer)?;
            return Err(protocol_error("a first packet that is not a connect"));
        }
        self.service = service_name(&tns::read_connect(&connect)?);
        tns::accept().write(&mut self.writer)?;
        let protocol = self.expect(tag::PROTOCOL)?;
        let _ = protocol.cursor().string()?;
        let mut answer = Vec::new();
        answer.string(SERVER_BANNER);
        self.send(tag::PROTOCOL, answer)?;
        self.expect(tag::DATA_TYPES)?;
        self.send(tag::DATA_TYPES, Vec::new())
    }

    fn authenticate(&mut self, expected: Option<&Login>) -> Result<()> {
        let request = self.expect(tag::SESSION_KEY_REQUEST)?;
        let user = request.cursor().string()?;
        let challenge = fresh_challenge();
        let mut key = Vec::new();
        key.counted(&challenge);
        self.send(tag::SESSION_KEY, key)?;
        let auth = self.expect(tag::AUTHENTICATE)?;
        let mut reader = auth.cursor();
        self.user = reader.string()?;
        let offered = reader.counted()?;
        let accepted = expected.is_none_or(|login| {
            self.user == login.user
                && codec::constant_time::equal(
                    offered,
                    &verifier(&challenge, login.password.as_bytes()),
                )
        });
        if !accepted || self.user != user {
            let message = format!(
                "invalid username/password for '{}'; logon denied",
                self.user
            );
            self.send_error(INVALID_CREDENTIAL, &message)?;
            return Err(TransportError::permanent(format!("ORA-01017: {message}")));
        }
        self.send(tag::AUTH_ACCEPTED, Vec::new())
    }

    /// The user the client logged in as.
    #[must_use]
    pub fn user(&self) -> &str {
        &self.user
    }

    /// The service the connect named.
    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }

    /// What the column an INSERT names holds: bytes unless declared
    /// otherwise.
    #[must_use]
    pub const fn holding(mut self, column: Column) -> Self {
        self.column = column;
        self
    }

    /// Answer any SELECT with these `columns` and `rows`.
    #[must_use]
    pub fn with_table(mut self, columns: &[&str], rows: &[&[Option<&str>]]) -> Self {
        (self.columns, self.rows) = table(columns, rows);
        self
    }

    /// Answer statements with `answering` first; what it declines falls to
    /// the table.
    #[must_use]
    pub fn answering(
        mut self,
        answering: impl FnMut(&str) -> Option<Answer> + Send + 'static,
    ) -> Self {
        self.answering = Some(Box::new(answering));
        self
    }

    /// The next value the client inserts, or `None` when it closed.
    ///
    /// # Errors
    /// Where the connection broke, or nothing arrived before the timeout.
    pub fn next_insert(&mut self) -> Result<Option<Taken>> {
        next_insert(|| self.next_event())
    }

    /// The next statement the client ran, answered, or `None` when it
    /// logged off.
    ///
    /// # Errors
    /// Where the connection broke, nothing arrived before the timeout, or
    /// the client sent a message this crate does not serve.
    pub fn next_event(&mut self) -> Result<Option<Event>> {
        let Some(message) = ttc::read_message(&mut self.reader)? else {
            return Ok(None);
        };
        if message.tag == tag::LOGOFF {
            return Ok(None);
        }
        if message.tag != tag::EXECUTE {
            return Err(protocol_error(format!(
                "a message with tag {:#04x} after the login",
                message.tag
            )));
        }
        let sql = message.cursor().string()?;
        let (answer, event) = self.answer(&sql);
        self.write_answer(&answer)?;
        Ok(Some(event))
    }

    /// Answer every statement until the client logs off; what it did.
    ///
    /// # Errors
    /// As [`Session::next_event`].
    pub fn serve(mut self) -> Result<Vec<Event>> {
        let mut events = Vec::new();
        while let Some(event) = self.next_event()? {
            events.push(event);
        }
        Ok(events)
    }

    fn answer(&mut self, sql: &str) -> (Answer, Event) {
        if let Some(answer) = self.answering.as_mut().and_then(|f| f(sql)) {
            return (answer, Event::Executed(sql.to_string()));
        }
        let inserted = match Verb::of_statement(sql) {
            Some(Verb::Select) => {
                let rows = Answer::Rows {
                    columns: self.columns.clone(),
                    rows: self.rows.clone(),
                };
                return (rows, Event::Selected(sql.to_string()));
            }
            // What a client that keeps its session commits with, where a
            // logoff would have committed.
            Some(Verb::Commit) => {
                return (Answer::Complete(0), Event::Executed(sql.to_string()));
            }
            Some(Verb::Insert) => ORACLE.parse_insert_literal(sql),
            _ => None,
        };
        let Some((table, column, value)) = inserted else {
            let refused = Answer::Error {
                code: INVALID_STATEMENT,
                message: "only SELECT, INSERT INTO t (c) VALUES (...) and COMMIT are served here"
                    .to_string(),
            };
            return (refused, Event::Executed(sql.to_string()));
        };
        let origin = format!("oracle://{}/{}/{table}/{column}", self.peer, self.service);
        let stored = self.column.stored(value);
        (
            Answer::Complete(1),
            Event::Inserted(Taken::new(origin, stored)),
        )
    }

    fn write_answer(&mut self, answer: &Answer) -> Result<()> {
        match answer {
            Answer::Rows { columns, rows } => {
                let mut describe = Vec::new();
                describe.count(columns.len());
                for column in columns {
                    describe.string(column);
                }
                self.send(tag::DESCRIBE, describe)?;
                for row in rows {
                    let mut body = Vec::new();
                    body.count(row.len());
                    for value in row {
                        body.value(value.as_deref().map(str::as_bytes));
                    }
                    self.send(tag::ROW, body)?;
                }
                self.send_status(rows.len() as u64)
            }
            Answer::Complete(rows) => self.send_status(*rows),
            Answer::Error { code, message } => self.send_error(*code, message),
        }
    }

    fn send_status(&mut self, rows: u64) -> Result<()> {
        let mut body = Vec::new();
        body.counted(&rows.to_be_bytes());
        self.send(tag::STATUS, body)
    }

    fn send_error(&mut self, code: u32, message: &str) -> Result<()> {
        let mut body = Vec::new();
        body.counted(&code.to_be_bytes());
        body.string(message);
        self.send(tag::ERROR, body)
    }

    fn send(&mut self, tag: u8, body: Vec<u8>) -> Result<()> {
        ttc::write_message(&mut self.writer, &Message { tag, body })
    }

    fn expect(&mut self, tag: u8) -> Result<Message> {
        let message = ttc::expect_message(&mut self.reader)?;
        if message.tag == tag {
            Ok(message)
        } else {
            Err(protocol_error(format!(
                "a message with tag {:#04x} where {tag:#04x} was due",
                message.tag
            )))
        }
    }
}

/// The `SERVICE_NAME` a connect string names, or the whole string where
/// it carries no such field.
fn service_name(connect_string: &str) -> String {
    connect_string
        .split_once("SERVICE_NAME=")
        .and_then(|(_, rest)| rest.split(&[')', ' '][..]).next())
        .unwrap_or(connect_string)
        .to_string()
}

/// Sixteen random bytes: the challenge a login is verified against.
fn fresh_challenge() -> [u8; 16] {
    codec::random::array()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_challenge_is_sixteen_bytes_and_fresh_and_a_service_is_read_from_a_connect() {
        let first = fresh_challenge();
        assert_eq!(first.len(), 16);
        assert_ne!(first, fresh_challenge());
        assert_eq!(
            service_name("(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=ORDERS)))"),
            "ORDERS"
        );
        assert_eq!(service_name("ORDERS"), "ORDERS");
    }
}
