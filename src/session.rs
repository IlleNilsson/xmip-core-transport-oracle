//! The server's side of one connection: what a test puts at the far end,
//! and what the loopback pair drives.
//!
//! Not a database. One session accepts one client's TNS connect, answers
//! the protocol and data-type negotiation, hands out a session key and
//! checks the verifier against the one login it expects — or takes any,
//! where none is — and answers each statement from a closure or from one
//! fixed table: any SELECT gets the table's rows, an `INSERT ... VALUES
//! (:1)` records its bound RAW as a Stream, anything else is done with no
//! rows. Planning, storage and SQL are a database's.

use std::io::BufReader;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime};

use transport::Arrived;
use transport::error::{Result, TransportError, protocol_error};
use transport::socket;
use transport::sql::{self, Answering, Inserted, Rows};

use crate::client::Login;
use crate::tns;
use crate::ttc::{self, Message, tag, verifier};

/// The number Oracle answers a refused login with (`ORA-01017`).
pub const INVALID_CREDENTIAL: u32 = 1017;
/// The number it answers a statement it will not run (`ORA-00900`).
pub const INVALID_STATEMENT: u32 = 900;
/// What the far end names itself in the protocol handshake.
pub const SERVER_BANNER: &str = "Oracle Database (xmip)";

/// What the client did, as [`Session::next_event`] reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The client ran a SELECT; here it is.
    Selected(String),
    /// The client inserted one bound value; here is the Stream.
    Inserted(Arrived),
    /// The client ran something else; here it is.
    Executed(String),
}

impl Inserted for Event {
    fn inserted(self) -> Option<Arrived> {
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
        rows: Vec<Vec<Option<Vec<u8>>>>,
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
    columns: Vec<String>,
    rows: Rows<Vec<u8>>,
    answering: Option<Answering<Answer>>,
}

/// Ids handed out, one a session, so no two challenges are the same.
static SESSIONS: AtomicU32 = AtomicU32::new(1);

impl Session {
    /// Accept one client on `listener`, negotiate, and log it in: against
    /// `expected` where there is one, taking any login where there is not.
    ///
    /// # Errors
    /// Where the connection could not be accepted, the client did not open
    /// with a connect and a login, or gave the wrong verifier — which is
    /// told to the client as `ORA-01017` before this returns.
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
        let _ = protocol.reader().string()?;
        let mut answer = Vec::new();
        ttc::put_str(&mut answer, SERVER_BANNER);
        self.send(tag::PROTOCOL, answer)?;
        self.expect(tag::DATA_TYPES)?;
        self.send(tag::DATA_TYPES, Vec::new())
    }

    fn authenticate(&mut self, expected: Option<&Login>) -> Result<()> {
        let request = self.expect(tag::SESSION_KEY_REQUEST)?;
        let user = request.reader().string()?;
        let challenge = fresh_challenge(&self.peer);
        let mut key = Vec::new();
        ttc::put_bytes(&mut key, &challenge);
        self.send(tag::SESSION_KEY, key)?;
        let auth = self.expect(tag::AUTHENTICATE)?;
        let mut reader = auth.reader();
        self.user = reader.string()?;
        let offered = reader.bytes()?;
        let accepted = expected.is_none_or(|login| {
            self.user == login.user && offered == verifier(&challenge, login.password.as_bytes())
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

    /// Answer any SELECT with these `columns` and `rows`.
    #[must_use]
    pub fn with_table(mut self, columns: &[&str], rows: &[&[Option<&[u8]>]]) -> Self {
        (self.columns, self.rows) = sql::table(columns, rows);
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
    pub fn next_insert(&mut self) -> Result<Option<Arrived>> {
        sql::next_insert(|| self.next_event())
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
        let mut reader = message.reader();
        let sql = reader.string()?;
        let bind = ttc::take_value(&mut reader)?;
        let (answer, event) = self.answer(&sql, bind);
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

    fn answer(&mut self, sql: &str, bind: Option<Vec<u8>>) -> (Answer, Event) {
        if let Some(answer) = self.answering.as_mut().and_then(|f| f(sql)) {
            return (answer, Event::Executed(sql.to_string()));
        }
        let verb = sql::verb(sql);
        match verb.as_str() {
            "SELECT" => (
                Answer::Rows {
                    columns: self.columns.clone(),
                    rows: self.rows.clone(),
                },
                Event::Selected(sql.to_string()),
            ),
            "INSERT" => {
                let origin = format!("oracle://{}/{}", self.peer, table_of(sql));
                (
                    Answer::Complete(1),
                    Event::Inserted(Arrived::new(origin, bind.unwrap_or_default())),
                )
            }
            _ => (
                Answer::Error {
                    code: INVALID_STATEMENT,
                    message: "only SELECT and INSERT ... VALUES (:1) are served here".to_string(),
                },
                Event::Executed(sql.to_string()),
            ),
        }
    }

    fn write_answer(&mut self, answer: &Answer) -> Result<()> {
        match answer {
            Answer::Rows { columns, rows } => {
                let mut describe = Vec::new();
                ttc::put_count(&mut describe, columns.len());
                for column in columns {
                    ttc::put_str(&mut describe, column);
                }
                self.send(tag::DESCRIBE, describe)?;
                for row in rows {
                    let mut body = Vec::new();
                    ttc::put_count(&mut body, row.len());
                    for value in row {
                        ttc::put_value(&mut body, value.as_deref());
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
        ttc::put_bytes(&mut body, &rows.to_be_bytes());
        self.send(tag::STATUS, body)
    }

    fn send_error(&mut self, code: u32, message: &str) -> Result<()> {
        let mut body = Vec::new();
        ttc::put_bytes(&mut body, &code.to_be_bytes());
        ttc::put_str(&mut body, message);
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

/// The table an `INSERT INTO t (...) ...` names, or `?` where none is
/// plain to read; only for the origin URI.
fn table_of(sql: &str) -> String {
    sql.split_whitespace()
        .skip_while(|word| !word.eq_ignore_ascii_case("into"))
        .nth(1)
        .map_or_else(
            || "?".to_string(),
            |table| table.split('(').next().unwrap_or(table).to_string(),
        )
}

/// Sixteen bytes no two sessions share: the clock, the peer and a counter
/// folded to a block.
fn fresh_challenge(peer: &SocketAddr) -> [u8; 16] {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos());
    let seed = format!(
        "{nanos}:{peer}:{}",
        SESSIONS.fetch_add(1, Ordering::Relaxed)
    );
    let bytes = seed.into_bytes();
    let mut block = [0u8; 16];
    for (i, byte) in bytes.iter().enumerate() {
        block[i % 16] = block[i % 16].wrapping_add(*byte).rotate_left(1);
    }
    block
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_challenge_is_sixteen_bytes_and_fresh_and_a_table_is_read_for_the_origin() {
        let peer: SocketAddr = "127.0.0.1:1521".parse().expect("address");
        let first = fresh_challenge(&peer);
        assert_eq!(first.len(), 16);
        SESSIONS.fetch_add(1, Ordering::Relaxed);
        assert_ne!(first, fresh_challenge(&peer));
        assert_eq!(table_of("INSERT INTO inbox (payload) VALUES (:1)"), "inbox");
        assert_eq!(table_of("INSERT INTO inbox(payload) VALUES (:1)"), "inbox");
        assert_eq!(table_of("nonsense"), "?");
    }
}
