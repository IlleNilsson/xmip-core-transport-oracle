//! Xmip's side of one connection to an Oracle listener: the TNS connect
//! and its accept, the protocol and data-type negotiation, the O5LOGON
//! session key and authentication, then a statement executed with a bind
//! and its rows fetched. The text of a query is what a Receive Location
//! configured; a Send Location runs one `INSERT ... VALUES (:1)` with the
//! Stream bound as one RAW.

use std::io::BufReader;
use std::net::TcpStream;
use std::time::Duration;

use transport::error::{Result, TransportError, protocol_error};
use transport::socket;

use crate::tns;
use crate::ttc::{self, Message, Ttc, TtcWrite, tag};

/// What a login presents.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Login {
    pub user: String,
    pub password: String,
}

impl Login {
    /// A login for `user` with `password`.
    #[must_use]
    pub fn new(user: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            user: user.into(),
            password: password.into(),
        }
    }
}

/// What a statement came back with.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QueryResult {
    pub columns: Vec<String>,
    /// Each row, each column its bytes or NULL.
    pub rows: Vec<Vec<Option<Vec<u8>>>>,
    /// What a statement without rows reported.
    pub affected_rows: u64,
}

/// The banner this client names itself with in the protocol handshake.
const BANNER: &str = "xmip-thin";

pub struct Client {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
    banner: String,
}

impl Client {
    /// Connect to `server`, negotiate, and log in to `connect_string`'s
    /// service as `login`.
    ///
    /// # Errors
    /// Where the server could not be reached, refused the connection, or
    /// refused the login.
    pub fn connect(
        server: &str,
        connect_string: &str,
        login: &Login,
        timeout: Option<Duration>,
    ) -> Result<Self> {
        let stream = socket::connect_tcp(server, timeout)?;
        let (reader, writer) = socket::split(stream)?;
        let mut client = Self {
            reader,
            writer,
            banner: String::new(),
        };
        client.handshake(connect_string)?;
        client.authenticate(login)?;
        Ok(client)
    }

    fn handshake(&mut self, connect_string: &str) -> Result<()> {
        tns::connect(connect_string).write(&mut self.writer)?;
        let accept = tns::Packet::expect(&mut self.reader)?;
        if accept.kind != tns::ACCEPT {
            return Err(tns::refused(&accept));
        }
        let mut protocol = Vec::new();
        protocol.string(BANNER);
        self.send(tag::PROTOCOL, protocol)?;
        let answer = self.expect(tag::PROTOCOL)?;
        self.banner = answer.cursor().string()?;
        self.send(tag::DATA_TYPES, Vec::new())?;
        self.expect(tag::DATA_TYPES)?;
        Ok(())
    }

    fn authenticate(&mut self, login: &Login) -> Result<()> {
        let mut request = Vec::new();
        request.string(&login.user);
        self.send(tag::SESSION_KEY_REQUEST, request)?;
        let key = self.expect(tag::SESSION_KEY)?;
        let challenge = key
            .cursor()
            .counted()?
            .try_into()
            .map_err(|_| protocol_error("the session key was not sixteen bytes"))?;
        let verifier = ttc::verifier(&challenge, login.password.as_bytes());
        let mut auth = Vec::new();
        auth.string(&login.user);
        auth.counted(&verifier);
        self.send(tag::AUTHENTICATE, auth)?;
        match self.next()? {
            message if message.tag == tag::AUTH_ACCEPTED => Ok(()),
            message if message.tag == tag::ERROR => Err(error_of(&message)),
            message => Err(unexpected(&message)),
        }
    }

    /// The banner the server named itself with.
    #[must_use]
    pub fn server_banner(&self) -> &str {
        &self.banner
    }

    /// Run `sql`, binding `bind` where there is one, and take its rows.
    ///
    /// # Errors
    /// Where the server went away or answered with an error.
    pub fn query(&mut self, sql: &str, bind: Option<&[u8]>) -> Result<QueryResult> {
        let mut body = Vec::new();
        body.string(sql);
        body.value(bind);
        self.send(tag::EXECUTE, body)?;
        let mut result = QueryResult::default();
        loop {
            let message = self.next()?;
            match message.tag {
                tag::DESCRIBE => {
                    let mut reader = message.cursor();
                    result.columns = reader
                        .values()?
                        .into_iter()
                        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                        .collect();
                }
                tag::ROW => result.rows.push(read_row(&message)?),
                tag::STATUS => {
                    result.affected_rows = message.cursor().long()?;
                    return Ok(result);
                }
                tag::ERROR => return Err(error_of(&message)),
                _ => return Err(unexpected(&message)),
            }
        }
    }

    /// Run `sql` for its effect, binding `bind`; the rows it touched.
    ///
    /// # Errors
    /// Where the server went away or answered with an error.
    pub fn execute(&mut self, sql: &str, bind: Option<&[u8]>) -> Result<u64> {
        self.query(sql, bind).map(|result| result.affected_rows)
    }

    /// Log off and hang up.
    ///
    /// # Errors
    /// Where the server had already gone.
    pub fn close(mut self) -> Result<()> {
        ttc::write_message(&mut self.writer, &Message::bare(tag::LOGOFF))?;
        tns::data_eof().write(&mut self.writer).or(Ok(()))
    }

    fn send(&mut self, tag: u8, body: Vec<u8>) -> Result<()> {
        ttc::write_message(&mut self.writer, &Message { tag, body })
    }

    fn next(&mut self) -> Result<Message> {
        ttc::expect_message(&mut self.reader)
    }

    /// The next message, which must be of `tag`.
    fn expect(&mut self, tag: u8) -> Result<Message> {
        let message = self.next()?;
        if message.tag == tag {
            Ok(message)
        } else if message.tag == crate::ttc::tag::ERROR {
            Err(error_of(&message))
        } else {
            Err(unexpected(&message))
        }
    }
}

/// The `(name, value)` of a row's columns.
fn read_row(message: &Message) -> Result<Vec<Option<Vec<u8>>>> {
    let mut reader = message.cursor();
    let count = usize::from(reader.u16_be()?);
    (0..count).map(|_| reader.value()).collect()
}

/// The error an error message carries; `ORA-00600` and class say whether
/// a later attempt might fare better.
fn error_of(message: &Message) -> TransportError {
    let mut reader = message.cursor();
    let Ok(code) = reader.integer() else {
        return protocol_error("a malformed error message");
    };
    let text = reader.string().unwrap_or_default();
    oracle_error(code, &text)
}

/// An `ORA-` error, retryable where it is a resource shortage, a lock, a
/// serialisation failure or a listener not yet up — what a later attempt
/// might not meet.
#[must_use]
pub fn oracle_error(code: u32, message: &str) -> TransportError {
    let text = format!("the server answered ORA-{code:05}: {message}");
    let transient = matches!(
        code,
        54 | 60 | 8176 | 8177 | 12_514 | 12_520 | 12_528 | 30_006
    );
    if transient {
        TransportError::retryable(text)
    } else {
        TransportError::permanent(text)
    }
}

fn unexpected(message: &Message) -> TransportError {
    protocol_error(format!("a message with tag {:#04x}", message.tag))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_error_is_judged_by_its_code() {
        assert!(oracle_error(60, "deadlock detected").retryable);
        assert!(oracle_error(54, "resource busy").retryable);
        assert!(oracle_error(12_514, "no listener").retryable);
        assert!(!oracle_error(1, "unique constraint violated").retryable);
        assert!(!oracle_error(942, "table or view does not exist").retryable);
        assert!(oracle_error(1, "x").message.contains("ORA-00001"));
    }
}
