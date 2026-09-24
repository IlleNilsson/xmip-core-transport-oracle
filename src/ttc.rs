//! The two-task common layer (TTC), the function messages Oracle carries
//! inside TNS data packets. A real thin client speaks these as
//! python-oracledb's thin mode documents them: a protocol handshake, a
//! data-type negotiation, the O5LOGON key exchange and authentication,
//! then the OPI functions that open a cursor, execute a statement with a
//! bind and fetch rows.
//!
//! What is encoded here is that shape — a message tag and its fields —
//! carried faithfully as messages in order, with each string and each
//! opaque value counted. The O5LOGON verifier a real server checks is an
//! AES key schedule over the password (11g/12c); that computation is the
//! identity capability's, per ADR-0044, so the verifier is stood in by a
//! session-key mix this crate's own listener checks. TLS is the transport
//! capability's, per ADR-0033. A Stream binds as one RAW value and comes
//! back as one column, so a byte is a byte both ways.

use std::io::{Read, Write};

use codec::cursor::Cursor;
use codec::writer::ByteWriter;
use transport::error::{Result, protocol_error};

use crate::tns;

/// The message tags this layer carries. Their order is the session:
/// protocol, data types, the session key, authentication, then the
/// function calls.
pub mod tag {
    /// Client and server name their versions.
    pub const PROTOCOL: u8 = 0x01;
    /// The data-type negotiation, taken as agreed.
    pub const DATA_TYPES: u8 = 0x02;
    /// The client asks for a session key for `user` (O5LOGON `OSESSKEY`).
    pub const SESSION_KEY_REQUEST: u8 = 0x03;
    /// The server answers with the key (the auth challenge).
    pub const SESSION_KEY: u8 = 0x04;
    /// The client authenticates with the verifier (O5LOGON `OAUTH`).
    pub const AUTHENTICATE: u8 = 0x05;
    /// The server accepts the login.
    pub const AUTH_ACCEPTED: u8 = 0x06;
    /// The client executes a statement, with an optional bind.
    pub const EXECUTE: u8 = 0x07;
    /// The server describes the columns of a result.
    pub const DESCRIBE: u8 = 0x08;
    /// The server sends one row.
    pub const ROW: u8 = 0x09;
    /// The server says the statement is done, this many rows affected.
    pub const STATUS: u8 = 0x0a;
    /// The server answers an error (an `ORA-` code).
    pub const ERROR: u8 = 0x0b;
    /// The client logs off.
    pub const LOGOFF: u8 = 0x0c;
}

/// Reading TTC's own fields off codec's cursor.
pub trait Ttc<'a> {
    /// Counted opaque bytes: a big-endian two-byte length, then the bytes.
    ///
    /// # Errors
    /// Where the body ends first.
    fn counted(&mut self) -> Result<&'a [u8]>;

    /// A counted string, read as UTF-8, lossily.
    ///
    /// # Errors
    /// Where the body ends first.
    fn string(&mut self) -> Result<String>;

    /// A counted big-endian integer, which must be four bytes.
    ///
    /// # Errors
    /// Where the body ends first or the count is not four.
    fn integer(&mut self) -> Result<u32>;

    /// A counted big-endian long, which must be eight bytes.
    ///
    /// # Errors
    /// Where the body ends first or the count is not eight.
    fn long(&mut self) -> Result<u64>;

    /// A two-byte count, then that many counted values.
    ///
    /// # Errors
    /// Where the body ends first.
    fn values(&mut self) -> Result<Vec<Vec<u8>>>;

    /// A column value (see [`TtcWrite::value`]), `None` where it is NULL.
    ///
    /// # Errors
    /// Where the body ends first.
    fn value(&mut self) -> Result<Option<Vec<u8>>>;
}

impl<'a> Ttc<'a> for Cursor<'a> {
    fn counted(&mut self) -> Result<&'a [u8]> {
        let length = usize::from(self.u16_be()?);
        Ok(self.take(length)?)
    }

    fn string(&mut self) -> Result<String> {
        Ok(String::from_utf8_lossy(self.counted()?).into_owned())
    }

    fn integer(&mut self) -> Result<u32> {
        let bytes: [u8; 4] = self
            .counted()?
            .try_into()
            .map_err(|_| protocol_error("a TTC integer that is not four bytes"))?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn long(&mut self) -> Result<u64> {
        let bytes: [u8; 8] = self
            .counted()?
            .try_into()
            .map_err(|_| protocol_error("a TTC long that is not eight bytes"))?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn values(&mut self) -> Result<Vec<Vec<u8>>> {
        let count = usize::from(self.u16_be()?);
        (0..count)
            .map(|_| self.counted().map(<[u8]>::to_vec))
            .collect()
    }

    fn value(&mut self) -> Result<Option<Vec<u8>>> {
        if self.byte()? == 0 {
            return Ok(None);
        }
        Ok(Some(self.counted()?.to_vec()))
    }
}

/// Writing TTC's own fields beside codec's [`ByteWriter`].
pub trait TtcWrite {
    /// A count or length: two bytes, big-endian, saturating.
    fn count(&mut self, count: usize) -> &mut Self;

    /// Counted opaque bytes.
    fn counted(&mut self, bytes: &[u8]) -> &mut Self;

    /// A counted string.
    fn string(&mut self, text: &str) -> &mut Self;

    /// A column value: a present byte — one for a value, zero for NULL —
    /// then the value's counted bytes where it is present. A genuine empty
    /// value and a NULL are then two different shapes, which is what a
    /// database needs them to be.
    fn value(&mut self, value: Option<&[u8]>) -> &mut Self;
}

impl TtcWrite for Vec<u8> {
    fn count(&mut self, count: usize) -> &mut Self {
        self.u16_be(u16::try_from(count).unwrap_or(u16::MAX))
    }

    fn counted(&mut self, bytes: &[u8]) -> &mut Self {
        self.count(bytes.len()).bytes(bytes)
    }

    fn string(&mut self, text: &str) -> &mut Self {
        self.counted(text.as_bytes())
    }

    fn value(&mut self, value: Option<&[u8]>) -> &mut Self {
        match value {
            Some(bytes) => self.byte(1).counted(bytes),
            None => self.byte(0),
        }
    }
}

/// The O5LOGON verifier, stood in (see the module doc): the sixteen-byte
/// answer to `challenge` for `password`, a keyed mix a real client would
/// instead derive with AES. Deterministic, so this crate's own listener
/// checks it, and never the empty answer for a non-empty password.
#[must_use]
pub fn verifier(challenge: &[u8; 16], password: &[u8]) -> [u8; 16] {
    let mut state = *challenge;
    // Three passes fold the password into the challenge, each byte turned
    // by its neighbour so a one-byte change spreads across the block.
    for pass in 0u8..3 {
        for i in 0..16 {
            let key = password
                .get(i % password.len().max(1))
                .copied()
                .unwrap_or(pass);
            let prior = state[(i + 15) % 16];
            state[i] = state[i].wrapping_add(key ^ pass).rotate_left(3) ^ prior;
        }
    }
    state
}

/// One message: its tag and its already-encoded body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub tag: u8,
    pub body: Vec<u8>,
}

impl Message {
    /// A message of `tag` with an empty body.
    #[must_use]
    pub const fn bare(tag: u8) -> Self {
        Self {
            tag,
            body: Vec::new(),
        }
    }

    /// The two-task payload: the tag, then the body.
    #[must_use]
    pub fn to_payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.body.len() + 1);
        out.push(self.tag);
        out.extend_from_slice(&self.body);
        out
    }

    /// The message a two-task payload carries.
    ///
    /// # Errors
    /// Where the payload is empty.
    pub fn from_payload(payload: &[u8]) -> Result<Self> {
        let (tag, body) = payload
            .split_first()
            .ok_or_else(|| protocol_error("an empty two-task payload"))?;
        Ok(Self {
            tag: *tag,
            body: body.to_vec(),
        })
    }

    /// A cursor over this message's body.
    #[must_use]
    pub fn cursor(&self) -> Cursor<'_> {
        Cursor::new(&self.body)
    }
}

/// Write `message` as one TNS data packet.
///
/// # Errors
/// Where the connection broke.
pub fn write_message(writer: &mut impl Write, message: &Message) -> Result<()> {
    tns::data(&message.to_payload()).write(writer)
}

/// Read one TTC message off a TNS data packet; `None` where the peer sent
/// the end-of-file data flag (a logoff) or closed the connection.
///
/// # Errors
/// Where the connection broke, a non-data packet arrived, or the payload
/// was empty.
pub fn read_message(reader: &mut impl Read) -> Result<Option<Message>> {
    let Some(packet) = tns::Packet::read(reader)? else {
        return Ok(None);
    };
    let (flag, payload) = tns::read_data(&packet)?;
    if flag == tns::DATA_FLAG_EOF {
        return Ok(None);
    }
    Message::from_payload(payload).map(Some)
}

/// Read one TTC message, which must be there.
///
/// # Errors
/// As [`read_message`], and where the peer said goodbye or closed.
pub fn expect_message(reader: &mut impl Read) -> Result<Message> {
    read_message(reader)?.ok_or_else(|| protocol_error("the peer closed before its message"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_message_carries_its_tag_and_its_counted_fields() {
        let mut body = Vec::new();
        body.string("orders").counted(&[0, 0xff]);
        let message = Message {
            tag: tag::EXECUTE,
            body,
        };
        let read = Message::from_payload(&message.to_payload()).expect("message");
        assert_eq!(read, message);
        let mut reader = read.cursor();
        assert_eq!(reader.string().expect("service"), "orders");
        assert_eq!(reader.counted().expect("bind"), &[0, 0xff]);
        assert!(Message::from_payload(&[]).is_err());
        assert_eq!(Message::bare(tag::LOGOFF).to_payload(), [tag::LOGOFF]);
    }

    #[test]
    fn integers_arrays_and_values_read_back() {
        let mut body = Vec::new();
        body.counted(&7u32.to_be_bytes())
            .counted(&9u64.to_be_bytes())
            .count(2)
            .counted(b"a")
            .counted(b"bc")
            .value(Some(b"x"))
            .value(None);
        let mut reader = Cursor::new(&body);
        assert_eq!(reader.integer().expect("u32"), 7);
        assert_eq!(reader.long().expect("u64"), 9);
        assert_eq!(
            reader.values().expect("values"),
            vec![b"a".to_vec(), b"bc".to_vec()]
        );
        assert_eq!(reader.value().expect("value"), Some(b"x".to_vec()));
        assert_eq!(reader.value().expect("null"), None);
        let error = Cursor::new(&[0, 5, 1]).counted().expect_err("cut short");
        assert!(!error.retryable);
        assert!(error.message.contains("runs past"), "{error}");
        assert!(Cursor::new(&[0, 1, 7]).integer().is_err(), "not four bytes");
        assert!(Cursor::new(&[]).byte().is_err());
    }

    #[test]
    fn the_verifier_answers_the_challenge_and_a_wrong_password_answers_differently() {
        let challenge = [0x11u8; 16];
        let right = verifier(&challenge, b"secret");
        assert_eq!(right, verifier(&challenge, b"secret"), "deterministic");
        assert_ne!(right, verifier(&challenge, b"secrat"), "a byte spreads");
        assert_ne!(
            right,
            verifier(&[0x12; 16], b"secret"),
            "the challenge matters"
        );
        assert_ne!(right, [0u8; 16]);
        assert_ne!(verifier(&challenge, b""), verifier(&challenge, b"x"));
    }
}
