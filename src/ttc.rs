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

/// Append a count or length: two bytes, big-endian.
pub fn put_count(out: &mut Vec<u8>, count: usize) {
    out.extend_from_slice(&u16::try_from(count).unwrap_or(u16::MAX).to_be_bytes());
}

/// Append counted opaque bytes.
pub fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    put_count(out, bytes.len());
    out.extend_from_slice(bytes);
}

/// Append a counted string.
pub fn put_str(out: &mut Vec<u8>, text: &str) {
    put_bytes(out, text.as_bytes());
}

/// A reader over one message body.
pub struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    /// Counted opaque bytes.
    ///
    /// # Errors
    /// Where the body ends first.
    pub fn bytes(&mut self) -> Result<&'a [u8]> {
        if self.at + 2 > self.bytes.len() {
            return Err(protocol_error("a TTC field cut short"));
        }
        let len = u16::from_be_bytes([self.bytes[self.at], self.bytes[self.at + 1]]) as usize;
        let start = self.at + 2;
        let end = start
            .checked_add(len)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| protocol_error("a TTC field longer than its message"))?;
        self.at = end;
        Ok(&self.bytes[start..end])
    }

    /// A counted string, read as UTF-8, lossily.
    ///
    /// # Errors
    /// Where the body ends first.
    pub fn string(&mut self) -> Result<String> {
        Ok(String::from_utf8_lossy(self.bytes()?).into_owned())
    }

    /// One unsigned byte.
    ///
    /// # Errors
    /// Where the body ends first.
    pub fn u8(&mut self) -> Result<u8> {
        let byte = *self
            .bytes
            .get(self.at)
            .ok_or_else(|| protocol_error("a TTC byte past the end"))?;
        self.at += 1;
        Ok(byte)
    }

    /// A big-endian u32.
    ///
    /// # Errors
    /// Where the body ends first.
    pub fn u32(&mut self) -> Result<u32> {
        let bytes = self.bytes()?;
        if bytes.len() != 4 {
            return Err(protocol_error("a TTC integer that is not four bytes"));
        }
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// A big-endian u64.
    ///
    /// # Errors
    /// Where the body ends first.
    pub fn u64(&mut self) -> Result<u64> {
        let bytes = self.bytes()?;
        if bytes.len() != 8 {
            return Err(protocol_error("a TTC long that is not eight bytes"));
        }
        let mut value = [0u8; 8];
        value.copy_from_slice(bytes);
        Ok(u64::from_be_bytes(value))
    }

    /// A counted array of counted values.
    ///
    /// # Errors
    /// Where the body ends first.
    pub fn array(&mut self) -> Result<Vec<Vec<u8>>> {
        let count = u16::from_be_bytes([self.u8()?, self.u8()?]) as usize;
        (0..count)
            .map(|_| self.bytes().map(<[u8]>::to_vec))
            .collect()
    }
}

/// A column value: a present byte — one for a value, zero for NULL — then
/// the value's counted bytes where it is present. A genuine empty value
/// and a NULL are then two different shapes, which is what a database
/// needs them to be.
pub fn put_value(out: &mut Vec<u8>, value: Option<&[u8]>) {
    match value {
        Some(bytes) => {
            out.push(1);
            put_bytes(out, bytes);
        }
        None => out.push(0),
    }
}

/// The value at the reader, `None` where it is NULL.
///
/// # Errors
/// Where the body ends first.
pub fn take_value(reader: &mut Reader<'_>) -> Result<Option<Vec<u8>>> {
    if reader.u8()? == 0 {
        return Ok(None);
    }
    Ok(Some(reader.bytes()?.to_vec()))
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

    /// A reader over this message's body.
    #[must_use]
    pub fn reader(&self) -> Reader<'_> {
        Reader::new(&self.body)
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
        put_str(&mut body, "orders");
        put_bytes(&mut body, &[0, 0xff]);
        let message = Message {
            tag: tag::EXECUTE,
            body,
        };
        let read = Message::from_payload(&message.to_payload()).expect("message");
        assert_eq!(read, message);
        let mut reader = read.reader();
        assert_eq!(reader.string().expect("service"), "orders");
        assert_eq!(reader.bytes().expect("bind"), &[0, 0xff]);
        assert!(Message::from_payload(&[]).is_err());
        assert_eq!(Message::bare(tag::LOGOFF).to_payload(), [tag::LOGOFF]);
    }

    #[test]
    fn integers_arrays_and_values_read_back() {
        let mut body = Vec::new();
        put_bytes(&mut body, &7u32.to_be_bytes());
        put_bytes(&mut body, &9u64.to_be_bytes());
        body.extend_from_slice(&2u16.to_be_bytes());
        put_bytes(&mut body, b"a");
        put_bytes(&mut body, b"bc");
        put_value(&mut body, Some(b"x"));
        put_value(&mut body, None);
        let mut reader = Reader::new(&body);
        assert_eq!(reader.u32().expect("u32"), 7);
        assert_eq!(reader.u64().expect("u64"), 9);
        assert_eq!(
            reader.array().expect("array"),
            vec![b"a".to_vec(), b"bc".to_vec()]
        );
        assert_eq!(take_value(&mut reader).expect("value"), Some(b"x".to_vec()));
        assert_eq!(take_value(&mut reader).expect("null"), None);
        assert!(Reader::new(&[0, 5, 1]).bytes().is_err(), "cut short");
        assert!(Reader::new(&[]).u8().is_err());
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
