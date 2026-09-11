//! The Oracle Net transparent network substrate (TNS): a packet is an
//! eight-byte header — a big-endian length, two checksum fields a thin
//! client leaves zero, a type and a flag byte — and a body. Five types
//! carry a session: Connect offers a service, Accept agrees the sizes,
//! Refuse says no, Data carries the two-task layer under a two-byte data
//! flag, and Marker breaks in. Nothing here knows what the data means.

use std::io::{Read, Write};

use transport::error::{Result, TransportError, classify, protocol_error};

/// `NSPTCN`, a connect.
pub const CONNECT: u8 = 1;
/// `NSPTAC`, an accept.
pub const ACCEPT: u8 = 2;
/// `NSPTRF`, a refuse.
pub const REFUSE: u8 = 4;
/// `NSPTDA`, a data packet.
pub const DATA: u8 = 6;
/// `NSPTMK`, a marker.
pub const MARKER: u8 = 12;

/// The protocol version this crate offers and accepts.
pub const VERSION: u16 = 318;
/// The largest packet either side reads, the session data unit a modern
/// listener defaults to.
pub const MAX_PACKET: usize = 8192;
/// The data flag on an ordinary data packet.
const DATA_FLAG: u16 = 0;
/// The data flag that ends the session — a logoff's last packet.
pub const DATA_FLAG_EOF: u16 = 0x0040;

/// One packet read off the wire: its type, and its body past the header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    pub kind: u8,
    pub body: Vec<u8>,
}

impl Packet {
    /// The bytes of this packet, header and body.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let length = u16::try_from(self.body.len() + 8).unwrap_or(u16::MAX);
        let mut out = Vec::with_capacity(self.body.len() + 8);
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        out.push(self.kind);
        out.push(0);
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&self.body);
        out
    }

    /// Write this packet and flush.
    ///
    /// # Errors
    /// Where the connection broke.
    pub fn write(&self, writer: &mut impl Write) -> Result<()> {
        writer
            .write_all(&self.to_bytes())
            .and_then(|()| writer.flush())
            .map_err(|e| classify("writing a packet", &e))
    }

    /// Read one packet; `None` where the connection closed cleanly before
    /// one began.
    ///
    /// # Errors
    /// Where the connection broke mid-packet, or the packet is malformed
    /// or over [`MAX_PACKET`].
    pub fn read(reader: &mut impl Read) -> Result<Option<Self>> {
        let mut head = [0u8; 8];
        match reader.read_exact(&mut head) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(classify("reading a packet header", &e)),
        }
        let length = u16::from_be_bytes([head[0], head[1]]) as usize;
        if !(8..=MAX_PACKET).contains(&length) {
            return Err(protocol_error(format!("a TNS packet of {length} bytes")));
        }
        let mut body = vec![0u8; length - 8];
        reader
            .read_exact(&mut body)
            .map_err(|e| classify("reading a packet body", &e))?;
        Ok(Some(Self {
            kind: head[4],
            body,
        }))
    }

    /// Read one packet, which must be there.
    ///
    /// # Errors
    /// As [`Packet::read`], and where the connection closed.
    pub fn expect(reader: &mut impl Read) -> Result<Self> {
        Self::read(reader)?.ok_or_else(|| protocol_error("the peer closed the connection"))
    }
}

/// A connect packet carrying the connect string — the service a session
/// asks for.
#[must_use]
pub fn connect(connect_string: &str) -> Packet {
    let mut body = VERSION.to_be_bytes().to_vec();
    body.extend_from_slice(connect_string.as_bytes());
    Packet {
        kind: CONNECT,
        body,
    }
}

/// The connect string a connect packet carries.
///
/// # Errors
/// Where the packet is not a connect, or is too short to carry a version.
pub fn read_connect(packet: &Packet) -> Result<String> {
    if packet.kind != CONNECT || packet.body.len() < 2 {
        return Err(protocol_error("not a connect packet"));
    }
    Ok(String::from_utf8_lossy(&packet.body[2..]).into_owned())
}

/// An accept packet: the version agreed.
#[must_use]
pub fn accept() -> Packet {
    Packet {
        kind: ACCEPT,
        body: VERSION.to_be_bytes().to_vec(),
    }
}

/// A refuse packet carrying its reason.
#[must_use]
pub fn refuse(reason: &str) -> Packet {
    Packet {
        kind: REFUSE,
        body: reason.as_bytes().to_vec(),
    }
}

/// A data packet carrying `payload` under the ordinary data flag.
#[must_use]
pub fn data(payload: &[u8]) -> Packet {
    packet_with_flag(DATA_FLAG, payload)
}

/// A data packet with the end-of-file data flag and no payload: a
/// logoff's goodbye.
#[must_use]
pub fn data_eof() -> Packet {
    packet_with_flag(DATA_FLAG_EOF, &[])
}

fn packet_with_flag(flag: u16, payload: &[u8]) -> Packet {
    let mut body = flag.to_be_bytes().to_vec();
    body.extend_from_slice(payload);
    Packet { kind: DATA, body }
}

/// The two-task payload a data packet carries, and its data flag; the
/// end-of-file flag comes back with an empty payload.
///
/// # Errors
/// Where the packet is not a data packet or is too short for its flag.
pub fn read_data(packet: &Packet) -> Result<(u16, &[u8])> {
    if packet.kind != DATA || packet.body.len() < 2 {
        return Err(protocol_error("not a data packet"));
    }
    let flag = u16::from_be_bytes([packet.body[0], packet.body[1]]);
    Ok((flag, &packet.body[2..]))
}

/// The refusal a refuse packet or an unexpected type is, as an error.
#[must_use]
pub fn refused(packet: &Packet) -> TransportError {
    match packet.kind {
        REFUSE => TransportError::permanent(format!(
            "the listener refused the connection: {}",
            String::from_utf8_lossy(&packet.body)
        )),
        other => protocol_error(format!(
            "a packet of type {other} where a session was expected"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_connect_and_its_accept_read_back_over_a_wire() {
        let connect = connect("(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=orders)))");
        let mut wire = Vec::new();
        connect.write(&mut wire).expect("write");
        accept().write(&mut wire).expect("write");
        let mut cursor = &wire[..];
        let read = Packet::expect(&mut cursor).expect("connect");
        assert_eq!(read.kind, CONNECT);
        assert!(
            read_connect(&read)
                .expect("string")
                .contains("SERVICE_NAME=orders")
        );
        assert_eq!(Packet::expect(&mut cursor).expect("accept").kind, ACCEPT);
        assert_eq!(Packet::read(&mut cursor).expect("closed"), None);
    }

    #[test]
    fn a_data_packet_carries_its_flag_and_payload_and_a_refuse_is_an_error() {
        let mut wire = Vec::new();
        data(b"two-task").write(&mut wire).expect("write");
        data_eof().write(&mut wire).expect("write");
        let mut cursor = &wire[..];
        let first = Packet::expect(&mut cursor).expect("data");
        assert_eq!(read_data(&first).expect("payload"), (0, &b"two-task"[..]));
        let last = Packet::expect(&mut cursor).expect("eof");
        assert_eq!(read_data(&last).expect("eof"), (DATA_FLAG_EOF, &b""[..]));
        assert!(refused(&refuse("ORA-12514")).message.contains("ORA-12514"));
        assert!(!refused(&refuse("no")).retryable);
        assert!(refused(&accept()).message.contains("type 2"));
        let mut over = 9000u16.to_be_bytes().to_vec();
        over.extend_from_slice(&[0, 0, DATA, 0, 0, 0]);
        assert!(Packet::read(&mut &over[..]).is_err(), "over the maximum");
    }
}
