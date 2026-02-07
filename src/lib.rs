mod error;

use dns_message::{Header, Message};

pub use error::Error;

pub fn decode_header(data: &[u8]) -> Result<Header, Error> {
    if data.len() < 12 {
        return Err(Error::InvalidHeaderLength);
    }

    let id = (data[0] as u16) << 8 | data[1] as u16;
    let flags = (data[2] as u16) << 8 | data[3] as u16;
    let qd_count = (data[4] as u16) << 8 | data[5] as u16;
    let an_count = (data[6] as u16) << 8 | data[7] as u16;
    let ns_count = (data[8] as u16) << 8 | data[9] as u16;
    let ar_count = (data[10] as u16) << 8 | data[11] as u16;

    Ok(Header::new(
        id, flags, qd_count, an_count, ns_count, ar_count,
    ))
}

pub fn decode_message(data: &[u8]) -> Result<Message, Error> {
    let header = decode_header(data)?;

    Ok(Message::new(header))
}
