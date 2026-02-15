use crate::error::Error;

use dns_message::Header;
use dns_message::header::Flags;

pub fn decode_header(data: &[u8]) -> Result<(Header, usize), Error> {
    if data.len() < 12 {
        return Err(Error::InvalidHeaderLength);
    }

    let id = (data[0] as u16) << 8 | data[1] as u16;
    let flags = Flags::from_flags_bytes(data[2], data[3]);
    let qd_count = (data[4] as u16) << 8 | data[5] as u16;
    let an_count = (data[6] as u16) << 8 | data[7] as u16;
    let ns_count = (data[8] as u16) << 8 | data[9] as u16;
    let ar_count = (data[10] as u16) << 8 | data[11] as u16;

    let header = Header::new(id, flags, qd_count, an_count, ns_count, ar_count);
    Ok((header, 12))
}

pub fn decode_flags(data: &[u8]) -> Result<(Flags, usize), Error> {
    if data.len() < 2 {
        return Err(Error::InsufficientData);
    }

    let flags = Flags::from_flags_bytes(data[0], data[1]);

    Ok((flags, 2))
}
