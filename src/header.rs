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

pub fn encode_header<'a>(header: &Header, buf: &'a mut [u8]) -> Result<(&'a [u8], usize), Error> {
    if buf.len() < 12 {
        return Err(Error::InvalidHeaderLength);
    }

    let (h_flags, l_flags) = header.flags.to_flags_bytes();

    buf[0] = (header.id >> 8) as u8;
    buf[1] = header.id as u8;
    buf[2] = h_flags;
    buf[3] = l_flags;
    buf[4] = (header.qd_count >> 8) as u8;
    buf[5] = header.qd_count as u8;
    buf[6] = (header.an_count >> 8) as u8;
    buf[7] = header.an_count as u8;
    buf[8] = (header.ns_count >> 8) as u8;
    buf[9] = header.ns_count as u8;
    buf[10] = (header.ar_count >> 8) as u8;
    buf[11] = header.ar_count as u8;

    Ok((&buf[0..12], 12))
}

pub fn calculate_header_length(_header: &Header) -> usize {
    12
}

pub fn decode_header_flags(data: &[u8]) -> Result<(Flags, usize), Error> {
    if data.len() < 2 {
        return Err(Error::InsufficientData);
    }

    let flags = Flags::from_flags_bytes(data[0], data[1]);

    Ok((flags, 2))
}

pub fn encode_header_flags<'a>(
    flags: &Flags,
    buf: &'a mut [u8],
) -> Result<(&'a [u8], usize), Error> {
    if buf.len() < 2 {
        return Err(Error::InsufficientData);
    }

    let (h, l) = flags.to_flags_bytes();
    buf[0] = h;
    buf[1] = l;

    Ok((&buf[0..2], 2))
}

pub fn calculate_header_flags_length(_flags: &Flags) -> usize {
    2
}
