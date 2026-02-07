use crate::error::Error;

use dns_message::Header;

pub fn decode_header(data: &[u8]) -> Result<(Header, usize), Error> {
    if data.len() < 12 {
        return Err(Error::InvalidHeaderLength);
    }

    let id = (data[0] as u16) << 8 | data[1] as u16;
    let flags = (data[2] as u16) << 8 | data[3] as u16;
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

    buf[0] = (header.id >> 8) as u8;
    buf[1] = header.id as u8;
    buf[2] = (header.flags >> 8) as u8;
    buf[3] = header.flags as u8;
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
