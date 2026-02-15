use crate::error::Error;

use dns_message::Header;
use dns_message::header::Flags;

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

pub fn encode_flags<'a>(flags: &Flags, buf: &'a mut [u8]) -> Result<(&'a [u8], usize), Error> {
    if buf.len() < 2 {
        return Err(Error::InsufficientData);
    }

    let (h, l) = flags.to_flags_bytes();
    buf[0] = h;
    buf[1] = l;

    Ok((&buf[0..2], 2))
}
