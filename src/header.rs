use crate::error::Error;

use dns_message::Header;
use dns_message::header::{
    AuthoritativeAnswer, Flags, QueryResponse, RecursionDesired, Truncation,
};

pub fn decode_header(data: &[u8]) -> Result<(Header, usize), Error> {
    if data.len() < 12 {
        return Err(Error::InvalidHeaderLength);
    }

    let id = (data[0] as u16) << 8 | data[1] as u16;
    let flags = flags_from_bytes(data[2], data[3]);
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

    let (h_flags, l_flags) = flags_to_bytes(&header.flags);

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

fn flags_from_bytes(h: u8, l: u8) -> Flags {
    Flags::new(
        QueryResponse::from(h),
        (h >> 3) & 0x0F,
        AuthoritativeAnswer::from(h),
        Truncation::from(h),
        RecursionDesired::from(h),
        (l & 0x80) != 0,
        ((l >> 4) & 0x07) as u8,
        (l & 0x0F) as u8,
    )
}

fn flags_to_bytes(flags: &Flags) -> (u8, u8) {
    let h: u8 = u8::from(flags.qr)
        | (flags.op_code as u8 & 0x0F) << 3
        | u8::from(flags.aa)
        | u8::from(flags.tc)
        | u8::from(flags.rd);

    let mut l = 0u8;
    if flags.ra {
        l |= 0x0080;
    }
    l |= (flags.z & 0x07) << 4;
    l |= flags.r_code & 0x0F;
    (h, l)
}

pub fn decode_header_flags(data: &[u8]) -> Result<(Flags, usize), Error> {
    if data.len() < 2 {
        return Err(Error::InsufficientData);
    }

    let flags = flags_from_bytes(data[0], data[1]);
    Ok((flags, 2))
}

pub fn encode_header_flags<'a>(
    flags: &Flags,
    buf: &'a mut [u8],
) -> Result<(&'a [u8], usize), Error> {
    if buf.len() < 2 {
        return Err(Error::InsufficientData);
    }

    let (h, l) = flags_to_bytes(flags);
    buf[0] = h;
    buf[1] = l;

    Ok((&buf[0..2], 2))
}

pub fn calculate_header_flags_length(_flags: &Flags) -> usize {
    2
}
