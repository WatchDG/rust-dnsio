use crate::error::Error;

use dns_message::Flags;
use dns_message::Header;

pub fn decode_header(data: &[u8]) -> Result<(Header, usize), Error> {
    if data.len() < 12 {
        return Err(Error::InvalidHeaderLength);
    }

    let id = (data[0] as u16) << 8 | data[1] as u16;
    let flags = flags_from_u16((data[2] as u16) << 8 | data[3] as u16);
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

    let flags = flags_to_u16(&header.flags);

    buf[0] = (header.id >> 8) as u8;
    buf[1] = header.id as u8;
    buf[2] = (flags >> 8) as u8;
    buf[3] = flags as u8;
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

fn flags_from_u16(value: u16) -> Flags {
    Flags::new(
        (value & 0x8000) != 0,
        ((value >> 11) & 0x0F) as u8,
        (value & 0x0400) != 0,
        (value & 0x0200) != 0,
        (value & 0x0100) != 0,
        (value & 0x0080) != 0,
        ((value >> 4) & 0x07) as u8,
        (value & 0x0F) as u8,
    )
}

fn flags_to_u16(flags: &Flags) -> u16 {
    let mut value = 0u16;
    if flags.qr {
        value |= 0x8000;
    }
    value |= (flags.op_code as u16 & 0x0F) << 11;
    if flags.aa {
        value |= 0x0400;
    }
    if flags.tc {
        value |= 0x0200;
    }
    if flags.rd {
        value |= 0x0100;
    }
    if flags.ra {
        value |= 0x0080;
    }
    value |= (flags.z as u16 & 0x07) << 4;
    value |= flags.r_code as u16 & 0x0F;
    value
}

pub fn decode_header_flags(data: &[u8]) -> Result<(Flags, usize), Error> {
    if data.len() < 2 {
        return Err(Error::InsufficientData);
    }

    let flags_u16 = (data[0] as u16) << 8 | data[1] as u16;
    let flags = flags_from_u16(flags_u16);
    Ok((flags, 2))
}

pub fn encode_header_flags<'a>(
    flags: &Flags,
    buf: &'a mut [u8],
) -> Result<(&'a [u8], usize), Error> {
    if buf.len() < 2 {
        return Err(Error::InsufficientData);
    }

    let flags_u16 = flags_to_u16(flags);
    buf[0] = (flags_u16 >> 8) as u8;
    buf[1] = flags_u16 as u8;

    Ok((&buf[0..2], 2))
}

pub fn calculate_header_flags_length(_flags: &Flags) -> usize {
    2
}
