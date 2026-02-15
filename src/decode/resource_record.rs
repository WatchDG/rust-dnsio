use super::name::decode_name;
use crate::error::Error;
use dns_message::resource_record::{RRClass, RRType, ResourceRecord};

pub fn decode_resource_record<'a>(
    data: &'a [u8],
    message_data: &'a [u8],
    message_offset: usize,
) -> Result<(ResourceRecord<'a>, usize), Error> {
    let mut offset = 0;

    let (name, name_end) = decode_name(message_data, message_offset + offset)?;
    offset += name_end;

    if offset + 10 > data.len() {
        return Err(Error::InsufficientData);
    }

    let rr_type = RRType::from_rr_bytes(data[offset], data[offset + 1]);
    let rr_class = RRClass::from_rr_bytes(data[offset + 2], data[offset + 3]);

    let ttl = (data[offset + 4] as u32) << 24
        | (data[offset + 5] as u32) << 16
        | (data[offset + 6] as u32) << 8
        | data[offset + 7] as u32;
    let rdlength = (data[offset + 8] as u16) << 8 | data[offset + 9] as u16;
    offset += 10;

    if offset + rdlength as usize > data.len() {
        return Err(Error::InsufficientData);
    }

    let r_data = &data[offset..offset + rdlength as usize];
    offset += rdlength as usize;

    let resource_record = ResourceRecord::new(name, rr_type, rr_class, ttl, rdlength, r_data);
    Ok((resource_record, offset))
}

pub fn decode_resource_records<'a>(
    data: &'a [u8],
    message_data: &'a [u8],
    message_offset: usize,
    n: u16,
) -> Result<(Vec<ResourceRecord<'a>>, usize), Error> {
    if n == 0 {
        return Ok((Vec::new(), 0));
    }

    let mut records = Vec::with_capacity(n as usize);
    let mut offset = 0;

    for _ in 0..n {
        let (record, bytes_read) =
            decode_resource_record(&data[offset..], message_data, message_offset + offset)?;
        offset += bytes_read;
        records.push(record);
    }

    Ok((records, offset))
}
