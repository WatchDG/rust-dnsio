use super::name::encode_name;
use crate::error::Error;
use dns_message::resource_record::ResourceRecord;

pub fn encode_resource_record<'a>(
    record: &ResourceRecord<'a>,
    buf: &'a mut [u8],
) -> Result<(&'a [u8], usize), Error> {
    let mut offset = 0;

    let (_, name_len) = encode_name(&record.rr_name, &mut buf[offset..])?;
    offset += name_len;

    if offset + 10 > buf.len() {
        return Err(Error::InsufficientData);
    }

    let (h_rr_type, l_rr_type) = record.rr_type.to_rr_bytes();
    let (h_rr_class, l_rr_class) = record.rr_class.to_rr_bytes();

    buf[offset] = h_rr_type;
    buf[offset + 1] = l_rr_type;
    buf[offset + 2] = h_rr_class;
    buf[offset + 3] = l_rr_class;
    buf[offset + 4] = (record.rr_ttl >> 24) as u8;
    buf[offset + 5] = (record.rr_ttl >> 16) as u8;
    buf[offset + 6] = (record.rr_ttl >> 8) as u8;
    buf[offset + 7] = record.rr_ttl as u8;
    buf[offset + 8] = (record.rr_rd_length >> 8) as u8;
    buf[offset + 9] = record.rr_rd_length as u8;
    offset += 10;

    if offset + record.rr_data.len() > buf.len() {
        return Err(Error::InsufficientData);
    }

    buf[offset..offset + record.rr_data.len()].copy_from_slice(record.rr_data);
    offset += record.rr_data.len();

    Ok((&buf[..offset], offset))
}

pub fn encode_resource_records<'a>(
    records: &[ResourceRecord<'a>],
    buf: &'a mut [u8],
) -> Result<(&'a [u8], usize), Error> {
    if records.is_empty() {
        return Ok((&buf[..0], 0));
    }

    let mut offset = 0;

    for record in records {
        let (_, bytes_written) = encode_resource_record(record, &mut buf[offset..])?;
        offset += bytes_written;
    }

    Ok((&buf[..offset], offset))
}
