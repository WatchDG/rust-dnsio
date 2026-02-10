use crate::error::Error;
use crate::question::decode_name;
use dns_message::resource_record::{RRClass, RRType, ResourceRecord, ResourceRecordNameKind};

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

pub fn encode_resource_record<'a>(
    record: &ResourceRecord<'a>,
    buf: &'a mut [u8],
) -> Result<(&'a [u8], usize), Error> {
    let mut offset = 0;

    let (_, name_len) = crate::question::encode_name(record.rr_name, &mut buf[offset..])?;
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

pub fn calculate_resource_records_length(records: &[ResourceRecord<'_>]) -> usize {
    records
        .iter()
        .map(|r| {
            let name_len = match r.rr_name.kind {
                ResourceRecordNameKind::Inline(slice) => slice.len(),
                ResourceRecordNameKind::Pointer(_) => 2,
            };
            name_len + 10 + r.rr_data.len()
        })
        .sum()
}
