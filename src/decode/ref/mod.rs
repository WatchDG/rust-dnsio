//! Zero-copy decoding using offset-based ref structures.
//!
//! All structures store only offsets into the message buffer — no slices or lifetimes.

use crate::error::Error;
use crate::refs::{
    HeaderRef, MessageRef, MsgOffset, NameRef, QuestionRef, QuestionSectionRef, ResourceRecordRef,
    ResourceRecordSectionRef,
};

/// Returns the wire length of a domain name starting at `offset` in `buf`.
fn name_wire_length_at(buf: &[u8], offset: MsgOffset) -> Result<usize, Error> {
    let mut pos = offset as usize;

    loop {
        if pos >= buf.len() {
            return Err(Error::InsufficientData);
        }

        let len_byte = buf[pos] as usize;
        pos += 1;

        if len_byte == 0 {
            break;
        }

        if len_byte >= 192 {
            if pos >= buf.len() {
                return Err(Error::InsufficientData);
            }
            pos += 1;
            break;
        }

        if len_byte >= 64 {
            continue;
        }

        if len_byte > 63 {
            return Err(Error::InvalidDomainName);
        }

        if pos + len_byte > buf.len() {
            return Err(Error::InsufficientData);
        }
        pos += len_byte;
    }

    Ok(pos - offset as usize)
}

/// Returns the wire length of a question record starting at `offset`.
fn question_wire_length_at(buf: &[u8], offset: MsgOffset) -> Result<usize, Error> {
    let name_len = name_wire_length_at(buf, offset)?;
    if (offset as usize) + name_len + 4 > buf.len() {
        return Err(Error::InsufficientData);
    }
    Ok(name_len + 4)
}

fn fill_resource_record_section(
    data: &[u8],
    offset: &mut MsgOffset,
    count: u16,
    max: usize,
) -> Result<ResourceRecordSectionRef, Error> {
    if count as usize > max {
        return Err(Error::InvalidDomainName);
    }

    let mut records = [
        ResourceRecordRef::empty(),
        ResourceRecordRef::empty(),
        ResourceRecordRef::empty(),
        ResourceRecordRef::empty(),
        ResourceRecordRef::empty(),
        ResourceRecordRef::empty(),
        ResourceRecordRef::empty(),
        ResourceRecordRef::empty(),
        ResourceRecordRef::empty(),
        ResourceRecordRef::empty(),
    ];

    for i in 0..count as usize {
        let len = resource_record_wire_length_at(data, *offset)? as MsgOffset;
        let name = NameRef::from_buf(data, *offset)?;
        records[i] = ResourceRecordRef::new(name, len);
        *offset = offset.saturating_add(len);
    }

    Ok(ResourceRecordSectionRef::new(records, *offset, count as u8))
}

/// Returns the wire length of a resource record starting at `offset`.
fn resource_record_wire_length_at(buf: &[u8], offset: MsgOffset) -> Result<usize, Error> {
    let name_len = name_wire_length_at(buf, offset)?;
    let rr_start = (offset as usize) + name_len;

    if rr_start + 10 > buf.len() {
        return Err(Error::InsufficientData);
    }

    let rdlength = (buf[rr_start + 8] as u16) << 8 | buf[rr_start + 9] as u16;
    let total = name_len + 10 + rdlength as usize;

    if rr_start + 10 + rdlength as usize > buf.len() {
        return Err(Error::InsufficientData);
    }

    Ok(total)
}

/// Decode a DNS message into ref structures (zero-copy, offset-based).
///
/// The returned `MessageRef` holds only offsets into `data`; `data` must remain valid
/// for the lifetime of any access to the refs.
pub fn decode_message_ref(data: &[u8]) -> Result<MessageRef, Error> {
    let header_ref = HeaderRef;
    let header = header_ref.decode_header(data)?;

    let qd_count = header.qd_count;
    let an_count = header.an_count;
    let ns_count = header.ns_count;
    let ar_count = header.ar_count;

    if qd_count > 5 {
        return Err(Error::InvalidDomainName);
    }

    let mut questions = [QuestionRef::new(0, 0); 5];
    let mut offset: MsgOffset = 12;

    for i in 0..qd_count as usize {
        let len = question_wire_length_at(data, offset)? as MsgOffset;
        questions[i] = QuestionRef::new(offset, len);
        offset = offset.saturating_add(len);
    }

    let question = QuestionSectionRef::new(questions, offset, qd_count as u8);

    let answer = fill_resource_record_section(data, &mut offset, an_count, 10)?;
    let authority = fill_resource_record_section(data, &mut offset, ns_count, 10)?;
    let additional = fill_resource_record_section(data, &mut offset, ar_count, 10)?;

    Ok(MessageRef {
        header: header_ref,
        question,
        answer,
        authority,
        additional,
    })
}
