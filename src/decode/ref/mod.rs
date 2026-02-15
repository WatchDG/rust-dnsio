//! Zero-copy decoding using offset-based ref structures.
//!
//! All structures store only offsets into the message buffer — no slices or lifetimes.

use crate::error::Error;
use crate::refs::{HeaderRef, MessageRef, MsgOffset, NameRef, QuestionRef, ResourceRecordRef};

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
    if data.len() < 12 {
        return Err(Error::InvalidHeaderLength);
    }

    let qd_count = (data[4] as u16) << 8 | data[5] as u16;
    let an_count = (data[6] as u16) << 8 | data[7] as u16;
    let ns_count = (data[8] as u16) << 8 | data[9] as u16;
    let ar_count = (data[10] as u16) << 8 | data[11] as u16;

    let header = HeaderRef;

    let mut question = Vec::with_capacity(qd_count as usize);
    let mut offset: MsgOffset = 12;

    for _ in 0..qd_count {
        let len = question_wire_length_at(data, offset)? as MsgOffset;
        question.push(QuestionRef::new(offset, len));
        offset = offset.saturating_add(len);
    }

    let mut answer = Vec::with_capacity(an_count as usize);
    for _ in 0..an_count {
        let len = resource_record_wire_length_at(data, offset)? as MsgOffset;
        let name = NameRef::from_buf(data, offset)?;
        answer.push(ResourceRecordRef::new(name, len));
        offset = offset.saturating_add(len);
    }

    let mut authority = Vec::with_capacity(ns_count as usize);
    for _ in 0..ns_count {
        let len = resource_record_wire_length_at(data, offset)? as MsgOffset;
        let name = NameRef::from_buf(data, offset)?;
        authority.push(ResourceRecordRef::new(name, len));
        offset = offset.saturating_add(len);
    }

    let mut additional = Vec::with_capacity(ar_count as usize);
    for _ in 0..ar_count {
        let len = resource_record_wire_length_at(data, offset)? as MsgOffset;
        let name = NameRef::from_buf(data, offset)?;
        additional.push(ResourceRecordRef::new(name, len));
        offset = offset.saturating_add(len);
    }

    Ok(MessageRef {
        header,
        question,
        answer,
        authority,
        additional,
    })
}
