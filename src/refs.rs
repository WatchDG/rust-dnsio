//! Offset-based references into a DNS message buffer.
//!
//! All structures operate only with offsets relative to the message start.
//! No slices or lifetimes — suitable for zero-copy parsing and compression tables.
//!
//! Name elements are explicitly distinguished: Label, Pointer, Root, Reserved.

/// Offset from the start of the DNS message buffer.
/// DNS messages are limited to 65535 bytes (RFC 1035).
pub type MsgOffset = u16;

/// Length of the DNS header in bytes.
pub const HEADER_LEN: MsgOffset = 12;

/// First byte of a pointer: top 2 bits must be `11`.
pub const POINTER_MASK: u8 = 0xC0;

/// Maximum label length (RFC 1035).
pub const LABEL_MAX_LEN: u8 = 63;

/// Root label: single zero byte marking end of name.
pub const ROOT_LABEL: u8 = 0;

// -----------------------------------------------------------------------------
// Name element kinds (wire format)
// -----------------------------------------------------------------------------

/// A single element in a domain name wire representation.
///
/// Distinguishes between:
/// - **Label**: `[length][data...]` — length 1–63, top 2 bits of length byte = 00
/// - **Pointer**: 2 bytes, top 2 bits = 11, lower 14 bits = offset from message start
/// - **Root**: single 0x00 byte
/// - **Reserved**: top 2 bits = 01 or 10 (RFC 1035 reserved for future use)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NameElementRef {
    /// Normal label: offset points to the length byte.
    /// Wire: `[len][data...]` where len ∈ 1..=63.
    Label { offset: MsgOffset },

    /// Compression pointer: offset points to the first byte of the 2-byte pointer.
    /// Wire: `[0b11xxxxxx][xxxxxxxx]` — 14-bit offset from message start.
    Pointer { offset: MsgOffset },

    /// Root label: offset points to the 0x00 byte (end of name).
    Root { offset: MsgOffset },

    /// Reserved: top 2 bits = 01 or 10 (RFC 1035).
    Reserved { offset: MsgOffset },
}

impl NameElementRef {
    /// Returns the offset of this element in the message buffer.
    #[inline(always)]
    pub fn offset(&self) -> MsgOffset {
        match *self {
            NameElementRef::Label { offset }
            | NameElementRef::Pointer { offset }
            | NameElementRef::Root { offset }
            | NameElementRef::Reserved { offset } => offset,
        }
    }

    /// Classify a byte at `buf[offset]` as a name element kind.
    /// Does not validate bounds or pointer second byte.
    #[inline]
    pub fn classify_first_byte(byte: u8) -> NameElementKind {
        if byte == ROOT_LABEL {
            NameElementKind::Root
        } else if (byte & POINTER_MASK) == POINTER_MASK {
            NameElementKind::Pointer
        } else if (byte & POINTER_MASK) == 0 && byte <= LABEL_MAX_LEN {
            NameElementKind::Label
        } else {
            NameElementKind::Reserved
        }
    }

    /// Create a ref from offset, classifying using `buf[offset]`.
    #[inline]
    pub fn from_offset(buf: &[u8], offset: MsgOffset) -> Option<Self> {
        let off = offset as usize;
        if off >= buf.len() {
            return None;
        }
        let kind = Self::classify_first_byte(buf[off]);
        Some(match kind {
            NameElementKind::Label => NameElementRef::Label { offset },
            NameElementKind::Pointer => NameElementRef::Pointer { offset },
            NameElementKind::Root => NameElementRef::Root { offset },
            NameElementKind::Reserved => NameElementRef::Reserved { offset },
        })
    }
}

/// Classification of the first byte of a name element (no allocation).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NameElementKind {
    Label,
    Pointer,
    Root,
    Reserved,
}

// -----------------------------------------------------------------------------
// Message section refs
// -----------------------------------------------------------------------------

/// Reference to the header: always at offset 0, length 12.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HeaderRef;

impl HeaderRef {
    pub const OFFSET: MsgOffset = 0;
    pub const LEN: MsgOffset = HEADER_LEN;

    #[inline(always)]
    pub fn offset(&self) -> MsgOffset {
        Self::OFFSET
    }

    #[inline(always)]
    pub fn end(&self) -> MsgOffset {
        Self::OFFSET + Self::LEN
    }

    /// Decode the header from the full DNS message buffer.
    pub fn decode_header(&self, data: &[u8]) -> Result<dns_message::Header, crate::error::Error> {
        crate::decode::decode_header(data).map(|(header, _)| header)
    }
}

/// Reference to the question section (up to 5 questions).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct QuestionSectionRef {
    pub questions: [QuestionRef; 5],
    pub end_offset: MsgOffset,
    pub count: u8,
}

impl QuestionSectionRef {
    #[inline]
    pub fn new(questions: [QuestionRef; 5], end_offset: MsgOffset, count: u8) -> Self {
        Self {
            questions,
            end_offset,
            count,
        }
    }

    /// Returns a slice of valid question refs.
    #[inline]
    pub fn as_slice(&self) -> &[QuestionRef] {
        &self.questions[..self.count as usize]
    }
}

/// Reference to a question record.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct QuestionRef {
    /// Offset to the start of the question (first byte of QNAME).
    pub offset: MsgOffset,
    /// Length in bytes (QNAME + QTYPE + QCLASS).
    pub len: MsgOffset,
}

impl QuestionRef {
    #[inline]
    pub fn new(offset: MsgOffset, len: MsgOffset) -> Self {
        Self { offset, len }
    }

    #[inline]
    pub fn end(&self) -> MsgOffset {
        self.offset.saturating_add(self.len)
    }

    /// Decode the question from the full DNS message buffer.
    pub fn decode_question<'a>(
        &self,
        data: &'a [u8],
    ) -> Result<dns_message::Question<'a>, crate::error::Error> {
        let (questions, _) = crate::decode::decode_question(
            &data[self.offset as usize..],
            data,
            self.offset as usize,
            1,
        )?;
        Ok(questions.into_iter().next().unwrap())
    }
}

/// Reference to a resource record section (up to 10 records).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResourceRecordSectionRef {
    pub records: [ResourceRecordRef; 10],
    pub end_offset: MsgOffset,
    pub count: u8,
}

impl ResourceRecordSectionRef {
    #[inline]
    pub fn new(records: [ResourceRecordRef; 10], end_offset: MsgOffset, count: u8) -> Self {
        Self {
            records,
            end_offset,
            count,
        }
    }

    /// Returns a slice of valid resource record refs.
    #[inline]
    pub fn as_slice(&self) -> &[ResourceRecordRef] {
        &self.records[..self.count as usize]
    }
}

/// Reference to a resource record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResourceRecordRef {
    /// Reference to the domain name (first byte of RR).
    pub name: NameRef,
    /// Length in bytes (NAME + TYPE + CLASS + TTL + RDLENGTH + RDATA).
    pub len: MsgOffset,
}

impl ResourceRecordRef {
    #[inline]
    pub fn new(name: NameRef, len: MsgOffset) -> Self {
        Self { name, len }
    }

    /// Placeholder for unused slots in ResourceRecordSectionRef.
    #[inline]
    pub fn empty() -> Self {
        Self {
            name: NameRef::empty(),
            len: 0,
        }
    }

    /// Offset to the start of the RR (first byte of NAME).
    #[inline]
    pub fn offset(&self) -> MsgOffset {
        self.name.offset()
    }

    #[inline]
    pub fn end(&self) -> MsgOffset {
        self.name.offset().saturating_add(self.len)
    }

    /// Decode the resource record from the full DNS message buffer.
    pub fn decode_resource_record<'a>(
        &self,
        data: &'a [u8],
    ) -> Result<dns_message::resource_record::ResourceRecord<'a>, crate::error::Error> {
        let (record, _) = crate::decode::decode_resource_record(
            &data[self.offset() as usize..],
            data,
            self.offset() as usize,
        )?;
        Ok(record)
    }
}

/// Reference to a decoded DNS message.
///
/// Stores only offsets into the buffer; the buffer must outlive any access to the refs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MessageRef {
    pub header: HeaderRef,
    pub question: QuestionSectionRef,
    pub answer: ResourceRecordSectionRef,
    pub authority: ResourceRecordSectionRef,
    pub additional: ResourceRecordSectionRef,
}

impl MessageRef {
    /// Decode the full message from the DNS message buffer.
    pub fn decode_message<'a>(
        &self,
        data: &'a [u8],
    ) -> Result<dns_message::Message<'a>, crate::error::Error> {
        let header = self.header.decode_header(data)?;

        let mut questions = Vec::with_capacity(self.question.count as usize);
        for q in self.question.as_slice() {
            questions.push(q.decode_question(data)?);
        }

        let mut answers = Vec::with_capacity(self.answer.count as usize);
        for r in self.answer.as_slice() {
            answers.push(r.decode_resource_record(data)?);
        }

        let mut authority = Vec::with_capacity(self.authority.count as usize);
        for r in self.authority.as_slice() {
            authority.push(r.decode_resource_record(data)?);
        }

        let mut additional = Vec::with_capacity(self.additional.count as usize);
        for r in self.additional.as_slice() {
            additional.push(r.decode_resource_record(data)?);
        }

        Ok(dns_message::Message::new(
            header, questions, answers, authority, additional,
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NameRef {
    pub elements: [NameElementRef; 10],
    pub count: u8,
    pub end_offset: MsgOffset,
}

impl NameRef {
    #[inline]
    pub fn new(elements: [NameElementRef; 10], count: u8, end_offset: MsgOffset) -> Self {
        Self {
            elements,
            count,
            end_offset,
        }
    }

    /// Empty placeholder for unused slots.
    #[inline]
    pub fn empty() -> Self {
        Self {
            elements: [NameElementRef::Root { offset: 0 }; 10],
            count: 0,
            end_offset: 0,
        }
    }

    /// Parse a name from the buffer at the given offset.
    pub fn from_buf(buf: &[u8], offset: MsgOffset) -> Result<Self, crate::error::Error> {
        let (elements, count, end_offset) = parse_name_elements_into(buf, offset)?;
        Ok(Self::new(elements, count, end_offset))
    }

    /// Offset to the first byte of the name.
    #[inline]
    pub fn offset(&self) -> MsgOffset {
        if self.count == 0 {
            0
        } else {
            self.elements[0].offset()
        }
    }

    /// Returns a slice of valid elements.
    #[inline]
    pub fn as_slice(&self) -> &[NameElementRef] {
        &self.elements[..self.count as usize]
    }
}

/// Parse name elements starting at `offset` in `buf` into fixed array.
/// Returns (elements, count, end_offset). Max 10 elements.
fn parse_name_elements_into(
    buf: &[u8],
    offset: MsgOffset,
) -> Result<([NameElementRef; 10], u8, MsgOffset), crate::error::Error> {
    use crate::error::Error;

    let mut pos = offset as usize;
    let mut elements = [NameElementRef::Root { offset: 0 }; 10];
    let mut count: u8 = 0;

    loop {
        if pos >= buf.len() {
            return Err(Error::InsufficientData);
        }

        let len_byte = buf[pos];
        let elem_offset = pos as MsgOffset;

        if len_byte == 0 {
            if count >= 10 {
                return Err(Error::InvalidDomainName);
            }
            elements[count as usize] = NameElementRef::Root {
                offset: elem_offset,
            };
            count += 1;
            pos += 1;
            break;
        }

        if len_byte >= 192 {
            if pos + 1 >= buf.len() {
                return Err(Error::InsufficientData);
            }
            if count >= 10 {
                return Err(Error::InvalidDomainName);
            }
            elements[count as usize] = NameElementRef::Pointer {
                offset: elem_offset,
            };
            count += 1;
            pos += 2;
            break;
        }

        if len_byte >= 64 {
            if count >= 10 {
                return Err(Error::InvalidDomainName);
            }
            elements[count as usize] = NameElementRef::Reserved {
                offset: elem_offset,
            };
            count += 1;
            pos += 1;
            continue;
        }

        if len_byte > 63 {
            return Err(Error::InvalidDomainName);
        }

        if pos + 1 + len_byte as usize > buf.len() {
            return Err(Error::InsufficientData);
        }

        if count >= 10 {
            return Err(Error::InvalidDomainName);
        }
        elements[count as usize] = NameElementRef::Label {
            offset: elem_offset,
        };
        count += 1;
        pos += 1 + len_byte as usize;
    }

    let end_offset = pos as MsgOffset;
    Ok((elements, count, end_offset))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_label() {
        assert_eq!(
            NameElementRef::classify_first_byte(0),
            NameElementKind::Root
        );
        assert_eq!(
            NameElementRef::classify_first_byte(1),
            NameElementKind::Label
        );
        assert_eq!(
            NameElementRef::classify_first_byte(63),
            NameElementKind::Label
        );
        assert_eq!(
            NameElementRef::classify_first_byte(0xC0),
            NameElementKind::Pointer
        );
        assert_eq!(
            NameElementRef::classify_first_byte(0xFF),
            NameElementKind::Pointer
        );
        assert_eq!(
            NameElementRef::classify_first_byte(0x40),
            NameElementKind::Reserved
        );
        assert_eq!(
            NameElementRef::classify_first_byte(0x80),
            NameElementKind::Reserved
        );
    }
}
