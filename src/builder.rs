use crate::decode::decode_message;
use crate::encode::encode_header;
use crate::error::Error;
use crate::refs::{CompressionTable, MessageRef, QuestionRef, ResourceRecordRef};
use dns_message::header::{Flags, OpCode, RCode, RD};
use dns_message::resource_record::{RRClass, RRType};
use dns_message::{Message, QClass, QType};
use std::borrow::Cow;

#[derive(Debug, Clone)]
pub struct MessageBuilder<'a> {
    id: u16,
    flags: Flags,
    questions: Vec<QuestionBuilder<'a>>,
    answers: Vec<ResourceRecordBuilder<'a>>,
    authority: Vec<ResourceRecordBuilder<'a>>,
    additional: Vec<ResourceRecordBuilder<'a>>,
}

#[derive(Debug, Clone)]
pub struct QuestionBuilder<'a> {
    pub name: Cow<'a, str>,
    pub q_type: QType,
    pub q_class: QClass,
}

#[derive(Debug, Clone)]
pub struct ResourceRecordBuilder<'a> {
    pub name: Cow<'a, str>,
    pub rr_type: RRType,
    pub rr_class: RRClass,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

impl<'a> MessageBuilder<'a> {
    pub fn query(id: u16) -> Self {
        Self::new(id, false)
    }

    pub fn response(id: u16) -> Self {
        Self::new(id, true)
    }

    pub fn new(id: u16, is_response: bool) -> Self {
        use dns_message::header::{AA, AD, CD, TC, Z};

        let qr = if is_response {
            dns_message::header::QR::Response
        } else {
            dns_message::header::QR::Query
        };

        let flags = Flags::new(
            qr,
            OpCode::Query,
            AA::NonAuthoritative,
            TC::NotTruncated,
            RD::RecursionDesired,
            dns_message::header::RA::RecursionNotAvailable,
            Z::Reserved,
            AD::DataNotAuthenticated,
            CD::CheckingEnabled,
            RCode::NoError,
        );

        Self {
            id,
            flags,
            questions: Vec::new(),
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
        }
    }

    pub fn id(mut self, id: u16) -> Self {
        self.id = id;
        self
    }

    pub fn flags(mut self, flags: Flags) -> Self {
        self.flags = flags;
        self
    }

    pub fn question(
        mut self,
        name: impl Into<Cow<'a, str>>,
        q_type: QType,
        q_class: QClass,
    ) -> Self {
        self.questions.push(QuestionBuilder {
            name: name.into(),
            q_type,
            q_class,
        });
        self
    }

    pub fn answer(
        mut self,
        name: impl Into<Cow<'a, str>>,
        rr_type: RRType,
        rr_class: RRClass,
        ttl: u32,
        rdata: impl Into<Vec<u8>>,
    ) -> Self {
        let rdata = rdata.into();
        self.answers.push(ResourceRecordBuilder {
            name: name.into(),
            rr_type,
            rr_class,
            ttl,
            rdata,
        });
        self
    }

    pub fn authority(
        mut self,
        name: impl Into<Cow<'a, str>>,
        rr_type: RRType,
        rr_class: RRClass,
        ttl: u32,
        rdata: impl Into<Vec<u8>>,
    ) -> Self {
        let rdata = rdata.into();
        self.authority.push(ResourceRecordBuilder {
            name: name.into(),
            rr_type,
            rr_class,
            ttl,
            rdata,
        });
        self
    }

    pub fn additional(
        mut self,
        name: impl Into<Cow<'a, str>>,
        rr_type: RRType,
        rr_class: RRClass,
        ttl: u32,
        rdata: impl Into<Vec<u8>>,
    ) -> Self {
        let rdata = rdata.into();
        self.additional.push(ResourceRecordBuilder {
            name: name.into(),
            rr_type,
            rr_class,
            ttl,
            rdata,
        });
        self
    }

    pub fn build(self, buffer: &mut Vec<u8>) -> Result<Message<'_>, Error> {
        *buffer = self.build_encode_direct()?;
        decode_message(buffer)
    }

    pub fn build_encode_direct(self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();

        let mut total = 12u64;
        for q in &self.questions {
            total += encoded_name_len(&q.name)? as u64 + 4;
        }
        for r in &self.answers {
            total += encoded_name_len(&r.name)? as u64 + 10 + r.rdata.len() as u64;
        }
        for r in &self.authority {
            total += encoded_name_len(&r.name)? as u64 + 10 + r.rdata.len() as u64;
        }
        for r in &self.additional {
            total += encoded_name_len(&r.name)? as u64 + 10 + r.rdata.len() as u64;
        }
        buf.reserve(total.min(65535) as usize);

        let header = dns_message::Header::new(
            self.id,
            self.flags,
            self.questions.len() as u16,
            self.answers.len() as u16,
            self.authority.len() as u16,
            self.additional.len() as u16,
        );
        let mut offset = 0;
        buf.resize(12, 0);
        encode_header(&header, &mut buf[offset..])?;
        offset += 12;

        for q in &self.questions {
            let name_bytes = encode_name_bytes(&q.name)?;
            let need = name_bytes.len() + 4;
            buf.resize(offset + need, 0);
            buf[offset..offset + name_bytes.len()].copy_from_slice(&name_bytes);
            offset += name_bytes.len();
            let (h_type, l_type) = q.q_type.to_question_bytes();
            let (h_class, l_class) = q.q_class.to_question_bytes();
            buf[offset] = h_type;
            buf[offset + 1] = l_type;
            buf[offset + 2] = h_class;
            buf[offset + 3] = l_class;
            offset += 4;
        }

        for records in [&self.answers, &self.authority, &self.additional] {
            for r in records {
                let name_bytes = encode_name_bytes(&r.name)?;
                let need = name_bytes.len() + 10 + r.rdata.len();
                buf.resize(offset + need, 0);
                buf[offset..offset + name_bytes.len()].copy_from_slice(&name_bytes);
                offset += name_bytes.len();
                let (h_type, l_type) = r.rr_type.to_rr_bytes();
                let (h_class, l_class) = r.rr_class.to_rr_bytes();
                buf[offset] = h_type;
                buf[offset + 1] = l_type;
                buf[offset + 2] = h_class;
                buf[offset + 3] = l_class;
                buf[offset + 4] = (r.ttl >> 24) as u8;
                buf[offset + 5] = (r.ttl >> 16) as u8;
                buf[offset + 6] = (r.ttl >> 8) as u8;
                buf[offset + 7] = r.ttl as u8;
                buf[offset + 8] = (r.rdata.len() >> 8) as u8;
                buf[offset + 9] = r.rdata.len() as u8;
                buf[offset + 10..offset + 10 + r.rdata.len()].copy_from_slice(&r.rdata);
                offset += 10 + r.rdata.len();
            }
        }

        buf.truncate(offset);
        Ok(buf)
    }
}

fn encode_name_bytes(name: &str) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    if name.is_empty() {
        buf.push(0);
        return Ok(buf);
    }
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        if label.len() > 63 {
            return Err(Error::InvalidDomainName);
        }
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
    Ok(buf)
}

fn encoded_name_len(name: &str) -> Result<usize, Error> {
    Ok(encode_name_bytes(name)?.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_message::{QClass, QType};

    fn sample_dns_message() -> Vec<u8> {
        vec![
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ]
    }

    #[test]
    fn builder_produces_same_as_sample() {
        let expected = sample_dns_message();
        let mut buffer = Vec::new();
        let message = MessageBuilder::query(1)
            .question("example.com", QType::A, QClass::IN)
            .build(&mut buffer)
            .unwrap();
        assert_eq!(message.question.len(), 1);
        assert_eq!(buffer, expected);
    }

    #[test]
    fn build_encode_direct_returns_bytes() {
        let bytes = MessageBuilder::query(1)
            .question("example.com", QType::A, QClass::IN)
            .build_encode_direct()
            .unwrap();
        assert_eq!(bytes, sample_dns_message());
    }

    #[test]
    fn builder_with_answer() {
        let mut buffer = Vec::new();
        let message = MessageBuilder::response(1)
            .question("example.com", QType::A, QClass::IN)
            .answer(
                "example.com",
                dns_message::resource_record::RRType::A,
                dns_message::resource_record::RRClass::IN,
                3600,
                [93u8, 184, 216, 34],
            )
            .build(&mut buffer)
            .unwrap();
        assert_eq!(message.question.len(), 1);
        assert_eq!(message.answer.len(), 1);
    }
}

#[derive(Debug, Clone)]
pub struct MessageRefBuilder {
    id: Option<u16>,
    flags: Option<Flags>,
    questions: Vec<QuestionRef>,
    answers: Vec<ResourceRecordRef>,
    authority: Vec<ResourceRecordRef>,
    additional: Vec<ResourceRecordRef>,
}

impl MessageRefBuilder {
    pub fn from_ref(_ref: &MessageRef) -> Self {
        Self {
            id: None,
            flags: None,
            questions: Vec::new(),
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
        }
    }

    pub fn id(mut self, id: u16) -> Self {
        self.id = Some(id);
        self
    }

    pub fn flags(mut self, flags: Flags) -> Self {
        self.flags = Some(flags);
        self
    }

    pub fn question(mut self, q: QuestionRef) -> Self {
        self.questions.push(q);
        self
    }

    pub fn answer(mut self, r: ResourceRecordRef) -> Self {
        self.answers.push(r);
        self
    }

    pub fn authority(mut self, r: ResourceRecordRef) -> Self {
        self.authority.push(r);
        self
    }

    pub fn additional(mut self, r: ResourceRecordRef) -> Self {
        self.additional.push(r);
        self
    }

    pub fn buffer_size(&self) -> usize {
        12 + self.questions.iter().map(|q| q.len as usize).sum::<usize>()
            + self.answers.iter().map(|r| r.len as usize).sum::<usize>()
            + self.authority.iter().map(|r| r.len as usize).sum::<usize>()
            + self
                .additional
                .iter()
                .map(|r| r.len as usize)
                .sum::<usize>()
    }

    pub fn build_to(
        self,
        dst: &mut Vec<u8>,
        src: &[u8],
        base_id: u16,
        base_flags: Flags,
    ) -> Result<(), Error> {
        let id = self.id.unwrap_or(base_id);
        let flags = self.flags.unwrap_or(base_flags);

        let q_count = self.questions.len() as u16;
        let an_count = self.answers.len() as u16;
        let au_count = self.authority.len() as u16;
        let ad_count = self.additional.len() as u16;

        let header = dns_message::Header::new(id, flags, q_count, an_count, au_count, ad_count);

        let total_size = 12
            + self.questions.iter().map(|q| q.len as usize).sum::<usize>()
            + self.answers.iter().map(|r| r.len as usize).sum::<usize>()
            + self.authority.iter().map(|r| r.len as usize).sum::<usize>()
            + self
                .additional
                .iter()
                .map(|r| r.len as usize)
                .sum::<usize>();

        dst.reserve(total_size);
        dst.resize(12, 0);
        encode_header(&header, &mut dst[..12])?;

        for q in &self.questions {
            q.encode_to(dst, src)?;
        }

        for r in &self.answers {
            r.encode_to(dst, src)?;
        }

        for r in &self.authority {
            r.encode_to(dst, src)?;
        }

        for r in &self.additional {
            r.encode_to(dst, src)?;
        }

        Ok(())
    }

    pub fn write_to_slice(
        self,
        dst: &mut [u8],
        src: &[u8],
        base_id: u16,
        base_flags: Flags,
    ) -> Result<usize, Error> {
        let id = self.id.unwrap_or(base_id);
        let flags = self.flags.unwrap_or(base_flags);

        let q_count = self.questions.len() as u16;
        let an_count = self.answers.len() as u16;
        let au_count = self.authority.len() as u16;
        let ad_count = self.additional.len() as u16;

        let total_size = 12
            + self.questions.iter().map(|q| q.len as usize).sum::<usize>()
            + self.answers.iter().map(|r| r.len as usize).sum::<usize>()
            + self.authority.iter().map(|r| r.len as usize).sum::<usize>()
            + self
                .additional
                .iter()
                .map(|r| r.len as usize)
                .sum::<usize>();

        if dst.len() < total_size {
            return Err(Error::InsufficientData);
        }

        let header = dns_message::Header::new(id, flags, q_count, an_count, au_count, ad_count);

        encode_header(&header, &mut dst[..12])?;
        let mut offset = 12;

        for q in &self.questions {
            let qname_len = q.len.saturating_sub(4) as usize;
            let qname_end = q.offset as usize + qname_len;
            dst[offset..offset + qname_len].copy_from_slice(&src[q.offset as usize..qname_end]);
            offset += qname_len;
            dst[offset..offset + 4].copy_from_slice(&src[qname_end..qname_end + 4]);
            offset += 4;
        }

        for r in &self.answers {
            let rr_start = r.offset() as usize;
            let rr_end = rr_start + r.len as usize;
            dst[offset..offset + r.len as usize].copy_from_slice(&src[rr_start..rr_end]);
            offset += r.len as usize;
        }

        for r in &self.authority {
            let rr_start = r.offset() as usize;
            let rr_end = rr_start + r.len as usize;
            dst[offset..offset + r.len as usize].copy_from_slice(&src[rr_start..rr_end]);
            offset += r.len as usize;
        }

        for r in &self.additional {
            let rr_start = r.offset() as usize;
            let rr_end = rr_start + r.len as usize;
            dst[offset..offset + r.len as usize].copy_from_slice(&src[rr_start..rr_end]);
            offset += r.len as usize;
        }

        Ok(offset)
    }

    pub fn build_to_with_compression(
        self,
        dst: &mut Vec<u8>,
        src: &[u8],
        base_id: u16,
        base_flags: Flags,
    ) -> Result<(), Error> {
        let id = self.id.unwrap_or(base_id);
        let flags = self.flags.unwrap_or(base_flags);

        let q_count = self.questions.len() as u16;
        let an_count = self.answers.len() as u16;
        let au_count = self.authority.len() as u16;
        let ad_count = self.additional.len() as u16;

        let header = dns_message::Header::new(id, flags, q_count, an_count, au_count, ad_count);

        dst.reserve(12);
        dst.resize(12, 0);
        encode_header(&header, &mut dst[..12])?;

        let mut compression = CompressionTable::new();
        let mut offset = 12;

        for q in &self.questions {
            let qname_len = q.len.saturating_sub(4) as usize;
            let qname_end = q.offset as usize + qname_len;
            let name_bytes = &src[q.offset as usize..qname_end];

            if let Some(compressed_offset) = compression.get(name_bytes) {
                dst.push(0xC0 | ((compressed_offset >> 8) as u8));
                dst.push(compressed_offset as u8);
            } else {
                compression.insert(name_bytes, offset as u16);
                dst.extend_from_slice(name_bytes);
                offset += name_bytes.len();
            }
            dst.extend_from_slice(&src[qname_end..qname_end + 4]);
            offset += 4;
        }

        for r in &self.answers {
            let name_len = r.name.end_offset - r.name.offset();
            let name_offset = r.name.offset() as usize;
            let name_end = name_offset + name_len as usize;
            let name_bytes = &src[name_offset..name_end];

            if let Some(compressed_offset) = compression.get(name_bytes) {
                dst.push(0xC0 | ((compressed_offset >> 8) as u8));
                dst.push(compressed_offset as u8);
                offset += 2;
            } else {
                compression.insert(name_bytes, offset as u16);
                dst.extend_from_slice(name_bytes);
                offset += name_len as usize;
            }

            let rr_start = r.offset() as usize;
            let rr_end = rr_start + r.len as usize;
            dst.extend_from_slice(&src[rr_start + name_len as usize..rr_end]);
            offset += (r.len - name_len) as usize;
        }

        for r in &self.authority {
            let name_len = r.name.end_offset - r.name.offset();
            let name_offset = r.name.offset() as usize;
            let name_end = name_offset + name_len as usize;
            let name_bytes = &src[name_offset..name_end];

            if let Some(compressed_offset) = compression.get(name_bytes) {
                dst.push(0xC0 | ((compressed_offset >> 8) as u8));
                dst.push(compressed_offset as u8);
                offset += 2;
            } else {
                compression.insert(name_bytes, offset as u16);
                dst.extend_from_slice(name_bytes);
                offset += name_len as usize;
            }

            let rr_start = r.offset() as usize;
            let rr_end = rr_start + r.len as usize;
            dst.extend_from_slice(&src[rr_start + name_len as usize..rr_end]);
            offset += (r.len - name_len) as usize;
        }

        for r in &self.additional {
            let name_len = r.name.end_offset - r.name.offset();
            let name_offset = r.name.offset() as usize;
            let name_end = name_offset + name_len as usize;
            let name_bytes = &src[name_offset..name_end];

            if let Some(compressed_offset) = compression.get(name_bytes) {
                dst.push(0xC0 | ((compressed_offset >> 8) as u8));
                dst.push(compressed_offset as u8);
                offset += 2;
            } else {
                compression.insert(name_bytes, offset as u16);
                dst.extend_from_slice(name_bytes);
                offset += name_len as usize;
            }

            let rr_start = r.offset() as usize;
            let rr_end = rr_start + r.len as usize;
            dst.extend_from_slice(&src[rr_start + name_len as usize..rr_end]);
            offset += (r.len - name_len) as usize;
        }

        Ok(())
    }
}

#[cfg(test)]
mod message_ref_builder_tests {
    use super::*;

    fn sample_message_bytes() -> Vec<u8> {
        vec![
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ]
    }

    #[test]
    fn message_ref_builder_id_override() {
        let bytes = sample_message_bytes();
        let msg_ref = crate::decode::decode_message_ref(&bytes).unwrap();

        let base_header = msg_ref.header.decode_header(&bytes).unwrap();
        let base_flags = base_header.flags;

        let mut dst = Vec::new();
        MessageRefBuilder::from_ref(&msg_ref)
            .id(0xABCD)
            .build_to(&mut dst, &bytes, base_header.id, base_flags)
            .unwrap();

        assert_eq!((dst[0], dst[1]), (0xAB, 0xCD));
    }

    #[test]
    fn message_ref_builder_preserves_question() {
        let bytes = sample_message_bytes();
        let msg_ref = crate::decode::decode_message_ref(&bytes).unwrap();

        let base_header = msg_ref.header.decode_header(&bytes).unwrap();
        let base_flags = base_header.flags;

        let mut dst = Vec::new();
        MessageRefBuilder::from_ref(&msg_ref)
            .question(msg_ref.question.questions[0])
            .build_to(&mut dst, &bytes, base_header.id, base_flags)
            .unwrap();

        let question_bytes = &bytes[12..];
        assert_eq!(&dst[12..], question_bytes);
    }

    #[test]
    fn buffer_size_calculation() {
        let bytes = sample_message_bytes();
        let msg_ref = crate::decode::decode_message_ref(&bytes).unwrap();

        let builder = MessageRefBuilder::from_ref(&msg_ref).question(msg_ref.question.questions[0]);

        assert_eq!(builder.buffer_size(), bytes.len());
    }

    #[test]
    fn write_to_slice_success() {
        let bytes = sample_message_bytes();
        let msg_ref = crate::decode::decode_message_ref(&bytes).unwrap();

        let base_header = msg_ref.header.decode_header(&bytes).unwrap();
        let base_flags = base_header.flags;

        let builder = MessageRefBuilder::from_ref(&msg_ref).question(msg_ref.question.questions[0]);

        let size = builder.buffer_size();
        let mut buf = vec![0u8; size];

        let written = builder
            .write_to_slice(&mut buf, &bytes, base_header.id, base_flags)
            .unwrap();

        assert_eq!(written, size);
        assert_eq!(&buf[12..], &bytes[12..]);
    }

    #[test]
    fn write_to_slice_insufficient_buffer() {
        let bytes = sample_message_bytes();
        let msg_ref = crate::decode::decode_message_ref(&bytes).unwrap();

        let base_header = msg_ref.header.decode_header(&bytes).unwrap();
        let base_flags = base_header.flags;

        let builder = MessageRefBuilder::from_ref(&msg_ref).question(msg_ref.question.questions[0]);

        let mut buf = vec![0u8; 10];

        let result = builder.write_to_slice(&mut buf, &bytes, base_header.id, base_flags);
        assert!(result.is_err());
    }

    #[test]
    fn message_ref_builder_empty_sections() {
        let bytes = sample_message_bytes();
        let msg_ref = crate::decode::decode_message_ref(&bytes).unwrap();
        let base_header = msg_ref.header.decode_header(&bytes).unwrap();

        let mut dst = Vec::new();
        MessageRefBuilder::from_ref(&msg_ref)
            .build_to(&mut dst, &bytes, base_header.id, base_header.flags)
            .unwrap();

        assert_eq!(dst.len(), 12);
    }

    #[test]
    fn message_ref_builder_multiple_questions() {
        let bytes = vec![
            0x00, 0x01, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01, 0x04, b'n', b's', b'1', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x02, 0x00, 0x01,
        ];
        let msg_ref = crate::decode::decode_message_ref(&bytes).unwrap();
        let base_header = msg_ref.header.decode_header(&bytes).unwrap();

        let mut dst = Vec::new();
        let builder = MessageRefBuilder::from_ref(&msg_ref)
            .question(msg_ref.question.questions[0])
            .question(msg_ref.question.questions[1]);
        dst.reserve(builder.buffer_size());

        builder
            .build_to(&mut dst, &bytes, base_header.id, base_header.flags)
            .unwrap();

        assert_eq!(dst.len(), bytes.len());
        assert_eq!(dst[4..6], [0x00, 0x02]);
    }

    #[test]
    fn message_ref_builder_reuses_buffer() {
        let bytes = sample_message_bytes();
        let msg_ref = crate::decode::decode_message_ref(&bytes).unwrap();
        let base_header = msg_ref.header.decode_header(&bytes).unwrap();

        let builder = MessageRefBuilder::from_ref(&msg_ref).question(msg_ref.question.questions[0]);
        let size = builder.buffer_size();
        let mut dst = vec![0xFFu8; 100];

        builder
            .write_to_slice(&mut dst[..size], &bytes, base_header.id, base_header.flags)
            .unwrap();

        assert_eq!(&dst[12..size], &bytes[12..]);
        assert_eq!(dst[size], 0xFF);
    }

    #[test]
    fn buffer_size_with_empty_sections() {
        let bytes = sample_message_bytes();
        let msg_ref = crate::decode::decode_message_ref(&bytes).unwrap();

        let builder = MessageRefBuilder::from_ref(&msg_ref);
        assert_eq!(builder.buffer_size(), 12);

        let builder = MessageRefBuilder::from_ref(&msg_ref).question(msg_ref.question.questions[0]);
        assert_eq!(builder.buffer_size(), bytes.len());
    }

    #[test]
    fn message_ref_builder_roundtrip() {
        let bytes = sample_dns_message_with_answer();
        let msg_ref = crate::decode::decode_message_ref(&bytes).unwrap();
        let base_header = msg_ref.header.decode_header(&bytes).unwrap();

        let mut dst = Vec::new();
        MessageRefBuilder::from_ref(&msg_ref)
            .question(msg_ref.question.questions[0])
            .answer(msg_ref.answer.records[0])
            .build_to(&mut dst, &bytes, base_header.id, base_header.flags)
            .unwrap();

        let reparsed = crate::decode::decode_message_ref(&dst).unwrap();
        assert_eq!(reparsed.question.count, 1);
        assert_eq!(reparsed.answer.count, 1);
    }

    #[test]
    fn message_ref_builder_with_compression() {
        let bytes = sample_dns_message_with_answer();
        let msg_ref = crate::decode::decode_message_ref(&bytes).unwrap();
        let base_header = msg_ref.header.decode_header(&bytes).unwrap();

        let mut dst = Vec::new();
        MessageRefBuilder::from_ref(&msg_ref)
            .question(msg_ref.question.questions[0])
            .answer(msg_ref.answer.records[0])
            .build_to_with_compression(&mut dst, &bytes, base_header.id, base_header.flags)
            .unwrap();

        let reparsed = crate::decode::decode_message_ref(&dst).unwrap();
        assert_eq!(reparsed.question.count, 1);
        assert_eq!(reparsed.answer.count, 1);

        assert!(dst.len() < bytes.len());
    }

    #[test]
    fn compression_reduces_size() {
        let bytes = vec![
            0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01, 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x04, 0x5d, 0xb8, 0xd8, 0x22,
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
            0x01, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x04, 0x5d, 0xb8, 0xd8, 0x23, 0x07,
            b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01,
            0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x04, 0x5d, 0xb8, 0xd8, 0x24,
        ];
        let msg_ref = crate::decode::decode_message_ref(&bytes).unwrap();
        let base_header = msg_ref.header.decode_header(&bytes).unwrap();

        let mut dst_no_compress = Vec::new();
        MessageRefBuilder::from_ref(&msg_ref)
            .question(msg_ref.question.questions[0])
            .answer(msg_ref.answer.records[0])
            .answer(msg_ref.answer.records[1])
            .answer(msg_ref.answer.records[2])
            .build_to(
                &mut dst_no_compress,
                &bytes,
                base_header.id,
                base_header.flags,
            )
            .unwrap();

        let mut dst_compress = Vec::new();
        MessageRefBuilder::from_ref(&msg_ref)
            .question(msg_ref.question.questions[0])
            .answer(msg_ref.answer.records[0])
            .answer(msg_ref.answer.records[1])
            .answer(msg_ref.answer.records[2])
            .build_to_with_compression(&mut dst_compress, &bytes, base_header.id, base_header.flags)
            .unwrap();

        assert!(dst_compress.len() < dst_no_compress.len());
        assert_eq!(dst_compress.len(), bytes.len() - 3 * 11);
    }

    fn sample_dns_message_with_answer() -> Vec<u8> {
        vec![
            0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01, 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x04, 0x5d, 0xb8, 0xd8, 0x22,
        ]
    }
}
