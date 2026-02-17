use crate::decode::decode_message;
use crate::encode::encode_header;
use crate::error::Error;
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
