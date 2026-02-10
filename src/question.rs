use crate::error::Error;
use dns_message::resource_record::{ResourceRecordName, ResourceRecordNameKind};
use dns_message::{QClass, QType, Question};

pub fn decode_questions<'a>(
    data: &'a [u8],
    message_data: &'a [u8],
    message_offset: usize,
    qd_count: u16,
) -> Result<(Vec<Question<'a>>, usize), Error> {
    if qd_count == 0 {
        return Ok((Vec::new(), 0));
    }

    let mut questions = Vec::with_capacity(qd_count as usize);
    let mut offset = 0;

    for _ in 0..qd_count {
        let (q_name, q_name_end) = decode_name(message_data, message_offset + offset)?;
        offset += q_name_end;

        if offset + 4 > data.len() {
            return Err(Error::InsufficientData);
        }

        let q_type = QType::from_question_bytes(data[offset], data[offset + 1]);
        let q_class = QClass::from_question_bytes(data[offset + 2], data[offset + 3]);
        offset += 4;

        let q_name_slice = match q_name.kind {
            ResourceRecordNameKind::Inline(slice) => slice,
            ResourceRecordNameKind::Pointer(_) => return Err(Error::InvalidDomainName),
        };
        let question = Question::new(q_name_slice, q_type, q_class);
        questions.push(question);
    }

    Ok((questions, offset))
}

pub fn decode_name(
    data: &[u8],
    message_offset: usize,
) -> Result<(ResourceRecordName<'_>, usize), Error> {
    let mut offset = 0;
    let start_offset = message_offset;

    loop {
        if message_offset + offset >= data.len() {
            return Err(Error::InsufficientData);
        }

        let length = data[message_offset + offset] as usize;
        offset += 1;

        if length == 0 {
            break;
        }

        if length >= 192 {
            if message_offset + offset >= data.len() {
                return Err(Error::InsufficientData);
            }
            let second_byte = data[message_offset + offset] as u16;
            let pointer_value = ((length as u16 & 0x3F) << 8) | second_byte;
            offset += 1;

            let name = ResourceRecordName {
                offset: start_offset as u16,
                kind: ResourceRecordNameKind::Pointer(pointer_value),
            };
            return Ok((name, offset));
        }

        if length > 63 {
            println!("Invalid domain name length: {}", length);
            return Err(Error::InvalidDomainName);
        }

        if message_offset + offset + length > data.len() {
            return Err(Error::InsufficientData);
        }

        offset += length;
    }

    let name_slice = &data[start_offset..message_offset + offset];
    let name = ResourceRecordName {
        offset: start_offset as u16,
        kind: ResourceRecordNameKind::Inline(name_slice),
    };
    Ok((name, offset))
}

pub fn encode_name<'a>(
    name: ResourceRecordName<'a>,
    buf: &'a mut [u8],
) -> Result<(&'a [u8], usize), Error> {
    let name_slice = match name.kind {
        ResourceRecordNameKind::Inline(slice) => slice,
        ResourceRecordNameKind::Pointer(_) => return Err(Error::InvalidDomainName),
    };
    if name_slice.is_empty() {
        return Err(Error::InvalidDomainName);
    }

    if name_slice.last() != Some(&0) {
        return Err(Error::InvalidDomainName);
    }

    if buf.len() < name_slice.len() {
        return Err(Error::InsufficientData);
    }

    buf[..name_slice.len()].copy_from_slice(name_slice);
    Ok((&buf[..name_slice.len()], name_slice.len()))
}

pub fn encode_questions<'a>(
    questions: &[Question<'a>],
    buf: &'a mut [u8],
) -> Result<(&'a [u8], usize), Error> {
    if questions.is_empty() {
        return Ok((&buf[..0], 0));
    }

    let mut offset = 0;

    for question in questions {
        let name = ResourceRecordName {
            offset: 0,
            kind: ResourceRecordNameKind::Inline(question.q_name),
        };
        let (_, name_len) = encode_name(name, &mut buf[offset..])?;
        offset += name_len;

        if offset + 4 > buf.len() {
            return Err(Error::InsufficientData);
        }

        let (h_q_type, l_q_type) = question.q_type.to_question_bytes();
        let (h_q_class, l_q_class) = question.q_class.to_question_bytes();

        buf[offset] = h_q_type;
        buf[offset + 1] = l_q_type;
        buf[offset + 2] = h_q_class;
        buf[offset + 3] = l_q_class;
        offset += 4;
    }

    Ok((&buf[..offset], offset))
}

pub fn calculate_questions_length(questions: &[Question<'_>]) -> usize {
    questions.iter().map(|q| q.q_name.len() + 4).sum()
}
