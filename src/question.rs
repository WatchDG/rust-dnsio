use crate::error::Error;
use dns_message::{Label, NameElement};
use dns_message::{QClass, QType, Question};

pub fn decode_question<'a>(
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

        let question = Question::new(q_name, q_type, q_class);
        questions.push(question);
    }

    Ok((questions, offset))
}

pub fn decode_name(
    data: &[u8],
    message_offset: usize,
) -> Result<(Vec<NameElement<'_>>, usize), Error> {
    let mut offset = 0;
    let mut elements = Vec::new();

    loop {
        if message_offset + offset >= data.len() {
            return Err(Error::InsufficientData);
        }

        let length = data[message_offset + offset] as usize;
        offset += 1;

        if length == 0 {
            elements.push(NameElement::Root);
            break;
        }

        if length >= 192 {
            if message_offset + offset >= data.len() {
                return Err(Error::InsufficientData);
            }
            let second_byte = data[message_offset + offset] as u16;
            let pointer_value = ((length as u16 & 0x3F) << 8) | second_byte;
            offset += 1;

            elements.push(NameElement::Pointer(pointer_value));
            return Ok((elements, offset));
        }

        if length >= 64 {
            elements.push(NameElement::Reserved);
            continue;
        }

        if length > 63 {
            return Err(Error::InvalidDomainName);
        }

        if message_offset + offset + length > data.len() {
            return Err(Error::InsufficientData);
        }

        let label_data = &data[message_offset + offset..message_offset + offset + length];
        elements.push(NameElement::Label(Label::new(length as u8, label_data)));
        offset += length;
    }

    Ok((elements, offset))
}

pub fn encode_name<'a>(
    name: &[NameElement<'a>],
    buf: &'a mut [u8],
) -> Result<(&'a [u8], usize), Error> {
    let mut offset = 0;

    for element in name {
        match element {
            NameElement::Label(label) => {
                if buf.len() < offset + 1 + label.data.len() {
                    return Err(Error::InsufficientData);
                }
                buf[offset] = label.length;
                buf[offset + 1..offset + 1 + label.data.len()].copy_from_slice(label.data);
                offset += 1 + label.data.len();
            }
            NameElement::Pointer(ptr) => {
                if buf.len() < offset + 2 {
                    return Err(Error::InsufficientData);
                }
                buf[offset] = 0xC0 | ((ptr >> 8) as u8);
                buf[offset + 1] = (ptr & 0xFF) as u8;
                offset += 2;
            }
            NameElement::Root => {
                if buf.len() < offset + 1 {
                    return Err(Error::InsufficientData);
                }
                buf[offset] = 0;
                offset += 1;
            }
            NameElement::Reserved => return Err(Error::InvalidDomainName),
        }
    }

    Ok((&buf[..offset], offset))
}

pub fn encode_question<'a>(
    questions: &[Question<'a>],
    buf: &'a mut [u8],
) -> Result<(&'a [u8], usize), Error> {
    if questions.is_empty() {
        return Ok((&buf[..0], 0));
    }

    let mut offset = 0;

    for question in questions {
        let (_, name_len) = encode_name(&question.q_name, &mut buf[offset..])?;
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
