use super::name::decode_name;
use crate::error::Error;
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
