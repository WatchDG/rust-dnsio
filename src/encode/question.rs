use super::name::encode_name;
use crate::error::Error;
use dns_message::Question;

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
