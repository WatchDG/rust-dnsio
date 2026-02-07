use crate::error::Error;
use dns_message::Question;

pub fn decode_questions<'a>(data: &'a [u8], qd_count: u16) -> Result<Vec<Question<'a>>, Error> {
    if qd_count == 0 {
        return Ok(Vec::new());
    }

    let mut questions = Vec::with_capacity(qd_count as usize);
    let mut offset = 0;

    for _ in 0..qd_count {
        let (q_name_end, q_name) = decode_q_name(&data[offset..])?;
        offset += q_name_end;

        if offset + 4 > data.len() {
            return Err(Error::InsufficientData);
        }

        let q_type = (data[offset] as u16) << 8 | data[offset + 1] as u16;
        let q_class = (data[offset + 2] as u16) << 8 | data[offset + 3] as u16;
        offset += 4;

        let question = Question::new(q_name, q_type, q_class);
        questions.push(question);
    }

    Ok(questions)
}

fn decode_q_name(data: &[u8]) -> Result<(usize, &[u8]), Error> {
    let mut offset = 0;

    loop {
        if offset >= data.len() {
            return Err(Error::InsufficientData);
        }

        let length = data[offset] as usize;
        offset += 1;

        if length == 0 {
            break;
        }

        if length > 63 {
            return Err(Error::InvalidDomainName);
        }

        if offset + length > data.len() {
            return Err(Error::InsufficientData);
        }

        offset += length;
    }

    Ok((offset, &data[0..offset]))
}
