use super::header::encode_header;
use super::question::encode_question;
use super::resource_record::encode_resource_records;
use crate::error::Error;
use dns_message::Message;
use mt::WireLength;

pub fn encode_message<'a>(message: &Message<'a>) -> Result<Vec<u8>, Error> {
    let length = message.wire_length();
    let mut data = Vec::with_capacity(length);
    data.resize(length, 0);

    let mut offset = 0;

    let (_, header_len) = encode_header(&message.header, &mut data[offset..])?;
    offset += header_len;

    let (_, questions_len) = encode_question(&message.question, &mut data[offset..])?;
    offset += questions_len;

    let (_, answers_len) = encode_resource_records(&message.answer, &mut data[offset..])?;
    offset += answers_len;

    let (_, authorities_len) = encode_resource_records(&message.authority, &mut data[offset..])?;
    offset += authorities_len;

    let (_, additionals_len) = encode_resource_records(&message.additional, &mut data[offset..])?;
    offset += additionals_len;

    data.truncate(offset);

    Ok(data)
}
