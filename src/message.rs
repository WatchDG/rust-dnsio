use crate::error::Error;
use crate::header::{decode_header, encode_header};
use crate::question::{decode_question, encode_question};
use crate::resource_record::{decode_resource_records, encode_resource_records};

use dns_message::Message;
use mt::WireLength;

pub fn decode_message<'a>(data: &'a [u8]) -> Result<Message<'a>, Error> {
    let (header, header_index) = decode_header(&data)?;
    let mut offset = header_index;

    let (questions, questions_len) =
        decode_question(&data[offset..], data, offset, header.qd_count)?;
    offset += questions_len;

    let (answers, answers_len) =
        decode_resource_records(&data[offset..], data, offset, header.an_count)?;
    offset += answers_len;

    let (authority, authority_len) =
        decode_resource_records(&data[offset..], data, offset, header.ns_count)?;
    offset += authority_len;

    let (additional, _) = decode_resource_records(&data[offset..], data, offset, header.ar_count)?;

    Ok(Message::new(
        header, questions, answers, authority, additional,
    ))
}

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
