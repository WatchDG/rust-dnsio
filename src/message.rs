use crate::error::Error;
use crate::header::{calculate_header_length, decode_header, encode_header};
use crate::question::{calculate_questions_length, decode_questions, encode_questions};
use crate::resource_record::{
    calculate_resource_records_length, decode_resource_records, encode_resource_records,
};

use dns_message::Message;

pub fn decode_message<'a>(data: &'a [u8]) -> Result<Message<'a>, Error> {
    let (header, header_index) = decode_header(&data)?;
    let mut offset = header_index;

    let (questions, questions_len) =
        decode_questions(&data[offset..], data, offset, header.qd_count)?;
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

pub fn calculate_message_length<'a>(message: &Message<'a>) -> Result<usize, Error> {
    let length = calculate_header_length(&message.header);
    let length = length + calculate_questions_length(&message.question);
    let length = length + calculate_resource_records_length(&message.answer);
    let length = length + calculate_resource_records_length(&message.authority);
    let length = length + calculate_resource_records_length(&message.additional);
    Ok(length)
}

pub fn encode_message<'a>(message: &Message<'a>) -> Result<Vec<u8>, Error> {
    let length = calculate_message_length(message)?;
    let mut data = Vec::with_capacity(length);
    data.resize(length, 0);

    let mut offset = 0;

    let (_, header_len) = encode_header(&message.header, &mut data[offset..])?;
    offset += header_len;

    let (_, questions_len) = encode_questions(&message.question, &mut data[offset..])?;
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
