use super::header::decode_header;
use super::question::decode_question;
use super::resource_record::decode_resource_records;
use crate::error::Error;
use dns_message::Message;

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
