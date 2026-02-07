use crate::error::Error;
use crate::header::decode_header;
use crate::question::decode_questions;
use crate::resource_record::decode_resource_records;

use dns_message::Additional;
use dns_message::Answer;
use dns_message::Authority;
use dns_message::Message;
use dns_message::Question;

type Questions<'a> = Vec<Question<'a>>;
type Answers<'a> = Vec<Answer<'a>>;
type Authorities<'a> = Vec<Authority<'a>>;
type Additionals<'a> = Vec<Additional<'a>>;

pub fn decode_message<'a>(
    data: &'a [u8],
) -> Result<Message<'a, Questions<'a>, Answers<'a>, Authorities<'a>, Additionals<'a>>, Error> {
    let (header, header_index) = decode_header(&data)?;
    let mut offset = header_index;

    let (questions, questions_len) = decode_questions(&data[offset..], header.qd_count)?;
    offset += questions_len;

    let (answers, answers_len) = decode_resource_records(&data[offset..], header.an_count)?;
    offset += answers_len;

    let (authority, authority_len) = decode_resource_records(&data[offset..], header.ns_count)?;
    offset += authority_len;

    let (additional, _) = decode_resource_records(&data[offset..], header.ar_count)?;

    Ok(Message::new(
        header, questions, answers, authority, additional,
    ))
}
