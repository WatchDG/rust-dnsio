use crate::error::Error;
use crate::header::decode_header;
use crate::question::decode_questions;

use dns_message::Message;
use dns_message::Question;

type Questions<'a> = Vec<Question<'a>>;

pub fn decode_message<'a>(data: &'a [u8]) -> Result<Message<'a, Questions<'a>>, Error> {
    let header = decode_header(&data[..12])?;
    let questions = decode_questions(&data[12..], header.qd_count)?;

    Ok(Message::new(header, questions))
}
