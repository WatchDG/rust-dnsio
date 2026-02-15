mod error;
mod header;
mod message;
mod question;
mod resource_record;

pub use error::Error;
pub use header::{
    decode_flags, decode_header, encode_flags, encode_header, flags_wire_length, header_wire_length,
};
pub use message::{decode_message, encode_message, message_wire_length};
pub use question::{
    decode_name, decode_question, encode_name, encode_question, question_wire_length,
};
pub use resource_record::{
    decode_resource_records, encode_resource_records, resource_records_wire_length,
};
