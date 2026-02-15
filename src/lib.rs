mod decode;
mod encode;
mod error;

pub use decode::{
    MessageRef, decode_flags, decode_header, decode_message, decode_message_ref, decode_name,
    decode_question, decode_resource_record, decode_resource_records,
};
pub use encode::{
    encode_flags, encode_header, encode_message, encode_name, encode_question,
    encode_resource_record, encode_resource_records,
};
pub use error::Error;
