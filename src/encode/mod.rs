mod header;
mod message;
mod name;
mod question;
mod resource_record;

pub use header::{encode_flags, encode_header};
pub use message::encode_message;
pub use name::encode_name;
pub use question::encode_question;
pub use resource_record::{encode_resource_record, encode_resource_records};
