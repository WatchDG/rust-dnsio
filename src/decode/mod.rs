mod header;
mod message;
mod name;
mod question;
mod resource_record;

pub use header::{decode_flags, decode_header};
pub use message::decode_message;
pub use name::decode_name;
pub use question::decode_question;
pub use resource_record::{decode_resource_record, decode_resource_records};
