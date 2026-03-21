mod builder;
mod decode;
mod encode;
mod error;
mod refs;

pub use builder::MessageBuilder;
pub use builder::MessageRefBuilder;
pub use decode::{
    decode_dnskey, decode_ds, decode_flags, decode_header, decode_message, decode_message_ref,
    decode_name, decode_nsec, decode_nsec3, decode_nsec3param, decode_question,
    decode_resource_record, decode_resource_records, decode_rrsig,
};
pub use encode::{
    encode_dnskey, encode_ds, encode_flags, encode_header, encode_message, encode_name,
    encode_nsec, encode_nsec3, encode_nsec3param, encode_question, encode_resource_record,
    encode_resource_records, encode_rrsig,
};
pub use error::Error;
pub use refs::{
    BuildFromRef, Compressible, CompressionTable, DnsKeyRef, DsRef, Dst, MessageRef, NameRef,
    Nsec3ParamRef, Nsec3Ref, NsecRef, QuestionRef, ResourceRecordRef, RrsigRef, Section,
    SectionItemRef, SectionRef,
};
