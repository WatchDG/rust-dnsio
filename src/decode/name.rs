use crate::error::Error;
use dns_message::{Label, NameElement};

pub fn decode_name(
    data: &[u8],
    message_offset: usize,
) -> Result<(Vec<NameElement<'_>>, usize), Error> {
    let mut offset = 0;
    let mut elements = Vec::new();

    loop {
        if message_offset + offset >= data.len() {
            return Err(Error::InsufficientData);
        }

        let length = data[message_offset + offset] as usize;
        offset += 1;

        if length == 0 {
            elements.push(NameElement::Root);
            break;
        }

        if length >= 192 {
            if message_offset + offset >= data.len() {
                return Err(Error::InsufficientData);
            }
            let second_byte = data[message_offset + offset] as u16;
            let pointer_value = ((length as u16 & 0x3F) << 8) | second_byte;
            offset += 1;

            elements.push(NameElement::Pointer(pointer_value));
            return Ok((elements, offset));
        }

        if length >= 64 {
            elements.push(NameElement::Reserved);
            continue;
        }

        if length > 63 {
            return Err(Error::InvalidDomainName);
        }

        if message_offset + offset + length > data.len() {
            return Err(Error::InsufficientData);
        }

        let label_data = &data[message_offset + offset..message_offset + offset + length];
        elements.push(NameElement::Label(Label::new(length as u8, label_data)));
        offset += length;
    }

    Ok((elements, offset))
}
