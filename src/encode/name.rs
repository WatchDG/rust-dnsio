use crate::error::Error;
use dns_message::NameElement;

pub fn encode_name<'a>(
    name: &[NameElement<'a>],
    buf: &'a mut [u8],
) -> Result<(&'a [u8], usize), Error> {
    let mut offset = 0;

    for element in name {
        match element {
            NameElement::Label(label) => {
                if buf.len() < offset + 1 + label.data.len() {
                    return Err(Error::InsufficientData);
                }
                buf[offset] = label.length;
                buf[offset + 1..offset + 1 + label.data.len()].copy_from_slice(label.data);
                offset += 1 + label.data.len();
            }
            NameElement::Pointer(ptr) => {
                if buf.len() < offset + 2 {
                    return Err(Error::InsufficientData);
                }
                buf[offset] = 0xC0 | ((ptr >> 8) as u8);
                buf[offset + 1] = (ptr & 0xFF) as u8;
                offset += 2;
            }
            NameElement::Root => {
                if buf.len() < offset + 1 {
                    return Err(Error::InsufficientData);
                }
                buf[offset] = 0;
                offset += 1;
            }
            NameElement::Reserved => return Err(Error::InvalidDomainName),
        }
    }

    Ok((&buf[..offset], offset))
}
