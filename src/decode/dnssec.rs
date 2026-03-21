use super::name::decode_name;
use crate::error::Error;
use dns_message::dnssec::{
    DnskeyRdata, DnssecAlgorithm, DsDigestType, DsRdata, Nsec3Rdata, Nsec3paramRdata, NsecRdata,
    RrsigRdata,
};

pub fn decode_dnskey(buf: &[u8], offset: usize, rd_length: u16) -> Result<DnskeyRdata<'_>, Error> {
    let end = offset + rd_length as usize;
    if buf.len() < end {
        return Err(Error::InsufficientData);
    }
    let data = &buf[offset..end];

    if data.len() < 4 {
        return Err(Error::InsufficientData);
    }

    let flags = (data[0] as u16) << 8 | data[1] as u16;
    let protocol = data[2];
    let algorithm = DnssecAlgorithm::from_u8(data[3]);
    let public_key = &data[4..];

    Ok(DnskeyRdata {
        flags,
        protocol,
        algorithm,
        public_key,
    })
}

pub fn decode_rrsig(buf: &[u8], offset: usize, rd_length: u16) -> Result<RrsigRdata<'_>, Error> {
    let end = offset + rd_length as usize;
    if buf.len() < end {
        return Err(Error::InsufficientData);
    }
    let data = &buf[offset..end];

    const MIN_RRSIG_LENGTH: usize = 18;

    if data.len() < MIN_RRSIG_LENGTH {
        return Err(Error::InsufficientData);
    }

    let type_covered = (data[0] as u16) << 8 | data[1] as u16;
    let algorithm = DnssecAlgorithm::from_u8(data[2]);
    let labels = data[3];
    let original_ttl =
        (data[4] as u32) << 24 | (data[5] as u32) << 16 | (data[6] as u32) << 8 | data[7] as u32;
    let signature_expiration =
        (data[8] as u32) << 24 | (data[9] as u32) << 16 | (data[10] as u32) << 8 | data[11] as u32;
    let signature_inception = (data[12] as u32) << 24
        | (data[13] as u32) << 16
        | (data[14] as u32) << 8
        | data[15] as u32;
    let key_tag = (data[16] as u16) << 8 | data[17] as u16;

    let (signer_name, signer_name_len) = decode_name(buf, offset + 18)?;
    let signature = &data[18 + signer_name_len..];

    Ok(RrsigRdata {
        type_covered,
        algorithm,
        labels,
        original_ttl,
        signature_expiration,
        signature_inception,
        key_tag,
        signer_name,
        signature,
    })
}

pub fn decode_ds(buf: &[u8], offset: usize, rd_length: u16) -> Result<DsRdata<'_>, Error> {
    let end = offset + rd_length as usize;
    if buf.len() < end {
        return Err(Error::InsufficientData);
    }
    let data = &buf[offset..end];

    if data.len() < 4 {
        return Err(Error::InsufficientData);
    }

    let key_tag = (data[0] as u16) << 8 | data[1] as u16;
    let algorithm = DnssecAlgorithm::from_u8(data[2]);
    let digest_type = DsDigestType::from_u8(data[3]);
    let digest = &data[4..];

    Ok(DsRdata {
        key_tag,
        algorithm,
        digest_type,
        digest,
    })
}

pub fn decode_nsec(buf: &[u8], offset: usize, rd_length: u16) -> Result<NsecRdata<'_>, Error> {
    let end = offset + rd_length as usize;
    if buf.len() < end {
        return Err(Error::InsufficientData);
    }
    let data = &buf[offset..end];

    let (next_domain_name, next_domain_len) = decode_name(buf, offset)?;
    let type_bit_maps = &data[next_domain_len..];

    Ok(NsecRdata {
        next_domain_name,
        type_bit_maps,
    })
}

pub fn decode_nsec3(buf: &[u8], offset: usize, rd_length: u16) -> Result<Nsec3Rdata<'_>, Error> {
    let end = offset + rd_length as usize;
    if buf.len() < end {
        return Err(Error::InsufficientData);
    }
    let data = &buf[offset..end];

    const MIN_NSEC3_LENGTH: usize = 5;

    if data.len() < MIN_NSEC3_LENGTH {
        return Err(Error::InsufficientData);
    }

    let hash_algorithm = data[0];
    let flags = data[1];
    let iterations = (data[2] as u16) << 8 | data[3] as u16;
    let salt_length = data[4] as usize;

    let mut pos = 5;

    if pos + salt_length > data.len() {
        return Err(Error::InsufficientData);
    }

    let salt = &data[pos..pos + salt_length];
    pos += salt_length;

    if pos + 1 > data.len() {
        return Err(Error::InsufficientData);
    }

    let next_hashed_owner_name_length = data[pos] as usize;
    pos += 1;

    if pos + next_hashed_owner_name_length > data.len() {
        return Err(Error::InsufficientData);
    }

    let next_hashed_owner_name = &data[pos..pos + next_hashed_owner_name_length];
    pos += next_hashed_owner_name_length;

    let type_bit_maps = &data[pos..];

    Ok(Nsec3Rdata {
        hash_algorithm,
        flags,
        iterations,
        salt,
        next_hashed_owner_name,
        type_bit_maps,
    })
}

pub fn decode_nsec3param(
    buf: &[u8],
    offset: usize,
    rd_length: u16,
) -> Result<Nsec3paramRdata<'_>, Error> {
    let end = offset + rd_length as usize;
    if buf.len() < end {
        return Err(Error::InsufficientData);
    }
    let data = &buf[offset..end];

    const MIN_NSEC3PARAM_LENGTH: usize = 5;

    if data.len() < MIN_NSEC3PARAM_LENGTH {
        return Err(Error::InsufficientData);
    }

    let hash_algorithm = data[0];
    let flags = data[1];
    let iterations = (data[2] as u16) << 8 | data[3] as u16;
    let salt_length = data[4] as usize;

    if 5 + salt_length > data.len() {
        return Err(Error::InsufficientData);
    }

    let salt = &data[5..5 + salt_length];

    Ok(Nsec3paramRdata {
        hash_algorithm,
        flags,
        iterations,
        salt,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_dnskey() {
        let buf = [
            0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        ];

        let dnskey = decode_dnskey(&buf, 4, 10).unwrap();

        assert_eq!(dnskey.flags, 0x0103);
        assert_eq!(dnskey.protocol, 0x03);
        assert_eq!(dnskey.algorithm, DnssecAlgorithm::RsaSha256);
        assert_eq!(dnskey.public_key, &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
    }

    #[test]
    fn test_decode_dnskey_with_empty_public_key() {
        let buf = [0x00, 0x01, 0x03, 0x08];

        let dnskey = decode_dnskey(&buf, 0, 4).unwrap();

        assert_eq!(dnskey.flags, 0x0001);
        assert_eq!(dnskey.protocol, 0x03);
        assert_eq!(dnskey.algorithm, DnssecAlgorithm::RsaSha256);
        assert!(dnskey.public_key.is_empty());
    }

    #[test]
    fn test_decode_dnskey_insufficient_data() {
        let buf = [0x01, 0x03, 0x03];

        let result = decode_dnskey(&buf, 0, 3);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_rrsig() {
        let buf = [
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
            0x01, 0x08, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x5E, 0x0B, 0x4B, 0x50, 0x5D, 0xF9, 0x7A,
            0x3C, 0x00, 0x0A, 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o',
            b'm', 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        ];

        let rrsig = decode_rrsig(&buf, 13, 39).unwrap();

        assert_eq!(rrsig.type_covered, 1);
        assert_eq!(rrsig.algorithm, DnssecAlgorithm::RsaSha256);
        assert_eq!(rrsig.labels, 0x01);
        assert_eq!(rrsig.original_ttl, 0x0000012C);
        assert_eq!(rrsig.signature_expiration, 0x5E0B4B50);
        assert_eq!(rrsig.signature_inception, 0x5DF97A3C);
        assert_eq!(rrsig.key_tag, 0x000A);
        assert_eq!(rrsig.signer_name.len(), 3);
        assert_eq!(
            rrsig.signature,
            &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]
        );
    }

    #[test]
    fn test_decode_rrsig_with_pointer() {
        let buf = [
            0x00, 0x1C, 0x05, 0x03, 0x00, 0x00, 0x03, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x12, 0x34, 0x01, b'x', 0x00, 0xAB, 0xCD, 0xEF,
        ];

        let rrsig = decode_rrsig(&buf, 0, 23).unwrap();

        assert_eq!(rrsig.type_covered, 28);
        assert_eq!(rrsig.algorithm, DnssecAlgorithm::RsaSha1);
        assert_eq!(rrsig.labels, 3);
        assert_eq!(rrsig.original_ttl, 900);
        assert_eq!(rrsig.key_tag, 0x1234);
        assert_eq!(rrsig.signer_name.len(), 2);
        assert_eq!(rrsig.signature, &[0xAB, 0xCD]);
    }

    #[test]
    fn test_decode_rrsig_insufficient_data() {
        let buf = [0x00, 0x01, 0x08];

        let result = decode_rrsig(&buf, 0, 3);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_ds() {
        let buf = [0x12, 0x34, 0x08, 0x01, 0xAA, 0xBB, 0xCC, 0xDD];

        let ds = decode_ds(&buf, 0, 8).unwrap();

        assert_eq!(ds.key_tag, 0x1234);
        assert_eq!(ds.algorithm, DnssecAlgorithm::RsaSha256);
        assert_eq!(ds.digest_type, DsDigestType::Sha1);
        assert_eq!(ds.digest, &[0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_decode_ds_sha384() {
        let buf = [0x56, 0x78, 0x0E, 0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

        let ds = decode_ds(&buf, 0, 10).unwrap();

        assert_eq!(ds.key_tag, 0x5678);
        assert_eq!(ds.algorithm, DnssecAlgorithm::EcdsaP384Sha384);
        assert_eq!(ds.digest_type, DsDigestType::Sha256);
        assert_eq!(ds.digest, &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    }

    #[test]
    fn test_decode_ds_insufficient_data() {
        let buf = [0x12, 0x34, 0x08];

        let result = decode_ds(&buf, 0, 3);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_nsec() {
        let buf = [
            0x05, b'n', b's', b'1', b'e', b'x', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];

        let nsec = decode_nsec(&buf, 0, 15).unwrap();

        assert_eq!(nsec.next_domain_name.len(), 3);
        assert_eq!(nsec.type_bit_maps, &[0x00, 0x01, 0x00, 0x01]);
    }

    #[test]
    fn test_decode_nsec_with_pointer() {
        let buf = [0x03, b'w', b'w', b'w', 0xC0, 0x00, 0x00, 0x06, 0x00, 0x01];

        let nsec = decode_nsec(&buf, 0, 10).unwrap();

        assert_eq!(nsec.next_domain_name.len(), 2);
        assert_eq!(nsec.type_bit_maps, &[0x00, 0x06, 0x00, 0x01]);
    }

    #[test]
    fn test_decode_nsec3() {
        let buf = [
            0x01, 0x01, 0x00, 0x01, 0x10, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22,
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x13, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0x00, 0x01, 0x00, 0x02,
        ];

        let nsec3 = decode_nsec3(&buf, 0, 46).unwrap();

        assert_eq!(nsec3.hash_algorithm, 0x01);
        assert_eq!(nsec3.flags, 0x01);
        assert_eq!(nsec3.iterations, 0x0001);
        assert_eq!(
            nsec3.salt,
            &[
                0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                0x88, 0x99
            ]
        );
        assert_eq!(
            nsec3.next_hashed_owner_name,
            &[
                0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                0x88, 0x99, 0xAA, 0xBB, 0xCC
            ]
        );
        assert_eq!(nsec3.type_bit_maps, &[0xDD, 0x00, 0x01, 0x00, 0x02]);
    }

    #[test]
    fn test_decode_nsec3_empty_salt_and_hash() {
        let buf = [0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0xAA, 0x00, 0x01];

        let nsec3 = decode_nsec3(&buf, 0, 9).unwrap();

        assert_eq!(nsec3.hash_algorithm, 0x01);
        assert_eq!(nsec3.flags, 0x00);
        assert_eq!(nsec3.iterations, 0x0000);
        assert!(nsec3.salt.is_empty());
        assert_eq!(nsec3.next_hashed_owner_name, &[0xAA]);
        assert_eq!(nsec3.type_bit_maps, &[0x00, 0x01]);
    }

    #[test]
    fn test_decode_nsec3_insufficient_data() {
        let buf = [0x01, 0x01, 0x00];

        let result = decode_nsec3(&buf, 0, 3);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_nsec3param() {
        let buf = [
            0x01, 0x01, 0x00, 0x01, 0x08, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
        ];

        let nsec3param = decode_nsec3param(&buf, 0, 13).unwrap();

        assert_eq!(nsec3param.hash_algorithm, 0x01);
        assert_eq!(nsec3param.flags, 0x01);
        assert_eq!(nsec3param.iterations, 0x0001);
        assert_eq!(
            nsec3param.salt,
            &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11]
        );
    }

    #[test]
    fn test_decode_nsec3param_empty_salt() {
        let buf = [0x01, 0x00, 0x00, 0x00, 0x00];

        let nsec3param = decode_nsec3param(&buf, 0, 5).unwrap();

        assert_eq!(nsec3param.hash_algorithm, 0x01);
        assert_eq!(nsec3param.flags, 0x00);
        assert_eq!(nsec3param.iterations, 0x0000);
        assert!(nsec3param.salt.is_empty());
    }

    #[test]
    fn test_decode_nsec3param_insufficient_data() {
        let buf = [0x01, 0x01, 0x00];

        let result = decode_nsec3param(&buf, 0, 3);
        assert!(result.is_err());
    }
}
