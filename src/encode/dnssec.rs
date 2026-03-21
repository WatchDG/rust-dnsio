use dns_message::Name;
use dns_message::dnssec::{
    DnskeyRdata, DsRdata, Nsec3Rdata, Nsec3paramRdata, NsecRdata, RrsigRdata,
};

use super::name::encode_name;
use crate::error::Error;

pub fn encode_dnskey<'a>(key: &DnskeyRdata<'a>, buf: &'a mut [u8]) -> Result<usize, Error> {
    if buf.len() < 4 + key.public_key.len() {
        return Err(Error::InsufficientData);
    }

    let mut offset = 0;

    buf[offset] = (key.flags >> 8) as u8;
    buf[offset + 1] = key.flags as u8;
    offset += 2;

    buf[offset] = key.protocol;
    offset += 1;

    buf[offset] = key.algorithm.to_u8();
    offset += 1;

    buf[offset..offset + key.public_key.len()].copy_from_slice(key.public_key);
    offset += key.public_key.len();

    Ok(offset)
}

pub fn encode_rrsig<'a>(
    rrsig: &RrsigRdata<'a>,
    buf: &'a mut [u8],
    name_buf: &mut [u8],
) -> Result<usize, Error> {
    let (_, signer_name_len) = encode_name(&rrsig.signer_name, name_buf)?;

    let rdata_len = 18 + signer_name_len + rrsig.signature.len();
    if buf.len() < rdata_len {
        return Err(Error::InsufficientData);
    }

    let mut offset = 0;

    buf[offset] = (rrsig.type_covered >> 8) as u8;
    buf[offset + 1] = rrsig.type_covered as u8;
    offset += 2;

    buf[offset] = rrsig.algorithm.to_u8();
    offset += 1;

    buf[offset] = rrsig.labels;
    offset += 1;

    buf[offset] = (rrsig.original_ttl >> 24) as u8;
    buf[offset + 1] = (rrsig.original_ttl >> 16) as u8;
    buf[offset + 2] = (rrsig.original_ttl >> 8) as u8;
    buf[offset + 3] = rrsig.original_ttl as u8;
    offset += 4;

    buf[offset] = (rrsig.signature_expiration >> 24) as u8;
    buf[offset + 1] = (rrsig.signature_expiration >> 16) as u8;
    buf[offset + 2] = (rrsig.signature_expiration >> 8) as u8;
    buf[offset + 3] = rrsig.signature_expiration as u8;
    offset += 4;

    buf[offset] = (rrsig.signature_inception >> 24) as u8;
    buf[offset + 1] = (rrsig.signature_inception >> 16) as u8;
    buf[offset + 2] = (rrsig.signature_inception >> 8) as u8;
    buf[offset + 3] = rrsig.signature_inception as u8;
    offset += 4;

    buf[offset] = (rrsig.key_tag >> 8) as u8;
    buf[offset + 1] = rrsig.key_tag as u8;
    offset += 2;

    buf[offset..offset + signer_name_len].copy_from_slice(&name_buf[..signer_name_len]);
    offset += signer_name_len;

    buf[offset..offset + rrsig.signature.len()].copy_from_slice(rrsig.signature);
    offset += rrsig.signature.len();

    Ok(offset)
}

pub fn encode_ds<'a>(ds: &DsRdata<'a>, buf: &'a mut [u8]) -> Result<usize, Error> {
    if buf.len() < 4 + ds.digest.len() {
        return Err(Error::InsufficientData);
    }

    let mut offset = 0;

    buf[offset] = (ds.key_tag >> 8) as u8;
    buf[offset + 1] = ds.key_tag as u8;
    offset += 2;

    buf[offset] = ds.algorithm.to_u8();
    offset += 1;

    buf[offset] = ds.digest_type.to_u8();
    offset += 1;

    buf[offset..offset + ds.digest.len()].copy_from_slice(ds.digest);
    offset += ds.digest.len();

    Ok(offset)
}

pub fn encode_nsec<'a>(
    nsec: &NsecRdata<'a>,
    buf: &'a mut [u8],
    name_buf: &mut [u8],
) -> Result<usize, Error> {
    let (_, next_domain_len) = encode_name(&nsec.next_domain_name, name_buf)?;

    if buf.len() < next_domain_len + nsec.type_bit_maps.len() {
        return Err(Error::InsufficientData);
    }

    let mut offset = 0;

    buf[offset..offset + next_domain_len].copy_from_slice(&name_buf[..next_domain_len]);
    offset += next_domain_len;

    buf[offset..offset + nsec.type_bit_maps.len()].copy_from_slice(nsec.type_bit_maps);
    offset += nsec.type_bit_maps.len();

    Ok(offset)
}

pub fn encode_nsec3<'a>(nsec3: &Nsec3Rdata<'a>, buf: &'a mut [u8]) -> Result<usize, Error> {
    let salt_len = nsec3.salt.len();
    let next_hashed_len = nsec3.next_hashed_owner_name.len();
    let rdata_len = 5 + salt_len + 1 + next_hashed_len + nsec3.type_bit_maps.len();

    if buf.len() < rdata_len {
        return Err(Error::InsufficientData);
    }

    let mut offset = 0;

    buf[offset] = nsec3.hash_algorithm;
    offset += 1;

    buf[offset] = nsec3.flags;
    offset += 1;

    buf[offset] = (nsec3.iterations >> 8) as u8;
    buf[offset + 1] = nsec3.iterations as u8;
    offset += 2;

    buf[offset] = salt_len as u8;
    offset += 1;

    buf[offset..offset + salt_len].copy_from_slice(nsec3.salt);
    offset += salt_len;

    buf[offset] = next_hashed_len as u8;
    offset += 1;

    buf[offset..offset + next_hashed_len].copy_from_slice(nsec3.next_hashed_owner_name);
    offset += next_hashed_len;

    buf[offset..offset + nsec3.type_bit_maps.len()].copy_from_slice(nsec3.type_bit_maps);
    offset += nsec3.type_bit_maps.len();

    Ok(offset)
}

pub fn encode_nsec3param<'a>(
    param: &Nsec3paramRdata<'a>,
    buf: &'a mut [u8],
) -> Result<usize, Error> {
    let salt_len = param.salt.len();
    let rdata_len = 5 + salt_len;

    if buf.len() < rdata_len {
        return Err(Error::InsufficientData);
    }

    let mut offset = 0;

    buf[offset] = param.hash_algorithm;
    offset += 1;

    buf[offset] = param.flags;
    offset += 1;

    buf[offset] = (param.iterations >> 8) as u8;
    buf[offset + 1] = param.iterations as u8;
    offset += 2;

    buf[offset] = salt_len as u8;
    offset += 1;

    buf[offset..offset + salt_len].copy_from_slice(param.salt);
    offset += salt_len;

    Ok(offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_message::dnssec::{
        DnskeyRdata, DnssecAlgorithm, DsDigestType, DsRdata, Nsec3Rdata, Nsec3paramRdata,
        NsecRdata, RrsigRdata,
    };
    use dns_message::question::NameElement;

    fn create_name(elements: Vec<NameElement>) -> Name {
        elements
    }

    #[test]
    fn test_encode_dnskey() {
        let key = DnskeyRdata {
            flags: 256,
            protocol: 3,
            algorithm: DnssecAlgorithm::RsaSha256,
            public_key: &[0x01, 0x02, 0x03, 0x04],
        };

        let mut buf = [0u8; 64];
        let len = encode_dnskey(&key, &mut buf).unwrap();

        assert_eq!(len, 8);
        assert_eq!(buf[0], 0x01);
        assert_eq!(buf[1], 0x00);
        assert_eq!(buf[2], 0x03);
        assert_eq!(buf[3], 0x08);
        assert_eq!(buf[4], 0x01);
        assert_eq!(buf[5], 0x02);
        assert_eq!(buf[6], 0x03);
        assert_eq!(buf[7], 0x04);
    }

    #[test]
    fn test_encode_dnskey_with_large_key() {
        let key = DnskeyRdata {
            flags: 0x0100,
            protocol: 3,
            algorithm: DnssecAlgorithm::EcdsaP256Sha256,
            public_key: &[0u8; 32],
        };

        let mut buf = [0u8; 64];
        let len = encode_dnskey(&key, &mut buf).unwrap();

        assert_eq!(len, 36);
        assert_eq!(buf[0], 0x01);
        assert_eq!(buf[1], 0x00);
        assert_eq!(buf[2], 0x03);
        assert_eq!(buf[3], 0x0D);
    }

    #[test]
    fn test_encode_dnskey_insufficient_buffer() {
        let key = DnskeyRdata {
            flags: 256,
            protocol: 3,
            algorithm: DnssecAlgorithm::RsaSha256,
            public_key: &[0x01, 0x02, 0x03, 0x04],
        };

        let mut buf = [0u8; 2];
        let result = encode_dnskey(&key, &mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_rrsig() {
        let signer_name = create_name(vec![
            NameElement::Label(dns_message::question::Label {
                length: 7,
                data: b"example",
            }),
            NameElement::Label(dns_message::question::Label {
                length: 3,
                data: b"com",
            }),
            NameElement::Root,
        ]);

        let rrsig = RrsigRdata {
            type_covered: 48,
            algorithm: DnssecAlgorithm::RsaSha256,
            labels: 2,
            original_ttl: 3600,
            signature_expiration: 0x5A000000,
            signature_inception: 0x4A000000,
            key_tag: 12345,
            signer_name,
            signature: &[0xAA, 0xBB, 0xCC, 0xDD],
        };

        let mut buf = [0u8; 128];
        let mut name_buf = [0u8; 64];
        let len = encode_rrsig(&rrsig, &mut buf, &mut name_buf).unwrap();

        assert_eq!(buf[0], 0x00);
        assert_eq!(buf[1], 0x30);
        assert_eq!(buf[2], 0x08);
        assert_eq!(buf[3], 0x02);
        assert_eq!(buf[4], 0x00);
        assert_eq!(buf[5], 0x00);
        assert_eq!(buf[6], 0x0E);
        assert_eq!(buf[7], 0x10);
        assert_eq!(len, 35);
    }

    #[test]
    fn test_encode_rrsig_insufficient_buffer() {
        let signer_name = create_name(vec![NameElement::Root]);

        let rrsig = RrsigRdata {
            type_covered: 1,
            algorithm: DnssecAlgorithm::RsaSha1,
            labels: 1,
            original_ttl: 300,
            signature_expiration: 0,
            signature_inception: 0,
            key_tag: 1000,
            signer_name,
            signature: &[0xFF],
        };

        let mut buf = [0u8; 10];
        let mut name_buf = [0u8; 64];
        let result = encode_rrsig(&rrsig, &mut buf, &mut name_buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_ds() {
        let ds = DsRdata {
            key_tag: 12345,
            algorithm: DnssecAlgorithm::RsaSha256,
            digest_type: DsDigestType::Sha256,
            digest: &[0x01, 0x02, 0x03, 0x04, 0x05],
        };

        let mut buf = [0u8; 64];
        let len = encode_ds(&ds, &mut buf).unwrap();

        assert_eq!(len, 9);
        assert_eq!(buf[0], 0x30);
        assert_eq!(buf[1], 0x39);
        assert_eq!(buf[2], 0x08);
        assert_eq!(buf[3], 0x02);
        assert_eq!(buf[4], 0x01);
        assert_eq!(buf[5], 0x02);
        assert_eq!(buf[6], 0x03);
        assert_eq!(buf[7], 0x04);
        assert_eq!(buf[8], 0x05);
    }

    #[test]
    fn test_encode_ds_sha384() {
        let ds = DsRdata {
            key_tag: 0xABCD,
            algorithm: DnssecAlgorithm::RsaSha512,
            digest_type: DsDigestType::Sha384,
            digest: &[0xDE, 0xAD, 0xBE, 0xEF],
        };

        let mut buf = [0u8; 32];
        let len = encode_ds(&ds, &mut buf).unwrap();

        assert_eq!(len, 8);
        assert_eq!(buf[0], 0xAB);
        assert_eq!(buf[1], 0xCD);
        assert_eq!(buf[2], 0x0A);
        assert_eq!(buf[3], 0x04);
    }

    #[test]
    fn test_encode_ds_insufficient_buffer() {
        let ds = DsRdata {
            key_tag: 12345,
            algorithm: DnssecAlgorithm::RsaSha256,
            digest_type: DsDigestType::Sha256,
            digest: &[0x01, 0x02],
        };

        let mut buf = [0u8; 3];
        let result = encode_ds(&ds, &mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_nsec() {
        let next_domain = create_name(vec![
            NameElement::Label(dns_message::question::Label {
                length: 4,
                data: b"next",
            }),
            NameElement::Label(dns_message::question::Label {
                length: 3,
                data: b"com",
            }),
            NameElement::Root,
        ]);

        let nsec = NsecRdata {
            next_domain_name: next_domain,
            type_bit_maps: &[0x00, 0x01, 0x02],
        };

        let mut buf = [0u8; 64];
        let mut name_buf = [0u8; 32];
        let len = encode_nsec(&nsec, &mut buf, &mut name_buf).unwrap();

        assert_eq!(buf[0], 0x04);
        assert_eq!(buf[1..5], *b"next");
        assert_eq!(buf[5], 0x03);
        assert_eq!(buf[6..9], *b"com");
        assert_eq!(buf[9], 0x00);
        assert_eq!(buf[10], 0x00);
        assert_eq!(buf[11], 0x01);
        assert_eq!(buf[12], 0x02);
        assert_eq!(len, 13);
    }

    #[test]
    fn test_encode_nsec_with_pointer() {
        let next_domain = create_name(vec![NameElement::Pointer(0x0C)]);

        let nsec = NsecRdata {
            next_domain_name: next_domain,
            type_bit_maps: &[0x40],
        };

        let mut buf = [0u8; 64];
        let mut name_buf = [0u8; 32];
        let len = encode_nsec(&nsec, &mut buf, &mut name_buf).unwrap();

        assert_eq!(buf[0], 0xC0);
        assert_eq!(buf[1], 0x0C);
        assert_eq!(buf[2], 0x40);
        assert_eq!(len, 3);
    }

    #[test]
    fn test_encode_nsec_insufficient_buffer() {
        let next_domain = create_name(vec![NameElement::Root]);

        let nsec = NsecRdata {
            next_domain_name: next_domain,
            type_bit_maps: &[0x01],
        };

        let mut buf = [0u8; 1];
        let mut name_buf = [0u8; 32];
        let result = encode_nsec(&nsec, &mut buf, &mut name_buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_nsec3() {
        let nsec3 = Nsec3Rdata {
            hash_algorithm: 1,
            flags: 0,
            iterations: 150,
            salt: &[0xAB, 0xCD, 0xEF],
            next_hashed_owner_name: &[0x01, 0x02, 0x03, 0x04],
            type_bit_maps: &[0x00, 0x01],
        };

        let mut buf = [0u8; 64];
        let len = encode_nsec3(&nsec3, &mut buf).unwrap();

        assert_eq!(len, 15);
        assert_eq!(buf[0], 0x01);
        assert_eq!(buf[1], 0x00);
        assert_eq!(buf[2], 0x00);
        assert_eq!(buf[3], 0x96);
        assert_eq!(buf[4], 0x03);
        assert_eq!(buf[5], 0xAB);
        assert_eq!(buf[6], 0xCD);
        assert_eq!(buf[7], 0xEF);
        assert_eq!(buf[8], 0x04);
        assert_eq!(buf[9], 0x01);
        assert_eq!(buf[10], 0x02);
        assert_eq!(buf[11], 0x03);
        assert_eq!(buf[12], 0x04);
        assert_eq!(buf[13], 0x00);
        assert_eq!(buf[14], 0x01);
    }

    #[test]
    fn test_encode_nsec3_with_iterations() {
        let nsec3 = Nsec3Rdata {
            hash_algorithm: 1,
            flags: 1,
            iterations: 65535,
            salt: &[],
            next_hashed_owner_name: &[0xAA],
            type_bit_maps: &[0xC0],
        };

        let mut buf = [0u8; 32];
        let len = encode_nsec3(&nsec3, &mut buf).unwrap();

        assert_eq!(len, 8);
        assert_eq!(buf[0], 0x01);
        assert_eq!(buf[1], 0x01);
        assert_eq!(buf[2], 0xFF);
        assert_eq!(buf[3], 0xFF);
        assert_eq!(buf[4], 0x00);
        assert_eq!(buf[5], 0x01);
        assert_eq!(buf[6], 0xAA);
        assert_eq!(buf[7], 0xC0);
    }

    #[test]
    fn test_encode_nsec3_insufficient_buffer() {
        let nsec3 = Nsec3Rdata {
            hash_algorithm: 1,
            flags: 0,
            iterations: 100,
            salt: &[0x01, 0x02],
            next_hashed_owner_name: &[0x03],
            type_bit_maps: &[0x04],
        };

        let mut buf = [0u8; 5];
        let result = encode_nsec3(&nsec3, &mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_nsec3param() {
        let param = Nsec3paramRdata {
            hash_algorithm: 1,
            flags: 0,
            iterations: 1200,
            salt: &[0xAA, 0xBB, 0xCC],
        };

        let mut buf = [0u8; 32];
        let len = encode_nsec3param(&param, &mut buf).unwrap();

        assert_eq!(len, 8);
        assert_eq!(buf[0], 0x01);
        assert_eq!(buf[1], 0x00);
        assert_eq!(buf[2], 0x04);
        assert_eq!(buf[3], 0xB0);
        assert_eq!(buf[4], 0x03);
        assert_eq!(buf[5], 0xAA);
        assert_eq!(buf[6], 0xBB);
        assert_eq!(buf[7], 0xCC);
    }

    #[test]
    fn test_encode_nsec3param_empty_salt() {
        let param = Nsec3paramRdata {
            hash_algorithm: 1,
            flags: 1,
            iterations: 0,
            salt: &[],
        };

        let mut buf = [0u8; 16];
        let len = encode_nsec3param(&param, &mut buf).unwrap();

        assert_eq!(len, 5);
        assert_eq!(buf[0], 0x01);
        assert_eq!(buf[1], 0x01);
        assert_eq!(buf[2], 0x00);
        assert_eq!(buf[3], 0x00);
        assert_eq!(buf[4], 0x00);
    }

    #[test]
    fn test_encode_nsec3param_insufficient_buffer() {
        let param = Nsec3paramRdata {
            hash_algorithm: 1,
            flags: 0,
            iterations: 100,
            salt: &[0x01, 0x02],
        };

        let mut buf = [0u8; 4];
        let result = encode_nsec3param(&param, &mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_dnskey_all_algorithms() {
        let algorithms = [
            DnssecAlgorithm::Rsamd5,
            DnssecAlgorithm::RsaSha1,
            DnssecAlgorithm::RsaSha256,
            DnssecAlgorithm::RsaSha512,
            DnssecAlgorithm::EcdsaP256Sha256,
            DnssecAlgorithm::EcdsaP384Sha384,
            DnssecAlgorithm::Ed25519,
            DnssecAlgorithm::Ed448,
        ];

        for algorithm in algorithms {
            let key = DnskeyRdata {
                flags: 257,
                protocol: 3,
                algorithm,
                public_key: &[0x00],
            };

            let mut buf = [0u8; 16];
            let len = encode_dnskey(&key, &mut buf).unwrap();
            assert_eq!(len, 5);
        }
    }
}
