use cipher::KeyIvInit;
use aes::Aes128;
use cipher::{BlockDecryptMut, BlockEncrypt, KeyInit};
use crate::error::Error;

pub struct HeaderDecryptor {
    key: [u8; 16],
}

impl HeaderDecryptor {
    pub fn new(key: &[u8]) -> Result<HeaderDecryptor, Error> {
        let buffer = encrypt_subkey(key, 2)?;
        Ok(HeaderDecryptor { key: buffer })
    }

    pub fn decrypt(&mut self, input: &[u8], buffer_length: usize) -> Result<Vec<u8>, Error> {
        type Aes128CbcDec = cbc::Decryptor<Aes128>;
        let mut buf = input.to_vec();
        let decryptor = Aes128CbcDec::new_from_slices(&self.key, &[0u8; 16])
            .map_err(|e| Error::Cipher(format!("{:?}", e)))?;
        decryptor.decrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut buf)
            .map_err(|e| Error::Cipher(format!("{:?}", e)))?;

        let mut result = vec![0u8; buffer_length];
        let copy_len = buf.len().min(buffer_length);
        result[..copy_len].copy_from_slice(&buf[..copy_len]);
        Ok(result)
    }
}

pub fn encrypt_subkey(key: &[u8], zero_block: u8) -> Result<[u8; 16], Error> {
    let mut block = [0u8; 16];
    block[0] = zero_block;

    let cipher = Aes128::new_from_slice(key)
        .map_err(|e| Error::Cipher(format!("{:?}", e)))?;
    let block_ref = cipher::generic_array::GenericArray::from_mut_slice(&mut block);
    cipher.encrypt_block(block_ref);

    Ok(block)
}

#[cfg(test)]
mod tests {
    use crate::header::encrypt_subkey;

    #[test]
    fn key_encryption_pass() {
        let pass = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        let expected_results: [[u8; 16]; 4] = [
            [198, 161, 59, 55, 135, 143, 91, 130, 111, 79, 129, 98, 161, 200, 216, 121],
            [227, 124, 211, 99, 221, 124, 135, 160, 154, 255, 14, 62, 96, 224, 156, 130],
            [251, 138, 227, 27, 165, 219, 156, 173, 151, 54, 77, 135, 34, 212, 115, 38],
            [140, 184, 153, 20, 143, 31, 168, 255, 145, 50, 208, 235, 21, 169, 54, 242],
        ];

        for (i, expected) in expected_results.iter().enumerate() {
            let result = encrypt_subkey(&pass, i as u8);
            assert_eq!(matches!(result.as_ref().err(), Some(_)), false);
            assert_eq!(result.ok(), Some(*expected));
        }
    }

    #[test]
    fn key_encryption_fail() {
        let pass = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let expected: [u8; 16] = [198, 161, 59, 55, 135, 143, 91, 130, 111, 79, 129, 98, 161, 200, 216, 121];

        let result = encrypt_subkey(&pass, 5);
        assert_eq!(matches!(result.as_ref().err(), Some(_)), false);
        assert_ne!(result.ok(), Some(expected));
    }
}
