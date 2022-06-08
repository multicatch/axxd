use aes::cipher::block_padding::ZeroPadding;
use cbc::cipher::KeyIvInit;
use aes::cipher::BlockEncryptMut;
use crypto::aes::cbc_encryptor;
use crypto::aes::KeySize::KeySize128;
use crypto::blockmodes::{NoPadding, DecPadding, CbcDecryptor};
use crypto::buffer::{RefReadBuffer, RefWriteBuffer};
use crypto::symmetriccipher::{SymmetricCipherError, Decryptor, Encryptor};
use crypto::aessafe::{AesSafe128Decryptor};
use crate::error::Error;

pub struct HeaderDecryptor {
    decryptor: Box<CbcDecryptor<AesSafe128Decryptor, DecPadding<NoPadding>>>,
}

impl HeaderDecryptor {
    pub fn new(key: &[u8]) -> Result<HeaderDecryptor, SymmetricCipherError> {
        let buffer = encrypt_subkey(key, 2)?;
        let aes_dec = AesSafe128Decryptor::new(&buffer);
        Ok(HeaderDecryptor {
            decryptor:  Box::new(CbcDecryptor::new(aes_dec, NoPadding, vec![0u8; 16])),
        })
    }

    pub fn decrypt(&mut self, input: &[u8], buffer_length: usize) -> Result<Vec<u8>, Error> {
        self.decryptor.reset(&[0u8; 16]);
        decrypt(self.decryptor.as_mut(), input, buffer_length)
    }
}

pub struct HeaderEncryptor {
    key: [u8; 16]
}

/// Due to a bug in rust-crypto, I cannot use AesSafe128Encryptor (I always get InvalidLength error).
/// cbc crate seems to encrypt headers just fine.
type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

impl HeaderEncryptor {
    pub fn new(key: &[u8]) -> Result<HeaderEncryptor, SymmetricCipherError> {
        let buffer = encrypt_subkey(key, 2)?;
        Ok(HeaderEncryptor {
            key: buffer
        })
    }

    pub fn encrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, Error> {
        let mut buffer = vec![0u8; input.len()];
        buffer.copy_from_slice(input);

        let result = Aes128CbcEnc::new(&self.key.into(), &[0u8; 16].into())
            .encrypt_padded_vec_mut::<ZeroPadding>(&buffer);
        Ok(result)
    }
}

pub fn encrypt_subkey(key: &[u8], zero_block: u8) -> Result<[u8; 16], SymmetricCipherError> {
    let mut block = [0u8; 16];
    block[0] = zero_block;

    let mut read_buffer = RefReadBuffer::new(&block);
    let mut buffer = [0u8; 16];
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);

    let mut encryptor = cbc_encryptor(KeySize128, key, &[0u8; 16], NoPadding);
    encryptor.encrypt(&mut read_buffer, &mut write_buffer, true)?;

    Ok(buffer)
}

pub fn decrypt(decryptor: &mut dyn Decryptor, input: &[u8], buffer_length: usize) -> Result<Vec<u8>, Error> {
    let mut read_buffer = RefReadBuffer::new(input);
    let mut empty_vec = vec![0; buffer_length];
    let buffer: &mut [u8] = empty_vec.as_mut_slice();
    let mut write_buffer = RefWriteBuffer::new(buffer);

    decryptor.decrypt(&mut read_buffer, &mut write_buffer, true).map_err(Error::Cipher)?;

    Ok(buffer.to_vec())
}

pub fn encrypt(encryptor: &mut dyn Encryptor, input: &[u8], buffer_length: usize) -> Result<Vec<u8>, Error> {
    let mut read_buffer = RefReadBuffer::new(input);
    let mut empty_vec = vec![0; buffer_length];
    let buffer: &mut [u8] = empty_vec.as_mut_slice();
    let mut write_buffer = RefWriteBuffer::new(buffer);

    encryptor.encrypt(&mut read_buffer, &mut write_buffer, true).map_err(Error::Cipher)?;

    Ok(buffer.to_vec())
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
            assert_eq!(matches!(result.err(), Some(_)), false);
            assert_eq!(result.ok(), Some(*expected));
        }
    }

    #[test]
    fn key_encryption_fail() {
        let pass = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let expected: [u8; 16] = [198, 161, 59, 55, 135, 143, 91, 130, 111, 79, 129, 98, 161, 200, 216, 121];

        let result = encrypt_subkey(&pass, 5);
        assert_eq!(matches!(result.err(), Some(_)), false);
        assert_ne!(result.ok(), Some(expected));
    }
}