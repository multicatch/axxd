use crypto::aessafe::{AesSafe128Decryptor, AesSafe128Encryptor};
use crypto::blockmodes::{EcbDecryptor, EcbEncryptor, NoPadding};
use crate::error::Error;
use crate::header::{decrypt, encrypt};
use std::convert::TryInto;

pub struct KeyParams {
    wrapped_key: Vec<u8>,
    salt: Vec<u8>,
    iterations: u32,
}

const KEY_START: usize = 0;
const KEY_LENGTH: usize = 16 + 8;

const SALT_START: usize = KEY_START + KEY_LENGTH;
const SALT_LENGTH: usize = 16;

const ITERATIONS_STARTS: usize = SALT_START + SALT_LENGTH;
const ITERATIONS_LENGTH: usize = 4;

const AES_KEY_LENGTH: u32 = 16;
const KEY_ROUNDS_BASE: u64 = AES_KEY_LENGTH as u64 / 8;

impl KeyParams {
    pub fn generate(secret: &[u8]) -> Result<KeyParams, Error> {
        let mut aes_key = [0u8; 16];
        for byte in aes_key.iter_mut() {
            *byte = rand::random();
        }

        let mut salt = [0u8; SALT_LENGTH];
        for byte in salt.iter_mut() {
            *byte = rand::random();
        }
        let iterations: u16 = rand::random();
        let iterations: u32 = (iterations + 5) as u32;

        Ok(KeyParams {
            wrapped_key: wrap_key(secret, iterations, &salt, aes_key)?,
            salt: salt.to_vec(),
            iterations
        })
    }

    pub fn parse(key_wrap: &[u8]) -> KeyParams {
        let key = &key_wrap[KEY_START..(KEY_START + KEY_LENGTH)];
        let salt = &key_wrap[SALT_START..(SALT_START + SALT_LENGTH)];
        let iterations = &key_wrap[ITERATIONS_STARTS..(ITERATIONS_STARTS + ITERATIONS_LENGTH)];
        let iterations = u32::from_le_bytes(iterations.try_into().unwrap());

        KeyParams {
            wrapped_key: key.to_vec(),
            salt: salt.to_vec(),
            iterations,
        }
    }

    pub fn unwrap_key(&self, key: &[u8]) -> Result<Vec<u8>, Error> {
        let salted_key: Vec<u8> = xor(key, &self.salt);

        let mut wrapped = self.wrapped_key.to_vec();

        let aes_dec = AesSafe128Decryptor::new(salted_key.as_slice());
        let mut decryptor = Box::new(EcbDecryptor::new(aes_dec, NoPadding));

        let rounds: u64 = KEY_ROUNDS_BASE * self.iterations as u64;
        for t in (1..(rounds + 1)).rev() {
            let block = &wrapped[0..8];
            let mut block = xor(block, &t.to_le_bytes());
            let second_start: usize = ((((t + 1) % KEY_ROUNDS_BASE) + 1) * 8) as usize;

            block.extend_from_slice(&wrapped[second_start..(second_start + 8)]);

            decryptor.reset();
            let buffer = decrypt(decryptor.as_mut(), block.as_slice(), 16)?;

            let (first_half, second_half) = buffer.split_at(8);
            wrapped.splice(..8, first_half.to_vec());
            wrapped.splice(second_start..(second_start + 8), second_half.to_vec());
        }

        Ok(wrapped[8..].to_vec())
    }
}

fn wrap_key(key: &[u8], iterations: u32, salt: &[u8], key_to_wrap: [u8; 16]) -> Result<Vec<u8>, Error> {
    let salted_key: Vec<u8> = xor(key, salt);

    let mut result = [0u8; KEY_LENGTH].to_vec();
    result[8..].copy_from_slice(&key_to_wrap);

    let aes_enc = AesSafe128Encryptor::new(salted_key.as_slice());
    let mut encryptor = Box::new(EcbEncryptor::new(aes_enc, NoPadding));

    let rounds: u64 = KEY_ROUNDS_BASE * iterations as u64;
    for t in 1..(rounds + 1) {
        let second_start: usize = ((((t + 1) % KEY_ROUNDS_BASE) + 1) * 8) as usize;

        let mut buffer = vec![0u8; 16];
        buffer[0..8].copy_from_slice(&result[..8]);
        buffer[8..16].copy_from_slice(&result[second_start..(second_start + 8)]);

        encryptor.reset();
        let buffer = encrypt(encryptor.as_mut(), buffer.as_slice(), 16)?;

        result[second_start..(second_start + 8)].copy_from_slice(&buffer[8..]);

        let block = xor(&buffer[..8], &t.to_le_bytes());
        result[0..8].copy_from_slice(&block);
    }

    Ok(result)
}

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter()
        .zip(b.iter())
        .map(|(x1, x2)| *x1 ^ *x2)
        .collect::<Vec<u8>>()
}


#[cfg(test)]
mod tests {
    use crate::key::{KeyParams, wrap_key};

    #[test]
    fn unwrap_key() {
        let wrapped_key: [u8; 44] = [
            // raw key
            0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47, 0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A, 0x7B, 0x82, 0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5,
            // salt
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            // iterations
            6, 0, 0, 0
        ];
        let encryption_key: [u8; 16] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];

        let params = KeyParams::parse(&wrapped_key);
        let result = params.unwrap_key(&encryption_key);

        let expected: Vec<u8> = vec![237, 149, 127, 244, 80, 250, 212, 169, 7, 60, 73, 31, 165, 26, 13, 46];
        assert_eq!(result.unwrap(), expected);
    }

    #[test]
    fn wrap_and_unwrap() {
        let encryption_key: [u8; 16] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];

        let aes_key = [237, 149, 127, 244, 80, 250, 212, 169, 7, 60, 73, 31, 165, 26, 13, 46];
        let salt = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let iterations: u32 = 6;

        let wrapped = wrap_key(&encryption_key, iterations, &salt, aes_key).unwrap();

        let key_param = KeyParams {
            wrapped_key: wrapped,
            salt: salt.to_vec(),
            iterations
        };

        let unwrapped = key_param.unwrap_key(&encryption_key).unwrap();

        assert_eq!(&unwrapped, &aes_key);
    }
}