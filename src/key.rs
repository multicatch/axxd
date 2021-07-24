use std::convert::TryInto;
use crypto::aessafe::AesSafe128Decryptor;
use crypto::blockmodes::{EcbDecryptor, NoPadding, DecPadding, CbcDecryptor};
use crypto::symmetriccipher::{SymmetricCipherError, Decryptor};
use crypto::buffer::{RefReadBuffer, RefWriteBuffer};
use crypto::aes::cbc_encryptor;
use crypto::aes::KeySize::KeySize128;

pub struct KeyParams<'a> {
    wrapped_key: &'a [u8],
    salt: &'a [u8],
    iterations: u32,
}

const KEY_START: usize = 0;
const KEY_LENGTH: usize = 16 + 8;

const SALT_START: usize = KEY_START + KEY_LENGTH;
const SALT_LENGTH: usize = 16;

const ITERATIONS_STARTS: usize = SALT_START + SALT_LENGTH;
const ITERATIONS_LENGTH: usize = 4;

const AES_KEY_LENGTH: u32 = 16;

impl<'a> KeyParams<'a> {
    pub fn parse(key_wrap: &[u8]) -> KeyParams {
        let key = &key_wrap[KEY_START..(KEY_START + KEY_LENGTH)];
        let salt = &key_wrap[SALT_START..(SALT_START + SALT_LENGTH)];
        let iterations = &key_wrap[ITERATIONS_STARTS..(ITERATIONS_STARTS + ITERATIONS_LENGTH)];
        let iterations = u32::from_le_bytes(iterations.try_into().unwrap());

        KeyParams {
            wrapped_key: key,
            salt,
            iterations,
        }
    }

    pub fn unwrap_key(&self, key: &[u8]) -> Result<Vec<u8>, SymmetricCipherError> {
        let salted_key: Vec<u8> = xor(key, self.salt);

        let mut wrapped = self.wrapped_key.to_vec();

        let aes_dec = AesSafe128Decryptor::new(salted_key.as_slice());
        let mut decryptor = Box::new(EcbDecryptor::new(aes_dec, NoPadding));
        for j in (0..self.iterations).rev() {
            for i in (1..(AES_KEY_LENGTH / 8 + 1)).rev() {
                let t: u64 = (((AES_KEY_LENGTH / 8) * j) + i) as u64;
                let block = &wrapped[0..8];
                let mut block = xor(&block, &t.to_le_bytes());
                let second_start: usize = (i * 8) as usize;

                block.extend_from_slice(&wrapped[second_start..(second_start + 8)]);

                decryptor.reset();
                let buffer = decrypt(decryptor.as_mut(), block.as_slice(), 16)?;

                let (first_half, second_half) = buffer.split_at(8);
                wrapped.splice(..8, first_half.to_vec());
                wrapped.splice(second_start..(second_start + 8), second_half.to_vec());
            }
        }

        Ok(wrapped[8..].to_vec())
    }
}

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter()
        .zip(b.iter())
        .map(|(x1, x2)| *x1 ^ *x2)
        .collect::<Vec<u8>>()
}

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

    pub fn decrypt(&mut self, input: &[u8], buffer_length: usize) -> Result<Vec<u8>, SymmetricCipherError> {
        self.decryptor.reset(&[0u8; 16]);
        decrypt(self.decryptor.as_mut(), input, buffer_length)
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

pub fn decrypt(decryptor: &mut dyn Decryptor, input: &[u8], buffer_length: usize) -> Result<Vec<u8>, SymmetricCipherError> {
    let mut read_buffer = RefReadBuffer::new(input);
    let mut empty_vec = vec![0; buffer_length];
    let buffer: &mut [u8] = empty_vec.as_mut_slice();
    let mut write_buffer = RefWriteBuffer::new(buffer);

    decryptor.decrypt(&mut read_buffer, &mut write_buffer, true)?;

    Ok(buffer.to_vec())
}
