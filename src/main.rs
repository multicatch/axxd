use crypto::pbkdf2::pbkdf2;
use crypto::hmac::Hmac;
use crypto::sha1::Sha1;
use crypto::digest::Digest;
use std::path::PathBuf;
use std::fs;
use axxd::content::EncryptedContent;
use axxd::content::HeaderBlockType::{EncryptionInfo, FileNameInfo, Data, KeyWrap1};
use crypto::aes::cbc_decryptor;
use crypto::aes::KeySize::KeySize256;
use crypto::blockmodes::NoPadding;
use crypto::buffer::{RefReadBuffer, RefWriteBuffer};
use std::convert::TryInto;
use axxd::key::{KeyParams, HeaderDecryptor};

fn main() {
    let pass = "a";
    let salt = [0u8; 32];
    let key = derive_key_256(pass.as_bytes(), &salt);
    println!("{:?}", key);

    let input = fs::read(PathBuf::from("test.axx")).unwrap();
    let data = EncryptedContent::parse(&input);
    println!("data: {:?}", data);

    let key_wrap = data.headers.get(&KeyWrap1).unwrap();
    let key_params = KeyParams::parse(&key_wrap);
    let master_key = key_params.unwrap_key(&key).unwrap();

    let mut header_decryptor = HeaderDecryptor::new(&master_key).unwrap();

    let iv = data.headers.get(&EncryptionInfo).unwrap();
    let iv = header_decryptor.decrypt(*iv, 16).unwrap();

    let file_name = data.headers.get(&FileNameInfo).unwrap();
    let file_name = header_decryptor.decrypt(*file_name, 16).unwrap();
    unsafe { println!("{}", String::from_utf8_unchecked(file_name)); }

    let buffer_size = data.headers.get(&Data).unwrap();
    let buffer_size = usize::from_le_bytes((*buffer_size).try_into().unwrap());

    let mut read_buffer = RefReadBuffer::new(data.content);
    let mut buffer_vec = vec![0; buffer_size];
    let mut buffer = buffer_vec.as_mut_slice();
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);
    let mut decryptor = cbc_decryptor(KeySize256, &master_key, &iv, NoPadding);
    decryptor.decrypt(&mut read_buffer, &mut write_buffer, true).unwrap();

    unsafe { println!("{}", String::from_utf8_unchecked(buffer_vec)); }

    println!("Hello, world!");
}

fn derive_key_256(pass: &[u8], salt: &[u8]) -> [u8; 32] {
    let sha1 = AxxSha1::new();
    let mut key = [0u8; 32];
    let mut hmac = Hmac::new(sha1, pass);
    pbkdf2(&mut hmac, &salt, 48000, &mut key);
    key
}

struct AxxSha1 {
    sha1: Sha1
}

impl AxxSha1 {
    pub fn new() -> AxxSha1 {
        AxxSha1 {
            sha1: Sha1::new()
        }
    }
}

impl Digest for AxxSha1 {
    fn input(&mut self, input: &[u8]) {
        self.sha1.input(input)
    }

    fn result(&mut self, out: &mut [u8]) {
        self.sha1.result(out)
    }

    fn reset(&mut self) {
        self.sha1.reset()
    }

    fn output_bits(&self) -> usize {
        self.sha1.output_bits()
    }

    fn block_size(&self) -> usize {
        20
    }
}