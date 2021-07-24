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
    let key = derive_key(pass.as_bytes());
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

fn derive_key(pass: &[u8]) -> [u8; 16] {
    let mut key = [0; 20];
    let mut sha1 = Sha1::new();
    sha1.input(pass);
    sha1.result(&mut key);
    let mut result: [u8; 16] = Default::default();
    result.copy_from_slice(&key[0..16]);
    result
}