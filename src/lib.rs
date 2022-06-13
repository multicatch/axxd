#[macro_use]
extern crate num_derive;
extern crate rand;

use crate::error::Error;
use crate::content::{EncryptedContent, PlainContent, RawBytes};
use crate::decrypt::decrypt;
use crate::encrypt::encrypt;
use std::fs;
use std::path::{Path, PathBuf};
use std::io::Write;

pub mod content;
pub mod key;
pub mod header;
pub mod error;
pub mod decrypt;
pub mod cli;
pub mod encrypt;
mod hmacsha;

pub type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

pub fn decrypt_file<P: AsRef<Path>>(path: P, passphrase: &str) -> Result<PlainContent, Error> {
    let input = fs::read(&path).map_err(Error::Io)?;
    let data = EncryptedContent::parse(&input);
    decrypt(&data, passphrase)
}

pub fn encrypt_file<P: AsRef<Path>>(path: P, passphrase: &str) -> Result<EncryptedContent, Error> {
    let input = fs::read(&path).map_err(Error::Io)?;
    let file_name = path.as_ref()
        .file_name()
        .and_then(|it| it.to_str())
        .unwrap();

    let data = PlainContent::new(file_name.to_string(), input);
    encrypt(&data, passphrase)
}

pub fn create_target_path<P: AsRef<Path>>(path: P, target: &str) -> PathBuf {
    let target_path = PathBuf::from(target);
    path.as_ref()
        .parent()
        .map(|parent| parent.join(&target_path))
        .unwrap_or(target_path)
}

pub fn save_decrypted<P: AsRef<Path>, B: RawBytes>(decrypted: B, target_path: P) -> Result<P, Error> {
    let mut file = fs::File::create(&target_path).map_err(Error::Io)?;
    file.write_all(&decrypted.as_raw_bytes()).map(|_| target_path).map_err(Error::Io)
}