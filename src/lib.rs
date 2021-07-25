#[macro_use]
extern crate num_derive;

use crate::error::Error;
use crate::content::EncryptedContent;
use crate::decrypt::{decrypt, PlainContent};
use std::fs;
use std::path::{Path, PathBuf};
use std::io::Write;

pub mod content;
pub mod key;
pub mod header;
pub mod error;
pub mod decrypt;
pub mod cli;

pub fn decrypt_file<P: AsRef<Path>>(path: P, passphrase: &str) -> Result<PlainContent, Error> {
    let input = fs::read(&path).map_err(Error::Io)?;
    let data = EncryptedContent::parse(&input);
    decrypt(&data, passphrase)
}

pub fn create_target_path<P: AsRef<Path>>(path: P, decrypted: &PlainContent) -> PathBuf {
    let target_path = PathBuf::from(&decrypted.file_name);
    path.as_ref()
        .parent()
        .map(|parent| parent.join(&target_path))
        .unwrap_or(target_path)
}

pub fn save_decrypted<P: AsRef<Path>>(decrypted: PlainContent, target_path: P) -> Result<P, Error> {
    let mut file = fs::File::create(&target_path).map_err(Error::Io)?;
    file.write_all(&decrypted.content).map(|_| target_path).map_err(Error::Io)
}