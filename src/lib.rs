#[macro_use]
extern crate num_derive;

use crate::error::Error;
use crate::content::EncryptedContent;
use crate::decrypt::decrypt;
use std::fs;
use std::path::{Path, PathBuf};
use std::io::Write;

pub mod content;
pub mod key;
pub mod header;
pub mod error;
pub mod decrypt;

pub fn decrypt_file<P: AsRef<Path>>(path: P, passphrase: &str) -> Result<PathBuf, Error> {
    let input = fs::read(&path).map_err(Error::Io)?;
    let data = EncryptedContent::parse(&input);
    let decrypted = decrypt(&data, passphrase)?;

    let target_path = PathBuf::from(decrypted.file_name);
    let target_path = path.as_ref()
        .parent()
        .map(|parent| parent.join(&target_path))
        .unwrap_or(target_path);

    let mut file = fs::File::create(&target_path).map_err(Error::Io)?;
    file.write_all(&decrypted.content).map(|_| target_path).map_err(Error::Io)
}