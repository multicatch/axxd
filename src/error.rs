use std::io;
use crypto::symmetriccipher::SymmetricCipherError;
use crate::content::HeaderBlockType;
use std::string::FromUtf8Error;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Cipher(SymmetricCipherError),
    MissingHeader(HeaderBlockType),
    FileNameEncoding(FromUtf8Error),
    MalformedContent {
        description: String,
        content: Vec<u8>,
    }
}
