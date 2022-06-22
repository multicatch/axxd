use std::io;
use crypto::symmetriccipher::SymmetricCipherError;
use crate::content::HeaderBlockType;
use std::string::FromUtf8Error;
use cbc::cipher::block_padding::UnpadError;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Cipher(SymmetricCipherError),
    CbcUnpadError(UnpadError),
    MissingHeader(HeaderBlockType),
    FileNameEncoding(FromUtf8Error),
    MalformedContent {
        description: String,
        content: Vec<u8>,
    }
}
