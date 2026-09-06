use std::io;
use std::string::FromUtf8Error;
use crate::content::HeaderBlockType;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Cipher(String),
    MissingHeader(HeaderBlockType),
    FileNameEncoding(FromUtf8Error),
    MalformedContent {
        description: String,
        content: Vec<u8>,
    }
}
