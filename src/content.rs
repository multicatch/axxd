use std::convert::TryInto;
use std::collections::HashMap;
use std::hash::Hash;

#[derive(Debug, FromPrimitive, Hash, Eq, PartialEq, Copy, Clone)]
pub enum HeaderBlockType {
    None = 0,
    Any = 1,
    Preamble = 2,
    Version = 3,
    KeyWrap1 = 4,
    KeyWrap2 = 5,
    IdTag = 6,
    Unrecognized = 61,
    Undefined = 62,
    Data = 63,
    Encrypted = 64,
    FileNameInfo = 65,
    EncryptionInfo = 66,
    CompressionInfo = 67,
    FileInfo = 68,
    Compression = 69,
    UnicodeFileNameInfo = 70,
}

#[derive(Debug, Eq, PartialEq)]
pub struct EncryptedContent<'a> {
    pub headers: HashMap<HeaderBlockType, &'a [u8]>,
    pub content: &'a [u8],
}

impl<'a> EncryptedContent<'a> {
    pub fn parse(input: &[u8]) -> EncryptedContent {
        let (_, input) = slice_guid(input);

        let mut headers: HashMap<HeaderBlockType, &[u8]> = HashMap::new();
        let mut block_type = HeaderBlockType::Unrecognized;
        let mut remaining = input;

        while block_type != HeaderBlockType::Data && remaining.len() >= 5 {
            let (bt, data, rem) = parse_block(remaining);
            block_type = bt;
            remaining = rem;
            headers.insert(block_type, data);
        }

        EncryptedContent {
            headers,
            content: remaining,
        }
    }
}

fn parse_block(input: &[u8]) -> (HeaderBlockType, &[u8], &[u8]) {
    let (header_length, remaining) = input.split_at(4);
    let header_length = u32::from_le_bytes(header_length.try_into().unwrap()) - 5;

    let (block_type, remaining) = remaining.split_at(1);
    let block_type = num::FromPrimitive::from_u8(block_type[0]).unwrap_or(HeaderBlockType::Unrecognized);
    let (data, remaining) = remaining.split_at(header_length as usize);

    (block_type, data, remaining)
}

fn slice_guid(input: &[u8]) -> (&[u8], &[u8]) {
    input.split_at(16)
}