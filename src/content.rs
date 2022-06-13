use std::convert::TryInto;
use std::collections::HashMap;
use std::hash::Hash;
use crate::content::HeaderBlockType::{Compression, Data, EncryptionInfo, FileInfo, FileNameInfo, KeyWrap1, Preamble, UnicodeFileNameInfo, Version};
use crate::encrypt::GUID;
use crate::error::Error;
use crate::hmacsha::AxHmacSha1;

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

pub trait RawBytes {
    fn as_raw_bytes(&self) -> Vec<u8>;
}

#[derive(Debug, Eq, PartialEq)]
pub struct PlainContent {
    pub file_name: String,
    pub content: Vec<u8>,
}

impl PlainContent {
    pub fn new(file_name: String, content: Vec<u8>) -> PlainContent {
        PlainContent {
            file_name,
            content,
        }
    }
}

impl RawBytes for PlainContent {
    fn as_raw_bytes(&self) -> Vec<u8> {
        self.content.clone()
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct EncryptedContent {
    pub headers: HashMap<HeaderBlockType, Vec<u8>>,
    pub content: Vec<u8>,
    pub hmac_key: [u8; 16],
}

impl EncryptedContent {
    pub fn new(headers: HashMap<HeaderBlockType, Vec<u8>>, content: Vec<u8>, hmac_key: [u8; 16]) -> EncryptedContent {
        EncryptedContent {
            headers,
            content,
            hmac_key,
        }
    }

    pub fn parse(input: &[u8]) -> EncryptedContent {
        let (_, input) = slice_guid(input);

        let mut headers: HashMap<HeaderBlockType, Vec<u8>> = HashMap::new();
        let mut block_type = HeaderBlockType::Unrecognized;
        let mut remaining = input;

        while block_type != Data && remaining.len() >= 5 {
            let (bt, data, rem) = parse_block(remaining);
            block_type = bt;
            remaining = rem;
            headers.insert(block_type, data.to_vec());
        }

        EncryptedContent {
            headers,
            content: remaining.to_vec(),
            hmac_key: [0u8; 16],
        }
    }

    pub fn header(&self, header_type: &HeaderBlockType) -> Result<&Vec<u8>, Error> {
        self.headers.get(header_type).ok_or(Error::MissingHeader(*header_type))
    }
}

const HEADERS_ORDER: [HeaderBlockType; 9] = [
    Preamble,
    Version,
    KeyWrap1,
    EncryptionInfo,
    FileNameInfo,
    UnicodeFileNameInfo,
    Compression,
    FileInfo,
    Data,
];

const EMPTY_PREAMBLE_HEADER: [u8; 5 + 16] = [0x15, 0x00, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

impl RawBytes for EncryptedContent {
    fn as_raw_bytes(&self) -> Vec<u8> {
        let mut result = vec![];
        result.extend_from_slice(&GUID);
        result.extend_from_slice(&EMPTY_PREAMBLE_HEADER);

        let mut hmac_sha1 = AxHmacSha1::new(&self.hmac_key);

        for header_kind in HEADERS_ORDER {
            let header_content = self.header(&header_kind);
            if let Ok(content) = header_content {
                let header_kind_bytes = [header_kind as u8];
                let length: u32 = (5 + content.len()) as u32;
                let length = length.to_le_bytes();

                let mut header_block: Vec<u8> = vec![];

                header_block.extend_from_slice(&length);
                header_block.extend_from_slice(&header_kind_bytes);
                header_block.extend_from_slice(content);

                hmac_sha1.input(&header_block);

                result.extend_from_slice(&header_block);
            }
        }

        let mac_result = hmac_sha1.result();
        let hmac = mac_result.code();

        let preamble_start = GUID.len() + 5;
        result[preamble_start..(preamble_start + 16)].copy_from_slice(&hmac[..16]);

        result.extend_from_slice(&self.content);

        result
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

#[cfg(test)]
mod tests {
    use crate::content::{EncryptedContent, HeaderBlockType};
    use std::collections::HashMap;
    use crate::content::HeaderBlockType::{UnicodeFileNameInfo, CompressionInfo, KeyWrap1, FileNameInfo, Preamble, Data, Compression, Version, EncryptionInfo, FileInfo};

    #[test]
    fn parse_hello_world() {
        let content = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x15, 0x00, 0x00, 0x00, 0x02, 0xf9, 0xaf, 0x2e, 0x67, 0x7d, 0xcf, 0xc9, 0xfe, 0x06, 0x4b, 0x39,
            0x08, 0xe7, 0x5a, 0x87, 0x81, 0x25, 0x00, 0x00, 0x00, 0x42, 0xdc, 0x39, 0xe8, 0xd6, 0xb9, 0xdb,
            0xf1, 0x8c, 0x49, 0xac, 0x72, 0xd4, 0x67, 0x59, 0x64, 0x20, 0xa1, 0x80, 0x62, 0xa8, 0xe6, 0xda,
            0xbd, 0x61, 0xde, 0x88, 0x37, 0x07, 0x38, 0x8e, 0x0e, 0x21, 0x15, 0x00, 0x00, 0x00, 0x45, 0x8f,
            0xfb, 0x89, 0xf1, 0x49, 0x1e, 0x29, 0x3a, 0xad, 0x67, 0x1d, 0x06, 0x9d, 0x15, 0xd2, 0x4a, 0x15,
            0x00, 0x00, 0x00, 0x43, 0x2c, 0xa8, 0x3b, 0x8c, 0x65, 0xa2, 0xe4, 0x23, 0x17, 0xfd, 0x17, 0x99,
            0x92, 0x27, 0x7b, 0x91, 0x25, 0x00, 0x00, 0x00, 0x44, 0x9a, 0x22, 0xb3, 0xc9, 0x77, 0xe4, 0x95,
            0x24, 0x9d, 0xbc, 0x82, 0x44, 0x3b, 0x88, 0x54, 0xa1, 0x3a, 0x37, 0xa0, 0xbc, 0xe9, 0x33, 0x6e,
            0x11, 0x7a, 0x68, 0xa1, 0x05, 0x7f, 0x0f, 0x54, 0x2c, 0x25, 0x00, 0x00, 0x00, 0x41, 0x7e, 0x90,
            0x2d, 0x1d, 0x6f, 0x54, 0xff, 0x60, 0x10, 0x03, 0xee, 0x65, 0xbf, 0x03, 0xa6, 0x4f, 0x9f, 0x5a,
            0x41, 0x55, 0xb1, 0x65, 0xce, 0x0f, 0xc0, 0xaa, 0xdc, 0x08, 0xe8, 0xf1, 0x30, 0xd0, 0x35, 0x00,
            0x00, 0x00, 0x46, 0x5b, 0xdd, 0x45, 0x57, 0x0d, 0xa0, 0xfc, 0x8e, 0x92, 0xc7, 0x74, 0xb3, 0x06,
            0x9e, 0xd7, 0x18, 0x55, 0xef, 0x23, 0xbc, 0x11, 0xc0, 0x3a, 0x11, 0x8d, 0x8a, 0xea, 0x5c, 0x84,
            0x6e, 0x62, 0x4e, 0x11, 0xbe, 0x26, 0xb4, 0x4b, 0x5b, 0x7a, 0xc8, 0x05, 0x69, 0x8f, 0x9b, 0x3b,
            0x20, 0x11, 0x66, 0x31, 0x00, 0x00, 0x00, 0x04, 0x4e, 0xea, 0x07, 0xf3, 0x45, 0x91, 0x70, 0xed,
            0x8e, 0x40, 0xf9, 0x22, 0xf4, 0xee, 0xcb, 0xa1, 0x4d, 0x9e, 0xee, 0x9a, 0x5b, 0x30, 0x18, 0x63,
            0x24, 0x87, 0x83, 0x8c, 0xf3, 0xcd, 0xaa, 0x5c, 0xc1, 0xcc, 0x34, 0x84, 0xf1, 0x30, 0x6a, 0x0e,
            0x98, 0x3a, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x0d, 0x00, 0x00, 0x00, 0x3f, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x5f,
            0xe3, 0x5c, 0x86, 0x97, 0xed, 0x81, 0x84, 0xfe, 0x2b, 0x4a, 0x9a, 0xd2, 0xbe, 0xfd,
        ];

        let encrypted_content = EncryptedContent::parse(&content);

        let mut expected_headers: HashMap<HeaderBlockType, Vec<u8>> = HashMap::new();
        expected_headers.insert(UnicodeFileNameInfo, vec![91, 221, 69, 87, 13, 160, 252, 142, 146, 199, 116, 179, 6, 158, 215, 24, 85, 239, 35, 188, 17, 192, 58, 17, 141, 138, 234, 92, 132, 110, 98, 78, 17, 190, 38, 180, 75, 91, 122, 200, 5, 105, 143, 155, 59, 32, 17, 102]);
        expected_headers.insert(CompressionInfo, vec![44, 168, 59, 140, 101, 162, 228, 35, 23, 253, 23, 153, 146, 39, 123, 145]);
        expected_headers.insert(KeyWrap1, vec![78, 234, 7, 243, 69, 145, 112, 237, 142, 64, 249, 34, 244, 238, 203, 161, 77, 158, 238, 154, 91, 48, 24, 99, 36, 135, 131, 140, 243, 205, 170, 92, 193, 204, 52, 132, 241, 48, 106, 14, 152, 58, 0, 0]);
        expected_headers.insert(FileNameInfo, vec![126, 144, 45, 29, 111, 84, 255, 96, 16, 3, 238, 101, 191, 3, 166, 79, 159, 90, 65, 85, 177, 101, 206, 15, 192, 170, 220, 8, 232, 241, 48, 208]);
        expected_headers.insert(Data, vec![16, 0, 0, 0, 0, 0, 0, 0]);
        expected_headers.insert(Preamble, vec![249, 175, 46, 103, 125, 207, 201, 254, 6, 75, 57, 8, 231, 90, 135, 129]);
        expected_headers.insert(Compression, vec![143, 251, 137, 241, 73, 30, 41, 58, 173, 103, 29, 6, 157, 21, 210, 74]);
        expected_headers.insert(Version, vec![3, 0, 0, 0, 0, 0, 0, 0]);
        expected_headers.insert(EncryptionInfo, vec![220, 57, 232, 214, 185, 219, 241, 140, 73, 172, 114, 212, 103, 89, 100, 32, 161, 128, 98, 168, 230, 218, 189, 97, 222, 136, 55, 7, 56, 142, 14, 33]);
        expected_headers.insert(FileInfo, vec![154, 34, 179, 201, 119, 228, 149, 36, 157, 188, 130, 68, 59, 136, 84, 161, 58, 55, 160, 188, 233, 51, 110, 17, 122, 104, 161, 5, 127, 15, 84, 44]);

        assert_eq!(encrypted_content, EncryptedContent {
            headers: expected_headers,
            content: vec![52, 95, 227, 92, 134, 151, 237, 129, 132, 254, 43, 74, 154, 210, 190, 253],
            hmac_key: [0u8; 16]
        })
    }
}