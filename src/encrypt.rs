use std::collections::HashMap;
use crypto::aes::cbc_encryptor;
use crypto::aes::KeySize::KeySize128;
use crypto::blockmodes::PkcsPadding;
use crypto::buffer::{RefReadBuffer, RefWriteBuffer};
use encoding_rs::{Encoding, UTF_8, WINDOWS_1252};
use crate::decrypt::derive_key;
use crate::{EncryptedContent, Error, PlainContent};
use crate::content::HeaderBlockType;
use crate::content::HeaderBlockType::{Compression, Data, EncryptionInfo, FileNameInfo, KeyWrap1, UnicodeFileNameInfo, Version};
use crate::header::{encrypt_subkey, HeaderEncryptor};
use crate::key::KeyParams;

pub const GUID: [u8; 16] = [0xc0, 0xb9, 0x07, 0x2e, 0x4f, 0x93, 0xf1, 0x46, 0xa0, 0x15, 0x79, 0x2c, 0xa1, 0xd9, 0xe8, 0x21];

pub fn encrypt(data: &PlainContent, passphrase: &str) -> Result<EncryptedContent, Error> {
    let key = derive_key(passphrase);
    let key_params = KeyParams::generate(&key)?;
    let key = key_params.unwrap_key(&key)?;

    let mut header_encryptor = HeaderEncryptor::new(&key).unwrap();
    let (iv, padded_iv) = create_iv();

    let mut headers: HashMap<HeaderBlockType, Vec<u8>> = HashMap::new();

    insert_headers(&mut headers,
                   &mut header_encryptor,
                   &key_params,
                   &padded_iv,
                   &data.file_name,
                   data.content.len() as u64
    )?;

    let encrypted = encrypt_data(&key, &iv, &data.content, data.content.len())?;
    Ok(EncryptedContent::new(headers, encrypted))
}

fn create_iv() -> ([u8; 16], [u8; 24]) {
    let mut actual_iv = [0u8; 16];
    for item in &mut actual_iv {
        *item = rand::random();
    }

    let mut padded_iv = [0u8; 24];
    padded_iv[8..(actual_iv.len() + 8)].copy_from_slice(&actual_iv);
    (actual_iv, padded_iv)
}

fn insert_headers(
    headers: &mut HashMap<HeaderBlockType, Vec<u8>>,
    header_encryptor: &mut HeaderEncryptor,
    key_params: &KeyParams,
    padded_iv: &[u8],
    file_name: &str,
    buffer_size: u64,
) -> Result<(), Error> {
    // TODO: headers.insert(Preamble, vec![249, 175, 46, 103, 125, 207, 201, 254, 6, 75, 57, 8, 231, 90, 135, 129]);
    headers.insert(Version, vec![3, 0, 0, 0, 0, 0, 0, 0]);
    headers.insert(KeyWrap1, key_params.format_key_wrap());
    headers.insert(EncryptionInfo, header_encryptor.encrypt(padded_iv, padded_iv.len())?);
    headers.insert(FileNameInfo, encrypt_file_name(header_encryptor, file_name, WINDOWS_1252)?);
    headers.insert(UnicodeFileNameInfo, encrypt_file_name(header_encryptor, file_name, UTF_8)?);
    headers.insert(Compression, encrypt_is_compressed(header_encryptor, false)?);
    //headers.insert(CompressionInfo, vec![44, 168, 59, 140, 101, 162, 228, 35, 23, 253, 23, 153, 146, 39, 123, 145]);
    //required: headers.insert(FileInfo, vec![154, 34, 179, 201, 119, 228, 149, 36, 157, 188, 130, 68, 59, 136, 84, 161, 58, 55, 160, 188, 233, 51, 110, 17, 122, 104, 161, 5, 127, 15, 84, 44]);
    headers.insert(Data, buffer_size.to_le_bytes().to_vec());
    Ok(())
}

fn encrypt_file_name(header_encryptor: &mut HeaderEncryptor, file_name: &str, encoding: &'static Encoding) -> Result<Vec<u8>, Error> {
    let (file_name, _, has_errors) = encoding.encode(file_name);
    let file_name = if !has_errors {
        file_name
    } else {
        file_name.to_owned()
    };

    let slice_len = file_name.len();
    let mut file_name_bytes = vec![0u8; slice_len];
    file_name_bytes[0..slice_len].copy_from_slice(&file_name[..slice_len]);

    header_encryptor.encrypt(&file_name_bytes, slice_len)
}

fn encrypt_is_compressed(header_encryptor: &mut HeaderEncryptor, data: bool) -> Result<Vec<u8>, Error> {
    let is_compressed_bytes = i32::to_le_bytes(
        if data {
            1
        } else {
            0
        }
    );

    header_encryptor.encrypt(&is_compressed_bytes, 16)
}

fn encrypt_data(key: &[u8], iv: &[u8], data: &[u8], buffer_size: usize) -> Result<Vec<u8>, Error> {
    let mut read_buffer = RefReadBuffer::new(data);
    let mut buffer_vec = vec![0u8; buffer_size];
    let buffer = buffer_vec.as_mut_slice();
    let mut write_buffer = RefWriteBuffer::new(buffer);

    let data_key = encrypt_subkey(key, 3).map_err(Error::Cipher)?;
    let mut encryptor = cbc_encryptor(KeySize128, &data_key, iv, PkcsPadding);
    encryptor.encrypt(&mut read_buffer, &mut write_buffer, true).map_err(Error::Cipher)?;

    Ok(buffer.to_vec())
}

#[cfg(test)]
mod tests {
    use crate::{encrypt, PlainContent};
    use crate::encrypt::create_iv;

    #[test]
    fn test_iv_generation() {
        let (iv, padded) = create_iv();

        let iv: &[u8] = &iv;
        let padded: &[u8] = &padded[8..];

        assert_eq!(iv, padded);
    }

    #[test]
    fn encrypt_and_decrypt() {
        let content = PlainContent::new("test-file.txt".to_string(), "Hello World".as_bytes().to_vec());
        let encrypted = encrypt(&content, "secret").unwrap();
    }
}