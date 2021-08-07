use crate::error::Error;
use crate::content::EncryptedContent;
use crate::header::{HeaderDecryptor, encrypt_subkey};
use crate::content::HeaderBlockType::{EncryptionInfo, KeyWrap1, FileNameInfo, Compression, Data};
use crypto::blockmodes::PkcsPadding;
use crypto::aes::KeySize::KeySize128;
use crypto::aes::cbc_decryptor;
use crypto::buffer::{RefWriteBuffer, RefReadBuffer};
use std::convert::TryInto;
use flate2::read::ZlibDecoder;
use std::io::Read;
use crypto::sha1::Sha1;
use crate::key::KeyParams;
use crypto::digest::Digest;
use encoding_rs::WINDOWS_1252;

#[derive(Debug, Eq, PartialEq)]
pub struct PlainContent {
    pub file_name: String,
    pub content: Vec<u8>,
}

pub fn decrypt(data: &EncryptedContent, passphrase: &str) -> Result<PlainContent, Error> {
    let key = derive_key(passphrase);
    let key = extract_master_key(&data, &key)?;

    let mut header_decryptor = HeaderDecryptor::new(&key).unwrap();
    let iv = extract_iv(&mut header_decryptor, &data)?;
    let file_name = extract_file_name(&mut header_decryptor, data)?;
    let is_compressed = extract_is_compressed(&mut header_decryptor, data)?;
    let buffer_size = extract_buffer_size(data)?;

    decrypt_data(&key, &iv, &data.content, buffer_size).and_then(|buffer| {
        if is_compressed {
            decompress(&buffer)
        } else {
            Ok(buffer)
        }
    }).map(|content| PlainContent {
        file_name,
        content,
    })
}

fn derive_key(password: &str) -> [u8; 16] {
    let mut key = [0; 20];
    let mut sha1 = Sha1::new();
    let (pass_bytes, _, _) = WINDOWS_1252.encode(password);
    sha1.input(pass_bytes.as_ref());
    sha1.result(&mut key);
    let mut result: [u8; 16] = Default::default();
    result.copy_from_slice(&key[0..16]);
    result
}

fn decrypt_data(key: &[u8], iv: &[u8], data: &[u8], buffer_size: usize) -> Result<Vec<u8>, Error> {
    let mut read_buffer = RefReadBuffer::new(data);
    let mut buffer_vec = vec![0u8; buffer_size];
    let buffer = buffer_vec.as_mut_slice();
    let mut write_buffer = RefWriteBuffer::new(buffer);

    let data_key = encrypt_subkey(&key, 3).map_err(Error::Cipher)?;
    let mut decryptor = cbc_decryptor(KeySize128, &data_key, &iv, PkcsPadding);
    decryptor.decrypt(&mut read_buffer, &mut write_buffer, true).map_err(Error::Cipher)?;

    Ok(buffer.to_vec())
}

fn extract_master_key(data: &EncryptedContent, key: &[u8]) -> Result<Vec<u8>, Error> {
    let raw_key_wrap = data.header(&KeyWrap1)?;
    let params = KeyParams::parse(*raw_key_wrap);
    params.unwrap_key(&key)
}

fn extract_iv(header_decryptor: &mut HeaderDecryptor, data: &EncryptedContent) -> Result<Vec<u8>, Error> {
    let encryption_info = data.header(&EncryptionInfo)?;
    let iv = header_decryptor.decrypt(*encryption_info, 24)?;
    Ok(iv[8..].to_vec())
}

fn extract_file_name(header_decryptor: &mut HeaderDecryptor, data: &EncryptedContent) -> Result<String, Error> {
    let file_name = data.header(&FileNameInfo)?;
    let mut file_name = header_decryptor.decrypt(*file_name, 260)?;
    let mut end = file_name.iter().position(|&c| c == 0).unwrap_or(file_name.len());
    let (result, _, has_errors) = WINDOWS_1252.decode(&file_name);
    if !has_errors {
        file_name = result.as_bytes().to_vec();
        end = file_name.iter().position(|&c| c == 0).unwrap_or(file_name.len());
    }

    String::from_utf8(file_name[..end].to_vec()).map_err(Error::Encoding)
}

fn extract_is_compressed(header_decryptor: &mut HeaderDecryptor, data: &EncryptedContent) -> Result<bool, Error> {
    let is_compressed_bytes = data.header(&Compression)?;
    let is_compressed = header_decryptor.decrypt(*is_compressed_bytes, 4)?;
    let is_compressed: [u8; 4] = is_compressed.try_into().map_err(|_| Error::MalformedContent {
        description: "Wrong format of compression flag".to_string(),
        content: is_compressed_bytes.to_vec(),
    })?;
    Ok(i32::from_le_bytes(is_compressed) != 0)
}

fn extract_buffer_size(data: &EncryptedContent) -> Result<usize, Error> {
    let buffer_size = data.header(&Data)?;
    let buffer_size: [u8; 8] = (*buffer_size).try_into().map_err(|_| Error::MalformedContent {
        description: "Wrong format of data length".to_string(),
        content: buffer_size.to_vec(),
    })?;
    Ok(usize::from_le_bytes(buffer_size))
}

fn decompress(buffer: &[u8]) -> Result<Vec<u8>, Error> {
    let mut result = vec![];
    let mut decoder = ZlibDecoder::new(buffer);
    decoder.read_to_end(&mut result).map_err(Error::Io)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use crate::content::{EncryptedContent, HeaderBlockType};
    use std::collections::HashMap;
    use crate::content::HeaderBlockType::{KeyWrap1, FileNameInfo, Data, Preamble, Compression, EncryptionInfo};
    use crate::decrypt::{decrypt, PlainContent};

    #[test]
    fn decrypt_content() {
        let mut headers: HashMap<HeaderBlockType, &'static [u8]> = HashMap::new();
        headers.insert(KeyWrap1, &[78, 234, 7, 243, 69, 145, 112, 237, 142, 64, 249, 34, 244, 238, 203, 161, 77, 158, 238, 154, 91, 48, 24, 99, 36, 135, 131, 140, 243, 205, 170, 92, 193, 204, 52, 132, 241, 48, 106, 14, 152, 58, 0, 0]);
        headers.insert(FileNameInfo, &[126, 144, 45, 29, 111, 84, 255, 96, 16, 3, 238, 101, 191, 3, 166, 79, 159, 90, 65, 85, 177, 101, 206, 15, 192, 170, 220, 8, 232, 241, 48, 208]);
        headers.insert(Data, &[16, 0, 0, 0, 0, 0, 0, 0]);
        headers.insert(Preamble, &[249, 175, 46, 103, 125, 207, 201, 254, 6, 75, 57, 8, 231, 90, 135, 129]);
        headers.insert(Compression, &[143, 251, 137, 241, 73, 30, 41, 58, 173, 103, 29, 6, 157, 21, 210, 74]);
        headers.insert(EncryptionInfo, &[220, 57, 232, 214, 185, 219, 241, 140, 73, 172, 114, 212, 103, 89, 100, 32, 161, 128, 98, 168, 230, 218, 189, 97, 222, 136, 55, 7, 56, 142, 14, 33]);

        let encrypted_content = EncryptedContent {
            headers,
            content: &[52, 95, 227, 92, 134, 151, 237, 129, 132, 254, 43, 74, 154, 210, 190, 253],
        };

        let expected = PlainContent {
            file_name: "HelloWorld-Key-a".to_string(),
            content: vec![72, 101, 108, 108, 111, 87, 111, 114, 108, 100, 0, 0, 0, 0, 0, 0],
        };
        let result = decrypt(&encrypted_content, "a");

        assert_eq!(result.unwrap(), expected);
    }
}