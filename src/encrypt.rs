use std::collections::HashMap;
use crate::decrypt::derive_key;
use crate::{EncryptedContent, Error, PlainContent};
use crate::content::HeaderBlockType;
use crate::content::HeaderBlockType::{Compression, CompressionInfo, Data, EncryptionInfo, FileInfo, FileNameInfo, KeyWrap1, Preamble, UnicodeFileNameInfo, Version};
use crate::header::HeaderEncryptor;
use crate::key::KeyParams;

pub fn encrypt(data: &PlainContent, passphrase: &str) -> Result<EncryptedContent, Error> {
    let key = derive_key(passphrase);
    let key_params = KeyParams::generate(&key)?;
    let key = key_params.unwrap_key(&key)?;

    let mut header_encryptor = HeaderEncryptor::new(&key).unwrap();
    let (_iv, padded_iv) = create_iv();

    let mut headers: HashMap<HeaderBlockType, Vec<u8>> = HashMap::new();

    insert_headers(&mut headers, &mut header_encryptor, &padded_iv)?;

    let vec = data.content.clone();
    Ok(EncryptedContent::new(headers, vec))
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
    padded_iv: &[u8]
) -> Result<(), Error> {
    headers.insert(Preamble, vec![249, 175, 46, 103, 125, 207, 201, 254, 6, 75, 57, 8, 231, 90, 135, 129]);
    headers.insert(Version, vec![3, 0, 0, 0, 0, 0, 0, 0]);
    headers.insert(EncryptionInfo, header_encryptor.encrypt(padded_iv, 24)?);
    headers.insert(KeyWrap1, vec![78, 234, 7, 243, 69, 145, 112, 237, 142, 64, 249, 34, 244, 238, 203, 161, 77, 158, 238, 154, 91, 48, 24, 99, 36, 135, 131, 140, 243, 205, 170, 92, 193, 204, 52, 132, 241, 48, 106, 14, 152, 58, 0, 0]);
    headers.insert(UnicodeFileNameInfo, vec![91, 221, 69, 87, 13, 160, 252, 142, 146, 199, 116, 179, 6, 158, 215, 24, 85, 239, 35, 188, 17, 192, 58, 17, 141, 138, 234, 92, 132, 110, 98, 78, 17, 190, 38, 180, 75, 91, 122, 200, 5, 105, 143, 155, 59, 32, 17, 102]);
    headers.insert(CompressionInfo, vec![44, 168, 59, 140, 101, 162, 228, 35, 23, 253, 23, 153, 146, 39, 123, 145]);
    headers.insert(FileNameInfo, vec![126, 144, 45, 29, 111, 84, 255, 96, 16, 3, 238, 101, 191, 3, 166, 79, 159, 90, 65, 85, 177, 101, 206, 15, 192, 170, 220, 8, 232, 241, 48, 208]);
    headers.insert(Compression, vec![143, 251, 137, 241, 73, 30, 41, 58, 173, 103, 29, 6, 157, 21, 210, 74]);
    headers.insert(FileInfo, vec![154, 34, 179, 201, 119, 228, 149, 36, 157, 188, 130, 68, 59, 136, 84, 161, 58, 55, 160, 188, 233, 51, 110, 17, 122, 104, 161, 5, 127, 15, 84, 44]);
    headers.insert(Data, vec![16, 0, 0, 0, 0, 0, 0, 0]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::encrypt::create_iv;

    #[test]
    fn test_iv_generation() {
        let (iv, padded) = create_iv();

        let iv: &[u8] = &iv;
        let padded: &[u8] = &padded[8..];

        assert_eq!(iv, padded);
    }
}