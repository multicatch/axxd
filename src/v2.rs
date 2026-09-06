use crate::content::{EncryptedContent, HeaderBlockType};
use crate::decrypt::PlainContent;
use crate::error::Error;
use aes::Aes256;
use cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use flate2::read::ZlibDecoder;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha512;
use std::convert::TryInto;
use std::io::Read;

pub fn decrypt_v2(data: &EncryptedContent, passphrase: &str) -> Result<PlainContent, Error> {
    let raw_key_wrap = data.header(&HeaderBlockType::SymmetricKeyWrap)?;
    if raw_key_wrap.len() < 248 {
        return Err(Error::MalformedContent {
            description: "SymmetricKeyWrap header block is too short".to_string(),
            content: raw_key_wrap.to_vec(),
        });
    }

    let wrapped_key = &raw_key_wrap[0..144];
    let wrap_salt = &raw_key_wrap[144..208];
    let wrap_iterations = u32::from_le_bytes(raw_key_wrap[208..212].try_into().unwrap());
    let deriv_salt = &raw_key_wrap[212..244];
    let deriv_iterations = u32::from_le_bytes(raw_key_wrap[244..248].try_into().unwrap());

    let mut seed = [0u8; 64];
    pbkdf2_hmac::<Sha512>(passphrase.as_bytes(), deriv_salt, deriv_iterations, &mut seed);

    let mut kek = [0u8; 32];
    for i in 0..64 {
        kek[i % 32] ^= seed[i];
    }
    for i in 0..32 {
        kek[i] ^= wrap_salt[i];
    }

    let (master_key, ctr_iv) = unwrap_master_key(&kek, wrapped_key, wrap_iterations)?;

    let file_name = if let Ok(fn_data) = data.header(&HeaderBlockType::UnicodeFileNameInfo) {
        let plain = decrypt_at(&master_key, &ctr_iv, fn_data, 768);
        let end = plain.iter().position(|&b| b == 0).unwrap_or(plain.len());
        String::from_utf8_lossy(&plain[..end]).to_string()
    } else if let Ok(fn_data) = data.header(&HeaderBlockType::FileNameInfo) {
        let plain = decrypt_at(&master_key, &ctr_iv, fn_data, 768);
        let end = plain.iter().position(|&b| b == 0).unwrap_or(plain.len());
        String::from_utf8_lossy(&plain[..end]).to_string()
    } else {
        "decrypted.bin".to_string()
    };

    let is_compressed = if let Ok(comp_data) = data.header(&HeaderBlockType::Compression) {
        let plain = decrypt_at(&master_key, &ctr_iv, comp_data, 512);
        !plain.is_empty() && plain[0] != 0
    } else {
        false
    };

    let mut off = 0;
    let mut ciphertext = Vec::new();
    while off + 5 <= data.content.len() {
        let block_len = u32::from_le_bytes(data.content[off..off + 4].try_into().unwrap()) as usize;
        if block_len < 5 || off + block_len > data.content.len() {
            break;
        }
        let block_type = data.content[off + 4];
        if block_type != 20 {
            break;
        }
        ciphertext.extend_from_slice(&data.content[off + 5..off + block_len]);
        off += block_len;
    }

    let decrypted_data = decrypt_at(&master_key, &ctr_iv, &ciphertext, 1048576);

    let content = if is_compressed {
        decompress(&decrypted_data)?
    } else {
        decrypted_data
    };

    Ok(PlainContent {
        file_name,
        content,
    })
}

fn unwrap_master_key(kek: &[u8; 32], wrapped_key: &[u8], iterations: u32) -> Result<([u8; 32], [u8; 16]), Error> {
    if wrapped_key.len() < 56 {
        return Err(Error::MalformedContent {
            description: "wrapped key too short".to_string(),
            content: wrapped_key.to_vec(),
        });
    }

    let mut wrapped = wrapped_key[0..56].to_vec();
    let cipher = Aes256::new_from_slice(kek).map_err(|e| Error::Cipher(format!("{:?}", e)))?;

    for j in (0..iterations).rev() {
        for k in (1..=6).rev() {
            let t = 6 * j as u64 + k as u64;
            let mut block = [0u8; 16];
            block[0..8].copy_from_slice(&wrapped[0..8]);
            block[4] ^= ((t >> 24) & 0xff) as u8;
            block[5] ^= ((t >> 16) & 0xff) as u8;
            block[6] ^= ((t >> 8) & 0xff) as u8;
            block[7] ^= (t & 0xff) as u8;
            block[8..16].copy_from_slice(&wrapped[k * 8..(k + 1) * 8]);

            let block_ref = cipher::generic_array::GenericArray::from_mut_slice(&mut block);
            cipher.decrypt_block(block_ref);

            wrapped[0..8].copy_from_slice(&block[0..8]);
            wrapped[k * 8..(k + 1) * 8].copy_from_slice(&block[8..16]);
        }
    }

    if &wrapped[0..8] != b"\xa6\xa6\xa6\xa6\xa6\xa6\xa6\xa6" {
        return Err(Error::Cipher("key unwrap integrity check failed (wrong password?)".to_string()));
    }

    let mut master_key = [0u8; 32];
    master_key.copy_from_slice(&wrapped[8..40]);
    let mut ctr_iv = [0u8; 16];
    ctr_iv.copy_from_slice(&wrapped[40..56]);

    Ok((master_key, ctr_iv))
}

fn keystream(master_key: &[u8; 32], iv: &[u8; 16], start_index: usize, length: usize) -> Vec<u8> {
    let cipher = Aes256::new_from_slice(master_key).unwrap();
    let first_block = (start_index / 16) as u64;
    let skip = start_index % 16;
    let n_blocks = (skip + length + 15) / 16;

    let mut ks = Vec::with_capacity(n_blocks * 16);
    for i in 0..n_blocks {
        let counter = (first_block + i as u64).to_be_bytes();
        let mut block = [0u8; 16];
        block[0..8].copy_from_slice(&iv[0..8]);
        for b in 0..8 {
            block[8 + b] = iv[8 + b] ^ counter[b];
        }
        let block_ref = cipher::generic_array::GenericArray::from_mut_slice(&mut block);
        cipher.encrypt_block(block_ref);
        ks.extend_from_slice(&block);
    }
    ks[skip..skip + length].to_vec()
}

fn decrypt_at(master_key: &[u8; 32], iv: &[u8; 16], ciphertext: &[u8], ksi: usize) -> Vec<u8> {
    let ks = keystream(master_key, iv, ksi, ciphertext.len());
    ciphertext.iter().zip(ks.iter()).map(|(c, k)| c ^ k).collect()
}

fn decompress(buffer: &[u8]) -> Result<Vec<u8>, Error> {
    let mut result = vec![];
    let mut decoder = ZlibDecoder::new(buffer);
    decoder.read_to_end(&mut result).map_err(Error::Io)?;
    Ok(result)
}
