use crypto::pbkdf2::pbkdf2;
use crypto::hmac::Hmac;
use crypto::sha1::Sha1;
use crypto::digest::Digest;
use std::path::PathBuf;
use std::fs;
use axxd::content::EncryptedContent;

fn main() {
    let pass = "a";
    let salt = [0u8; 32];
    let key = derive_key_256(pass.as_bytes(), &salt);
    println!("{:?}", key);

    let input = fs::read(PathBuf::from("test.axx")).unwrap();
    let data = EncryptedContent::parse(&input);
    println!("data: {:?}", data);

    println!("Hello, world!");
}

fn derive_key_256(pass: &[u8], salt: &[u8]) -> [u8; 32] {
    let sha1 = AxxSha1::new();
    let mut key = [0u8; 32];
    let mut hmac = Hmac::new(sha1, pass);
    pbkdf2(&mut hmac, &salt, 48000, &mut key);
    key
}

struct AxxSha1 {
    sha1: Sha1
}

impl AxxSha1 {
    pub fn new() -> AxxSha1 {
        AxxSha1 {
            sha1: Sha1::new()
        }
    }
}

impl Digest for AxxSha1 {
    fn input(&mut self, input: &[u8]) {
        self.sha1.input(input)
    }

    fn result(&mut self, out: &mut [u8]) {
        self.sha1.result(out)
    }

    fn reset(&mut self) {
        self.sha1.reset()
    }

    fn output_bits(&self) -> usize {
        self.sha1.output_bits()
    }

    fn block_size(&self) -> usize {
        20
    }
}