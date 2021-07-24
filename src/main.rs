use std::path::PathBuf;
use std::fs;
use axxd::content::EncryptedContent;
use axxd::decrypt::decrypt;

fn main() {
    let pass = "a";

    let input = fs::read(PathBuf::from("test.axx")).unwrap();
    let data = EncryptedContent::parse(&input);
    println!("data: {:?}", data);

    let result = decrypt(&data, &pass).unwrap();

    println!("{:?}", result);
}