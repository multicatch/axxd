use axxd::cli::{setup_args, decrypt_or_encrypt};

fn main() {
    let args = setup_args();
    decrypt_or_encrypt(args);
}