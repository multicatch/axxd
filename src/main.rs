use axxd::cli::{setup_args, cli_decrypt};

fn main() {
    let args = setup_args();
    cli_decrypt(args);
}