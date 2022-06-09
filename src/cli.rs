use crate::{decrypt_file, create_target_path, save_decrypted, encrypt_file};
use std::path::{PathBuf, Path};
use clap::{App, Arg, ArgMatches};
use std::io;
use crate::error::Error;
use std::process::exit;
use crate::content::RawBytes;

const FILE_PARAM: &str = "file";
const PASSPHRASE_PARAM: &str = "passphrase";
const OVERWRITE_PARAM: &str = "overwrite";
const NO_OVERWRITE_PARAM: &str = "no-overwrite";
const ENCRYPT_MODE: &str = "encrypt-mode";

pub fn setup_args() -> ArgMatches<'static> {
    App::new("axxd")
        .version("0.1.0")
        .about("Axxd - an [axx] file [d]ecryptor")
        .arg(
            Arg::with_name(ENCRYPT_MODE)
                .short("e")
                .long("encrypt-mode")
                .help("Use encryption instead of decryption")
                .takes_value(false)
        )
        .arg(
            Arg::with_name(FILE_PARAM)
                .short("f")
                .long("file")
                .value_name("FILE")
                .help("Input file path")
                .takes_value(true),
        )
        .arg(
            Arg::with_name(PASSPHRASE_PARAM)
                .short("p")
                .long("passphrase")
                .value_name("PASS")
                .help("Encryption passphrase")
                .takes_value(true),
        )
        .arg(
            Arg::with_name(OVERWRITE_PARAM)
                .short("o")
                .long("overwrite")
                .help("Overwrite target file if exists")
                .takes_value(false)
                .conflicts_with(NO_OVERWRITE_PARAM),
        )
        .arg(
            Arg::with_name(NO_OVERWRITE_PARAM)
                .short("n")
                .long("no-overwrite")
                .help("Abort when target file already exists")
                .takes_value(false)
                .conflicts_with(OVERWRITE_PARAM),
        )
        .get_matches()
}

pub fn decrypt_or_encrypt(args: ArgMatches) {
    let encrypt = args.is_present(ENCRYPT_MODE);
    if encrypt {
        cli_encrypt(args)
    } else {
        cli_decrypt(args)
    }
}

pub fn cli_encrypt(args: ArgMatches) {
    let overwrite = should_overwrite(&args);
    let (filename, pass) = retrieve_params(args);

    println!("Encrypting {}...", filename);
    let source_file = PathBuf::from(filename.clone());
    match encrypt_file(&source_file, &pass) {
        Ok(content) => {
            let new_file_name = format!("{}.axx", filename);
            prompt_save_file_cli(source_file, &new_file_name, content, overwrite);
        }
        Err(e) => {
            println!("Cannot decrypt file.");
            display_error_and_quit(e);
        }
    }
}

pub fn cli_decrypt(args: ArgMatches) {
    let overwrite = should_overwrite(&args);
    let (filename, pass) = retrieve_params(args);

    println!("Decrypting {}...", filename);
    let source_file = PathBuf::from(filename);
    match decrypt_file(&source_file, &pass) {
        Ok(content) => {
            let new_file_name = content.file_name.clone();
            prompt_save_file_cli(source_file, &new_file_name, content, overwrite);
        }
        Err(e) => {
            println!("Cannot decrypt file.");
            display_error_and_quit(e);
        }
    }
}

fn should_overwrite(args: &ArgMatches) -> Option<bool> {
    let overwrite = args.is_present(OVERWRITE_PARAM);
    let no_overwrite = args.is_present(NO_OVERWRITE_PARAM);

    if overwrite || no_overwrite {
        Some(overwrite)
    } else {
        None
    }
}

fn retrieve_params(args: ArgMatches) -> (String, String) {
    let filename = get_param_or_prompt(&args, FILE_PARAM, "Enter file path: ", prompt_plain_text);
    let pass = get_param_or_prompt(&args, PASSPHRASE_PARAM, "Enter passphrase: ", prompt_pass);

    (filename, pass)
}

fn get_param_or_prompt<F>(args: &ArgMatches, param: &str, message: &str, prompt: F) -> String
    where F: Fn(&str) -> Option<String> {
    let value = match args.value_of(param) {
        Some(value) => value.to_string(),
        None => prompt(message).unwrap()
    };

    value.trim_end_matches('\n')
        .trim_end_matches('\r')
        .to_string()
}

fn prompt_plain_text(prompt: &str) -> Option<String> {
    println!("{}", prompt);
    let mut value: String = String::new();
    if io::stdin().read_line(&mut value).is_ok() {
        Some(value)
    } else {
        None
    }
}

fn prompt_pass(prompt: &str) -> Option<String> {
    rpassword::prompt_password_stdout(prompt).ok()
}

fn display_error_and_quit(e: Error) {
    match e {
        Error::FileNameEncoding(e) => {
            println!("Passphrase may be incorrect or file is is corrupted. \nDetails: {:?}", e);
        },
        Error::Io(e) => {
            println!("Cannot read/write the file. \nDetails: {:?}", e);
        }
        Error::Cipher(e) => {
            println!("Decryption error, passphrase is incorrect or data is corrupted. \nDetails {:?}", e);
        }
        Error::MissingHeader(e) => {
            println!("Encrypted file is in incorrect format. Missing metadata that is needed to decrypt it. \nDetails: {:?}", e);
        }
        Error::MalformedContent { description, content } => {
            println!("Cannot read metadata from file. \n{}, encountered on {:?}", description, content);
        }
    }
    exit(254);
}

fn prompt_save_file_cli<P: AsRef<Path>, B: RawBytes>(source_file: P, target: &str, content: B, overwrite: Option<bool>) {
    let target_path = create_target_path(&source_file, target);
    println!("File successfully decrypted. Saving into {:?}.", target_path);

    if target_path.exists() {
        print!("WARNING: File already exits. ");
        let overwrite = if let Some(param_value) = overwrite {
            param_value
        } else {
            ask("Proceed? [y/n]")
        };

        if overwrite {
            println!("Overwriting {:?}.", target_path);
        } else {
            println!("Aborting.");
            exit(255);
        }
    }

    if let Err(e) = save_decrypted(content, target_path) {
        display_error_and_quit(e);
    }
}

fn ask(question: &str) -> bool {
    println!("{}", question);

    let mut answer: String = String::new();
    io::stdin().read_line(&mut answer).unwrap();

    answer.to_lowercase().starts_with('y')
}