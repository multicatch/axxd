# axxd

An **axx** file **d**ecryption tool.

This tool can decrypt AxCrypt-encrypted files. 
I made this because I needed a simple native tool to decrypt axx files on Linux
and I didn't want to use WINE.

## Usage

The newest standalone version can be downladed from GitHub Releases or build from sources using `cargo build --release`.

```text
axxd 0.1.0
Axxd - an [axx] file [d]ecryptor

USAGE:
    axxd [FLAGS] [OPTIONS]

FLAGS:
    -h, --help            Prints help information
    -n, --no-overwrite    Abort when target file already exists
    -o, --overwrite       Overwrite target file if exists
    -V, --version         Prints version information

OPTIONS:
    -f, --file <FILE>          Input file path
    -p, --passphrase <PASS>    Encryption passphrase
```

If you don't specify `-f` or `-p` options, you will be asked for the missing parameters.

Example:
```text
$ ./axxd -p secret.axx
Enter passphrase: 
test
Decrypting secret.axx...
File successfully decrypted. Saving into "secret.txt".
```

The app will ask you if a target file already exists.
To decrypt files in fully non-interactive mode, use `-o` or `-n`.

```text
$ ./axxd -f secret.axx
Enter passphrase: 
test
Decrypting secret.axx...
File successfully decrypted. Saving into "secret.txt".
WARNING: File already exits. Proceed? [y/n]
n
Aborting.

$ ./axxd -f secret.axx -p test -n
Decrypting secret.axx...
File successfully decrypted. Saving into "secret.txt".
WARNING: File already exits. Aborting.
```

## Using the API

You can simply decrypt a file using a `decrypt_file<P: AsRef<Path>>(path: P, passphrase: &str)` function.
It reads the file and then tries to decrypt it using a given passphrase.
Returns decrypted content as result.

```rust
    match decrypt_file(&source_file, &pass) {
        Ok(content) => save_file(content),
        Err(e) => {
            println!("Cannot decrypt file.");
            display_error_and_quit(e);
        }
    }
```

You can also use `decrypt(data: &EncryptedContent, passphrase: &str)` to decrypt raw content.
To parse raw bytes into `EncryptedContent`, use the `parse` function

```rust
    let data = EncryptedContent::parse(&input);
    decrypt(&data, passphrase)
````

