# Rust Encryptor UI

Rust Encryptor UI is a small cross‑platform desktop application for encrypting and decrypting files with a passphrase.  It is built with the [`eframe`](https://crates.io/crates/eframe) GUI framework and uses modern cryptography to protect your data.

## Features

- **File encryption/decryption** via a simple graphical interface.
- Uses **AES‑256‑GCM** for authenticated encryption and **Argon2** for password‑based key derivation.
- Random 16‑byte salt and 12‑byte nonce are generated for each encryption run.
- Output format: `MAGIC | VERSION | SALT | NONCE | CIPHERTEXT`.
- Passwords are wiped from memory after each operation.

## Building

1. Install the [Rust toolchain](https://www.rust-lang.org/).
2. Build and run the application:

   ```bash
   cd rust-enc-ui
   cargo run --release
   ```

The release build will produce a native executable and launch the GUI.

## Usage

1. Choose whether to **Encrypt** or **Decrypt**.
2. Select the input and output files.
3. Enter the password (and confirmation when encrypting).
4. Click the action button and wait for the status message.

## File format

Encrypted files are written with a small header so the app can verify integrity during decryption:

```
[0..3]  "RENC" magic bytes
[4]     version byte
[5..20] salt (16 bytes)
[21..32] nonce (12 bytes)
[33..]  ciphertext
```

## Development

Run the test build to verify the project compiles:

```bash
cargo test
```

## License

This project is released under the MIT License.

