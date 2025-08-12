use rust_enc_ui::{run_decrypt, run_encrypt};
use std::fs;
use tempfile::tempdir;

#[test]
fn encrypt_decrypt_roundtrip() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let input = dir.path().join("plain.txt");
    let encrypted = dir.path().join("cipher.bin");
    let output = dir.path().join("decrypted.txt");
    let data = b"secret message";
    fs::write(&input, data)?;

    run_encrypt(Some(input.clone()), Some(encrypted.clone()), "pw")?;
    run_decrypt(Some(encrypted), Some(output.clone()), "pw")?;

    let decrypted = fs::read(output)?;
    assert_eq!(decrypted, data);
    Ok(())
}

#[test]
fn decrypt_with_wrong_password_fails() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let input = dir.path().join("plain.txt");
    let encrypted = dir.path().join("cipher.bin");
    fs::write(&input, b"top secret")?;

    run_encrypt(Some(input.clone()), Some(encrypted.clone()), "correct")?;
    let result = run_decrypt(Some(encrypted), Some(dir.path().join("out.txt")), "wrong");
    assert!(result.is_err());
    Ok(())
}
