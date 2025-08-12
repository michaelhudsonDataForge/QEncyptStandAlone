use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Key},
};
use anyhow::{Context, Result, anyhow};
use argon2::Argon2;
use getrandom::fill;
use std::{fs, io::Write, path::PathBuf};
use zeroize::Zeroize;

const MAGIC: &[u8; 4] = b"RENC";
const VERSION: u8 = 1;

pub fn run_encrypt(input: Option<PathBuf>, output: Option<PathBuf>, password: &str) -> Result<()> {
    let in_path = input.context("No input file selected")?;
    let out_path = output.context("No output file selected")?;
    let mut plaintext =
        fs::read(&in_path).with_context(|| format!("Reading {}", in_path.display()))?;

    // Derive key
    let mut salt = [0u8; 16];
    fill(&mut salt).map_err(|e| anyhow!("OS RNG failed for salt: {e}"))?;
    let mut key = derive_key(password, &salt)?;

    // AEAD
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let mut nonce = [0u8; 12];
    fill(&mut nonce).map_err(|e| anyhow!("OS RNG failed for nonce: {e}"))?;

    let ciphertext = cipher
        .encrypt((&nonce).into(), plaintext.as_ref())
        .map_err(|_| anyhow!("Encryption failed"))?;

    // Write: MAGIC|VERSION|SALT|NONCE|CIPHERTEXT
    let mut out = Vec::with_capacity(4 + 1 + 16 + 12 + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);

    let mut f =
        fs::File::create(&out_path).with_context(|| format!("Creating {}", out_path.display()))?;
    f.write_all(&out)?;
    f.flush()?;

    // Wipe sensitive material
    plaintext.zeroize();
    key.zeroize();

    Ok(())
}

pub fn run_decrypt(input: Option<PathBuf>, output: Option<PathBuf>, password: &str) -> Result<()> {
    let in_path = input.context("No input file selected")?;
    let out_path = output.context("No output file selected")?;
    let data = fs::read(&in_path).with_context(|| format!("Reading {}", in_path.display()))?;

    // Parse header
    if data.len() < 4 + 1 + 16 + 12 {
        anyhow::bail!("File too short");
    }
    if &data[0..4] != MAGIC {
        anyhow::bail!("Bad magic");
    }
    if data[4] != VERSION {
        anyhow::bail!("Unsupported version");
    }

    let salt = &data[5..21];
    let nonce = &data[21..33];
    let ciphertext = &data[33..];

    let mut key = derive_key(password, salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

    let mut plaintext = cipher
        .decrypt(nonce.into(), ciphertext)
        .map_err(|_| anyhow!("Decryption failed (wrong password or corrupted file)"))?;

    fs::write(&out_path, &plaintext).with_context(|| format!("Writing {}", out_path.display()))?;

    plaintext.zeroize();
    key.zeroize();

    Ok(())
}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let argon = Argon2::default();
    let mut key = [0u8; 32];

    argon
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|_| anyhow!("Key derivation failed"))?;

    Ok(key)
}
