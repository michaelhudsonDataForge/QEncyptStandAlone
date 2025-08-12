use anyhow::{Context, Result, anyhow};
use eframe::{NativeOptions, egui};
use std::{fs, io::Write, path::PathBuf};
use zeroize::Zeroize;

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Key},
};
use argon2::Argon2;
use getrandom::fill;

const MAGIC: &[u8; 4] = b"RENC";
const VERSION: u8 = 1;

fn main() -> eframe::Result<()> {
    let options = NativeOptions::default();
    eframe::run_native(
        "Rust Encryptor",
        options,
        Box::new(|_cc| Ok(Box::new(App::default()))),
    )
}

#[derive(Default)]
struct App {
    mode_encrypt: bool,
    input_path: Option<PathBuf>,
    output_path: Option<PathBuf>,
    // Passwords only live in memory briefly and are wiped after use.
    password: String,
    // Confirmation is treated the same and cleared alongside `password`.
    confirm_password: String,
    status: String,
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("File Encrypt/Decrypt");

            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.mode_encrypt, true, "Encrypt");
                ui.selectable_value(&mut self.mode_encrypt, false, "Decrypt");
            });
            ui.separator();

            ui.horizontal(|ui| {
                if ui.button("Choose input file…").clicked() {
                    if let Some(p) = rfd::FileDialog::new().pick_file() {
                        self.input_path = Some(p);
                    }
                }
                if let Some(p) = &self.input_path {
                    ui.label(p.display().to_string());
                }
            });

            ui.horizontal(|ui| {
                if ui.button("Choose output file…").clicked() {
                    if let Some(p) = rfd::FileDialog::new().save_file() {
                        self.output_path = Some(p);
                    }
                }
                if let Some(p) = &self.output_path {
                    ui.label(p.display().to_string());
                }
            });

            ui.separator();
            ui.label("Password (not stored on disk):");
            ui.add(egui::TextEdit::singleline(&mut self.password).password(true));

            if self.mode_encrypt {
                ui.label("Confirm password:");
                ui.add(egui::TextEdit::singleline(&mut self.confirm_password).password(true));
            }

            ui.separator();

            if ui
                .button(if self.mode_encrypt {
                    "Encrypt"
                } else {
                    "Decrypt"
                })
                .clicked()
            {
                self.status.clear();
                let res = if self.mode_encrypt {
                    if self.password != self.confirm_password {
                        Err(anyhow!("Passwords do not match"))
                    } else {
                        run_encrypt(
                            self.input_path.clone(),
                            self.output_path.clone(),
                            &self.password,
                        )
                    }
                } else {
                    run_decrypt(
                        self.input_path.clone(),
                        self.output_path.clone(),
                        &self.password,
                    )
                };

                match res {
                    Ok(_) => self.status = "Success ✅".to_string(),
                    Err(e) => self.status = format!("Error: {e:#}"),
                }

                // Best-effort wipe so the password only resides in memory briefly.
                self.password.zeroize();
                self.confirm_password.zeroize();
            }

            if !self.status.is_empty() {
                ui.separator();
                ui.label(&self.status);
            }
        });
    }
}

fn run_encrypt(input: Option<PathBuf>, output: Option<PathBuf>, password: &str) -> Result<()> {
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

    // Wipe sensitive material from memory before returning
    plaintext.zeroize();
    key.zeroize();

    Ok(())
}

fn run_decrypt(input: Option<PathBuf>, output: Option<PathBuf>, password: &str) -> Result<()> {
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
    // Tunable Argon2id params (defaults OK to start; consider raising memory for production)
    let argon = Argon2::default();
    let mut key = [0u8; 32];

    argon
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|_| anyhow!("Key derivation failed"))?;

    Ok(key)
}
