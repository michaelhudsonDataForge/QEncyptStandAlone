use anyhow::anyhow;
use eframe::{NativeOptions, egui};
use rust_enc_ui::{run_decrypt, run_encrypt};
use std::path::PathBuf;
use zeroize::Zeroize;

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
    password: String,
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
            ui.label("Password (never stored):");
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

                // best-effort wipe
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
