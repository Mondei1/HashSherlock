use std::{
    sync::{Arc, Mutex}
};

use egui::{panel::Side, Button, Color32, ComboBox, DragValue, RichText, TextEdit};
use egui_extras::{Column, TableBuilder};
use num_format::{Locale, ToFormattedString};
use sysinfo::{System, SystemExt, CpuExt};

use crate::{Application, HashAlgorithm, visualizations::table::TableVisualization};

pub enum Visualization {
    Table,
    Graph
}

pub struct HashSherlockUI {
    application: Arc<Mutex<Application>>,
    algorithm: HashAlgorithm,
    cpu_name: String,
    cpu_freq: u64,
    visualization: Visualization
}

impl HashSherlockUI {
    pub fn new(application: Arc<Mutex<Application>>, cpu_name: String, cpu_freq: u64) -> Self {
        Self {
            application,
            algorithm: HashAlgorithm::SHA256,
            cpu_name,
            cpu_freq,
            visualization: Visualization::Table
        }
    }
}

pub fn show(application: Arc<Mutex<Application>>) {
    let mut info = System::new();
    info.refresh_cpu();

    let cpu_name = match info.cpus().get(0) {
        Some(cpu) => {
            cpu.brand().to_string()
        },
        None => {
            String::from("unknown")
        }
    };

    let cpu_freq = match info.cpus().get(0) {
        Some(f) => f.frequency(),
        None => {
            0
        }
    };

    let ui = HashSherlockUI::new(application, cpu_name, cpu_freq);

    let options = eframe::NativeOptions {
        initial_window_size: Some(egui::vec2(1200.0, 740.0)),
        centered: true,
        ..Default::default()
    };

    eframe::run_native("Hash Sherlock", options, Box::new(|_cc| Box::new(ui)));
}

impl eframe::App for HashSherlockUI {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let mut app = self.application.lock().unwrap();

        ctx.set_pixels_per_point(1.0);

        egui::CentralPanel::default().show(ctx, |ui| {

            /*
             * Settings
             */
            egui::SidePanel::left("settings")
            .show_inside(ui, |ui| {
                ui.heading("Hash Sherlock");
                ui.label("This program aims to find certain hashes.");

                ui.separator();

                ui.vertical(|ui| {
                    let _ = ui.label("Hash start: ");

                    ui.horizontal(|ui| {
                        let edit = TextEdit::singleline(&mut app.target_beginning)
                            .desired_width(64.0)
                            .hint_text("If Hash Sherlock finds a hash that begins with this value it will be added to the table on the right.");

                        ui.add(edit);
                    });

                    ui.label("Choose algorithm");
                    ComboBox::from_label("")
                    .selected_text(format!("{}", self.algorithm))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.algorithm, HashAlgorithm::SHA1, "SHA-1 (insecure)");
                        ui.selectable_value(&mut self.algorithm, HashAlgorithm::SHA256, "SHA-256");
                        ui.selectable_value(&mut self.algorithm, HashAlgorithm::SHA384, "SHA-384");
                        ui.selectable_value(&mut self.algorithm, HashAlgorithm::SHA512, "SHA-512");
                        ui.selectable_value(&mut self.algorithm, HashAlgorithm::ED25519, "Ed25519");
                    });

                    ui.label("Nonce length");
                    ui.add(DragValue::new(&mut app.nonce_length).speed(1.0).clamp_range(3..=128));

                    /*let input = ui.text_edit_singleline(&mut String::new())
                        .labelled_by(name_label.id);

                    if edit.ctx.input().keys_down.len() > 0 {
                        println!("Key is down!");
                    }*/

                    ui.add_space(12.0);
                    ui.horizontal(|ui| {
                        if app.is_running() {
                            if app.is_stopping() {
                                ui.add_enabled(false, Button::new("Stopping ..."));
                            } else {
                                if ui.button("Stop").clicked() {
                                    app.stop();
                                }
                            }
                        } else {
                            if ui.button("Run").clicked() {
                                app.start_worker(self.algorithm.clone());
                            }
                        }

                        if ui.button("Clear findings").clicked()  {
                            app.clear_results();
                        }

                        if !app.finished() {
                            ui.spinner();
                        }
                    });

                    ui.separator();

                    if app.is_running() && !app.get_speeds().is_empty() {
                        ui.heading("Speeds");
                        ui.spacing();

                        egui::SidePanel::new(Side::Left, "speeds")
                        .resizable(false)
                        .show_separator_line(false)
                        .show_inside(ui, |ui| {
                            let table = TableBuilder::new(ui)
                            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                            .column(Column::auto().at_most(16.0))
                            .column(Column::auto())
                            .min_scrolled_height(0.0);

                            table.header(20.0, |mut header| {
                                header.col(|ui| {
                                    ui.strong("#");
                                });
                                header.col(|ui| {
                                    ui.strong("H/s");
                                });
                            })
                            .body(|mut body| {
                                let speeds_map = app.get_speeds();
                                let mut speeds: Vec<&usize> = speeds_map.keys().collect();

                                speeds.sort_by(|a, b| a.cmp(b));

                                for thread_id in speeds {
                                    let speed = speeds_map.get(thread_id).unwrap();

                                    // We paint the thread that found the latest hash with a green background color.
                                    let latest_thread = match app.results().last() {
                                        Some(hr) => hr.thread == *thread_id,
                                        None => false
                                    };

                                    body.row(16.0, |mut row| {
                                        row.col(|ui| {
                                            let mut label = RichText::new(thread_id.to_string());
                                            if latest_thread {
                                                label = label.color(Color32::LIGHT_GREEN);
                                            }

                                            ui.label(label);
                                        });
                                        row.col(|ui| {
                                            let mut label = RichText::new(speed.to_formatted_string(&Locale::en));
                                            if latest_thread {
                                                label = label.color(Color32::LIGHT_GREEN);
                                            }

                                            ui.label(label);
                                        });
                                    });
                                }
                            });
                        });

                        ui.vertical(|ui| {
                            ui.label(RichText::new("CPU").strong());
                            ui.label(format!("{}", self.cpu_name));
                        });

                        ui.add_space(16.0);

                        ui.vertical(|ui| {
                            ui.label(RichText::new("Average speed").strong());

                            let average = app.get_speeds().values().into_iter().sum::<u64>() / app.get_speeds().len() as u64;
                            ui.label(format!("{} H/s", average.to_formatted_string(&Locale::en)));
                        });

                        ui.add_space(16.0);

                        ui.vertical(|ui| {
                            ui.label(RichText::new("Total speed").strong());

                            let average = app.get_speeds().values().into_iter().sum::<u64>();
                            ui.label(format!("{} H/s", average.to_formatted_string(&Locale::en)));
                        });
                    }
                });
            });

            // Context menu
            ui.horizontal(|ui| {
                ui.menu_button("Visualization", |ui| {
                    if ui.button("Table (default)").clicked() {

                    }

                    if ui.button("Graph").clicked() {
                        
                    }
                });
            });

            /*
             * Table
             */
            if app.results().is_empty() {
                ui.horizontal_centered(|ui| {
                    ui.vertical_centered(|ui| {
                        ui.add_space(64.0);
                        ui.label(RichText::new("No results yet!").strong().size(24.0));
                        ui.label("Start your search and see your unique hashs appear.");
                        ui.spacing();
                    });
                });
            } else {
                match self.visualization {
                    Visualization::Table => {
                        TableVisualization::new(ui, app)
                            .show();
                    },
                    _ => {
                        ui.label("You got me! This visualization isn't implemented yet.");
                    }
                }
            }
        });
    }
}
