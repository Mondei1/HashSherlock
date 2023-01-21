use std::sync::{MutexGuard};

use egui::{Ui, RichText, Color32, TextStyle};
use egui_extras::{Column, TableBuilder};
use num_format::{Locale, ToFormattedString};

use crate::Application;

/// Default visualization for found hashes. It simply shows all found hashes.
pub struct TableVisualization<'a> {
    ui: &'a mut Ui,
    application: MutexGuard<'a, Application>
}

impl<'a> TableVisualization<'a> {
    pub fn new(ui: &'a mut Ui, application: MutexGuard<'a, Application>) -> Self {
        Self { ui, application }
    }

    pub fn show(&mut self) {
        self.ui.vertical(|ui| {
            // Table that shows found hashs
            ui.vertical(|ui| {
                egui::ScrollArea::horizontal().show(ui, |ui| {
                    let table = TableBuilder::new(ui)
                        .striped(true)
                        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                        .column(Column::initial(16.0))    // Thread
                        .column(Column::auto())                 // Iteration
                        .column(Column::auto())                 // Time
                        .column(Column::initial(256.0))   // Hash
                        .column(Column::remainder())   // Nonce
                        .min_scrolled_height(0.0)
                        .stick_to_bottom(true);

                    table.header(20.0, |mut header| {
                        header.col(|ui| {
                            ui.strong("# Thread");
                        });
                        header.col(|ui| {
                            ui.strong("# Iteration");
                        });
                        header.col(|ui| {
                            ui.strong("Time");
                        });
                        header.col(|ui| {
                            ui.strong("Hash");
                        });
                        header.col(|ui| {
                            ui.strong("Nonce");
                        });
                    })
                    .body(|mut body| {
                        for result in self.application.results() {
                            body.row(16.0, |mut row| {
                                row.col(|ui| { ui.label(result.thread.to_string()); });
                                row.col(|ui| { ui.label(result.iteration.to_formatted_string(&Locale::en)); });
                                row.col(|ui| { ui.label(result.time.format("%H:%M:%S%.3f").to_string()); });
                                row.col(|ui| {
                                    let white_hash = RichText::new(result.hash)
                                        .color(Color32::WHITE)
                                        .text_style(TextStyle::Monospace);

                                    let _= ui.label(white_hash);
                                });

                                row.col(|ui| {
                                    let monospace_nonce = RichText::new(result.nonce)
                                        .text_style(TextStyle::Monospace);

                                    ui.label(monospace_nonce);
                                });
                            });
                        }
                    });
                });
            });
        });
    }
}