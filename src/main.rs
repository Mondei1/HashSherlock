/*
    MIT License

    Copyright (c) 2023 Nicolas Klier

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/


use std::{
    fmt::{Display, Formatter, Result},
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
    time::SystemTime,
};

use chrono::Utc;
use eframe::epaint::ahash::{HashMap, HashMapExt};
use rand::{distributions::Alphanumeric, Rng};
use ring::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY, SHA256, SHA384, SHA512};

mod ui;
mod visualizations;

#[derive(Debug, Clone)]
pub struct HashResult {
    iteration: u64,
    thread: usize,
    hash: String,
    nonce: String,
    time: chrono::DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum HashAlgorithm {
    SHA1,
    SHA256,
    SHA384,
    SHA512,
}

impl Display for HashAlgorithm {
    fn fmt(&self, f: &mut Formatter) -> Result {
        match &self {
            HashAlgorithm::SHA1 => write!(f, "SHA-1"),
            HashAlgorithm::SHA256 => write!(f, "SHA-256"),
            HashAlgorithm::SHA384 => write!(f, "SHA-384"),
            HashAlgorithm::SHA512 => write!(f, "SHA-512"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Application {
    pub target_beginning: String,
    pub nonce_length: usize,

    worker: Vec<Arc<JoinHandle<()>>>,
    hashs: Arc<Mutex<Vec<HashResult>>>,
    speeds: Arc<Mutex<HashMap<usize, u64>>>,
    stopping: Arc<Mutex<bool>>,
}

impl Default for Application {
    fn default() -> Self {
        Self {
            target_beginning: String::from("00000"),
            nonce_length: 16,
            worker: Vec::new(),
            hashs: Arc::new(Mutex::new(Vec::new())),
            speeds: Arc::new(Mutex::new(HashMap::new())),
            stopping: Arc::new(Mutex::new(false)),
        }
    }
}

impl Application {
    pub fn start_worker(&mut self, algorithm: HashAlgorithm) {
        let thread_count = num_cpus::get();
        println!(
            "Start guessing random hashes on {} threads ...",
            thread_count
        );

        for i in 0..thread_count {
            let thread_builder =
                thread::Builder::new().name(format!("Hash Sherlock worker #{}", i));

            // We need to clone a lot of things. But we only copy the Arc (increasing reference coung)
            // and not the actual value.
            let hash_clone = self.hashs.clone();
            let speeds_clone = self.speeds.clone();
            let stopping_clone = self.stopping.clone();
            let nonce_length_clone = self.nonce_length.clone();
            let beginning_clone = self.target_beginning.clone();
            let alg_clone = algorithm.clone();

            match thread_builder.spawn(move || {
                let mut iteration: u64 = 0;
                let mut nonce_iteration: u32 = 0;
                let mut last_speed_check = SystemTime::now();
                let mut last_speed_iteration: u64 = 0;

                let alg = match alg_clone {
                    HashAlgorithm::SHA1 => &SHA1_FOR_LEGACY_USE_ONLY,
                    HashAlgorithm::SHA256 => &SHA256,
                    HashAlgorithm::SHA384 => &SHA384,
                    HashAlgorithm::SHA512 => &SHA512,
                };

                let mut context = Context::new(alg);
                let mut nonce: String = rand::thread_rng()
                    .sample_iter(&Alphanumeric)
                    .take(nonce_length_clone)
                    .map(char::from)
                    .collect();

                loop {
                    if *stopping_clone.lock().unwrap() {
                        break;
                    }

                    // A second passed, lets update our speeds.
                    if last_speed_check.elapsed().unwrap().as_millis() > 1000 {
                        let mut sc = speeds_clone.lock().unwrap();

                        sc.insert(i, iteration - last_speed_iteration);

                        last_speed_check = SystemTime::now();
                        last_speed_iteration = iteration;
                    }

                    iteration += 1;
                    nonce_iteration += 1;

                    // Only switch nonce after 1 million operations because generating a new nonce
                    // for every operation is quite heavy. This gives us ~0,3 MH/s more.
                    if nonce_iteration > 1_000_000 {
                        nonce = rand::thread_rng()
                            .sample_iter(&Alphanumeric)
                            .take(nonce_length_clone)
                            .map(char::from)
                            .collect();

                        nonce_iteration = 0;
                    }

                    let value = format!("{}{}", nonce, nonce_iteration);
                    context.update(value.as_bytes());

                    let digest = context.clone().finish();
                    let raw_result = digest.as_ref();
                    let hash = hex::encode(raw_result);

                    if hash.starts_with(&beginning_clone) {
                        println!("Thread (#{}): Found hash {}", i, hash);
                        hash_clone.lock().unwrap().push(HashResult {
                            iteration,
                            thread: i,
                            hash,
                            nonce: value,
                            time: Utc::now(),
                        })
                    }
                }

                println!("Thread #{} finished", i);
            }) {
                Ok(join) => {
                    println!("Worker thread #{} started", i);
                    self.worker.push(Arc::new(join));
                }
                Err(err) => {
                    println!("Couldn't spawn thread: {}", err);
                }
            }
        }
    }

    pub fn finished(&mut self) -> bool {
        for thread in &self.worker {
            if !thread.is_finished() {
                return false;
            }
        }

        let _ = &self.worker.clear();
        *self.stopping.lock().unwrap() = false;
        self.speeds.lock().unwrap().clear();

        true
    }

    pub fn stop(&mut self) {
        *self.stopping.lock().unwrap() = true;
    }

    pub fn is_stopping(&self) -> bool {
        *self.stopping.lock().unwrap()
    }

    pub fn is_running(&self) -> bool {
        !&self.worker.is_empty()
    }

    pub fn results(&self) -> Vec<HashResult> {
        self.hashs.lock().unwrap().to_vec()
    }

    pub fn clear_results(&mut self) {
        self.hashs.lock().unwrap().clear();
    }

    pub fn get_speeds(&self) -> HashMap<usize, u64> {
        self.speeds.lock().unwrap().to_owned()
    }
}

fn main() {
    let app = Arc::new(Mutex::new(Application::default()));
    let _ = ui::show(app.clone());
}
