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
    sync::{Arc, Mutex, RwLock},
    thread::{self, JoinHandle},
    time::SystemTime,
};

use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use cuda::Cuda;
use ed25519_dalek::PublicKey;
use eframe::epaint::ahash::{HashMap, HashMapExt};
use rand::{distributions::Alphanumeric, Rng, RngCore};
use ring::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY, SHA256, SHA384, SHA512};

mod cuda;
mod ui;
mod visualizations;

#[derive(Debug, Clone)]
pub struct IterationResult {
    iteration: u64,
    thread: usize,

    /// This may be a hash or a public key
    value: String,
    nonce: String,
    time: chrono::DateTime<Utc>,

    /// Private/Public key exclusive
    private_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum HashAlgorithm {
    SHA1,
    SHA256,
    SHA384,
    SHA512,
    ED25519,
}

impl Display for HashAlgorithm {
    fn fmt(&self, f: &mut Formatter) -> Result {
        match &self {
            HashAlgorithm::SHA1 => write!(f, "SHA-1"),
            HashAlgorithm::SHA256 => write!(f, "SHA-256"),
            HashAlgorithm::SHA384 => write!(f, "SHA-384"),
            HashAlgorithm::SHA512 => write!(f, "SHA-512"),
            HashAlgorithm::ED25519 => write!(f, "Ed25519"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Device {
    CPU,
    GPU,
}

impl Display for Device {
    fn fmt(&self, f: &mut Formatter) -> Result {
        match &self {
            Device::CPU => write!(f, "CPU"),
            Device::GPU => write!(f, "GPU"),
        }
    }
}

#[derive(Debug)]
pub struct Task {
    pub worker: Vec<Arc<JoinHandle<()>>>,
    pub hashs: Arc<Mutex<Vec<IterationResult>>>,
    pub speeds: Arc<Mutex<HashMap<usize, u64>>>,
    pub stopping: Arc<RwLock<bool>>,
    pub current_algorithm: Option<HashAlgorithm>,
}

#[derive(Debug)]
pub struct Application {
    pub target_beginning: String,
    pub nonce_length: usize,
    pub task: Task,
}

impl Default for Application {
    fn default() -> Self {
        Self {
            target_beginning: String::from("00000"),
            nonce_length: 16,

            task: Task {
                worker: Vec::new(),
                hashs: Arc::new(Mutex::new(Vec::new())),
                speeds: Arc::new(Mutex::new(HashMap::new())),
                stopping: Arc::new(RwLock::new(false)),
                current_algorithm: None,
            },
        }
    }
}

impl Application {
    pub fn start_worker(&mut self, algorithm: HashAlgorithm, device: Device) {
        match (device) {
            Device::CPU => {
                let thread_count = num_cpus::get();
                println!(
                    "Start guessing random hashes on {} threads ...",
                    thread_count
                );

                self.task.current_algorithm = Some(algorithm.clone());

                for i in 0..thread_count {
                    let thread_builder =
                        thread::Builder::new().name(format!("Hash Sherlock worker #{}", i));

                    // We need to clone a lot of things. But we only copy the Arc (increasing reference coung)
                    // and not the actual value.
                    let hash_clone = self.task.hashs.clone();
                    let speeds_clone = self.task.speeds.clone();
                    let stopping_clone = self.task.stopping.clone();
                    let nonce_length_clone = self.nonce_length.clone();
                    let beginning_clone = self.target_beginning.clone();
                    let alg_clone = algorithm.clone();

                    match thread_builder.spawn(move || {
                        let mut iteration: u64 = 0;
                        let mut nonce_iteration: u32 = 0;
                        let mut last_speed_check = SystemTime::now();
                        let mut last_speed_iteration: u64 = 0;

                        let mut nonce: String = rand::thread_rng()
                            .sample_iter(&Alphanumeric)
                            .take(nonce_length_clone)
                            .map(char::from)
                            .collect();

                        let mut rng = rand::thread_rng();

                        loop {
                            if *stopping_clone.read().unwrap() {
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

                            let value = format!("{}{}", nonce, nonce_iteration);
                            let hash: String;
                            let mut private_key: Option<String> = None;

                            if alg_clone == HashAlgorithm::ED25519 {
                                let mut bytes = [0u8; 32];
                                rng.fill_bytes(&mut bytes);

                                let secret = ed25519_dalek::SecretKey::from_bytes(&bytes)
                                    .expect("Invalid length");
                                let public: PublicKey = (&secret).into();

                                hash = general_purpose::STANDARD.encode(public.as_bytes());
                                private_key =
                                    Some(general_purpose::STANDARD.encode(secret.as_bytes()));
                            } else {
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

                                let alg = match alg_clone {
                                    HashAlgorithm::SHA1 => &SHA1_FOR_LEGACY_USE_ONLY,
                                    HashAlgorithm::SHA256 => &SHA256,
                                    HashAlgorithm::SHA384 => &SHA384,
                                    HashAlgorithm::SHA512 => &SHA512,
                                    _ => {
                                        return;
                                    }
                                };

                                let mut context = Context::new(alg);

                                context.update(value.as_bytes());

                                let digest = context.clone().finish();
                                let raw_result = digest.as_ref();
                                hash = hex::encode(raw_result);
                            }

                            if hash.starts_with(&beginning_clone) {
                                println!("Thread (#{}): Found hash {}", i, hash);
                                hash_clone.lock().unwrap().push(IterationResult {
                                    iteration,
                                    thread: i,
                                    value: hash,
                                    nonce: value,
                                    time: Utc::now(),
                                    private_key,
                                })
                            }
                        }
                    }) {
                        Ok(join) => {
                            println!("Worker thread #{} started", i);
                            self.task.worker.push(Arc::new(join));
                        }
                        Err(err) => {
                            println!("Couldn't spawn thread: {}", err);
                        }
                    }
                }
            }
            Device::GPU => {
                let job = Cuda::new().run_job(10_000_000, 12);

                match job {
                    Ok(_) => {},
                    Err(err) => {
                        println!("CUDA job failed: {}", err);
                    }
                }
            }
        }
    }

    pub fn finished(&mut self) -> bool {
        for thread in &self.task.worker {
            if !thread.is_finished() {
                return false;
            }
        }

        let _ = &self.task.worker.clear();
        *self.task.stopping.write().unwrap() = false;
        self.task.speeds.lock().unwrap().clear();

        true
    }

    pub fn stop(&mut self) {
        *self.task.stopping.write().unwrap() = true;
    }

    pub fn is_stopping(&self) -> bool {
        *self.task.stopping.read().unwrap()
    }

    pub fn is_running(&self) -> bool {
        !&self.task.worker.is_empty()
    }

    pub fn results(&self) -> Vec<IterationResult> {
        self.task.hashs.lock().unwrap().to_vec()
    }

    pub fn clear_results(&mut self) {
        self.task.hashs.lock().unwrap().clear();
    }

    pub fn get_speeds(&self) -> HashMap<usize, u64> {
        self.task.speeds.lock().unwrap().to_owned()
    }
}

fn main() {
    let app = Arc::new(Mutex::new(Application::default()));
    //init_opencl();

    let _ = ui::show(app.clone());
}
