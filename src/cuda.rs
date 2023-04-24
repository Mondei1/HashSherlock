use chrono::Utc;
use cust::{prelude::*};
use rand::{distributions::Alphanumeric, Rng, rngs::SmallRng, SeedableRng};
use rustc_serialize::hex::ToHex;
use std::{error::Error, time::{Instant, Duration}};

use crate::IterationResult;

pub struct Cuda {
    ctx: Context,
    module: Module,
    block_size: u32
}

struct BenchmarkStage {
    batch_size: usize,
    nonce_length: usize
}

struct BenchmarkResult<'a> {
    benchmark: &'a BenchmarkStage,
    time: Duration
}

/// How many numbers to generate and add together.
const SHA256_BLOCK_SIZE: usize = 32;

static PTX: &str = include_str!("kernel/sha256.ptx");

impl Cuda {
    pub fn new() -> Result<Self, Box<dyn Error>> {
        println!("[CUDA] Initializing CUDA compute ...");

        // Initialize CUDA, this will pick the first available device and will make a CUDA context from it.
        // We don't need the context for anything but it must be kept alive.
        let ctx = cust::quick_init()?;

        // Make the CUDA module, modules just house the GPU code for the kernels we created.
        // they can be made from PTX code, cubins, or fatbins.
        let module = Module::from_ptx(PTX, &[])?;

        // retrieve the add kernel from the module so we can calculate the right launch config.
        let func = module.get_function("kernel_sha256_hash")?;

        // use the CUDA occupancy API to find an optimal launch configuration for the grid and block size.
        // This will try to maximize how much of the GPU is used by finding the best launch configuration for the
        // current CUDA device/architecture.
        let (_, block_size) = func.suggested_launch_configuration(0, 0.into())?;

        Ok(Self {
            ctx,
            module,
            block_size
        })
    }

    fn random_nonce(&self, len: usize) -> String {
        // We use the SmallRng instead of the ThreadRng because the GPU is faster than we are with generating
        // random data for it. Now the CPU is the bottleneck -_-
        // This way we are ~70 % faster compared with the ThreadRng.
        SmallRng::from_entropy()
            .sample_iter(&Alphanumeric)
            .take(len)
            .map(char::from)
            .collect::<String>()
    }

    pub fn benchmark(&self) {
        let stages: Vec<BenchmarkStage> = vec![
            BenchmarkStage { batch_size: 1_000, nonce_length: 8 },
            BenchmarkStage { batch_size: 10_000, nonce_length: 8 },
            BenchmarkStage { batch_size: 10_000, nonce_length: 8 },
            BenchmarkStage { batch_size: 100_000, nonce_length: 8 },
            BenchmarkStage { batch_size: 1_000_000, nonce_length: 8 },
            BenchmarkStage { batch_size: 10_000_000, nonce_length: 8 },
            BenchmarkStage { batch_size: 1_000, nonce_length: 12 },
            BenchmarkStage { batch_size: 10_000, nonce_length: 12 },
            BenchmarkStage { batch_size: 10_000, nonce_length: 12 },
            BenchmarkStage { batch_size: 100_000, nonce_length: 12 },
            BenchmarkStage { batch_size: 1_000_000, nonce_length: 12 },
            BenchmarkStage { batch_size: 10_000_000, nonce_length: 12 },
            BenchmarkStage { batch_size: 1_000, nonce_length: 18 },
            BenchmarkStage { batch_size: 10_000, nonce_length: 18 },
            BenchmarkStage { batch_size: 10_000, nonce_length: 18 },
            BenchmarkStage { batch_size: 100_000, nonce_length: 18 },
            BenchmarkStage { batch_size: 1_000_000, nonce_length: 18 },
            BenchmarkStage { batch_size: 10_000_000, nonce_length: 18 },
        ];

        let mut results: Vec<BenchmarkResult> = vec![];

        for stage in stages.iter() {
            let now = Instant::now();
            self.run(stage.batch_size, stage.nonce_length, "");

            println!("[CUDA] Run benchmark | Batch size: {}; Nonce length: {}", stage.batch_size, stage.nonce_length);
            results.push(BenchmarkResult { benchmark: stage, time: now.elapsed() })
        }

        results.sort_by(|a, b| a.time.as_nanos().partial_cmp(&b.time.as_nanos()).unwrap());

        println!("\nBenchmark results ordered by ascending time:");
        for (i, result) in results.iter().enumerate() {
            println!("#{} ({}ms)\t: Batch size: {}\t| Nonce length: {}", i + 1, result.time.as_millis(), result.benchmark.batch_size, result.benchmark.nonce_length);
        }

    }

    /// Run a batch of hash operations on the GPU.
    /// 
    /// **Notice:** The returned iteration inside an IterationResult represents the iteration within this run. Not globally.
    pub fn run(&self, batch_size: usize, nonce_length: usize, target_beginning: &str) -> Result<Vec<IterationResult>, Box<dyn Error>> {
        let mut now = Instant::now();
        let string_input = &self.random_nonce(nonce_length * batch_size);
        println!("[CUDA] Random generation took {}ms", now.elapsed().as_millis());

        let input = string_input.as_bytes();

        // allocate the GPU memory needed to house our numbers and copy them over.
        let input_gpu = input.as_dbuf()?;

        // allocate our output buffer. You could also use DeviceBuffer::uninitialized() to avoid the
        // cost of the copy, but you need to be careful not to read from the buffer.
        let mut out = vec![0u8; batch_size * SHA256_BLOCK_SIZE];
        let out_buf = out.as_slice().as_dbuf()?;

        let grid_size: u32 = (batch_size as u32 + self.block_size - 1) / self.block_size;

        let func = self.module.get_function("kernel_sha256_hash")?;

        // make a CUDA stream to issue calls to. You can think of this as an OS thread but for dispatching
        // GPU calls.
        let stream = Stream::new(StreamFlags::NON_BLOCKING, None)?;

        // Actually launch the GPU kernel. This will queue up the launch on the stream, it will
        // not block the thread until the kernel is finished.
        now = Instant::now();
        unsafe {
            launch!(
                // slices are passed as two parameters, the pointer and the length.
                func<<<grid_size, self.block_size, 0, stream>>>(
                    input_gpu.as_device_ptr(),
                    nonce_length,
                    out_buf.as_device_ptr(),
                    batch_size
                )
            )?;
        }

        stream.synchronize()?;
        println!("[CUDA] Hashing took {:?}ms", now.elapsed().as_millis());

        // copy back the data from the GPU.
        out_buf.copy_to(&mut out)?;

        let mut result: Vec<IterationResult> = vec![];

        // We will only fill the result array if the there is a target beginning set. Or else we would flut the system with
        // millions of useless hashes.
        if !target_beginning.is_empty() {
            for i in 0..batch_size {
                let mut cuda_output = [0u8; SHA256_BLOCK_SIZE];
                let cuda_input = input.get((i * nonce_length)..(i * nonce_length) + nonce_length).unwrap().to_vec();
    
                cuda_output
                    .copy_from_slice(&out[(i * SHA256_BLOCK_SIZE)..(i * SHA256_BLOCK_SIZE) + 32]);
    
                let hex = cuda_output.to_hex();
    
                if hex.starts_with(&target_beginning) {
                    result.push(IterationResult {
                        iteration: i as u64,
                        thread: 0,
                        value: hex.clone(),
                        nonce: std::str::from_utf8(&cuda_input).unwrap().to_string(),
                        time: Utc::now(),
                        private_key: None
                    });

                    // println!("[CUDA] ({}) {}: {}", i, std::str::from_utf8(&cuda_input).unwrap(), hex);
                }
            }
        }        

        Ok(result)
    }
}
