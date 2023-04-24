use cust::prelude::*;
use rand::{distributions::Alphanumeric, Rng};
use rustc_serialize::hex::ToHex;
use std::{error::Error, time::Instant};

pub struct Cuda {}

/// How many numbers to generate and add together.
const SHA256_BLOCK_SIZE: usize = 32;

static PTX: &str = include_str!("kernel/sha256.ptx");

impl Cuda {
    pub fn new() -> Self {
        Self {}
    }

    fn random_nonce(&self, len: usize) -> String {
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(len)
            .map(char::from)
            .collect::<String>()
    }

    pub fn run_job(&self, batch_size: usize, nonce_length: usize) -> Result<(), Box<dyn Error>> {
        println!("[CUDA] Initializing CUDA compute ...");

        let mut now = Instant::now();
        let string_input = &self.random_nonce(nonce_length * batch_size);
        println!("[CUDA] Random generation took {}ms", now.elapsed().as_millis());
        let input = string_input.as_bytes();

        // initialize CUDA, this will pick the first available device and will
        // make a CUDA context from it.
        // We don't need the context for anything but it must be kept alive.
        let _ctx = cust::quick_init()?;

        // Make the CUDA module, modules just house the GPU code for the kernels we created.
        // they can be made from PTX code, cubins, or fatbins.
        let module = Module::from_ptx(PTX, &[])?;

        // make a CUDA stream to issue calls to. You can think of this as an OS thread but for dispatching
        // GPU calls.
        let stream = Stream::new(StreamFlags::NON_BLOCKING, None)?;

        // allocate the GPU memory needed to house our numbers and copy them over.
        let input_gpu = input.as_dbuf()?;

        // allocate our output buffer. You could also use DeviceBuffer::uninitialized() to avoid the
        // cost of the copy, but you need to be careful not to read from the buffer.
        let mut out = vec![0u8; batch_size * SHA256_BLOCK_SIZE];
        let out_buf = out.as_slice().as_dbuf()?;

        // retrieve the add kernel from the module so we can calculate the right launch config.
        let func = module.get_function("kernel_sha256_hash")?;

        // use the CUDA occupancy API to find an optimal launch configuration for the grid and block size.
        // This will try to maximize how much of the GPU is used by finding the best launch configuration for the
        // current CUDA device/architecture.
        let (_, block_size) = func.suggested_launch_configuration(0, 0.into())?;

        let grid_size = (batch_size as u32 + block_size - 1) / block_size;

        println!(
            "[CUDA] Using {} blocks and {} threads per block",
            grid_size, block_size
        );

        // Actually launch the GPU kernel. This will queue up the launch on the stream, it will
        // not block the thread until the kernel is finished.
        now = Instant::now();
        unsafe {
            launch!(
                // slices are passed as two parameters, the pointer and the length.
                func<<<grid_size, block_size, 0, stream>>>(
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

        /*for i in 0..batch_size {
            let mut cuda_output = [0u8; SHA256_BLOCK_SIZE];
            let cuda_input = input.get((i * nonce_length)..(i * nonce_length) + nonce_length).unwrap().to_vec();

            cuda_output
                .copy_from_slice(&out[(i * SHA256_BLOCK_SIZE)..(i * SHA256_BLOCK_SIZE) + 32]);

            let hex = cuda_output.to_hex();

            println!("[CUDA] ({}) {}: {}", i, std::str::from_utf8(&cuda_input).unwrap(), hex);
        }*/

        Ok(())
    }
}
