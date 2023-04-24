# Hash Sherlock
Search for hashes that match your criteria.

![Screenshot of HashSherlock](https://raw.githubusercontent.com/Mondei1/HashSherlock/master/img/showcase.png)

## Important
This project is small and is just my playground to explore Rust, `egui` and multithreading. As for now I cannot think of any practical reason for this program but does everything need a purpose?

## What does it do?
Hash Sherlock utilizes all your available cores, generates some unique value (called nonce) and then hashes it with an algorithm of your choice (see below). If the random hash matches your criteria, like six leading zeros at the beginning, then the hash is considered "found".

## Supported search criteria
- Beginning of the hash (like `00000` at the start is considered "found")

## Is it fast?
Depends on your hardware. Hash Sherlock will utilize all available cores. So your CPU will be used as much as possible. If you own a NVIDIA GPU (only tested on a 3070 Ti) you may be able to utilize the CUDA backend.

My **AMD Ryzen 9 5900X** with 12 physical cores and 24 logical cores with a clock speed of 4.8 GHz is able to perform **27,0 MH/s** (27,000,000 H/s). While this sounds fast, it's not. A **NVIDIA GeForce RTX 3090** may reach **2,864 MH/s** (for SHA-512: [source](https://openbenchmarking.org/test/pts/hashcat-1.0.0))

## Future plans
- [x] Support hashing on GPU (using CUDA)
- [ ] Other crypto operations as finding keypairs where the public key starts with something interesting.

*more coming soon*