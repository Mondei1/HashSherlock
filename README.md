# Hash Sherlock
Search for hashes that match your criteria.

![Screenshot of HashSherlock](https://raw.githubusercontent.com/Mondei1/HashSherlock/main/img/showcase.png)

## Important
This project is small and is just my playground to explore Rust, `egui` and multithreading.

## What does it do?
Hash Sherlock utilizes all your available cores, generates some unique value (called nonce) and then hashes it with an algorithm of your choice (see below). If the random hash matches your criteria, like six leading zeros at the beginning, then the hash is considered "found".

## Supported search criteria
- Beginning of the hash (like `00000` at the start is considered "found")

*more coming soon*