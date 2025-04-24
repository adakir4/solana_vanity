use std::fs::{OpenOptions, File};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bs58;
use clap::Parser;
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use rayon::prelude::*;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Base58 prefix to match
    prefix: String,

    #[arg(long)]
    force_uppercase: bool,

    /// Force match only if the prefix in the public key is lowercase
    #[arg(long)]
    force_lowercase: bool,
}

fn format_duration(dur: Duration) -> String {
    let secs = dur.as_secs();
    let hours = secs / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;
    format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
}

fn append_log(file: &mut File, message: &str) {
    writeln!(file, "{}", message).unwrap();
}

fn main() {
    let args = Args::parse();
    let prefix = args.prefix.to_lowercase();
    let found = Arc::new(AtomicBool::new(false));
    let start_time = Instant::now();

    let log_file = Arc::new(
        OpenOptions::new()
            .create(true)
            .append(true)
            .open("log.txt")
            .expect("Unable to open log.txt"),
    );

    let key_file = Arc::new(
        OpenOptions::new()
            .create(true)
            .append(true)
            .open("keys.txt")
            .expect("Unable to open keys.txt"),
    );

    (0..num_cpus::get()).into_par_iter().for_each(|thread_id| {
        let local_found = Arc::clone(&found);
        let mut tries: u64 = 0;
        let mut last_log = Instant::now();

        let mut log_file = log_file.try_clone().unwrap();
        let mut key_file = key_file.try_clone().unwrap();

        while !local_found.load(Ordering::Relaxed) {
            let mut csprng = OsRng;
            let signing_key = SigningKey::generate(&mut csprng);
            let verifying_key = signing_key.verifying_key();
            let pubkey_bs58 = bs58::encode(verifying_key.as_bytes()).into_string();
            tries += 1;

            if tries % 1_000_000 == 0 {
                let elapsed = start_time.elapsed();
                let speed = (tries as f64) / elapsed.as_secs_f64();

                if thread_id == 0 || last_log.elapsed() > Duration::from_secs(10) {
                    let log_line = format!(
                        "[Thread {}] Tries: {:>10} | Elapsed: {} | Speed: {:>8.2} keys/s",
                        thread_id,
                        tries,
                        format_duration(elapsed),
                        speed                   
 );
                    println!("{}", log_line);
                    append_log(&mut log_file, &log_line);
                    last_log = Instant::now();
                }
            }

            if pubkey_bs58.starts_with(&prefix) {
                let segment = &pubkey_bs58[..prefix.len()];

                if args.force_lowercase && !segment.chars().all(|c| c.is_lowercase()) {
                    continue;
                }
                if args.force_uppercase && !segment.chars().all(|c| c.is_uppercase()) {
                    continue;
                }
                
                local_found.store(true, Ordering::Relaxed);
                let elapsed = start_time.elapsed();

                let result = format!(
                    "\n🎉 Match found on thread {} after {} tries!\n⏱️  Elapsed time: {}\n🔑 Public Key:  {}\n🛡️  Private Key: {}\n",
                    thread_id,
                    tries,
                    format_duration(elapsed),
                    pubkey_bs58,
                    bs58::encode(signing_key.to_keypair_bytes()).into_string()
                );

                println!("{}", result);
                append_log(&mut log_file, &result);
                append_log(&mut key_file, &result);
            }
        }
    });
}
