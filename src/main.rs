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
}

fn format_duration(dur: Duration) -> String {
    let secs = dur.as_secs();
    let hours = secs / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;
    format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
}

fn main() {
    let args = Args::parse();
    let prefix = args.prefix.to_lowercase();
    let found = Arc::new(AtomicBool::new(false));
    let start_time = Instant::now();

    // Calculate the expected number of tries (roughly)
    let expected_tries = 58f64.powi(prefix.len() as i32);

    (0..num_cpus::get()).into_par_iter().for_each(|thread_id| {
        let local_found = Arc::clone(&found);
        let mut tries: u64 = 0;
        let mut last_log = Instant::now();

        while !local_found.load(Ordering::Relaxed) {
            let mut csprng = OsRng;
            let signing_key = SigningKey::generate(&mut csprng);
            let verifying_key = signing_key.verifying_key();
            let pubkey_bs58 = bs58::encode(verifying_key.as_bytes()).into_string();
            tries += 1;

            if tries % 1_000_000 == 0 {
                let elapsed = start_time.elapsed();
                let speed = (tries as f64) / elapsed.as_secs_f64();
                let remaining_tries = expected_tries - (tries as f64);
                let eta_secs = if speed > 0.0 {
                    remaining_tries / speed
                } else {
                    0.0
                };
                let eta = Duration::from_secs_f64(eta_secs);

                if thread_id == 0 || last_log.elapsed() > Duration::from_secs(10) {
                    println!(
                        "[Thread {}] Tries: {:>10} | Elapsed: {} | Speed: {:>8.2} keys/s | ETA: ~{}",
                        thread_id,
                        tries,
                        format_duration(elapsed),
                        speed,
                        format_duration(eta),
                    );
                    last_log = Instant::now();
                }
            }

            if pubkey_bs58.starts_with(&prefix) {
                if args.force_lowercase && !pubkey_bs58[..prefix.len()].chars().all(|c| c.is_lowercase()) {
                    continue;
                }
            
                local_found.store(true, Ordering::Relaxed);
                let elapsed = start_time.elapsed();
            
                println!("\n🎉 Match found on thread {} after {} tries!", thread_id, tries);
                println!("⏱️  Elapsed time: {}", format_duration(elapsed));
                println!("🔑 Public Key:  {}", pubkey_bs58);
                println!(
                    "🛡️  Private Key: {}",
                    bs58::encode(signing_key.to_keypair_bytes()).into_string()
                );
            }
            
        }
    });
}
