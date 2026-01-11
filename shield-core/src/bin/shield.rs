//! Shield CLI - Command-line interface for Shield encryption.
//!
//! # Usage
//!
//! ```bash
//! # Encrypt a file
//! shield encrypt secret.txt -o secret.enc
//!
//! # Decrypt a file
//! shield decrypt secret.enc -o secret.txt
//!
//! # Check password strength
//! shield check "your_password"
//!
//! # Encrypt text directly
//! shield text encrypt "secret message" -p password -s service
//!
//! # Generate a random key
//! shield keygen
//! ```

use std::fs;
use std::io::{self, Write};
use std::process::ExitCode;

use shield_core::password::{check_password, StrengthLevel};
use shield_core::Shield;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_help();
        return ExitCode::SUCCESS;
    }

    match args[1].as_str() {
        "encrypt" => cmd_encrypt(&args[2..]),
        "decrypt" => cmd_decrypt(&args[2..]),
        "check" => cmd_check(&args[2..]),
        "text" => cmd_text(&args[2..]),
        "keygen" => cmd_keygen(&args[2..]),
        "info" => cmd_info(),
        "--help" | "-h" | "help" => {
            print_help();
            ExitCode::SUCCESS
        }
        "--version" | "-V" => {
            println!("shield {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        cmd => {
            eprintln!("Unknown command: {cmd}");
            eprintln!("Run 'shield --help' for usage");
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    println!(
        r#"Shield - EXPTIME-Secure Encryption

USAGE:
    shield <COMMAND> [OPTIONS]

COMMANDS:
    encrypt <file>     Encrypt a file
    decrypt <file>     Decrypt a file
    check <password>   Check password strength
    text <encrypt|decrypt> <data>  Encrypt/decrypt text
    keygen             Generate random key
    info               Show Shield information

OPTIONS:
    -o, --output <file>    Output file
    -p, --password <pass>  Password (prefer prompt for security)
    -s, --service <name>   Service identifier
    -h, --help             Show help
    -V, --version          Show version

EXAMPLES:
    shield encrypt secret.txt -o secret.enc
    shield decrypt secret.enc
    shield check "MyP@ssw0rd123"
    shield text encrypt "hello" -p mypass -s myservice
    shield keygen

For more info: https://github.com/Guard8-ai/Shield"#
    );
}

fn cmd_encrypt(args: &[String]) -> ExitCode {
    let (file, output, password) = match parse_file_args(args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::FAILURE;
        }
    };

    let password = match password.or_else(|| prompt_password("Password: ", true)) {
        Some(p) => p,
        None => {
            eprintln!("Error: Password required");
            return ExitCode::FAILURE;
        }
    };

    // Check password strength
    let strength = check_password(&password);
    if matches!(strength.level, StrengthLevel::Critical | StrengthLevel::Weak) {
        eprintln!(
            "Warning: Weak password ({:.0} bits). {}",
            strength.entropy,
            strength.suggestions.first().unwrap_or(&String::new())
        );
    }

    let output = output.unwrap_or_else(|| format!("{}.enc", file));

    // Use filename as service identifier for deterministic key derivation
    let shield = Shield::new(&password, &file);

    match encrypt_file(&shield, &file, &output) {
        Ok(()) => {
            println!("Encrypted: {file} -> {output}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_decrypt(args: &[String]) -> ExitCode {
    let (file, output, password) = match parse_file_args(args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::FAILURE;
        }
    };

    let password = match password.or_else(|| prompt_password("Password: ", false)) {
        Some(p) => p,
        None => {
            eprintln!("Error: Password required");
            return ExitCode::FAILURE;
        }
    };

    let output = output.unwrap_or_else(|| {
        if file.ends_with(".enc") {
            file[..file.len() - 4].to_string()
        } else {
            format!("{file}.dec")
        }
    });

    // Use original filename as service identifier
    let original_name = if file.ends_with(".enc") {
        &file[..file.len() - 4]
    } else {
        &file
    };

    let shield = Shield::new(&password, original_name);

    match decrypt_file(&shield, &file, &output) {
        Ok(()) => {
            println!("Decrypted: {file} -> {output}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            if e.to_string().contains("authentication") || e.to_string().contains("Authentication")
            {
                eprintln!("Error: Authentication failed - wrong password or corrupted file");
            } else {
                eprintln!("Error: {e}");
            }
            ExitCode::FAILURE
        }
    }
}

fn cmd_check(args: &[String]) -> ExitCode {
    if args.is_empty() {
        eprintln!("Usage: shield check <password>");
        return ExitCode::FAILURE;
    }

    let password = &args[0];
    let result = check_password(password);

    let level_str = match result.level {
        StrengthLevel::Critical => "CRITICAL",
        StrengthLevel::Weak => "WEAK",
        StrengthLevel::Fair => "FAIR",
        StrengthLevel::Strong => "STRONG",
        StrengthLevel::VeryStrong => "VERY STRONG",
    };

    let level_desc = result.level.description();

    println!("Password Strength Analysis");
    println!("==========================");
    println!("Length:      {} characters", result.length);
    println!("Entropy:     {:.1} bits", result.entropy);
    println!("Level:       {level_str} - {level_desc}");
    println!("Crack time:  {}", result.crack_time_display());
    println!();

    if !result.suggestions.is_empty() {
        println!("Suggestions:");
        for suggestion in &result.suggestions {
            println!("  - {suggestion}");
        }
    }

    if result.is_recommended() {
        ExitCode::SUCCESS
    } else if result.is_acceptable() {
        ExitCode::from(1) // Warning
    } else {
        ExitCode::from(2) // Critical
    }
}

fn cmd_text(args: &[String]) -> ExitCode {
    if args.is_empty() {
        eprintln!("Usage: shield text <encrypt|decrypt> <data> -p <password> -s <service>");
        return ExitCode::FAILURE;
    }

    let subcmd = &args[0];
    let mut data: Option<String> = None;
    let mut password: Option<String> = None;
    let mut service: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-p" | "--password" => {
                i += 1;
                password = args.get(i).cloned();
            }
            "-s" | "--service" => {
                i += 1;
                service = args.get(i).cloned();
            }
            _ if data.is_none() => {
                data = Some(args[i].clone());
            }
            _ => {}
        }
        i += 1;
    }

    let data = match data {
        Some(d) => d,
        None => {
            eprintln!("Error: Data required");
            return ExitCode::FAILURE;
        }
    };

    let password = match password.or_else(|| prompt_password("Password: ", subcmd == "encrypt")) {
        Some(p) => p,
        None => {
            eprintln!("Error: Password required");
            return ExitCode::FAILURE;
        }
    };

    let service = service.unwrap_or_else(|| "shield-cli".to_string());

    let shield = Shield::new(&password, &service);

    match subcmd.as_str() {
        "encrypt" => match shield.encrypt(data.as_bytes()) {
            Ok(encrypted) => {
                println!("{}", hex::encode(&encrypted));
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("Error: {e}");
                ExitCode::FAILURE
            }
        },
        "decrypt" => {
            let encrypted = match hex::decode(&data) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error: Invalid hex input - {e}");
                    return ExitCode::FAILURE;
                }
            };
            match shield.decrypt(&encrypted) {
                Ok(decrypted) => {
                    match String::from_utf8(decrypted) {
                        Ok(s) => println!("{s}"),
                        Err(_) => {
                            eprintln!("Warning: Output is not valid UTF-8, showing hex");
                            // Just show we got binary data
                            println!("(binary data decrypted successfully)");
                        }
                    }
                    ExitCode::SUCCESS
                }
                Err(_) => {
                    eprintln!("Error: Decryption failed - wrong password or corrupted data");
                    ExitCode::FAILURE
                }
            }
        }
        _ => {
            eprintln!("Unknown text subcommand: {subcmd}");
            eprintln!("Use: shield text encrypt|decrypt");
            ExitCode::FAILURE
        }
    }
}

fn cmd_keygen(args: &[String]) -> ExitCode {
    let mut length = 32usize;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--length" | "-l" => {
                i += 1;
                if let Some(len_str) = args.get(i) {
                    length = len_str.parse().unwrap_or(32);
                }
            }
            _ => {}
        }
        i += 1;
    }

    let mut key = vec![0u8; length];
    getrandom::getrandom(&mut key).expect("Failed to generate random bytes");

    println!("{}", hex::encode(&key));
    ExitCode::SUCCESS
}

fn cmd_info() -> ExitCode {
    println!("Shield - EXPTIME-Secure Encryption");
    println!("===================================");
    println!("Version:     {}", env!("CARGO_PKG_VERSION"));
    println!("Algorithm:   SHA256-CTR + HMAC-SHA256");
    println!("Key Size:    256 bits");
    println!("KDF:         PBKDF2-SHA256 (100,000 iterations)");
    println!("Security:    2^256 operations to break");
    println!();
    println!("Repository:  https://github.com/Guard8-ai/Shield");
    ExitCode::SUCCESS
}

// Helper functions

fn parse_file_args(args: &[String]) -> Result<(String, Option<String>, Option<String>), String> {
    if args.is_empty() {
        return Err("File path required".to_string());
    }

    let mut file: Option<String> = None;
    let mut output: Option<String> = None;
    let mut password: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-o" | "--output" => {
                i += 1;
                output = args.get(i).cloned();
            }
            "-p" | "--password" => {
                i += 1;
                password = args.get(i).cloned();
            }
            _ if file.is_none() => {
                file = Some(args[i].clone());
            }
            _ => {}
        }
        i += 1;
    }

    match file {
        Some(f) => Ok((f, output, password)),
        None => Err("File path required".to_string()),
    }
}

fn prompt_password(prompt: &str, confirm: bool) -> Option<String> {
    eprint!("{prompt}");
    io::stderr().flush().ok()?;

    let password = rpassword::read_password().ok()?;

    if confirm {
        eprint!("Confirm password: ");
        io::stderr().flush().ok()?;
        let password2 = rpassword::read_password().ok()?;
        if password != password2 {
            eprintln!("Passwords do not match");
            return None;
        }
    }

    Some(password)
}

fn encrypt_file(shield: &Shield, input: &str, output: &str) -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read(input)?;
    let encrypted = shield.encrypt(&data)?;
    fs::write(output, encrypted)?;
    Ok(())
}

fn decrypt_file(shield: &Shield, input: &str, output: &str) -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read(input)?;
    let decrypted = shield.decrypt(&data)?;
    fs::write(output, decrypted)?;
    Ok(())
}
