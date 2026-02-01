//! Build script for the dxauth0 crate.
//!
//! This script loads environment variables at compile time, making them available
//! to the `option_env!()` macro in the source code.
//!
//! Priority order:
//! 1. Environment variables already set (e.g., from CI/CD, system env)
//! 2. Variables from `.env` file (if it exists)
//! 3. Variables from `.env.example` file (fallback for CI builds)

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    // Tell Cargo to rerun this build script if .env or .env.example changes
    println!("cargo:rerun-if-changed=../.env");
    println!("cargo:rerun-if-changed=../.env.example");

    // Get the workspace root directory (parent of dxauth0/)
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let workspace_root = PathBuf::from(&manifest_dir).parent().unwrap().to_path_buf();
    let env_file = workspace_root.join(".env");
    let env_example_file = workspace_root.join(".env.example");

    // Count how many variables are already set in the environment
    let required_vars = ["AUTH0_CLIENT_ID", "AUTH0_DOMAIN", "AUTH0_AUDIENCE"];
    let env_vars_set = required_vars
        .iter()
        .filter(|&var| env::var(var).is_ok())
        .count();

    // Determine which env file to load
    let (file_to_load, file_description) = if env_file.exists() {
        (Some(env_file), ".env")
    } else if env_vars_set == 0 && env_example_file.exists() {
        (Some(env_example_file), ".env.example (fallback)")
    } else {
        (None, "")
    };

    // Load the env file if one was found
    if let Some(file_path) = file_to_load {
        println!(
            "cargo:warning=Found {} file, loading configuration (environment variables take priority)",
            file_description
        );

        // Read and parse env file
        let contents = fs::read_to_string(&file_path).expect("Failed to read env file");

        for line in contents.lines() {
            // Skip empty lines and comments
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse KEY=VALUE
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim();

                // Only set if not already set in environment
                if env::var(key).is_err() {
                    println!("cargo:rustc-env={}={}", key, value);
                }
            }
        }
    } else if env_vars_set > 0 {
        println!(
            "cargo:warning=Using Auth0 configuration from environment variables ({}/{} set)",
            env_vars_set,
            required_vars.len()
        );
    } else {
        println!(
            "cargo:warning=No .env or .env.example file found and no environment variables set"
        );
        println!("cargo:warning=Set AUTH0_* environment variables or create a .env file");
    }
}
