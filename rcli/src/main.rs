use anyhow::Result;
use rc4::Rc4;
use std::{
    fs::File,
    io::{Read, Seek, Write},
};

use clap::Parser;

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, required = true, value_name = "FILE_NAME")]
    file: String,

    // Key
    #[clap(
        short,
        long,
        required = true,
        value_name = "HEX_BYTES",
        min_values = 5,
        max_values = 256
    )]
    key: Vec<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let key_bytes = args
        .key
        .iter()
        .map(|s| s.trim_start_matches("0x"))
        .map(|s| u8::from_str_radix(s, 16).expect("Invalid key hex byte!"))
        .collect::<Vec<u8>>();

    let mut file = File::options()
        .read(true)
        .write(true)
        .open(&args.file)
        .map_err(|e| anyhow::anyhow!("Could not open file: {}, {}", args.file, e))?;

    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;

    // Encrypt/decrypt
    Rc4::apply_keystream_static(&key_bytes, &mut contents);

    // Overwrite file with results
    file.rewind()?;
    file.write_all(&contents)
        .map_err(|e| anyhow::anyhow!("Could not write to file: {}, {}", args.file, e))?;

    println!("Processed {}", args.file);

    Ok(())
}
