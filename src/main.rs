use filter_merge::{merge, serve, Config, VERSION};
use std::path::Path;

fn run_merge(config: &str, output: &str, adaptive: bool) -> Result<(), String> {
    let mut config = Config::load(Path::new(config))?;
    // Preview the adaptive list without switching the served one.
    if adaptive {
        if config.state_dir.is_none() {
            return Err("--adaptive requires state_dir".into());
        }
        config.adaptive = true;
    }
    let stats = merge(&config, Path::new(output))?;
    println!(
        "input_bytes={} rules={} output_bytes={}",
        stats.input_bytes, stats.rules, stats.output_bytes
    );
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let result = match args.as_slice() {
        [_, flag] if flag == "--version" => {
            println!("{VERSION}");
            Ok(())
        }
        [_, command, config] if command == "serve" => {
            Config::load(Path::new(config)).and_then(serve)
        }
        [_, command, config, output] if command == "merge" => run_merge(config, output, false),
        [_, command, config, output, flag] if command == "merge" && flag == "--adaptive" => {
            run_merge(config, output, true)
        }
        _ => Err(
            "usage: filter-merge serve CONFIG | merge CONFIG OUTPUT [--adaptive] | --version"
                .into(),
        ),
    };
    if let Err(error) = result {
        eprintln!("filter-merge: {error}");
        std::process::exit(1);
    }
}
