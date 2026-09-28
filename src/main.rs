use filter_merge::{merge, serve, Config, VERSION};
use std::path::Path;
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
        [_, command, config, output] if command == "merge" => Config::load(Path::new(config))
            .and_then(|config| {
                merge(&config, Path::new(output)).map(|stats| {
                    println!(
                        "input_bytes={} rules={} output_bytes={}",
                        stats.input_bytes, stats.rules, stats.output_bytes
                    );
                })
            }),
        _ => Err("usage: filter-merge serve CONFIG | merge CONFIG OUTPUT | --version".into()),
    };
    if let Err(error) = result {
        eprintln!("filter-merge: {error}");
        std::process::exit(1);
    }
}
