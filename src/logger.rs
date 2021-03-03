use chrono::Local;
use env_logger;
use std::io::Write;

pub fn init(matches: &clap::ArgMatches) {
    let mut level = log::LevelFilter::Info;

    if matches.is_present("debug") {
        level = log::LevelFilter::Debug;
    }

    env_logger::Builder::new()
        .format(|buf, record| {
            writeln!(
                buf,
                "{} [{:>5}] {}",
                Local::now().format("%Y-%m-%dT%H:%M:%S%.3f"),
                record.level(),
                record.args()
            )
        })
        .filter_module("kungfu", level)
        .init();
}
