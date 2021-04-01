extern crate serde_derive;

#[macro_use]
extern crate log;

use std::sync::Arc;

mod dns;
mod gateway;
mod logger;
mod setting;

static VERSION: &str = "v2.0.0";

fn main() {
    let matches = clap::App::new("kungfu")
        .version(VERSION)
        .about(
            "\nFlexible DNS hijacking and proxy tool.\nmore info: http://github.com/yinheli/kungfu",
        )
        .arg(
            clap::Arg::with_name("config")
                .long("config")
                .short("c")
                .value_name("config_file")
                .takes_value(true)
                .default_value("config.yml")
                .help("configuration file"),
        )
        .arg(
            clap::Arg::with_name("debug")
                .long("debug")
                .takes_value(false)
                .help("set log debug level"),
        )
        .arg(
            clap::Arg::with_name("test")
                .long("test")
                .short("t")
                .takes_value(false)
                .help("test configuration"),
        )
        .get_matches();

    logger::init(&matches);
    slogan();

    serve(&matches);
}

fn slogan() {
    info!(
        "kungfu version: {}, {}",
        VERSION, "Across the Great Wall, we can reach every corner in the world."
    )
}

fn serve(matches: &clap::ArgMatches) {
    let config_file = matches.value_of("config").unwrap_or("config.yml");

    let setting = match setting::Setting::load(config_file) {
        Ok(s) => s,
        Err(e) => {
            error!("{:?}", e);
            std::process::exit(1);
        }
    };

    if matches.is_present("test") {
        return;
    }

    let cpu = num_cpus::get();
    debug!("num_cpus: {}", cpu);

    // let rt = tokio::runtime::Builder::new_multi_thread()
    //     .worker_threads(4)
    //     .enable_all()
    //     .thread_stack_size(1024 * 256)
    //     .thread_name("kungfu-worker")
    //     .build()
    //     .expect("runtime build failed");

    let rt = tokio::runtime::Builder::new()
        .threaded_scheduler()
        .enable_all()
        .max_threads(cpu * 8)
        .core_threads(cpu)
        .thread_name("kungfu-worker")
        .thread_stack_size(1024 * 512)
        .build()
        .expect("tokio build failed");

    let rt = Arc::new(rt);
    let bootstrap_runtime = rt.clone();
    let bootstrap = bootstrap_runtime.handle();

    let dns_runtime = rt.clone();

    bootstrap.block_on(async move {
        let gateway = gateway::serve(setting.clone());
        let dns = dns::serve(setting.clone(), dns_runtime);
        let result = tokio::try_join!(gateway, dns);
        if let Err(e) = result {
            println!("{}", e);
        }
    });
}
