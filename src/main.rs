mod adapters;
mod analyzers;
mod audit;
mod cli;
mod doctor;
mod integrity;
mod json;
mod model;
mod paths;
mod platform;
mod policy;
mod project;
mod shell;
mod version;

fn main() {
    std::process::exit(cli::run());
}
