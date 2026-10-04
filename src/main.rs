mod adapters;
mod analyzers;
mod audit;
mod capabilities;
mod cli;
mod doctor;
mod integrity;
mod json;
mod model;
mod paths;
mod platform;
mod policy;
mod project;
mod sensitivity;
mod shell;
mod sink;
mod state;
mod version;

fn main() {
    std::process::exit(cli::run());
}
