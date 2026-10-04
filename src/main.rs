mod adapters;
mod analyzers;
mod audit;
mod capabilities;
mod cli;
mod doctor;
mod guarded;
mod integrity;
mod json;
mod mcp;
#[cfg(unix)]
mod mcp_runtime;
mod model;
mod paths;
mod platform;
mod policy;
mod project;
mod result;
mod scanner;
mod sensitivity;
mod shell;
mod sink;
mod state;
mod version;

fn main() {
    std::process::exit(cli::run());
}
