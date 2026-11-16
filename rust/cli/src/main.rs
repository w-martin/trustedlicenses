use std::ffi::OsString;

fn main() {
    let args: Vec<OsString> = std::env::args_os().collect();
    let mut context = trustedlicenses_cli::Context::from_process();
    let code = trustedlicenses_cli::run(&args, &mut context);
    std::process::exit(code);
}
