//! Launch with one protected JSON configuration path; diagnostics contain static codes only.
#[cfg(unix)]
#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(unix)]
async fn run() -> Result<(), symbiotic_egress::EgressError> {
    use symbiotic_credential_process::{
        CredentialProcess, ProcessConfig, secrets::SecretSource, server,
    };
    use symbiotic_egress::EgressError;
    // This executable owns its process, so disabling core dumps precedes all secret reads.
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit reads the initialized rlimit and retains no pointer.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0 {
        return Err(EgressError::StateUnavailable);
    }
    let mut args = std::env::args_os().skip(1);
    let path = args.next().ok_or(EgressError::InvalidRequest)?;
    if args.next().is_some() {
        return Err(EgressError::InvalidRequest);
    }
    let bytes = SecretSource::OwnerOnlyFile { path: path.into() }.load(1024 * 1024)?;
    let config: ProcessConfig =
        serde_json::from_slice(&bytes).map_err(|_| EgressError::InvalidRequest)?;
    let process = CredentialProcess::open(config)?;
    let listener = server::bind(&process)?;
    server::serve(process, listener).await
}

#[cfg(not(unix))]
fn main() {
    eprintln!("credential process requires Unix sockets and owner-only filesystem protection");
    std::process::exit(1);
}
