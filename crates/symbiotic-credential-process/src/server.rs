//! Owner-only Unix-socket transport. Request handling never prints a request/body.
use crate::CredentialProcess;
use std::{os::unix::fs::PermissionsExt, sync::Arc, time::Duration};
use symbiotic_egress::{
    EgressError, PROTOCOL_VERSION, Request, Response,
    socket::{read_frame, write_frame},
};
use tokio::{net::UnixListener, sync::Semaphore};

/// Bind without replacing an existing socket. Remove a stale socket explicitly after
/// proving its prior process is stopped; never unlink another process's listener.
pub fn bind(process: &CredentialProcess) -> Result<UnixListener, EgressError> {
    let path = &process.config().socket_path;
    let parent = path.parent().ok_or(EgressError::InvalidRequest)?;
    symbiotic_ai_runtime::model::private_fs::check_private_dir(parent)
        .map_err(|_| EgressError::StateUnavailable)?;
    let listener = UnixListener::bind(path).map_err(|_| EgressError::StateUnavailable)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|_| EgressError::StateUnavailable)?;
    Ok(listener)
}

/// Serve one framed exchange per same-user connection. Dropping the client does not
/// cancel a dispatched provider call; the process owns completion and accounting.
pub async fn serve(process: CredentialProcess, listener: UnixListener) -> Result<(), EgressError> {
    let slots = Arc::new(Semaphore::new(process.config().max_connections));
    let serve = async {
        loop {
            let slot = slots
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| EgressError::StateUnavailable)?;
            let (mut stream, _) = listener
                .accept()
                .await
                .map_err(|_| EgressError::Transport)?;
            // A disconnected peer can make credential lookup fail (notably on
            // macOS). Refuse that connection without terminating recovery for all
            // other clients. No request is read before successful authentication.
            let Ok(credentials) = stream.peer_cred() else {
                continue;
            };
            // SAFETY: geteuid has no preconditions and does not access memory.
            if credentials.uid() != unsafe { libc::geteuid() } {
                continue;
            }
            let process = process.clone();
            tokio::spawn(async move {
                let _slot = slot;
                let limit = process.config().max_frame_bytes;
                let timeout = Duration::from_secs(process.config().io_timeout_seconds);
                let response =
                    match tokio::time::timeout(timeout, read_frame::<Request>(&mut stream, limit))
                        .await
                    {
                        Ok(Ok(request)) => process.handle(request).await,
                        Ok(Err(error)) => Response {
                            version: PROTOCOL_VERSION,
                            result: Err(error),
                        },
                        Err(_) => Response {
                            version: PROTOCOL_VERSION,
                            result: Err(EgressError::Transport),
                        },
                    };
                let _ =
                    tokio::time::timeout(timeout, write_frame(&mut stream, &response, limit)).await;
            });
        }
    };
    let cleanup = async {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            if let Err(error) = process.purge_expired_results() {
                break Err(error);
            }
        }
    };
    tokio::select! {
        result = serve => result,
        result = cleanup => result,
    }
}
