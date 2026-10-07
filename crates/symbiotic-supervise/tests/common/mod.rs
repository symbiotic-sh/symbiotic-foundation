use std::{
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use symbiotic_supervise::{Event, Policy, Supervisor};

pub(super) fn policy() -> Policy {
    Policy {
        version: 1,
        max_restarts: 2,
        crash_window_ms: 10_000,
        backoff_ms: 40,
        stop_grace_ms: 100,
        poll_ms: 5,
    }
}
pub(super) fn fixture(executable: &Path, role: &str, dir: &Path) -> Command {
    let mut command = Command::new(executable);
    command
        .env("SUPERVISE_TEST_ROLE", role)
        .env("SUPERVISE_TEST_DIR", dir)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    command
}
pub(super) fn until(mut check: impl FnMut() -> bool) {
    let start = Instant::now();
    while !check() {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "process deadline exceeded"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}
pub(super) fn until_termination(mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while !check() {
        assert!(
            Instant::now() < deadline,
            "60 s termination hang guard fired"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}
pub(super) fn alive(pid: u32) -> bool {
    // Linux containers may leave an exited orphan as a zombie until PID 1 reaps it.
    #[cfg(target_os = "linux")]
    if std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        stat.rsplit_once(") ")
            .is_some_and(|(_, fields)| fields.starts_with('Z'))
    }) {
        return false;
    }
    // SAFETY: signal 0 only probes the process.
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

pub(super) fn started(supervisor: &Supervisor) -> u32 {
    match supervisor.next_event().unwrap() {
        Event::Started(pid) => pid,
        event => panic!("expected spawn, got {event:?}"),
    }
}
