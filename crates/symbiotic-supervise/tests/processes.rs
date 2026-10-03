#![cfg(unix)]
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use symbiotic_supervise::{Error, Event, Policy, Supervisor, watch_parent};

fn policy() -> Policy {
    Policy {
        version: 1,
        max_restarts: 2,
        crash_window_ms: 10_000,
        backoff_ms: 40,
        stop_grace_ms: 100,
        poll_ms: 5,
    }
}
fn fixture(role: &str, dir: &Path) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "process_fixture", "--nocapture"])
        .env("SUPERVISE_TEST_ROLE", role)
        .env("SUPERVISE_TEST_DIR", dir)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    command
}
fn until(mut check: impl FnMut() -> bool) {
    let start = Instant::now();
    while !check() {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "process deadline exceeded"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn started(supervisor: &Supervisor) -> u32 {
    match supervisor.next_event().unwrap() {
        Event::Started(pid) => pid,
        event => panic!("expected spawn, got {event:?}"),
    }
}
fn alive(pid: u32) -> bool {
    // Linux containers may leave an exited orphan as a zombie until PID 1 reaps it.
    #[cfg(target_os = "linux")]
    if fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        stat.rsplit_once(") ")
            .is_some_and(|(_, fields)| fields.starts_with('Z'))
    }) {
        return false;
    }
    // SAFETY: signal 0 only probes the process.
    unsafe { libc::kill(pid as i32, 0) == 0 }
}
struct Reap(Child);
impl Drop for Reap {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn read_pid(path: &Path) -> u32 {
    until(|| fs::read_to_string(path).is_ok_and(|text| text.trim().parse::<u32>().is_ok()));
    fs::read_to_string(path).unwrap().trim().parse().unwrap()
}

// A real executable entrypoint in the test binary, never a fork of a running engine.
#[test]
fn process_fixture() {
    let Ok(role) = std::env::var("SUPERVISE_TEST_ROLE") else {
        return;
    };
    let dir = PathBuf::from(std::env::var_os("SUPERVISE_TEST_DIR").unwrap());
    if role == "closed-stdin-parent" {
        // Close all standard streams so both pipe ends need relocation.
        // SAFETY: this isolated fixture owns its standard descriptors.
        unsafe {
            for fd in 0..3 {
                libc::close(fd);
            }
        }
        let child_dir = dir.clone();
        let child = Supervisor::start(
            move || {
                let mut command = fixture("busy", &child_dir);
                command.stdin(Stdio::null()).stderr(Stdio::null());
                command
            },
            policy(),
        )
        .unwrap();
        until(|| dir.join("busy.ready").exists());
        child.stop().unwrap();
        std::process::exit(0);
    }
    if role == "shutdown-error-parent" {
        let child_dir = dir.clone();
        let child = Supervisor::start(move || fixture("busy", &child_dir), policy()).unwrap();
        let pid = started(&child);
        until(|| dir.join("busy.ready").exists());
        assert!(
            matches!(child.stop(), Err(Error::Io(error)) if error.raw_os_error() == Some(libc::EPERM))
        );
        assert!(!alive(pid), "shutdown failure must still kill and reap");
        std::process::exit(0);
    }
    if role == "broken-stderr" {
        use std::os::fd::{FromRawFd, OwnedFd};
        let mut fds = [-1; 2];
        // SAFETY: this fixture owns both pipe descriptors; disconnect the reader
        // and replace stderr with the writer (closing stderr alone is insufficient).
        unsafe {
            assert_eq!(libc::pipe(fds.as_mut_ptr()), 0);
            let reader = OwnedFd::from_raw_fd(fds[0]);
            let writer = OwnedFd::from_raw_fd(fds[1]);
            assert_eq!(libc::dup2(fds[1], libc::STDERR_FILENO), libc::STDERR_FILENO);
            drop(reader);
            drop(writer);
        }
        watch_parent(|| Err(std::io::Error::from_raw_os_error(libc::EPERM))).unwrap();
        fs::write(dir.join("broken-stderr.ready"), "ready").unwrap();
        loop {
            std::hint::spin_loop();
        }
    }
    #[cfg(target_os = "linux")]
    if role == "linux-parent" {
        let child_dir = dir.clone();
        let child = Supervisor::start(move || fixture("unwatched", &child_dir), policy()).unwrap();
        fs::write(dir.join("child.pid"), started(&child).to_string()).unwrap();
        until(|| dir.join("unwatched.ready").exists());
        fs::write(dir.join("parent.ready"), "ready").unwrap();
        loop {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    #[cfg(target_os = "linux")]
    {
        if role != "parent" && role != "crash" {
            let mut signal = 0;
            // SAFETY: PR_GET_PDEATHSIG writes the signal to the supplied integer.
            assert_eq!(
                unsafe {
                    libc::prctl(
                        libc::PR_GET_PDEATHSIG,
                        &mut signal,
                        0 as libc::c_ulong,
                        0 as libc::c_ulong,
                        0 as libc::c_ulong,
                    )
                },
                0
            );
            assert_eq!(signal, libc::SIGKILL);
        }
        if role == "unwatched" {
            fs::write(dir.join("unwatched.ready"), "ready").unwrap();
            loop {
                std::hint::spin_loop();
            }
        }
    }
    if role == "parent" {
        let wrapped = std::env::var_os("SUPERVISE_TEST_WRAPPER").is_some();
        let first_dir = dir.clone();
        let first = Supervisor::start(
            move || fixture(if wrapped { "wrapper" } else { "grandchild" }, &first_dir),
            policy(),
        )
        .unwrap();
        fs::write(dir.join("child.pid"), started(&first).to_string()).unwrap();
        let second_dir = dir.clone();
        let second = Supervisor::start(move || fixture("busy", &second_dir), policy()).unwrap();
        fs::write(dir.join("sibling.pid"), started(&second).to_string()).unwrap();
        until(|| dir.join("grandchild.pid").exists() && dir.join("busy.ready").exists());
        fs::write(dir.join("parent.ready"), "ready").unwrap();
        loop {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    if role == "crash" {
        std::process::exit(7);
    }
    if role == "wrapper" {
        use std::os::unix::process::CommandExt;
        let mut tool = Command::new("/bin/sh")
            .args(["-c", "sleep 20 & echo $! > \"$1\"; wait", "fixture"])
            .arg(dir.join("tool-descendant.pid"))
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = tool.id();
        watch_parent(move || {
            // SAFETY: the wrapper owns this still-unreaped tool's process group.
            if unsafe { libc::kill(-(pid as i32), libc::SIGKILL) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            tool.wait()?;
            Ok(())
        })
        .unwrap();
        fs::write(dir.join("grandchild.pid"), pid.to_string()).unwrap();
    } else {
        watch_parent(|| Ok(())).unwrap();
    }
    assert!(
        watch_parent(|| Ok(())).is_err(),
        "a second watcher must not own the same FD"
    );
    // Exercise the pipe even on Linux: PDEATHSIG must not mask inherited writers.
    #[cfg(target_os = "linux")]
    if role == "grandchild" || role == "busy" {
        // Disable only in the pipe-specific fixture, to distinguish EOF from SIGKILL.
        unsafe {
            assert_eq!(libc::prctl(libc::PR_SET_PDEATHSIG, 0 as libc::c_ulong), 0);
        }
    }
    if role == "grandchild" {
        let mut child = Command::new("/bin/sleep").arg("20").spawn().unwrap();
        fs::write(dir.join("grandchild.pid"), child.id().to_string()).unwrap();
        std::thread::spawn(move || child.wait().unwrap());
    }
    if role == "graceful" {
        // The shell's trap tests that SIGTERM arrives before forced stop.
        use std::os::unix::process::CommandExt;
        let error = Command::new("/bin/sh").args(["-c", "trap 'echo stopped > \"$1\"; exit 0' TERM; echo ready > \"$2\"; while :; do sleep 0.01; done", "fixture"])
            .arg(dir.join("stopped")).arg(dir.join("graceful.ready")).exec();
        panic!("exec failed: {error}");
    }
    if role == "stubborn" {
        // SAFETY: install the OS's signal-ignore disposition, with no callback.
        unsafe {
            libc::signal(libc::SIGTERM, libc::SIG_IGN);
        }
    }
    fs::write(dir.join(format!("{role}.ready")), "ready").unwrap();
    // Parent watcher runs independently while the main thread is occupied.
    loop {
        std::hint::spin_loop();
    }
}

#[test]
fn restarts_after_reaping_and_reports_crash_limit_with_backoff() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_owned();
    let supervisor = Supervisor::start(move || fixture("crash", &path), policy()).unwrap();
    let begin = Instant::now();
    for _ in 0..3 {
        let pid = started(&supervisor);
        assert!(
            matches!(supervisor.next_event().unwrap(), Event::Exited(status) if status.code() == Some(7))
        );
        assert!(!alive(pid), "exit must be reaped before restart");
    }
    assert!(begin.elapsed() >= Duration::from_millis(80));
    assert!(matches!(
        supervisor.next_event(),
        Err(Error::CrashLimit {
            restarts: 2,
            window_ms: 10_000,
            ..
        })
    ));
    supervisor.stop().unwrap();
}

#[test]
fn graceful_stop_and_forced_stop_both_reap() {
    for role in ["graceful", "stubborn"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_owned();
        let supervisor = Supervisor::start(move || fixture(role, &path), policy()).unwrap();
        let pid = started(&supervisor);
        until(|| dir.path().join(format!("{role}.ready")).exists());
        let start = Instant::now();
        supervisor.stop().unwrap();
        assert!(!alive(pid));
        if role == "graceful" {
            assert!(dir.path().join("stopped").exists());
        } else {
            assert!(start.elapsed() >= Duration::from_millis(100));
        }
    }
}

#[test]
fn parent_sigkill_closes_pipe_while_children_are_busy_and_grandchild_lives() {
    let dir = tempfile::tempdir().unwrap();
    let mut parent = Reap(fixture("parent", dir.path()).spawn().unwrap());
    until(|| dir.path().join("parent.ready").exists());
    let child = read_pid(&dir.path().join("child.pid"));
    let sibling = read_pid(&dir.path().join("sibling.pid"));
    let grandchild = read_pid(&dir.path().join("grandchild.pid"));
    parent.0.kill().unwrap();
    parent.0.wait().unwrap();
    until(|| !alive(child) && !alive(sibling));
    assert!(alive(grandchild), "grandchild must not delay watcher EOF");
    // This unmodified test tool has no wrapper: clean it up explicitly.
    unsafe {
        libc::kill(grandchild as i32, libc::SIGKILL);
    }
}

#[test]
fn temporary_calling_thread_does_not_own_parent_death_signal() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_owned();
    let supervisor = std::thread::spawn(move || {
        Supervisor::start(move || fixture("stubborn", &path), policy()).unwrap()
    })
    .join()
    .unwrap();
    let pid = started(&supervisor);
    until(|| dir.path().join("stubborn.ready").exists());
    assert!(alive(pid));
    supervisor.stop().unwrap();
}

#[test]
fn failed_spawn_is_visible_and_invalid_policy_is_refused() {
    let supervisor =
        Supervisor::start(|| Command::new("/nonexistent-foundation-child"), policy()).unwrap();
    assert!(matches!(supervisor.next_event(), Err(Error::Io(_))));
    supervisor.stop().unwrap();
    let mut invalid = policy();
    invalid.version = 2;
    assert!(matches!(
        Supervisor::start(|| Command::new("unused"), invalid),
        Err(Error::InvalidPolicy)
    ));
}

#[cfg(target_os = "macos")]
#[test]
fn app_owned_wrapper_kills_and_reaps_tool_group_on_parent_eof() {
    let dir = tempfile::tempdir().unwrap();
    let mut command = fixture("parent", dir.path());
    command.env("SUPERVISE_TEST_WRAPPER", "1");
    let mut parent = Reap(command.spawn().unwrap());
    until(|| dir.path().join("parent.ready").exists());
    let wrapper = read_pid(&dir.path().join("child.pid"));
    let tool = read_pid(&dir.path().join("grandchild.pid"));
    let descendant = read_pid(&dir.path().join("tool-descendant.pid"));
    parent.0.kill().unwrap();
    parent.0.wait().unwrap();
    until(|| !alive(wrapper) && !alive(tool) && !alive(descendant));
}

#[cfg(target_os = "linux")]
#[test]
fn linux_parent_death_signal_kills_an_unwatched_busy_child() {
    let dir = tempfile::tempdir().unwrap();
    let mut parent = Reap(fixture("linux-parent", dir.path()).spawn().unwrap());
    until(|| dir.path().join("parent.ready").exists());
    let child = read_pid(&dir.path().join("child.pid"));
    assert!(alive(child));
    parent.0.kill().unwrap();
    parent.0.wait().unwrap();
    until(|| !alive(child));
}

#[test]
fn closed_standard_streams_do_not_replace_the_parent_pipe() {
    let dir = tempfile::tempdir().unwrap();
    let mut parent = Reap(fixture("closed-stdin-parent", dir.path()).spawn().unwrap());
    until(|| parent.0.try_wait().unwrap().is_some());
    assert!(parent.0.wait().unwrap().success());
}

#[test]
fn cleanup_failure_exits_even_with_a_broken_stderr_pipe() {
    use std::os::{
        fd::{FromRawFd, OwnedFd},
        unix::process::CommandExt,
    };
    let dir = tempfile::tempdir().unwrap();
    let mut fds = [-1; 2];
    // SAFETY: pipe initializes two uniquely owned descriptors.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    let (reader, writer) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    let mut command = fixture("broken-stderr", dir.path());
    command.env("SYMBIOTIC_PARENT_FD", fds[0].to_string());
    // SAFETY: pre_exec closes only the test's inherited writer.
    unsafe {
        command.pre_exec(move || {
            if libc::close(fds[1]) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = Reap(command.spawn().unwrap());
    drop(reader);
    until(|| dir.path().join("broken-stderr.ready").exists());
    drop(writer);
    until(|| child.0.try_wait().unwrap().is_some());
    assert_eq!(child.0.wait().unwrap().code(), Some(1));
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn shutdown_error_returns_after_emergency_cleanup() {
    let dir = tempfile::tempdir().unwrap();
    let mut command = fixture("shutdown-error-parent", dir.path());
    #[cfg(target_os = "macos")]
    {
        let library = dir.path().join("refuse-term.dylib");
        let compiler = std::env::var("CC").expect("configured compiler cache");
        let mut compiler = compiler.split_whitespace();
        let output = Command::new(compiler.next().unwrap())
            .args(compiler)
            .args(["-O2", "-dynamiclib"])
            .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/refuse_term.c"))
            .arg("-o")
            .arg(&library)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        command.env("DYLD_INSERT_LIBRARIES", library);
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: pre_exec uses only prctl and preallocated seccomp data.
        unsafe {
            command.pre_exec(|| {
                let filter = [
                    libc::sock_filter {
                        code: 0x20,
                        jt: 0,
                        jf: 0,
                        k: 0,
                    }, // syscall
                    libc::sock_filter {
                        code: 0x15,
                        jt: 0,
                        jf: 3,
                        k: libc::SYS_kill as u32,
                    },
                    libc::sock_filter {
                        code: 0x20,
                        jt: 0,
                        jf: 0,
                        k: 24,
                    }, // signal argument
                    libc::sock_filter {
                        code: 0x15,
                        jt: 0,
                        jf: 1,
                        k: libc::SIGTERM as u32,
                    },
                    libc::sock_filter {
                        code: 0x06,
                        jt: 0,
                        jf: 0,
                        k: libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
                    },
                    libc::sock_filter {
                        code: 0x06,
                        jt: 0,
                        jf: 0,
                        k: libc::SECCOMP_RET_ALLOW,
                    },
                ];
                let program = libc::sock_fprog {
                    len: filter.len() as u16,
                    filter: filter.as_ptr() as *mut _,
                };
                if libc::prctl(
                    libc::PR_SET_NO_NEW_PRIVS,
                    1 as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                ) != 0
                    || libc::prctl(
                        libc::PR_SET_SECCOMP,
                        libc::SECCOMP_MODE_FILTER as libc::c_ulong,
                        &program,
                    ) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let mut parent = Reap(command.spawn().unwrap());
    until(|| parent.0.try_wait().unwrap().is_some());
    assert!(parent.0.wait().unwrap().success());
}
