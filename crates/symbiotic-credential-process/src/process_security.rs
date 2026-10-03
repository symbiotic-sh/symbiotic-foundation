//! Process-wide crash protection, established before any secret reads.
/// Disable core dumps and Linux dumpability before reading configuration or secrets.
/// Any OS refusal must abort startup; this protection applies to the whole process.
pub fn protect_process() -> std::io::Result<()> {
    // Linux piped core collectors ignore RLIMIT_CORE. Disable dumpability as well,
    // before reading configuration or secrets; failure refuses startup.
    #[cfg(target_os = "linux")]
    // SAFETY: PR_SET_DUMPABLE accepts an integer and retains no pointers.
    if unsafe {
        libc::prctl(
            libc::PR_SET_DUMPABLE,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    // Retain the portable resource-limit protection on every supported Unix host.
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit reads the initialized rlimit and retains no pointer.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    #[test]
    fn guard_child() {
        let Ok(mode) = std::env::var("PROTECTION_TEST_MODE") else {
            return;
        };
        let result = super::protect_process();
        if mode == "refused" {
            assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EPERM));
            return;
        }
        result.unwrap();
        let mut limit = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        // SAFETY: getrlimit writes the initialized struct and retains no pointer.
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) }, 0);
        assert_eq!((limit.rlim_cur, limit.rlim_max), (0, 0));
        #[cfg(target_os = "linux")]
        // SAFETY: PR_GET_DUMPABLE accepts only integer arguments.
        assert_eq!(
            unsafe {
                libc::prctl(
                    libc::PR_GET_DUMPABLE,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                )
            },
            0
        );
    }

    fn child() -> Command {
        let mut child = Command::new(std::env::current_exe().unwrap());
        child.args([
            "--exact",
            "process_security::tests::guard_child",
            "--nocapture",
        ]);
        child
    }

    #[test]
    fn protection_is_applied_in_a_real_process() {
        assert!(
            child()
                .env("PROTECTION_TEST_MODE", "protected")
                .status()
                .unwrap()
                .success()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn either_os_refusal_reaches_the_startup_caller() {
        use std::os::unix::process::CommandExt;
        for syscall in [libc::SYS_prctl, libc::SYS_prlimit64] {
            let mut command = child();
            command.env("PROTECTION_TEST_MODE", "refused");
            // SAFETY: pre_exec performs only prctl on preallocated BPF data.
            unsafe {
                command.pre_exec(move || {
                    let filter = [
                        libc::sock_filter {
                            code: 0x20,
                            jt: 0,
                            jf: 0,
                            k: 0,
                        }, // load syscall
                        libc::sock_filter {
                            code: 0x15,
                            jt: 0,
                            jf: 1,
                            k: syscall as u32,
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
            assert!(command.status().unwrap().success());
        }
    }
}
