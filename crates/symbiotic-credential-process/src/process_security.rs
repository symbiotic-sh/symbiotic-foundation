//! Process-wide crash protection, established before any secret reads.
pub(super) fn disable_core_dumps() -> std::io::Result<()> {
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    #[test]
    fn linux_disables_dumpability_even_with_a_piped_core_collector() {
        // Start with the normal dumpable state to exercise the transition explicitly.
        // SAFETY: these prctl operations accept integer arguments and no pointers.
        assert_eq!(
            unsafe {
                libc::prctl(
                    libc::PR_SET_DUMPABLE,
                    1 as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                )
            },
            0
        );
        super::disable_core_dumps().unwrap();
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
        let mut limit = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        // SAFETY: getrlimit writes to the initialized rlimit and retains no pointer.
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) }, 0);
        assert_eq!((limit.rlim_cur, limit.rlim_max), (0, 0));
    }
}
