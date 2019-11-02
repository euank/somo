use clap::{App, AppSettings, Arg};
use libc;
use log::debug;
use nix::sys::signal;
use nix::unistd::Pid;
use std::os::unix::process::CommandExt;
use std::process::Command;

fn main() {
    env_logger::init();

    let opts = App::new("somo")
        .setting(AppSettings::TrailingVarArg)
        .arg(
            Arg::with_name("restart-exit-code")
                .long("restart-exit-code")
                .takes_value(true),
        )
        .arg(Arg::with_name("trailing").multiple(true))
        .get_matches();

    // TODO: parent death signal if not pid1
    // TODO: subreaper if not pid1
    // TODO: reaper check

    let restart_exit_code = match opts.value_of("restart-exit-code") {
        None => None,
        Some(s) => Some(s.parse::<i32>().expect("could not parse restart-exit-code")),
    };

    let cmd: Vec<_> = opts
        .values_of("trailing")
        .expect("must provide a program to run")
        .collect();

    if cmd.len() == 0 {
        println!("No arguments provided to run");
        std::process::exit(1);
    }

    let mut child = Command::new(cmd[0]);
    child.args(&cmd[1..]);

    let mut parent_sigs = signal::SigSet::all();
    for signal in vec![
        signal::Signal::SIGFPE,
        signal::Signal::SIGILL,
        signal::Signal::SIGSEGV,
        signal::Signal::SIGBUS,
        signal::Signal::SIGABRT,
        signal::Signal::SIGTRAP,
        signal::Signal::SIGSYS,
        signal::Signal::SIGTTIN,
        signal::Signal::SIGTTOU,
    ] {
        parent_sigs.remove(signal);
    }

    let mut original_signals = signal::SigSet::empty();
    signal::sigprocmask(
        signal::SigmaskHow::SIG_SETMASK,
        Some(&parent_sigs),
        Some(&mut original_signals),
    )
    .unwrap();

    let (orig_sigttin, orig_sigttou) = unsafe {
        let ttin = signal::sigaction(
            signal::Signal::SIGTTIN,
            &signal::SigAction::new(
                signal::SigHandler::SigIgn,
                signal::SaFlags::empty(),
                signal::SigSet::empty(),
            ),
        )
        .unwrap();
        let ttou = signal::sigaction(
            signal::Signal::SIGTTOU,
            &signal::SigAction::new(
                signal::SigHandler::SigIgn,
                signal::SaFlags::empty(),
                signal::SigSet::empty(),
            ),
        )
        .unwrap();
        (ttin, ttou)
    };

    unsafe {
        child.pre_exec(move || {
            // group
            nix::unistd::setpgid(Pid::from_raw(0), Pid::from_raw(0)).unwrap();

            // TTY stuff
            match nix::unistd::tcsetpgrp(libc::STDIN_FILENO, nix::unistd::getpgrp()) {
                Err(nix::Error::Sys(nix::errno::Errno::ENXIO)) => {
                    debug!("tcsetpgrp failed: no tty (proceeding anyway)");
                }
                Err(e) => {
                    // TODO: proper error handling, pre_exec is special
                    panic!("tcsetpgrp failed: {}", e);
                }
                Ok(_) => {}
            };

            signal::sigprocmask(
                signal::SigmaskHow::SIG_SETMASK,
                Some(&original_signals),
                None,
            )
            .unwrap();
            signal::sigaction(signal::Signal::SIGTTIN, &orig_sigttin).unwrap();
            signal::sigaction(signal::Signal::SIGTTOU, &orig_sigttou).unwrap();

            Ok(())
        });
    }


    loop {
        let result = child.spawn().unwrap();
        let child_pid = result.id();

        let mut exitcode = None;
        while exitcode.is_none() {
            wait_and_forward_signal(parent_sigs, child_pid).unwrap();
            exitcode = reap_zombies(child_pid).unwrap();
        }
        if exitcode != restart_exit_code {
            std::process::exit(exitcode.unwrap());
        }
        debug!("process exited with exitcode {}; restarting", exitcode.unwrap());
    }
}

fn reap_zombies(child_pid: u32) -> Result<Option<i32>, String> {
    let mut exitcode = None;
    loop {
        let waitres = match nix::sys::wait::waitpid(Some(Pid::from_raw(-1)), Some(nix::sys::wait::WaitPidFlag::WNOHANG)) {
            Err(nix::Error::Sys(nix::errno::Errno::ECHILD)) => {
                break
            }
            Err(e) => {
                return Err(format!("wait_pid error: {}", e));
            }
            Ok(o) => o,
        };
    
        match waitres {
            nix::sys::wait::WaitStatus::StillAlive => {
                break
            },
            nix::sys::wait::WaitStatus::Exited(pid, status) => {
                debug!("Reaped child with pid {}", pid);
                if pid == Pid::from_raw(child_pid as i32) {
                    debug!("Main child exited normally (status {})", status);
                    exitcode = Some(status);
                } else {
                    debug!("Reaped zombie process with pid={}", pid);
                }
            }
            nix::sys::wait::WaitStatus::Signaled(pid, signal, _) => {
                if pid == Pid::from_raw(child_pid as i32) {
                    debug!("Main child exited with signal (signal {})", signal);
                    exitcode = Some(128 + signal as i32);
                } else {
                    debug!("Reaped zombie process with pid={}", pid);
                }
            }
            nix::sys::wait::WaitStatus::Stopped(pid, signal) => {
                unreachable!("unreachable: WaitStatus::Stopped can only happen if we wait with 'WaitPidFlag::WUNTRACED'; got it for pid {}, signal {}", pid, signal)
            }
            nix::sys::wait::WaitStatus::Continued(pid) => {
                unreachable!("unreachable: WaitStatus::Continued can only happen if we wait with 'WaitPidFlag::WCONTINUED'; got it for pid {}", pid)
            }
            nix::sys::wait::WaitStatus::PtraceEvent(pid, signal, _) => {
                // Not implemented in tini
                panic!("todo: support for ptrace event: {}, {}", pid, signal)
            }
            nix::sys::wait::WaitStatus::PtraceSyscall(pid) => {
                panic!("todo: support for ptrace syscall event: {}", pid)
            }
        }
    }

    Ok(exitcode)
}

fn wait_and_forward_signal(parent_sigset: signal::SigSet, child_pid: u32) -> Result<(), String> {
    let mut sig: std::mem::MaybeUninit<libc::siginfo_t> = std::mem::MaybeUninit::<libc::siginfo_t>::uninit();
    let timespec = libc::timespec{
        tv_sec: 1,
        tv_nsec: 0,
    };
    let res = unsafe {
        libc::sigtimedwait(
            parent_sigset.as_ref(),
            sig.as_mut_ptr(),
            &timespec,
        )
    };
    if res == -1 {
        match nix::errno::from_i32(nix::errno::errno()) {
            nix::errno::Errno::EAGAIN => {
                return Ok(())
            }
            nix::errno::Errno::EINTR => {
                return Ok(())
            }
            e => {
                return Err(format!("unexpected errno: {}", e))
            }
        }
    } else {
        let sig = unsafe { sig.assume_init() };
        match signal::Signal::from_c_int(sig.si_signo).unwrap() {
            signal::Signal::SIGCHLD => {
                debug!("Received SIGCHLD");
                return Ok(())
            }
            sig => {
                debug!("Passing signal: {}", sig);
                // TODO: handle errno = ESRCH
                signal::kill(Pid::from_raw(child_pid as i32), sig)
                    .map_err(|e| format!("kill error: {}", e))
            }
        }
    }
}
