#!/usr/bin/env python3
"""Host/CLI regressions on disposable vaults. Passwords stay in memory and stdin pipes."""
import argparse
import importlib.util
import os
from pathlib import Path
import pty
import select
import signal
import subprocess
import sys
import time

sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location("integrity", Path(__file__).with_name("integrity-regressions.py"))
integrity = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(integrity)
TestVault, write = integrity.TestVault, integrity.write


def gocryptfs_mounts():
    return [line for line in subprocess.check_output(["/sbin/mount"], text=True).splitlines() if "gocryptfs" in line]


def run(v, *args, stdin=b"", timeout=45):
    return subprocess.run([v.app, *map(str, args)], input=stdin, capture_output=True, timeout=timeout)


def unknown_flag_rejected(v):
    # "--read-only" is a typo for "--readonly". Ignoring it would mount the vault writable.
    result = run(v, "mount", v.cipher, v.mount, "--read-only", "--password-stdin", stdin=v.password)
    mounted = bool(gocryptfs_mounts())
    if mounted:
        run(v, "umount", v.mount)
    assert result.returncode != 0 and not mounted, "a misspelled flag was ignored and the vault got mounted"
    assert b"--read-only" in result.stderr, "the error does not name the offending option"
    result = run(v, "umount", v.mount, "--forse")
    assert result.returncode != 0 and b"--forse" in result.stderr, "umount accepted an unknown flag"


def stdin_overlong_rejected(v):
    fresh = v.root / "long"
    result = run(v, "init", fresh, "--scryptn", "10", "--password-stdin", stdin=b"p" * 5000 + b"\n")
    assert result.returncode != 0, "an over-long stdin password was accepted (silently truncated)"
    assert not (fresh / "gocryptfs.conf").exists(), "a vault was created from a truncated password"


def stdin_strips_one_newline(v):
    # Only one trailing newline belongs to the pipe; anything else is part of the password.
    result = run(v, "mount", v.cipher, v.mount, "--password-stdin", stdin=v.password + b"\n")
    mounted = bool(gocryptfs_mounts())
    if mounted:
        run(v, "umount", v.mount)
    assert result.returncode != 0 and not mounted, "extra trailing newlines were stripped from the password"
    v.attach()
    v.detach()


def stdin_tty_rejected(v):
    # With a terminal on stdin, --password-stdin would echo the password while it is typed.
    master, slave = pty.openpty()
    try:
        child = subprocess.Popen([v.app, "mount", str(v.cipher), str(v.mount), "--password-stdin"],
                                 stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()
            raise AssertionError("--password-stdin waited on a terminal instead of refusing")
        assert child.returncode != 0, "--password-stdin accepted a terminal"
    finally:
        os.close(master)
        os.close(slave)


def ctrl_c_during_mount(v, delay):
    """Types the password at the prompt on a pseudo-terminal, then presses Ctrl-C after `delay`."""
    pid, master = pty.fork()
    if pid == 0:
        os.execv(v.app, [v.app, "mount", str(v.cipher), str(v.mount)])
    seen, deadline = b"", time.time() + 15
    while b"password" not in seen.lower() and time.time() < deadline:
        if select.select([master], [], [], 0.2)[0]:
            seen += os.read(master, 1024)
    os.write(master, v.password)
    time.sleep(delay)
    os.write(master, b"\x03")  # the terminal sends SIGINT to the CLI and to /sbin/mount
    deadline = time.time() + 30
    while time.time() < deadline:
        done, status = os.waitpid(pid, os.WNOHANG)
        if done:
            os.close(master)
            return status
        try:
            if select.select([master], [], [], 0.1)[0]:
                os.read(master, 4096)
        except OSError:
            pass
    os.kill(pid, signal.SIGKILL)
    os.waitpid(pid, 0)
    os.close(master)
    raise AssertionError("the CLI did not exit after Ctrl-C")


def interrupted_mount_leaves_no_credential(v):
    v.mount.mkdir(exist_ok=True)
    for delay in (0.02, 0.06, 0.1, 0.15, 0.2, 0.3):
        status = ctrl_c_during_mount(v, delay)
        time.sleep(1.0)
        if gocryptfs_mounts():  # Ctrl-C arrived after the mount had completed
            run(v, "umount", v.mount)
            continue
        assert status != 0, "an interrupted mount reported success"
        # Without a leftover credential the extension must refuse a bare mount.
        direct = subprocess.run(["/sbin/mount", "-t", "gocryptfs", str(v.cipher), str(v.mount)],
                                capture_output=True, timeout=45)
        if direct.returncode == 0:
            run(v, "umount", v.mount)
            raise AssertionError(f"Ctrl-C after {delay}s left the credential in the Keychain: a bare mount unlocked the vault")


def double_mount_rejected(v):
    v.attach()
    write(v.mount / "f", b"x\n")
    link = v.root / "cipher-link"
    os.symlink(v.cipher, link)
    aliases = [v.cipher, link, Path(str(v.cipher).replace("/private/tmp/", "/tmp/", 1)),
               Path("/System/Volumes/Data" + str(v.cipher))]  # firmlink of the data volume
    try:
        for index, alias in enumerate(aliases):
            target = v.root / f"second{index}"
            result = run(v, "mount", alias, target, "--password-stdin", stdin=v.password)
            count = len(gocryptfs_mounts())
            if count > 1:
                run(v, "umount", target)
            assert result.returncode != 0 and count == 1, f"the same vault got mounted twice via {alias.name}"
    finally:
        v.detach()


def double_mount_long_path(v):
    # The file URL of this path does not fit f_mntfromname, and FSKit records
    # "unknown" as the source: the mount table alone cannot name the vault.
    cipher = v.root.joinpath(*(["很长的中文目录名称用于测试路径截断问题" * 2] * 3))
    cipher.mkdir(parents=True)
    result = run(v, "init", cipher, "--scryptn", "10", "--password-stdin", stdin=v.password)
    assert result.returncode == 0, "init failed"
    first, second = v.root / "long-first", v.root / "long-second"
    assert run(v, "mount", cipher, first, "--password-stdin", stdin=v.password).returncode == 0, "mount failed"
    try:
        alias = Path(str(cipher).replace("/private/tmp/", "/tmp/", 1))
        result = run(v, "mount", alias, second, "--password-stdin", stdin=v.password)
        count = len(gocryptfs_mounts())
        if count > 1:
            run(v, "umount", second)
        assert result.returncode != 0 and count == 1, "a vault with a long path got mounted twice"
    finally:
        assert run(v, "umount", first).returncode == 0, "umount failed"


def names_not_logged(v):
    secret = v.root / "zq-private-name-7731"
    started = time.strftime("%Y-%m-%d %H:%M:%S")
    result = run(v, "mount", v.cipher, secret, "--password-stdin", stdin=v.password)
    assert result.returncode == 0, "mount failed"
    run(v, "umount", secret)
    time.sleep(1.5)
    log = subprocess.run(["/usr/bin/log", "show", "--info", "--debug", "--start", started, "--style", "compact",
                          "--predicate", 'subsystem BEGINSWITH "com.xwei.GocryptKit"'],
                         capture_output=True, text=True, timeout=90).stdout
    hits = [line for line in log.splitlines() if "zq-private-name-7731" in line]
    assert not hits, f"the volume name reached the system log in {len(hits)} line(s)"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--app", required=True)
    parser.add_argument("--only", help="comma-separated case names")
    args = parser.parse_args()
    assert not gocryptfs_mounts(), "Stop: another gocryptfs volume is mounted"
    cases = [("unknown-flag-rejected", unknown_flag_rejected), ("stdin-overlong-rejected", stdin_overlong_rejected),
             ("stdin-strips-one-newline", stdin_strips_one_newline), ("stdin-tty-rejected", stdin_tty_rejected),
             ("interrupted-mount-leaves-no-credential", interrupted_mount_leaves_no_credential),
             ("double-mount-rejected", double_mount_rejected), ("double-mount-long-path", double_mount_long_path),
             ("names-not-logged", names_not_logged)]
    if args.only:
        wanted = set(args.only.split(","))
        cases = [case for case in cases if case[0] in wanted]
        assert len(cases) == len(wanted), "unknown case name in --only"
    failures = 0
    for label, case in cases:
        vault = None
        try:
            vault = TestVault(args.app)
            case(vault)
            print(f"PASS {label}", flush=True)
        except Exception as error:
            failures += 1
            print(f"FAIL {label}: {type(error).__name__}: {error}", flush=True)
        finally:
            if vault:
                vault.cleanup()
    print(f"CLI regressions: {len(cases) - failures} passed, {failures} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
