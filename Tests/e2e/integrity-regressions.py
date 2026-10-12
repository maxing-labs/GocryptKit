#!/usr/bin/env python3
"""Disposable FSKit regressions. Passwords stay in memory and stdin pipes."""
import argparse
import contextlib
import errno
import os
from pathlib import Path
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time


class TestVault:
    def __init__(self, app):
        self.app = app
        self.root = Path(tempfile.mkdtemp(prefix="gk-integrity-", dir="/private/tmp"))
        self.cipher, self.mount = self.root / "cipher", self.root / "mnt"
        self.password = secrets.token_urlsafe(32).encode() + b"\n"
        self.mounted = False
        self.cli("init", self.cipher, "--scryptn", "10", "--password-stdin")

    def cli(self, *args):
        needs_password = "--password-stdin" in args
        result = subprocess.run([self.app, *map(str, args)],
                                input=self.password if needs_password else b"",
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45)
        if result.returncode:
            raise RuntimeError(f"CLI {args[0]} exit={result.returncode}: {result.stderr.decode(errors='replace').strip()}")

    def attach(self):
        self.cli("mount", self.cipher, self.mount, "--password-stdin")
        self.mounted = True

    def detach(self):
        if self.mounted:
            self.cli("umount", self.mount)
            self.mounted = False

    def remount(self):
        self.detach()
        self.attach()

    def cleanup(self):
        self.detach()
        shutil.rmtree(self.root)
        self.password = b""


def write(path, data, append=False):
    with open(path, "ab" if append else "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def headers_valid(cipher):
    for path in cipher.rglob("*"):
        if not path.is_file() or path.name in ("gocryptfs.conf", "gocryptfs.diriv") or path.name.endswith(".name"):
            continue
        if path.stat().st_size:
            with path.open("rb") as stream:
                assert stream.read(2) == b"\x00\x02", "invalid ciphertext header"


def repeated_overwrite(v):
    target = v.mount / "f"
    for value in ("1", "2", "3"):
        subprocess.run(["/bin/sh", "-c", 'echo "$2" > "$1"', "integrity", str(target), value], check=True)
    v.remount()
    assert target.read_bytes() == b"3\n", "overwrite lost content"
    headers_valid(v.cipher)


def copy_overwrite(v):
    target = v.mount / "f"
    write(target, b"original\n")
    source = v.root / "source"
    for data in (b"first copy\n", b"final copy\n"):
        source.write_bytes(data)
        subprocess.run(["/bin/cp", str(source), str(target)], check=True, capture_output=True)
    v.remount()
    assert target.read_bytes() == b"final copy\n", "copy lost content"
    headers_valid(v.cipher)


def reader_during_overwrite(v):
    target = v.mount / "f"
    write(target, b"original\n")
    v.remount()
    reader = subprocess.Popen([sys.executable, "-c", """
import os, sys
fd = os.open(sys.argv[1], os.O_RDONLY)
os.pread(fd, 64, 0)
print('ready', flush=True)
sys.stdin.readline()
good = os.pread(fd, 64, 0) == b'replacement\\n'
os.close(fd)
sys.exit(0 if good else 1)
""", str(target)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        assert reader.stdout.readline() == b"ready\n", "reader did not open"
        subprocess.run([sys.executable, "-c", """
import os, sys
with open(sys.argv[1], 'wb') as f:
    f.write(b'replacement\\n'); f.flush(); os.fsync(f.fileno())
""", str(target)], check=True, capture_output=True)
        reader.communicate(b"read\n", timeout=20)
        assert reader.returncode == 0, "held reader could not read replacement"
    finally:
        if reader.poll() is None:
            reader.kill()
        reader.wait()
    v.remount()
    assert target.read_bytes() == b"replacement\n", "remounted reader could not read replacement"
    headers_valid(v.cipher)


def directory_swap(v, remove=False):
    for name, content in (("A", b"original\n"), ("Old", b"incoming\n")):
        (v.mount / name / "x").mkdir(parents=True)
        write(v.mount / name / "x" / "f", content)
    v.remount()  # close all seeding handles before warming the directory cache
    (v.mount / "A/x/f").read_bytes()
    os.rename(v.mount / "A", v.mount / "Tmp")
    os.rename(v.mount / "Old", v.mount / "A")
    if remove:
        (v.mount / "A/x/f").unlink()
    else:
        write(v.mount / "A/x/f", b"X\n", append=True)
    v.remount()
    assert (v.mount / "Tmp/x/f").read_bytes() == b"original\n", "moved-away file changed"
    if remove:
        assert not (v.mount / "A/x/f").exists(), "wrong file removed"
    else:
        assert (v.mount / "A/x/f").read_bytes() == b"incoming\nX\n", "append went to wrong file"
    headers_valid(v.cipher)


def recreate_directory(v):
    (v.mount / "D").mkdir()
    write(v.mount / "D/probe", b"warm directory cache\n")
    (v.mount / "D/probe").unlink()
    (v.mount / "D").rmdir()
    (v.mount / "D").mkdir()
    write(v.mount / "D/f", b"new file\n")
    v.remount()
    assert (v.mount / "D/f").read_bytes() == b"new file\n"
    headers_valid(v.cipher)


def mode_sequences(v):
    target = v.mount / "f"
    write(target, b"original\n")
    for flags in (os.O_RDONLY, os.O_WRONLY, os.O_RDWR):
        os.close(os.open(target, flags))
    for order in ((0, 1), (1, 0)):
        children = []
        try:
            for flags in (os.O_RDONLY, os.O_WRONLY):
                child = subprocess.Popen([sys.executable, "-c", """
import os, sys
fd = os.open(sys.argv[1], int(sys.argv[2]))
print('ready', flush=True)
sys.stdin.readline()
os.close(fd)
""", str(target), str(flags)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                children.append(child)
                assert child.stdout.readline() == b"ready\n"
            for index in order:
                children[index].communicate(b"close\n", timeout=20)
                assert children[index].returncode == 0
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                child.wait()
    write(v.mount / "source", b"moved\n")
    subprocess.run(["/bin/mv", str(v.mount / "source"), str(target)], check=True, capture_output=True)
    v.remount()
    assert target.read_bytes() == b"moved\n"


WRITER = """
import os, sys
path, total, chunk = sys.argv[1], int(sys.argv[2]) << 20, 1 << 20
fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
written = 0
while written < total:
    written += os.write(fd, b'W' * chunk)
    if written == 8 * chunk:
        print('writing', flush=True)  # the parent removes or replaces the file now
size = os.fstat(fd).st_size
os.close(fd)
print(size, flush=True)
"""


def interrupted_writer(v, target, megabytes, interrupt):
    """Runs `interrupt` while a child is in the middle of writing `target`. Returns the child's fstat size."""
    child = subprocess.Popen([sys.executable, "-c", WRITER, str(target), str(megabytes)],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        assert child.stdout.readline() == b"writing\n", "writer did not start"
        interrupt()
        out, _ = child.communicate(timeout=180)  # a close/write deadlock (F-5) ends here
        assert child.returncode == 0, "writer failed after its file was removed or replaced"
    finally:
        if child.poll() is None:
            child.kill()
        child.wait()
    # The whole volume must still answer.
    subprocess.run(["/bin/ls", str(v.mount)], check=True, capture_output=True, timeout=20)
    write(v.mount / "probe", b"alive\n")
    return int(out)


def write_during_remove(v):
    target = v.mount / "big"
    size = interrupted_writer(v, target, 96, target.unlink)
    assert size == 96 << 20, "fstat on the unlinked open file reported a wrong size"
    assert not target.exists(), "a write after unlink resurrected the file"
    v.remount()
    assert not target.exists(), "removed file is back after remount"
    assert (v.mount / "probe").read_bytes() == b"alive\n"
    headers_valid(v.cipher)


def write_during_rename_over(v):
    target, other = v.mount / "big", v.mount / "other"
    write(other, b"replacement\n")
    interrupted_writer(v, target, 96, lambda: os.rename(other, target))
    assert target.read_bytes() == b"replacement\n", "writes to the replaced file landed in its replacement"
    v.remount()
    assert target.read_bytes() == b"replacement\n", "replacement unreadable after remount"
    headers_valid(v.cipher)


RACER = """
import os, sys, time
base, rounds, start = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
wins = []
for i in range(rounds):
    while time.time() < start + i * 0.02:
        pass
    try:
        os.close(os.open(f"{base}/lock{i}", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
        wins.append(i)
    except FileExistsError:
        pass
print(" ".join(map(str, wins)))
"""


def exclusive_create(v):
    rounds, start = 100, time.time() + 1.5
    racers = [subprocess.Popen([sys.executable, "-c", RACER, str(v.mount), str(rounds), str(start)],
                               stdout=subprocess.PIPE, text=True) for _ in range(8)]
    winners = [0] * rounds
    for racer in racers:
        out, _ = racer.communicate(timeout=120)
        for index in out.split():
            winners[int(index)] += 1
    wrong = sum(1 for count in winners if count != 1)
    assert wrong == 0, f"O_EXCL create had {wrong}/{rounds} rounds without exactly one winner (max {max(winners)})"


def attributes_after_remove(v):
    started = time.strftime("%Y-%m-%d %H:%M:%S")
    target = v.mount / "gone"
    write(target, b"x\n")
    target.read_bytes()
    target.unlink()
    time.sleep(1.5)  # let the fault, if any, reach the log store
    log = subprocess.run(["/usr/bin/log", "show", "--start", started, "--style", "compact", "--predicate",
                          'process == "GocryptKitExt" AND eventMessage CONTAINS "attributes are incomplete"'],
                         capture_output=True, text=True, timeout=60).stdout
    faults = [line for line in log.splitlines() if "attributes are incomplete" in line]
    assert not faults, f"FSKit faulted {len(faults)}x on incomplete attributes of a removed item"


def set_times(v):
    target, folder = v.mount / "f", v.mount / "d"
    write(target, b"x\n")
    folder.mkdir()
    v.remount()
    assert os.lstat(target).st_birthtime > 0, "birth time reported as 1970"
    atime_ns, mtime_ns = 1614834367_500000000, 1577934245_250000000  # 2021-03-04, 2020-01-02
    for path in (target, folder):
        os.utime(path, ns=(atime_ns, mtime_ns), follow_symlinks=False)
    v.remount()
    for path in (target, folder):
        st = os.lstat(path)
        assert st.st_mtime_ns == mtime_ns, f"{path.name}: utimes did not set mtime ({st.st_mtime_ns})"
        assert st.st_atime_ns == atime_ns, f"{path.name}: utimes did not set atime ({st.st_atime_ns})"


def set_flags(v):
    target = v.mount / "f"
    write(target, b"x\n")
    os.chflags(target, stat.UF_HIDDEN)
    v.remount()
    assert os.lstat(target).st_flags & stat.UF_HIDDEN, "chflags hidden was dropped"
    os.chflags(target, 0)
    v.remount()
    assert not os.lstat(target).st_flags & stat.UF_HIDDEN, "chflags 0 was dropped"


def append_flag_refused(v):
    # D-3: the engine writes at block offsets through an O_RDWR descriptor, which
    # an append-only ciphertext file refuses, so the flag would make it unwritable.
    target = v.mount / "f"
    write(target, b"x\n")
    try:
        os.chflags(target, stat.UF_APPEND)
    except OSError as error:
        assert error.errno == errno.ENOTSUP, f"chflags uappnd: {error}"
    else:
        os.chflags(target, 0)
        raise AssertionError("chflags uappnd was accepted")
    write(target, b"y\n")
    v.remount()
    assert target.read_bytes() == b"y\n", "the file was not writable after chflags uappnd"
    assert not os.lstat(target).st_flags & stat.UF_APPEND


def chown_refused(v):
    # On a noowners mount the kernel strips uid/gid from the setattr it sends
    # (chgrp still produces a call, without the group), so ownership changes
    # never reach the extension; giving a file away is refused before that.
    target = v.mount / "f"
    write(target, b"x\n")
    os.chown(target, os.getuid(), os.getgid())  # cp -p: our own uid and primary group
    try:
        os.chown(target, 0, -1)
    except PermissionError:
        return
    raise AssertionError("chown to another user reported success")


def copy_read_only(v):
    source = v.root / "read-only"
    source.write_bytes(b"read-only content\n")
    source.chmod(0o444)
    target = v.mount / "copied"
    subprocess.run(["/bin/cp", str(source), str(target)], check=True, capture_output=True)
    v.remount()
    assert target.read_bytes() == b"read-only content\n", "copy of a read-only file lost its content"
    assert stat.S_IMODE(os.lstat(target).st_mode) == 0o444, "copy of a read-only file lost its mode"


def large_directory(v):
    folder = v.mount / "many"
    folder.mkdir()
    names = [f"file-{i:05d}-{'x' * 40}" for i in range(1500)]  # long names: many readdir batches
    for name in names:
        (folder / name).touch()
    listed = os.listdir(folder)
    assert sorted(listed) == names, f"listing of {len(names)} files returned {len(listed)} ({len(set(listed))} distinct)"
    removed = set(names[::3])
    seen = []
    with os.scandir(folder) as entries:
        for index, entry in enumerate(entries):
            seen.append(entry.name)
            if index == 100:
                for name in removed:
                    (folder / name).unlink()
    skipped = set(names) - removed - set(seen)
    assert not skipped, f"{len(skipped)} entries skipped while others were removed"
    assert len(seen) == len(set(seen)), f"{len(seen) - len(set(seen))} entries listed twice"


def extension_pids():
    out = subprocess.run(["/usr/bin/pgrep", "-f", "GocryptKitExt.appex"], capture_output=True, text=True).stdout
    return {int(pid) for pid in out.split()}


def nested_vault_refused(v):
    # Mounting a vault that lies inside a mounted vault deadlocks FSKit: statfs of
    # every FSKit volume (external disks too) hangs until the extension is killed.
    inner, target = v.mount / "inner", v.root / "inner-mnt"
    inner.mkdir()
    v.cli("init", inner, "--scryptn", "10", "--password-stdin")
    before = extension_pids()
    mount = subprocess.Popen([v.app, "mount", str(inner), str(target), "--password-stdin"],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    mount.stdin.write(v.password)
    mount.stdin.close()
    try:
        mount.wait(timeout=30)
    except subprocess.TimeoutExpired:
        # Stop the CLI first: on SIGTERM it removes the stored credential and does
        # not retry. Then end the new extension, which unblocks FSKit.
        mount.terminate()
        for pid in extension_pids() - before:
            os.kill(pid, signal.SIGKILL)
        try:
            mount.wait(timeout=30)
        except subprocess.TimeoutExpired:
            mount.kill()
            mount.wait(timeout=30)
        raise AssertionError("mounting a vault inside a vault hung")
    stderr = mount.stderr.read()
    assert mount.returncode != 0, "a vault inside a mounted vault got mounted"
    assert b"inside the mounted vault" in stderr, f"unexpected error: {stderr[-200:]!r}"


def two_volumes(v):
    other = TestVault(v.app)
    try:
        other.attach()
        write(v.mount / "a", b"A\n")
        write(other.mount / "b", b"B\n")
        other.detach()
        assert (v.mount / "a").read_bytes() == b"A\n", "unmounting one volume disturbed the other"
        write(v.mount / "a2", b"A2\n")
        other.attach()
        assert (other.mount / "b").read_bytes() == b"B\n"
    finally:
        other.cleanup()
    v.remount()
    assert (v.mount / "a2").read_bytes() == b"A2\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--app", required=True)
    parser.add_argument("--trace-modes")
    parser.add_argument("--only", help="comma-separated case names")
    args = parser.parse_args()
    assert "gocryptfs" not in subprocess.check_output(["/sbin/mount"], text=True), "Stop: another gocryptfs volume is mounted"
    trace, trace_file = None, None
    failures = 0
    try:
        if args.trace_modes:
            trace_file = open(args.trace_modes, "w")
            trace = subprocess.Popen(["/usr/bin/log", "stream", "--style", "compact", "--level", "debug", "--predicate",
                                      'subsystem == "com.xwei.GocryptKit.AppEx" AND category == "GocryptfsVolume+ReadWrite"'],
                                     stdout=trace_file, stderr=subprocess.DEVNULL)
            time.sleep(0.3)
        cases = [("repeated-overwrite", repeated_overwrite), ("cp-overwrite", copy_overwrite),
                 ("held-reader", reader_during_overwrite), ("directory-swap-write", directory_swap),
                 ("directory-swap-remove", lambda v: directory_swap(v, remove=True)),
                 ("recreate-directory", recreate_directory),
                 ("write-during-remove", write_during_remove),
                 ("write-during-rename-over", write_during_rename_over),
                 ("exclusive-create", exclusive_create),
                 ("attributes-after-remove", attributes_after_remove),
                 ("set-times", set_times), ("set-flags", set_flags),
                 ("append-flag-refused", append_flag_refused), ("chown-refused", chown_refused),
                 ("copy-read-only", copy_read_only), ("large-directory", large_directory),
                 ("nested-vault-refused", nested_vault_refused),
                 ("two-volumes", two_volumes)]
        if trace:
            cases.append(("open-close-sequences", mode_sequences))
        if args.only:
            wanted = set(args.only.split(","))
            cases = [case for case in cases if case[0] in wanted]
            assert len(cases) == len(wanted), "unknown case name in --only"
        for label, case in cases:
            vault = None
            try:
                vault = TestVault(args.app)
                vault.attach()
                case(vault)
                print(f"PASS {label}", flush=True)
            except Exception as error:
                failures += 1
                print(f"FAIL {label}: {type(error).__name__}: {error}", flush=True)
            finally:
                if vault:
                    vault.cleanup()  # a failed unmount stops the suite without deleting mounted data
    finally:
        if trace:
            trace.terminate()
            trace.wait(timeout=10)
            trace_file.close()
    print(f"Integrity regressions: {len(cases) - failures} passed, {failures} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
