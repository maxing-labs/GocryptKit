import Foundation

/// Unmount policy for app termination.
///
/// Volumes are unmounted without force. A busy volume is reported back so the
/// caller can keep the app running and ask the user; force is applied only to
/// the volumes passed in with `force: true`, i.e. after an explicit confirmation.
/// A silent `umount -f` truncates files that are still being written.
public enum QuitUnmount {
    public struct Outcome: Sendable, Equatable {
        /// Volumes that are in use by another process.
        public var busy: [MountTable.Entry] = []
        /// Volumes that failed to unmount for any other reason.
        public var failed: [MountTable.Entry] = []

        public init(busy: [MountTable.Entry] = [], failed: [MountTable.Entry] = []) {
            self.busy = busy
            self.failed = failed
        }

        /// The app may only terminate once every volume is unmounted.
        public var allUnmounted: Bool { busy.isEmpty && failed.isEmpty }

        /// Force is offered only when it can let the app quit, i.e. every volume
        /// left is busy. With any other failure the app stays running anyway,
        /// and forcing would risk truncating open files for nothing.
        public var canQuitByForcing: Bool { !busy.isEmpty && failed.isEmpty }

        /// The outcome by the live mount table, read after the attempt. A forced
        /// round covers only the busy volumes, so a volume that failed earlier
        /// for another reason, or was mounted meanwhile, must still count; one
        /// whose unmount reported an error but is gone no longer does.
        public func settled(stillMounted: [MountTable.Entry]) -> Outcome {
            let busyMountPoints = Set(busy.map(\.mountPoint))
            return Outcome(busy: stillMounted.filter { busyMountPoints.contains($0.mountPoint) },
                           failed: stillMounted.filter { !busyMountPoints.contains($0.mountPoint) })
        }
    }

    /// Calls `unmount(entry, force)` once per entry and classifies the failures.
    public static func attempt(_ entries: [MountTable.Entry],
                               force: Bool = false,
                               unmount: (MountTable.Entry, Bool) throws -> Void) -> Outcome {
        var outcome = Outcome()
        for entry in entries {
            do {
                try unmount(entry, force)
            } catch let error as UnmountError where error.isBusy {
                outcome.busy.append(entry)
            } catch {
                outcome.failed.append(entry)
            }
        }
        return outcome
    }
}
