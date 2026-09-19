import Foundation

/// Thread-safe accumulator for streaming process pipe output in Swift 6 concurrency mode.
private final class LockedBuffer: @unchecked Sendable {
    private let lock = NSLock()
    private var data = Data()

    func append(_ chunk: Data) {
        lock.lock()
        data.append(chunk)
        lock.unlock()
    }

    func extract() -> Data {
        lock.lock()
        defer { lock.unlock() }
        return data
    }
}

/// Utility helper for executing external system commands and capturing outputs.
enum ProcessRunner {
    static let defaultTimeout: TimeInterval = 15.0

    static func runCapturingOutput(_ path: String, _ args: [String]) -> String? {
        run(path, args, captureStandardError: false)
    }

    static func runCapturingError(_ path: String, _ args: [String]) -> String? {
        run(path, args, captureStandardError: true)
    }

    static func run(_ path: String, _ args: [String], captureStandardError: Bool) -> String? {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: path)
        task.arguments = args
        let pipe = Pipe()
        if captureStandardError {
            task.standardError = pipe
            task.standardOutput = FileHandle.nullDevice
        } else {
            task.standardOutput = pipe
            task.standardError = FileHandle.nullDevice
        }

        let buffer = LockedBuffer()
        pipe.fileHandleForReading.readabilityHandler = { handle in
            let chunk = handle.availableData
            if !chunk.isEmpty {
                buffer.append(chunk)
            }
        }

        do {
            try task.run()
            task.waitUntilExit()
            pipe.fileHandleForReading.readabilityHandler = nil
            let remaining = pipe.fileHandleForReading.readDataToEndOfFile()
            buffer.append(remaining)
            _ = try? pipe.fileHandleForReading.close()
            return String(data: buffer.extract(), encoding: .utf8) ?? ""
        } catch {
            pipe.fileHandleForReading.readabilityHandler = nil
            _ = try? pipe.fileHandleForReading.close()
            return nil
        }
    }

    /// Executes a system command with strict timeout protection and streaming pipe draining to prevent hangs and deadlocks.
    static func runWithTimeout(
        executable: String,
        arguments: [String],
        timeout: TimeInterval = defaultTimeout
    ) throws -> (status: Int32, stderr: String) {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: executable)
        task.arguments = arguments
        let errPipe = Pipe()
        task.standardError = errPipe

        let buffer = LockedBuffer()
        errPipe.fileHandleForReading.readabilityHandler = { handle in
            let chunk = handle.availableData
            if !chunk.isEmpty {
                buffer.append(chunk)
            }
        }

        try task.run()

        let deadline = Date().addingTimeInterval(timeout)
        while task.isRunning && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.05)
        }

        if task.isRunning {
            task.terminate()
            let termDeadline = Date().addingTimeInterval(1.0)
            while task.isRunning && Date() < termDeadline {
                Thread.sleep(forTimeInterval: 0.05)
            }
            errPipe.fileHandleForReading.readabilityHandler = nil
            _ = try? errPipe.fileHandleForReading.close()
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(ETIMEDOUT), userInfo: [
                NSLocalizedDescriptionKey: "Command '\(executable)' timed out after \(Int(timeout)) seconds."
            ])
        }

        task.waitUntilExit()
        errPipe.fileHandleForReading.readabilityHandler = nil
        let remaining = errPipe.fileHandleForReading.readDataToEndOfFile()
        buffer.append(remaining)
        _ = try? errPipe.fileHandleForReading.close()

        let errMsg = String(data: buffer.extract(), encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        return (task.terminationStatus, errMsg)
    }
}
