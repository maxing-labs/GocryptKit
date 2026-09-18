import Foundation

/// Utility helper for executing external system commands and capturing outputs.
enum ProcessRunner {
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
        do {
            try task.run()
            // Drain pipe before waiting for exit to avoid pipe buffer deadlock
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            task.waitUntilExit()
            return String(data: data, encoding: .utf8) ?? ""
        } catch {
            return nil
        }
    }
}
