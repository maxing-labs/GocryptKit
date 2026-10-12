// F-23: compiled together with App/TypingSubstitutions.swift by
// typing-substitutions-test.sh. Types into an off-screen NSTextField through
// its field editor, as the keyboard would, with a text replacement defined for
// this process only ("gkzq" → "REPLACED"), so the user's own list does not matter.
import AppKit

func spin(_ seconds: TimeInterval) {
    RunLoop.current.run(until: Date().addingTimeInterval(seconds))
}

@MainActor
func typed(_ text: String) -> String {
    let window = NSWindow(contentRect: NSRect(x: -4000, y: -4000, width: 360, height: 80),
                          styleMask: [.titled], backing: .buffered, defer: false)
    let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 320, height: 24))
    window.contentView!.addSubview(field)
    window.orderFrontRegardless()
    guard window.makeFirstResponder(field), let editor = window.fieldEditor(true, for: field) as? NSTextView else {
        print("could not start editing")
        exit(2)
    }
    for character in text {
        editor.insertText(String(character), replacementRange: editor.selectedRange())
        spin(0.05)
    }
    spin(0.8)
    defer { window.close() }
    return field.stringValue
}

@MainActor
func main() -> Int32 {
    let defaults = UserDefaults.standard
    var arguments = defaults.volatileDomain(forName: UserDefaults.argumentDomain)
    arguments["NSUserDictionaryReplacementItems"] = [["on": 1, "replace": "gkzq", "with": "REPLACED"]]
    defaults.setVolatileDomain(arguments, forName: UserDefaults.argumentDomain)
    _ = NSApplication.shared
    NSApp.setActivationPolicy(.prohibited)

    // D-12: inline predictions (macOS 14) show a completion that a key press
    // accepts into the field. Checked on the setting: no input shows one reliably.
    let editor = NSTextView()
    TypingSubstitutions.disable(in: editor)
    guard editor.inlinePredictionType == .no else {
        print("inline predictions are still on")
        return 1
    }

    let input = "gkzq \"Pw\"--it's teh "
    let control = typed(input)
    guard control != input else {
        print("SKIP the system did not substitute anything; the probe cannot tell")
        return 2
    }
    TypingSubstitutions.disableInTextFields()
    let result = typed(input)
    print("control :", control.debugDescription)
    print("disabled:", result.debugDescription)
    return result == input ? 0 : 1
}

exit(main())
