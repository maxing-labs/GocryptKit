// F-23 probe: does a plain SwiftUI TextField rewrite what the user types?
//
// The "show password" mode swaps SecureField for TextField. If the system's
// text substitutions (smart quotes, dashes, text replacement, spelling
// correction) apply there, the vault is created with a password the user did
// not type. This hosts the field in an off-screen window, types through the
// field editor (no UI automation needed) and prints what the binding received.
//
// Usage: swift Tests/host/textfield-substitution.swift [plain|hardened|password-type]
// Exit status 0: the typed text arrived unchanged. 1: it was altered.
import AppKit
import SwiftUI

final class Model: ObservableObject {
    @Published var text = ""
}

struct PlainField: View {
    @ObservedObject var model: Model
    var body: some View {
        TextField("password", text: $model.text).frame(width: 320)
    }
}

struct HardenedField: View {
    @ObservedObject var model: Model
    var body: some View {
        TextField("password", text: $model.text)
            .autocorrectionDisabled()
            .frame(width: 320)
    }
}

struct PasswordTypedField: View {
    @ObservedObject var model: Model
    var body: some View {
        TextField("password", text: $model.text)
            .autocorrectionDisabled()
            .textContentType(.password)
            .frame(width: 320)
    }
}

func findTextField(_ view: NSView) -> NSTextField? {
    if let field = view as? NSTextField, field.isEditable { return field }
    for sub in view.subviews {
        if let found = findTextField(sub) { return found }
    }
    return nil
}

func spin(_ seconds: TimeInterval) {
    RunLoop.current.run(until: Date().addingTimeInterval(seconds))
}

let mode = CommandLine.arguments.dropFirst().first ?? "plain"
let app = NSApplication.shared
app.setActivationPolicy(.prohibited)

let model = Model()
let window = NSWindow(contentRect: NSRect(x: -4000, y: -4000, width: 360, height: 80),
                      styleMask: [.titled], backing: .buffered, defer: false)
switch mode {
case "hardened":
    window.contentView = NSHostingView(rootView: HardenedField(model: model))
case "password-type":
    window.contentView = NSHostingView(rootView: PasswordTypedField(model: model))
default:
    window.contentView = NSHostingView(rootView: PlainField(model: model))
}
window.orderFrontRegardless()
spin(0.3)

guard let field = findTextField(window.contentView!) else {
    print("no NSTextField found under the hosting view")
    exit(2)
}
guard window.makeFirstResponder(field), let editor = window.fieldEditor(true, for: field) as? NSTextView else {
    print("could not start editing")
    exit(2)
}
print("mode=\(mode)",
      "quotes=\(editor.isAutomaticQuoteSubstitutionEnabled)",
      "dashes=\(editor.isAutomaticDashSubstitutionEnabled)",
      "replacement=\(editor.isAutomaticTextReplacementEnabled)",
      "spelling=\(editor.isAutomaticSpellingCorrectionEnabled)")

// A password-like string that exercises quotes, double hyphens and a common typo.
let typed = "it's \"Pw\"--teh 1 "
for character in typed {
    editor.insertText(String(character), replacementRange: editor.selectedRange())
    spin(0.05)
}
spin(0.8)
let received = model.text
let unchanged = received == typed
print("typed    :", Array(typed.unicodeScalars).map { String($0.value, radix: 16) }.joined(separator: " "))
print("received :", Array(received.unicodeScalars).map { String($0.value, radix: 16) }.joined(separator: " "))
print(unchanged ? "UNCHANGED" : "ALTERED")
exit(unchanged ? 0 : 1)
