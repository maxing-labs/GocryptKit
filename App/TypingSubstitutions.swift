import AppKit

/// The system's typing substitutions rewrite what is typed: text replacement
/// ("omw" → "On my way!"), smart quotes and dashes, spelling correction, inline
/// predictions. In the field that shows a password in clear text the vault would
/// get a password the user did not type, and `.autocorrectionDisabled()` only
/// turns off spelling correction. Every text field of the app takes what is
/// typed literally.
///
/// The field editor does not take these settings from user defaults (text
/// replacement stays on even when NSAutomaticTextReplacementEnabled is false),
/// so they are switched off on the editor itself whenever a field starts editing.
@MainActor
enum TypingSubstitutions {
    private static var observer: NSObjectProtocol?

    static func disableInTextFields() {
        guard observer == nil else { return }
        observer = NotificationCenter.default.addObserver(
            forName: NSControl.textDidBeginEditingNotification, object: nil, queue: nil
        ) { notification in
            guard let editor = notification.userInfo?["NSFieldEditor"] as? NSTextView else { return }
            MainActor.assumeIsolated { disable(in: editor) }
        }
    }

    static func disable(in editor: NSTextView) {
        editor.enabledTextCheckingTypes = 0
        editor.isAutomaticTextReplacementEnabled = false
        editor.isAutomaticQuoteSubstitutionEnabled = false
        editor.isAutomaticDashSubstitutionEnabled = false
        editor.isAutomaticSpellingCorrectionEnabled = false
        editor.isAutomaticTextCompletionEnabled = false
        editor.inlinePredictionType = .no
    }
}
