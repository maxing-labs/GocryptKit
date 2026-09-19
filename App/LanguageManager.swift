import Foundation
import SwiftUI

extension Notification.Name {
    static let appLanguageDidChange = Notification.Name("com.xwei.GocryptKit.appLanguageDidChange")
}

public final class LanguageManager: ObservableObject, @unchecked Sendable {
    public static let shared = LanguageManager()

    private let lock = NSLock()
    private var activeLanguage: String = "system"
    private var activeBundle: Bundle = Bundle.main
    private var activeLocale: Locale = Locale.autoupdatingCurrent

    @Published public private(set) var currentLanguage: String = "system"
    @Published public private(set) var currentBundle: Bundle = Bundle.main
    @Published public private(set) var currentLocale: Locale = Locale.autoupdatingCurrent

    private init() {
        let saved = UserDefaults.standard.string(forKey: "appLanguage") ?? "system"
        syncInternal(lang: saved, syncAppleLanguages: false)
        self.currentLanguage = saved
        self.currentBundle = activeBundle
        self.currentLocale = activeLocale
    }

    /// Synchronizes AppleLanguages at app startup before NSApplication initializes.
    public func syncStartupLanguage() {
        let saved = UserDefaults.standard.string(forKey: "appLanguage") ?? "system"
        if saved == "system" {
            UserDefaults.standard.removeObject(forKey: "AppleLanguages")
        } else {
            UserDefaults.standard.set([saved], forKey: "AppleLanguages")
        }
        syncInternal(lang: saved, syncAppleLanguages: false)
        self.currentLanguage = saved
        self.currentBundle = activeBundle
        self.currentLocale = activeLocale
    }

    @MainActor
    public func setLanguage(_ lang: String) {
        syncInternal(lang: lang, syncAppleLanguages: true)
        self.currentLanguage = lang
        self.currentBundle = activeBundle
        self.currentLocale = activeLocale
        NotificationCenter.default.post(name: .appLanguageDidChange, object: nil)
    }

    private func syncInternal(lang: String, syncAppleLanguages: Bool) {
        lock.lock()
        activeLanguage = lang

        let bundle: Bundle
        let locale: Locale

        switch lang {
        case "en":
            locale = Locale(identifier: "en")
            if let path = Bundle.main.path(forResource: "en", ofType: "lproj"),
               let b = Bundle(path: path) {
                bundle = b
            } else {
                bundle = Bundle.main
            }
        case "zh-Hans":
            locale = Locale(identifier: "zh-Hans")
            if let path = Bundle.main.path(forResource: "zh-Hans", ofType: "lproj"),
               let b = Bundle(path: path) {
                bundle = b
            } else {
                bundle = Bundle.main
            }
        default:
            locale = Locale.autoupdatingCurrent
            let preferred = Bundle.preferredLocalizations(from: ["en", "zh-Hans"], forPreferences: Locale.preferredLanguages).first ?? "en"
            if let path = Bundle.main.path(forResource: preferred, ofType: "lproj"),
               let b = Bundle(path: path) {
                bundle = b
            } else {
                bundle = Bundle.main
            }
        }

        activeBundle = bundle
        activeLocale = locale
        lock.unlock()

        UserDefaults.standard.set(lang, forKey: "appLanguage")
        if syncAppleLanguages {
            if lang == "system" {
                UserDefaults.standard.removeObject(forKey: "AppleLanguages")
            } else {
                UserDefaults.standard.set([lang], forKey: "AppleLanguages")
            }
        }
    }

    public func localized(_ key: String.LocalizationValue) -> String {
        lock.lock()
        let b = activeBundle
        let l = activeLocale
        lock.unlock()
        return String(localized: key, bundle: b, locale: l)
    }
}

public func loc(_ key: String.LocalizationValue) -> String {
    LanguageManager.shared.localized(key)
}
