import Foundation

/// Password strength rating provided to users when creating a new vault.
///
/// This is a **heuristic hint**, not a hard requirement: the engine will not reject
/// vault creation due to weak passwords, except for completely empty ones.
/// The estimation is intentionally kept simple and conservative — it calculates a lower bound
/// of entropy based on the character classes actually present. Repeated characters only contribute
/// half length to prevent classifying inputs like `aaaaaaaaaaaa` as strong. It does not perform dictionary
/// lookups and cannot recognize common passwords such as `password123`, so it prefers underestimating over overestimating.
public enum PasswordStrength: Int, Sendable, Comparable, CaseIterable {
    case tooShort
    case weak
    case fair
    case strong

    public static func < (lhs: PasswordStrength, rhs: PasswordStrength) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    /// Minimum password length required by the UI when creating a vault.
    public static let minimumLength = 4

    public var label: String {
        switch self {
        case .tooShort: return "Too short"
        case .weak:     return "Weak"
        case .fair:     return "Fair"
        case .strong:   return "Strong"
        }
    }

    public var advice: String {
        switch self {
        case .tooShort: return "At least \(Self.minimumLength) characters required"
        case .weak:     return "Make it longer; mix uppercase, lowercase, numbers, and symbols"
        case .fair:     return "A bit longer would be safer"
        case .strong:   return "Sufficient strength"
        }
    }

    /// Estimates the strength of `password`.
    public static func evaluate(_ password: String) -> PasswordStrength {
        let chars = Array(password.unicodeScalars)
        guard chars.count >= minimumLength else { return .tooShort }

        var pool = 0
        if chars.contains(where: { $0.properties.isLowercase }) { pool += 26 }
        if chars.contains(where: { $0.properties.isUppercase }) { pool += 26 }
        if chars.contains(where: { ("0"..."9").contains(String($0)) }) { pool += 10 }
        // Treat remaining characters as belonging to the printable ASCII symbol set (33 chars);
        // non-ASCII characters are also bucketed here: underestimating will not make weak passwords appear strong.
        if chars.contains(where: {
            !$0.properties.isAlphabetic && !("0"..."9").contains(String($0))
        }) { pool += 33 }
        guard pool > 1 else { return .weak }

        // Repeated characters provide significantly less marginal entropy than unique characters; count them at half weight.
        let unique = Set(chars).count
        let effectiveLength = Double(unique) + Double(chars.count - unique) / 2
        let bits = effectiveLength * log2(Double(pool))

        switch bits {
        case ..<40:  return .weak
        case ..<60:  return .fair
        default:     return .strong
        }
    }
}
