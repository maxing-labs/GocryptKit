import Foundation

public enum VaultCredentialPayload {
    case password(String)
    case scryptHash(Data)
    
    // Protocol format: [Magic 4B: "VCP1"][Tag 1B][Length 2B (BE)][Value NB]
    private static let magic: [UInt8] = [0x56, 0x43, 0x50, 0x31] // "VCP1"
    
    public func serialize() -> Data {
        var data = Data()
        data.append(contentsOf: Self.magic)
        
        switch self {
        case .password(let pwd):
            data.append(0x01)
            let pwdData = Data(pwd.utf8)
            let length = UInt16(pwdData.count)
            data.append(UInt8((length >> 8) & 0xFF))
            data.append(UInt8(length & 0xFF))
            data.append(pwdData)
        case .scryptHash(let hash):
            data.append(0x02)
            let length = UInt16(hash.count)
            data.append(UInt8((length >> 8) & 0xFF))
            data.append(UInt8(length & 0xFF))
            data.append(hash)
        }
        return data
    }
    
    public static func deserialize(from data: Data) -> VaultCredentialPayload? {
        // Minimum header: 4B Magic + 1B Tag + 2B Length = 7B
        guard data.count >= 7 else { return nil }
        guard data[0] == magic[0], data[1] == magic[1], data[2] == magic[2], data[3] == magic[3] else {
            return nil
        }
        
        let tag = data[4]
        let length = Int(UInt16(data[5]) << 8 | UInt16(data[6]))
        guard data.count == 7 + length else { return nil }
        
        let payload = data.dropFirst(7)
        
        switch tag {
        case 0x01:
            guard let pwdString = String(data: payload, encoding: .utf8) else { return nil }
            return .password(pwdString)
        case 0x02:
            guard payload.count == 32 else { return nil }
            return .scryptHash(Data(payload))
        default:
            return nil
        }
    }
}
