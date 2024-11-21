import Foundation
import mpc_core_kit_swift

internal class MemoryStorage: ILocalStorage {
    var memory: [String: Data] = [:]

    public func get(key: String) async throws -> Data {
        guard let result = memory[key] else {
            return Data()
        }
        return result
    }

    public func set(key: String, payload: Data) async throws {
        memory.updateValue(payload, forKey: key)
    }
}
