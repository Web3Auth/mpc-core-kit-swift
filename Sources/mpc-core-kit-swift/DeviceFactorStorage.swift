import Foundation

public class DeviceFactorStorage: IFactorStorage {
    let storage: CoreKitStorage

    public init(storage: CoreKitStorage) {
        self.storage = storage
    }

    public func setFactor(metadataPubKey: String, factorKey: String) async throws {
        var localMetadata: [String: Any] = try await storage.get(key: metadataPubKey)
    
        localMetadata["factorKey"] = factorKey
        try await storage.set(key: metadataPubKey, payload: localMetadata)
    }

    public func getFactor(metadataPubKey: String) async throws -> String {
        let localMetadata: [String: Any] = try await storage.get(key: metadataPubKey)
        guard let deviceFactor = localMetadata["factorKey"] as? String else {
            throw CoreKitError.notFound(msg: "device factor not found")
        }
        return deviceFactor
    }
}

