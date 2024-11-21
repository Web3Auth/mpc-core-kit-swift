import Foundation

public class DeviceFactorStorage: IFactorStorage {
    let storage: CoreKitStorage

    public init(storage: CoreKitStorage) {
        self.storage = storage
    }

    public func setFactor(metadataPubKey: String, factorKey: String) async throws {
        guard let factorKeyData = Data(hexString: factorKey) else {
            throw CoreKitError.invalidFactorKey
        }
        try await storage.set(key: metadataPubKey, payload: factorKeyData)
    }

    public func getFactor(metadataPubKey: String) async throws -> String {
        let localMetadata: Data = try await storage.get(key: metadataPubKey)
        return localMetadata.hexString
    }
}
