import Foundation

public class CoreKitStorage {
    public var storage: ILocalStorage
    private var storeKey: String

    public init(storeKey: String, storage: ILocalStorage) {
        self.storage = storage
        self.storeKey = storeKey
    }

    public func resetStore() async throws -> Data {
        let result = try await storage.get(key: storeKey)
        let payload = try JSONSerialization.data(withJSONObject: [:])

        try await storage.set(key: storeKey, payload: payload)

        return result
    }

    public func getStringified() async throws -> String {
        // TODO: JSONDecoder and appropriate types, if applicable
        let result = try await storage.get(key: storeKey)
        guard let resultStr = String(data: result, encoding: .utf8) else {
            throw CoreKitError.invalidStore
        }
        return resultStr
    }

    public func getStore() async throws -> [String: Any] {
        let result = try await storage.get(key: storeKey)
        if result.isEmpty { return [:] }
        let store = try JSONSerialization.jsonObject(with: result) as? [String: Any]
        guard let storeUnwrapped = store else {
            throw CoreKitError.invalidStore
        }
        return storeUnwrapped
    }

    public func get<T>(key: String) async throws -> T {
        let store = try await getStore()
        guard let item = store[key] as? T else {
            throw CoreKitError.notFound(msg: "key \(key) value  not found")
        }
        return item
    }

    public func set<T>(key: String, payload: T) async throws {
        var store: [String: Any] = try await getStore()
        store.updateValue(payload, forKey: key)
        let jsonData = try JSONSerialization.data(withJSONObject: store)
        try await storage.set(key: storeKey, payload: jsonData)
    }

    public func remove(key: String) async throws {
        var store = try await getStore()
        store[key] = nil
        let jsonData = try JSONSerialization.data(withJSONObject: store)
        try await storage.set(key: storeKey, payload: jsonData)
    }
}
