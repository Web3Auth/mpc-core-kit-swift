import Foundation

public protocol IStorage {
    func set(key: String, payload: Data) async throws -> Void
    func get(key: String) async throws -> Data
}
