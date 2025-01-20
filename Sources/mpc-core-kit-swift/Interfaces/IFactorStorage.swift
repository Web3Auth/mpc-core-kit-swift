import Foundation

public protocol IFactorStorage {
    func setFactor(metadataPubKey: String, factorKey: String) async throws -> Void
    func getFactor(metadataPubKey: String) async throws -> String
}
