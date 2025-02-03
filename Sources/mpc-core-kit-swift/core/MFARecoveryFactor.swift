import Foundation

public class MFARecoveryFactor {
    public var factorKey: String?
    public var factorTypeDescription: FactorType
    public var additionalMetadata: [String: Codable]

    public init(factorKey: String? = nil, factorTypeDescription: FactorType = .other, additionalMetadata: [String: Codable] = [:]) {
        self.factorKey = factorKey
        self.factorTypeDescription = factorTypeDescription
        self.additionalMetadata = additionalMetadata
    }
}
