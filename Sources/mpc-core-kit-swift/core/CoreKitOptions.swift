import Foundation
import SingleFactorAuth

public struct CoreKitOptions {
    public var disableHashFactor: Bool
    public var Web3AuthClientId: String
    public var network: Web3AuthNetwork
    public var manualSync: Bool
}
