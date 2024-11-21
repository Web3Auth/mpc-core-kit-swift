import FetchNodeDetails
import Foundation

public class CoreKitWeb3AuthOptions {
    public let web3AuthClientId: String
    public let manualSync: Bool
    public let web3AuthNetwork: Web3AuthNetwork
    public let storageKey: String?
    public let sessionTime: Int?
    public let disableHashFactor: Bool
    public let localStorage: ILocalStorage
    public let overwriteMetadataUrl: String?

    public init(web3AuthClientId: String, manualSync: Bool, web3AuthNetwork: Web3AuthNetwork, localStorage: ILocalStorage, storageKey: String? = "local", sessionTime: Int? = 86000, disableHashFactor: Bool = false, overwriteMetadataUrl: String? = nil) {
        self.web3AuthClientId = web3AuthClientId
        self.manualSync = manualSync
        self.web3AuthNetwork = web3AuthNetwork
        self.storageKey = storageKey
        self.sessionTime = sessionTime
        self.localStorage = localStorage
        self.disableHashFactor = disableHashFactor
        self.overwriteMetadataUrl = overwriteMetadataUrl
    }
}
