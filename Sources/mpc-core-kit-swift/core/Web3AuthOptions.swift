import FetchNodeDetails
import Foundation

public class CoreKitWeb3AuthOptions {
    public let web3AuthClientId: String
    public let manualSync: Bool
    public let web3AuthNetwork: Web3AuthNetwork
    public let storageKey: String?
    public let sessionTime: Int?
    public let disableHashedFactorKey: Bool
    public let storage: IStorage
    // It is used to define the URL for the Metadata to be used in the SDK.
    // This is for internal testing only, and shouldn't be used.
    public let overwriteMetadataUrl: String?
    public let hashedFactorNonce: String

    public init(web3AuthClientId: String, manualSync: Bool = false, web3AuthNetwork: Web3AuthNetwork, storage: IStorage, storageKey: String? = "local", sessionTime: Int? = 86000, disableHashedFactorKey: Bool = false, overwriteMetadataUrl: String? = nil, hashedFactorNonce: String? = nil) {
        self.web3AuthClientId = web3AuthClientId
        self.manualSync = manualSync
        self.web3AuthNetwork = web3AuthNetwork
        self.storageKey = storageKey
        self.sessionTime = sessionTime
        self.storage = storage
        self.disableHashedFactorKey = disableHashedFactorKey
        self.overwriteMetadataUrl = overwriteMetadataUrl
        self.hashedFactorNonce = hashedFactorNonce ?? web3AuthClientId
    }
}
