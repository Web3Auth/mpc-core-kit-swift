import Foundation

#if canImport(tkey)
    import tkey
#endif

public class CoreKitstate: Codable, Equatable {
    public static func == (lhs: CoreKitstate, rhs: CoreKitstate) -> Bool {
        return lhs.factorKey == rhs.factorKey && lhs.metadataPubKey == rhs.metadataPubKey && lhs.deviceMetadataShareIndex == rhs.deviceMetadataShareIndex && lhs.loginTime == rhs.loginTime && lhs.postboxKey == rhs.postboxKey
    }

    public var factorKey: String? = nil
    public var metadataPubKey: String? = nil
    public var postboxKey: String? = nil

    // share index used for backup share recovery
    public var deviceMetadataShareIndex: String? = nil

    public var loginTime: Date? = nil

    init(factorKey: String? = nil, metadataPubKey: String? = nil, deviceMetadataShareIndex: String? = nil, loginTime: Date? = nil, postboxKey: String? = nil) {
        self.factorKey = factorKey
        self.metadataPubKey = metadataPubKey
        self.deviceMetadataShareIndex = deviceMetadataShareIndex
        self.loginTime = loginTime
        self.postboxKey = postboxKey
    }

    // Method to merge data from another instance of MyStruct
    func merge(with other: CoreKitstate) {
        // TODO: Is this supposed to be a potentially partial merge vs a deep copy?

        // Update properties based on merging logic
        if other.factorKey != nil {
            factorKey = other.factorKey
        }
        if other.metadataPubKey != nil {
            metadataPubKey = other.metadataPubKey
        }
        if other.deviceMetadataShareIndex != nil {
            deviceMetadataShareIndex = other.deviceMetadataShareIndex
        }
        if other.loginTime != nil {
            loginTime = other.loginTime
        }
    }
}

public struct MpcKeyDetails: Codable {
    public let tssPubKey: String
    public let metadataPubKey: String
    public let requiredFactors: Int32
    public let threshold: UInt32
    public let shareDescriptions: String
    public let totalShares: UInt32
    public let totalFactors: UInt32?
//    public let requiredFactors: String
}

public struct IdTokenLoginParams: Codable {
    /**
     * Name of the verifier created on Web3Auth Dashboard. In case of Aggregate Verifier, the name of the top level aggregate verifier.
     */
    public var verifier: String

    /**
     * Unique Identifier for the User. The verifier identifier field set for the verifier/ sub verifier. E.g. "sub" field in your on jwt id token.
     */
    public var verifierId: String

    /**
     * The idToken received from the Auth Provider.
     */
    public var idToken: String

    /**
     * Name of the sub verifier in case of aggregate verifier setup. This field should only be provided in case of an aggregate verifier.
     */
    public var subVerifier: String?

    /**
     * Extra verifier params in case of a WebAuthn verifier type.
     */
    //  public var extraVerifierParams?: WebAuthnExtraParams;

    //  /**
    //   * Any additional parameter (key value pair) you'd like to pass to the login function.
    //   */
    //  public var additionalParams: [String: Any]?

    /**
     * Key to import key into Tss during first time login.
     */
    //  public var importTssKey?: String

    public var domain: String?
}

public struct FactorKeyData : Codable {
    public var factorKey: String;
    public var tssIndex: String;
}

public enum CoreKitStatus {
    case notInitialized
    case requireFactor
    case loggedIn
}
