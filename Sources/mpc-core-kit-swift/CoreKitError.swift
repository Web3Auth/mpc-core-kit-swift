import Foundation

public enum CoreKitError: Error {
    case invalidResult
    case invalidInput
    case notFound(msg: String)
    case factorKeyUnavailable
    case metadataPubKeyUnavailable
    case shareIndexNotFound
    case notLoggedIn
    case notInitialized
    case keyDetailsNotFound
    case invalidVerifierOrVerifierID
    case invalidNode
    case invalidMetadataEndpoint
    case invalidPostboxKey
    case invalidSessionData
    case invalidTKey
    case nodeDetailsMissing
    case invalidMetadataUrl
    case invalidOAuthKey
    case invalidHashKey
    case invalidAuthSignatures
    case invalidFactorKey
    case factorKeyAndFactorPubMismatch
    case invalidMetadataPubKey
    case currentFactorNotHashFactor
    case requireUncompressedPublicKey
    case invalidStore
    case noTssTags

    public var errorDescription: String {
        switch self {
        case .invalidResult:
            return "Invalid Result"
        case let .notFound(msg: msg):
            return msg
        case .metadataPubKeyUnavailable:
            return "Metadata public key is not available"
        case .invalidInput:
            return "Invalid input"
        case .factorKeyUnavailable:
            return "Factor key unavailable"
        case .shareIndexNotFound:
            return "Share index not found"
        case .notLoggedIn:
            return "User is not logged in"
        case .notInitialized:
            return "User is not initialized"
        case .keyDetailsNotFound:
            return "Key details not found"
        case .invalidVerifierOrVerifierID:
            return "Invalid verifier or verifierID"
        case .invalidNode:
            return "Invalid verifier or verifierID"
        case .invalidMetadataEndpoint:
            return "Invalid verifier or verifierID"
        case .invalidPostboxKey:
            return "Invalid postbox key"
        case .invalidSessionData:
            return "Invalid session data"
        case .invalidTKey:
            return "Invalid tKey"
        case .nodeDetailsMissing:
            return "Node details absent"
        case .invalidMetadataUrl:
            return "Invalid metadata url"
        case .invalidOAuthKey:
            return "Invalid OAuthKey"
        case .invalidHashKey:
            return "Invalid hash key"
        case .invalidAuthSignatures:
            return "Invalid auth signatures"
        case .invalidFactorKey:
            return "Invalid factor key"
        case .factorKeyAndFactorPubMismatch:
            return "Factor key does not match factor public key"
        case .invalidMetadataPubKey:
            return "Invalid metadata public key"
        case .currentFactorNotHashFactor:
            return "Current factor is not hash factor"
        case .requireUncompressedPublicKey:
            return "Public key needs to be in uncompressed format"
        case .invalidStore:
            return "Invalid Store"
        case .noTssTags:
            return "No Tss tags have been set"
        }
    }
}
