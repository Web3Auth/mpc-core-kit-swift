import Foundation
import JWTDecode

#if canImport(curveSecp256k1)
    import curveSecp256k1
#endif

#if canImport(tssClientSwift)
    import tssClientSwift
#endif

#if canImport(tkey)
    import tkey
#endif

class Utilities {
    public static func generateFactorKey() throws -> (SecretKey, PublicKey) {
        let factorKey = SecretKey()
        let factorPub = try factorKey.toPublic()
        return (factorKey, factorPub)
    }

    public static func generateTssEndpoints(tssNodeEndpoints: [String], parties: Int, clientIndex: Int, nodeIndexes: [Int?] = []) throws -> ([String?], [String?], partyIndexes: [Int], nodeIndexes: [Int]) {
        return try TSSHelpers.generateEndpoints(parties: parties, clientIndex: clientIndex, nodeIndexes: nodeIndexes, urls: tssNodeEndpoints)
    }

    public static func parseToken(token: String) throws -> any JWT {
        let jwt = try decode(jwt: token)
        return jwt
    }

    public static func getHashedPrivateKey(postboxKey: String, hashedFactorNonce: String) throws -> String {
        if postboxKey.isEmpty || hashedFactorNonce.isEmpty {
            throw CoreKitError.invalidInput
        }

        let uid = postboxKey + "_" + hashedFactorNonce

        let hashUID = try uid.data(using: .utf8)!.sha3(varient: .KECCAK256).hexString

        let key = try curveSecp256k1.SecretKey(hex: hashUID).serialize()

        return key
    }

    public static func convertPublicKeyFormat(publicKey: String, outFormat: PublicKeyEncoding) throws -> String {
        let point = try KeyPoint(address: publicKey)
        let result = try point.getPublicKey(format: outFormat)
        return result
    }

    public static func hashMessage(message: String) throws -> String {
        return try TSSHelpers.hashMessage(message: message)
    }

    internal enum httpMethod {
        case get
        case post

        var name: String {
            switch self {
            case .get:
                return "GET"
            case .post:
                return "POST"
            }
        }
    }

    internal static func makeUrlRequest(url: String, httpMethod: httpMethod = .post) throws -> URLRequest {
        guard
            let url = URL(string: url)
        else {
            throw CoreKitError.runtime("Invalid Url \(url)")
        }
        var rq = URLRequest(url: url)
        rq.httpMethod = httpMethod.name
        rq.addValue("application/json", forHTTPHeaderField: "Content-Type")
        rq.addValue("application/json", forHTTPHeaderField: "Accept")
        return rq
    }
}
