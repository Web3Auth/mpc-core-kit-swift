import Foundation

public enum FactorType: String, Codable {
    case hashedShare = "hashedShare"
    case securityQuestions = "tssSecurityQuestions"
    case deviceShare = "deviceShare"
    case seedPhrase = "seedPhrase"
    case passwordShare = "passwordShare"
    case socialShare = "socialShare"
    case other
}
