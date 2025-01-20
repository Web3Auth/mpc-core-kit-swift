import Foundation

public enum FactorType: String, Codable {
    case HashedShare = "hashedShare"
    case SecurityQuestions = "tssSecurityQuestions"
    case DeviceShare = "deviceShare"
    case SeedPhrase = "seedPhrase"
    case PasswordShare = "passwordShare"
    case SocialShare = "socialShare"
    case Other
}
