import Foundation

public class TssSecurityQuestionStore: Codable {
    public var shareIndex: String
    public var factorPublicKey: String
    public var question: String

    public init(shareIndex: String, factorPublicKey: String, question: String) {
        self.shareIndex = shareIndex
        self.factorPublicKey = factorPublicKey
        self.question = question
    }
}
