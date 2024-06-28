import Foundation

public class SetSecurityQuestionParams: Codable {
    public var question: String
    public var answer: String
    public var shareType: TssShareType
    public var description: String?
    public var tssIndex: TssShareType
    public var tssTag: String
    
    public init(question: String, answer: String, shareType: TssShareType = TssShareType.recovery, description: String? = nil, tssIndex: TssShareType, tssTag: String) {
        self.question = question
        self.answer = answer
        self.shareType = shareType
        self.description = description
        self.tssIndex = tssIndex
        self.tssTag = tssTag
    }
}
