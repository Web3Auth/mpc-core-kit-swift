import Foundation

public class ChangeSecurityQuestionParams: Codable {
    public var newQuestion: String
    public var newAnswer: String
    public var answer: String

    public init(newQuestion: String, newAnswer: String, answer: String) {
        self.newQuestion = newQuestion
        self.newAnswer = newAnswer
        self.answer = answer
    }
}
