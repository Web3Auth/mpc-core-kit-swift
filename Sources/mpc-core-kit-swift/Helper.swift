import BigInt
import FetchNodeDetails
import Foundation

#if canImport(tkey)
    import tkey
#endif

#if canImport(curveSecp256k1)
    import curveSecp256k1
#endif

#if canImport(tssClientSwift)
    import tssClientSwift
#endif

public class FactorDescription: Codable {
    public let module: FactorType
    public let tssIndex: TssShareType
    public let description: String?
    public let dateAdded: Int

    public init(module: FactorType, tssIndex: TssShareType, description: String?, dateAdded: Int) {
        self.module = module
        self.tssIndex = tssIndex
        self.description = description
        self.dateAdded = dateAdded
    }
}

public func createCoreKitFactorDescription(module: FactorType, tssIndex: TssShareType, dateAdded: Int, description: String? = nil) -> FactorDescription {
    return FactorDescription(module: module, tssIndex: tssIndex, description: description, dateAdded: dateAdded)
}

func factorDescriptionToJsonStr(dataObj: FactorDescription) throws -> String {
    let json = try JSONEncoder().encode(dataObj)
    guard let jsonStr = String(data: json, encoding: .utf8) else {
        throw CoreKitError.invalidResult
    }
    return jsonStr
}
