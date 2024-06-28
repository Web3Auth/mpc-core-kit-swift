import Foundation

@testable import mpc_core_kit_swift
import XCTest

class helper_swiftTests: XCTestCase {
    func testJsonSerialization() throws {
        let state = CoreKitAppState(factorKey: nil, metadataPubKey: nil, deviceMetadataShareIndex: "", loginTime: nil)
        let jsonState = try JSONEncoder().encode(state).bytes
        let result = try JSONSerialization.data(withJSONObject: ["test": jsonState])

        let resultObject = try JSONSerialization.jsonObject(with: result) as! [String: Any]
        let obj = resultObject["test"] as! Array<UInt8>
        let decoded = try JSONDecoder().decode(CoreKitAppState.self, from: Data(obj))
        XCTAssertEqual(state, decoded)
    }
}
