import Foundation

@testable import mpc_core_kit_swift
import XCTest

class helper_swiftTests: XCTestCase {
    func testJsonSerialization() throws {
        let state = CoreKitstate(factorKey: nil, metadataPubKey: nil, deviceMetadataShareIndex: "", loginTime: nil)
        let jsonState = try JSONEncoder().encode(state)
        let decoded = try JSONDecoder().decode(CoreKitstate.self, from: Data(jsonState))
        
        XCTAssertEqual(state, decoded)
    }
}
