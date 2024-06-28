import BigInt
import FetchNodeDetails
import Foundation
import SingleFactorAuth

#if canImport(tkey)
    import tkey
#endif

#if canImport(curveSecp256k1)
    import curveSecp256k1
#endif

#if canImport(tssClientSwift)
    import tssClientSwift
#endif


public func createCoreKitFactorDescription(module: FactorType, tssIndex: TssShareType, additional: [String: Any] = [:]) -> [String: Any] {
    var description = additional

    description["module"] = module
    description["tssShareIndex"] = tssIndex
    description["dateAdded"] = Date().timeIntervalSince1970

    return description
}

func factorDescriptionToJsonStr(dataObj: [String: Any]) throws -> String {
    let json = try JSONSerialization.data(withJSONObject: dataObj)
    guard let jsonStr = String(data: json, encoding: .utf8) else {
        throw CoreKitError.invalidResult
    }
    return jsonStr
}

func convertWeb3AuthNetworkToTorusNetWork(network: Web3AuthNetwork) -> TorusNetwork {
    switch network {
    case Web3AuthNetwork.SAPPHIRE_DEVNET: return .sapphire(.SAPPHIRE_DEVNET)
    case Web3AuthNetwork.SAPPHIRE_MAINNET: return .sapphire(.SAPPHIRE_MAINNET)
    case Web3AuthNetwork.MAINNET: return .legacy(.MAINNET)
    case Web3AuthNetwork.TESTNET: return .legacy(.TESTNET)
    case Web3AuthNetwork.CYAN: return .legacy(.CYAN)
    case Web3AuthNetwork.AQUA: return .legacy(.AQUA)
    case Web3AuthNetwork.CELESTE: return .legacy(.CELESTE)
    case Web3AuthNetwork.CUSTOM: return .sapphire(.SAPPHIRE_MAINNET)
    }
}

public extension Web3AuthNetwork {
    func toTorusNetwork() -> TorusNetwork {
        return convertWeb3AuthNetworkToTorusNetWork(network: self)
    }
}
