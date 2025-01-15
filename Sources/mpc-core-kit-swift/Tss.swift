import BigInt
import CustomAuth
import Foundation
import TorusUtils
import tssClientSwift

#if canImport(UIKit)
import UIKit
#elseif canImport(AppKit)
import AppKit
#endif

#if canImport(tkey)
    import tkey
#endif

#if canImport(curveSecp256k1)
    import curveSecp256k1
#endif

extension MpcCoreKit {
    public func getTssPubKey() throws -> Data {
        guard tkey != nil else {
            throw CoreKitError.invalidTKey
        }

        guard let tssPubKey = tssPubKey else {
            throw CoreKitError.invalidTssPubKey
        }

        guard let res = Data(hexString: tssPubKey) else {
            throw CoreKitError.invalidTssPubKey
        }
        return res
    }

    /// Signing Data without hashing
    public func tssSign(message: Data) async throws -> Data {
        guard let signatures = signatures else {
            throw CoreKitError.invalidAuthSignatures
        }

        guard let tkey = tkey else {
            throw CoreKitError.invalidTKey
        }

        if factorKey == nil {
            throw CoreKitError.invalidFactorKey
        }

        let selectedTag = try TssModule.get_tss_tag(threshold_key: tkey)
        // Create tss Client using helper

        let (client, coeffs) = try await bootstrapTssClient(selected_tag: selectedTag)

        // Wait for sockets to be connected
        let connected = try client.checkConnected()
        if !connected {
            throw TSSClientError("Client not connected")
        }

        let precompute = try client.precompute(serverCoeffs: coeffs, signatures: signatures)
        let ready = try client.isReady()
        if !ready {
            throw TSSClientError("Error, client not ready")
        }

        let signingMessage = message.base64EncodedString()
        let (s, r, v) = try! client.sign(message: signingMessage, hashOnly: true, original_message: "", precompute: precompute, signatures: signatures)

        try! client.cleanup(signatures: signatures)

        return r.magnitude.serialize() + s.magnitude.serialize() + Data([v])
    }
    
    
    private func tssSignCompletion( message: Data,  completion: @escaping (_ tssResult:Data? , _ tssError:Error?) -> Void) {
        Task {
            do {
                let localSignature = try await self.tssSign(message: message)
                completion(localSignature, nil)
            } catch {
                completion(nil , error)
            }
        }
    }
    
    public func tssSignSync(message: Data) throws -> Data {
        var signature: Data?;
        var error: Error?

        let semaphore = DispatchSemaphore(value: 0)
        tssSignCompletion(message: message){ tssReult , tssError in
            signature = tssReult
            error = tssError
            semaphore.signal()
        }
        semaphore.wait()

        if let unwrapSignature = signature {
            return unwrapSignature
        }

        throw error ?? CoreKitError.invalidResult
    }

    public func getAllFactorPubs() async throws -> [String] {
        guard let threshold_key = tkey else {
            throw CoreKitError.invalidTKey
        }
        let currentTag = try TssModule.get_tss_tag(threshold_key: threshold_key)
        return try await TssModule.get_all_factor_pub(threshold_key: threshold_key, tss_tag: currentTag)
    }

    /// * A BN used for encrypting your Device/ Recovery TSS Key Share. You can generate it using `generateFactorKey()` function or use an existing one.
    ///
    /// factorKey?: BN;
    /// Setting the Description of Share - Security Questions, Device Share, Seed Phrase, Password Share, Social Share, Other. Default is Other.
    ///
    /// shareDescription?: FactorKeyTypeShareDescription;
    ///  * Additional metadata information you want to be stored alongside this factor for easy identification.
    /// additionalMetadata?: Record<string, string>;
    public func createFactor(tssShareIndex: TssShareType, factorKey: String?, factorDescription: FactorType, additionalMetadata: [String: Any] = [:]) async throws -> String {
        // check for index is same as factor key
        guard let thresholdKey = tkey else {
            throw CoreKitError.invalidTKey
        }
        guard let curFactorKey = self.factorKey else {
            throw CoreKitError.invalidFactorKey
        }

        let newFactor = try factorKey ?? curveSecp256k1.SecretKey().serialize()
        let selectedTag = try TssModule.get_tss_tag(threshold_key: thresholdKey)
        let (tssIndex, _) = try await TssModule.get_tss_share(threshold_key: thresholdKey, tss_tag: selectedTag, factorKey: curFactorKey)
        // create new factor if different index
        if tssIndex == String(tssShareIndex.rawValue) {
            try await copyFactor(newFactorKey: newFactor, tssShareIndex: tssShareIndex)
        } else {
            // copy if same index
            try await addNewFactor(newFactorKey: newFactor, tssShareIndex: tssShareIndex)
        }

        // backup metadata share using factorKey
        let shareIndex = try getDeviceMetadataShareIndex()
        try TssModule.backup_share_with_factor_key(threshold_key: thresholdKey, shareIndex: shareIndex, factorKey: newFactor)

        // update description
        let description = createCoreKitFactorDescription(module: FactorType.HashedShare, tssIndex: tssShareIndex, dateAdded: Int(Date().timeIntervalSince1970))
        let jsonStr = try factorDescriptionToJsonStr(dataObj: description)
        let factorPub = try curveSecp256k1.SecretKey(hex: newFactor).toPublic().serialize(compressed: true)
        try await thresholdKey.add_share_description(key: factorPub, description: jsonStr)

        return newFactor
    }

    public func deleteFactor(deleteFactorPub: String, deleteFactorKey: String? = nil) async throws {
        guard let thresholdKey = tkey, let factorKey = factorKey, let sigs = signatures else {
            throw CoreKitError.invalidTKey
        }
        let selectedTag = try TssModule.get_tss_tag(threshold_key: thresholdKey)
        try await TssModule.delete_factor_pub(threshold_key: thresholdKey, tss_tag: selectedTag, factor_key: factorKey, auth_signatures: sigs, delete_factor_pub: deleteFactorPub, nodeDetails: nodeDetails!, torusUtils: torusUtils)

        // delete backup metadata share with factorkey
        if let deleteFactorKey = deleteFactorKey {
            let factorkey = try curveSecp256k1.SecretKey(hex: deleteFactorKey)
            if try factorkey.toPublic().serialize(compressed: true) != curveSecp256k1.PublicKey(hex: deleteFactorPub).serialize(compressed: true) {
                // unmatch public key
                throw CoreKitError.factorKeyAndFactorPubMismatch
            }
            // set metadata to Not Found
            try await thresholdKey.storage_layer_set_metadata(private_key: deleteFactorKey, json: "{ \"message\": \"KEY_NOT_FOUND\" }")
        }
    }

    private func copyFactor(newFactorKey: String, tssShareIndex: TssShareType) async throws {
        guard let threshold_key = tkey, let factorKey = factorKey else {
            throw CoreKitError.invalidTKey
        }
        let selectedTag = try TssModule.get_tss_tag(threshold_key: threshold_key)

        let newkey = try curveSecp256k1.SecretKey(hex: newFactorKey)
        let newFactorPub = try newkey.toPublic().serialize(compressed: true)

        // backup metadata share with factorkey
        let shareIndex = try getDeviceMetadataShareIndex()
        try TssModule.backup_share_with_factor_key(threshold_key: threshold_key, shareIndex: shareIndex, factorKey: newFactorKey)

        try await TssModule.copy_factor_pub(threshold_key: threshold_key, tss_tag: selectedTag, factorKey: factorKey, newFactorPub: newFactorPub, tss_index: tssShareIndex.rawValue)
    }

    private func addNewFactor(newFactorKey: String, tssShareIndex: TssShareType) async throws {
        guard let threshold_key = tkey, let factorKey = factorKey, let sigs = signatures else {
            throw CoreKitError.invalidTKey
        }

        let selectedTag = try TssModule.get_tss_tag(threshold_key: threshold_key)

        let newkey = try curveSecp256k1.SecretKey(hex: newFactorKey)
        let newFactorPub = try newkey.toPublic().serialize(compressed: true)

        // backup metadata share with factorkey
        let shareIndex = try getDeviceMetadataShareIndex()
        try TssModule.backup_share_with_factor_key(threshold_key: threshold_key, shareIndex: shareIndex, factorKey: newFactorKey)

        try await TssModule.add_factor_pub(threshold_key: threshold_key, tss_tag: selectedTag, factor_key: factorKey, auth_signatures: sigs, new_factor_pub: newFactorPub, new_tss_index: tssShareIndex.rawValue, nodeDetails: nodeDetails!, torusUtils: torusUtils)
    }

    public func enableMFA() async throws {
        if factorKey == nil {
            throw CoreKitError.invalidMetadataPubKey
        }

        let hashFactorKey = try Utilities.getHashedPrivateKey(postboxKey: postboxKey!, hashedFactorNonce: option.hashedFactorNonce)
        let currentFactor = try getCurrentFactorKey().factorKey

        if currentFactor != hashFactorKey {
            throw CoreKitError.currentFactorNotHashFactor
        }
        #if canImport(UIKit)
        let additionalDeviceMetadata = await [
            "device": UIDevice.current.model,
            "name": UIDevice.current.name,
        ]
        #elseif canImport(AppKit)
        let additionalDeviceMetadata = [
            "device": "Mac",
            "name": ProcessInfo.processInfo.hostName,
        ]
        #endif
        
        let deviceFactor = try await createFactor(tssShareIndex: .device, factorKey: nil, factorDescription: .DeviceShare, additionalMetadata: additionalDeviceMetadata)

        // store to device
        try await setDeviceFactor(factorKey: deviceFactor)
        try await inputFactorKey(factorKey: deviceFactor)

        // delete hash factor key
        let hashFactorPub = try curveSecp256k1.SecretKey(hex: hashFactorKey).toPublic().serialize(compressed: true)
        try await deleteFactor(deleteFactorPub: hashFactorPub, deleteFactorKey: hashFactorKey)
    }

    public func enableMFAWithRecoveryFactor(enableMFA: MFARecoveryFactor = MFARecoveryFactor()) async throws -> String {
        try await self.enableMFA()
        let recovery = try await createFactor(tssShareIndex: .recovery, factorKey: enableMFA.factorKey, factorDescription: enableMFA.factorTypeDescription, additionalMetadata: enableMFA.additionalMetadata)
        return recovery
    }

    private func bootstrapTssClient(selected_tag: String) async throws -> (TSSClient, [String: String]) {
        guard let tkey = tkey else {
            throw CoreKitError.invalidTKey
        }

        guard let verifier = verifier, let verifierId = verifierId, let tssEndpoints = tssEndpoints, let nodeIndexes = nodeIndexes,
              let tssIndex = tssIndex, let tssPubKey = tssPubKey , let factorKey = factorKey else {
            throw CoreKitError.invalidInput
            
        }
        
        let (_, tssShare) = try await TssModule.get_tss_share(threshold_key: tkey, tss_tag: selected_tag, factorKey: factorKey)
        
        
        let tssNonce = try TssModule.get_tss_nonce(threshold_key: tkey, tss_tag: selected_tag)

        let publicKey = try curveSecp256k1.PublicKey(hex: tssPubKey).serialize(compressed: false)

        if publicKey.count < 128 || publicKey.count > 130 {
            throw CoreKitError.requireUncompressedPublicKey
        }

        // generate a random nonce for sessionID
        let randomKey = try BigUInt(Data(hexString: curveSecp256k1.SecretKey().serialize())!)
        let random = BigInt(sign: .plus, magnitude: randomKey) + BigInt(Date().timeIntervalSince1970)
        let sessionNonce = TSSHelpers.base64ToBase64url(base64: try TSSHelpers.hashMessage(message: random.magnitude.serialize().addLeading0sForLength64().hexString))

        // create the full session string
        let session = TSSHelpers.assembleFullSession(verifier: verifier, verifierId: verifierId, tssTag: selected_tag, tssNonce: String(tssNonce), sessionNonce: sessionNonce)

        let userTssIndex = BigInt(tssIndex, radix: 16)!
        // total parties, including the client
        let parties = nodeIndexes.count > 0 ? nodeIndexes.count + 1 : 4

        // index of the client, last index of partiesIndexes
        let clientIndex = Int32(parties - 1)

        let (urls, socketUrls, partyIndexes, nodeInd) = try TSSHelpers.generateEndpoints(parties: parties, clientIndex: Int(clientIndex), nodeIndexes: nodeIndexes, urls: tssEndpoints)

        let coeffs = try TSSHelpers.getServerCoefficients(participatingServerDKGIndexes: nodeInd.map({ BigInt($0) }), userTssIndex: userTssIndex)

        let shareUnsigned = BigUInt(tssShare, radix: 16)!
        let share = try TSSHelpers.denormalizeShare(participatingServerDKGIndexes: nodeInd.map({ BigInt($0) }), userTssIndex: userTssIndex, userTssShare: BigInt(sign: .plus, magnitude: shareUnsigned))

        let client = try TSSClient(session: session, index: Int32(clientIndex), parties: partyIndexes.map({ Int32($0) }), endpoints: urls.map({ URL(string: $0 ?? "") }), tssSocketEndpoints: socketUrls.map({ URL(string: $0 ?? "") }), share: TSSHelpers.base64Share(share: share), pubKey: try TSSHelpers.base64PublicKey(pubKey: Data(hexString: publicKey)!))

        return (client, coeffs)
    }
}
