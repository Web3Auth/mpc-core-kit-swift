import CustomAuth
import FetchNodeDetails
import Foundation
import SingleFactorAuth
import TorusUtils

#if canImport(tkey)
    import tkey
#endif

#if canImport(curveSecp256k1)
    import curveSecp256k1
#endif

public class MpcCoreKit {
    internal var selectedTag: String?
    internal var factorKey: String?
    internal var userInfo: [String:Any]
    internal var option: Web3AuthOptions
//    internal var state: CoreKitstate
    
    
    public var metadataPubKey: String? = nil
    public var oAuthKey: String? = nil
    // share index used for backup share recovery
    public var deviceMetadataShareIndex: String? = nil
    public var loginTime: Date? = nil

    public var metadataHostUrl: String?
    public var tkey: ThresholdKey?
    public var tssEndpoints: [String]?
    public var authSigs: [String]?
    public var verifier: String?
    public var verifierId: String?
    public var torusUtils: TorusUtils
    public var nodeIndexes: [Int]?
    public var nodeDetails: AllNodeDetailsModel?
    public var nodeDetailsManager: NodeDetailManager
    public var sigs: [String]?
    
    public var coreKitStorage: CoreKitStorage
    private let storeKey = "corekitStore"
    private let localstateKey = "localstate"
    private let customAuth: CustomAuth

    
    public init(options: Web3AuthOptions) throws {
        if options.web3AuthClientId.isEmpty {
            throw CoreKitError.invalidInput
        }
        self.option = options

        self.nodeDetailsManager = NodeDetailManager(network: option.web3AuthNetwork)
        let torusOptions = TorusOptions(clientId: option.web3AuthClientId, network: option.web3AuthNetwork, enableOneKey: true)
        self.torusUtils = try TorusUtils(params: torusOptions)

        self.coreKitStorage = CoreKitStorage(storeKey: storeKey, storage: option.localStorage)

        let config = CustomAuthArgs(urlScheme: "tdsdk://tdsdk/oauthCallback", network: option.web3AuthNetwork, enableOneKey: true, web3AuthClientId: option.web3AuthClientId)
        self.customAuth = try CustomAuth(config: config)
        self.userInfo = [:]
    }

    public func getCurrentFactorKey() throws -> String {
        guard let factor = self.factorKey else {
            throw CoreKitError.factorKeyUnavailable
        }
        return factor
    }

    public func getDeviceMetadataShareIndex() throws -> String {
        guard let shareIndex = self.deviceMetadataShareIndex else {
            throw CoreKitError.notFound(msg: "share index not found")
        }
        return shareIndex
    }

    public func loginWithOAuth(singleLoginParams: SingleLoginParams) async throws -> MpcKeyDetails {
        let loginResponse = try await customAuth.triggerLogin(args: singleLoginParams)

        let result = try await login(keyDetails: loginResponse.torusKey, verifier: loginResponse.singleVerifierResponse.userInfo.verifier, verifierId: loginResponse.singleVerifierResponse.userInfo.verifierId)
        let jsonData = try JSONEncoder().encode(loginResponse.singleVerifierResponse.userInfo)
        
        self.userInfo = try JSONSerialization.jsonObject(with: jsonData, options: []) as? [String: Any] ?? [:]
        
        return result
    }

    public func loginWithOAuth(aggregateLoginParams: AggregateLoginParams) async throws -> MpcKeyDetails {
        let loginResponse = try await customAuth.triggerAggregateLogin(args: aggregateLoginParams)
        let result = try await login(keyDetails: loginResponse.torusKey, verifier: loginResponse.torusAggregateVerifierResponse.first!.userInfo.verifier, verifierId: loginResponse.torusAggregateVerifierResponse.first!.userInfo.verifierId)
        
        let jsonData = try JSONEncoder().encode(loginResponse.torusAggregateVerifierResponse.first?.userInfo)
        self.userInfo = try JSONSerialization.jsonObject(with: jsonData, options: []) as? [String: Any] ?? [:]
        
        return result
    }

    public func mnemonicToKey(shareMnemonic: String, format: String) throws -> String {
        let factorKey = try ShareSerializationModule.deserialize_share(threshold_key: tkey!, share: shareMnemonic, format: format)
        return factorKey
    }

    public func keyToMnemonic(factorKey: String, format: String) throws -> String {
        let mnemonic = try ShareSerializationModule.serialize_share(threshold_key: tkey!, share: factorKey, format: format)
        return mnemonic
    }

    public func loginWithJwt(verifier: String, verifierId: String, idToken: String) async throws -> MpcKeyDetails {
        let singleFactor = try SingleFactorAuth(singleFactorAuthArgs: SingleFactorAuthArgs(web3AuthClientId: option.web3AuthClientId, network: option.web3AuthNetwork))
        let torusKey = try await singleFactor.getTorusKey(loginParams: LoginParams(verifier: verifier, verifierId: verifierId, idToken: idToken))
        
        let result = try await login(keyDetails: torusKey, verifier: verifier, verifierId: verifierId)
        
        self.userInfo["verifier"] = verifier
        self.userInfo["verifierId"] = verifierId
        self.userInfo["idToken"] = idToken
        
        return result
    }

    public func getUserInfo() throws -> [String: Any] {
        return userInfo
    }

    public func getKeyDetails() async throws -> MpcKeyDetails {
        if tkey == nil {
            throw CoreKitError.notInitialized
        }

        guard let finalKeyDetails = try tkey?.get_key_details() else {
            throw CoreKitError.keyDetailsNotFound
        }
        let tssTag = try TssModule.get_tss_tag(threshold_key: tkey!)
        let tssPubKey = try await TssModule.get_tss_pub_key(threshold_key: tkey!, tss_tag: tssTag)

        let factorsCount = try await getAllFactorPubs().count
        let keyDetails = MpcKeyDetails(
            tssPubKey: tssPubKey,
            metadataPubKey: try finalKeyDetails.pub_key.getPublicKey(format: PublicKeyEncoding.FullAddress),
            requiredFactors: self.factorKey == nil ? 1 : 0,  // assuming we 2/n
            threshold: finalKeyDetails.threshold,
            shareDescriptions: finalKeyDetails.share_descriptions,
            totalShares: finalKeyDetails.total_shares,
            totalFactors: UInt32(factorsCount) + 1
        )
        return keyDetails
    }

    // login should return key_details
    // with factor key if new user
    // with required factor > 0 if existing user
    private func login(keyDetails: TorusKey, verifier: String, verifierId: String) async throws -> MpcKeyDetails {
        self.oAuthKey = getOAuthKey(result: keyDetails)
        
        self.verifier = verifier
        self.verifierId = verifierId
        
        // get from service provider/ torusUtils
        nodeIndexes = keyDetails.nodesData.nodeIndexes.sorted()

        let fnd = nodeDetailsManager
        
        let nodeDetails = try await fnd.getNodeDetails(verifier: verifier, verifierID: verifierId)
        
        if (self.option.overwriteMetadataUrl != nil) {
            metadataHostUrl = self.option.overwriteMetadataUrl
        } else {
            guard let host = nodeDetails.getTorusNodeEndpoints().first else {
                throw CoreKitError.invalidNode
            }
            guard let metadatahost = URL(string: host)?.host else {
                throw CoreKitError.invalidMetadataEndpoint
            }
            metadataHostUrl = "https://" + metadatahost + "/metadata"
        }

        self.nodeDetails = nodeDetails

        tssEndpoints = nodeDetails.torusNodeTSSEndpoints

        guard let postboxkey = self.oAuthKey else {
            throw CoreKitError.invalidPostboxKey
        }

        let sessionTokenData = keyDetails.sessionData.sessionTokenData

        let signatures = sessionTokenData.map { token in
            ["data": token!.token,
             "sig": token!.signature]
        }

        let sigs: [String] = try signatures.map { String(decoding: try JSONSerialization.data(withJSONObject: $0), as: UTF8.self) }

        authSigs = sigs

        guard let metadataEndpoint = metadataHostUrl else {
            throw "Invalid metadata url endpoint"
        }
        
        // initialize tkey
        let storage_layer = try StorageLayer(enable_logging: true, host_url: metadataEndpoint, server_time_offset: 2)

        let service_provider = try ServiceProvider(enable_logging: true, postbox_key: postboxkey, useTss: true, verifier: verifier, verifierId: verifierId, nodeDetails: nodeDetails)

        let rss_comm = try RssComm()

        self.tkey = try ThresholdKey(
            storage_layer: storage_layer,
            service_provider: service_provider,
            enable_logging: true,
            manual_sync: option.manualSync,
            rss_comm: rss_comm)

        let key_details = try await self.tkey!.initialize(never_initialize_new_key: false, include_local_metadata_transitions: false)
        self.metadataPubKey = try key_details.pub_key.getPublicKey(format: .EllipticCompress)

        if key_details.required_shares > 0 {
            try await existingUser()
        } else {
            try await newUser()
        }

        return try await self.getKeyDetails()
    }

    private func existingUser() async throws {
        guard let thresholdKey = tkey else {
            throw CoreKitError.invalidTKey
        }
        
        do {
            // try check for hash factor
            
            let hashFactor = try Utilities.getHashedPrivateKey(postboxKey: self.oAuthKey!, clientID: option.web3AuthClientId)
            let hashFactorPub = try SecretKey(hex: hashFactor).toPublic().serialize(compressed: true)
            let allFactorPub = try await self.getAllFactorPubs()
            
            if option.disableHashFactor == false && !allFactorPub.contains(hashFactorPub){
                try await inputFactor(factorKey: hashFactor)
                factorKey = hashFactor
            } else {
                let factor = try await getDeviceFactor()
                // TODO: factors need to be verified before insertion
                try await inputFactor(factorKey: factor)
                factorKey = factor
            }
            
            self.deviceMetadataShareIndex = try await TssModule.find_device_share_index(threshold_key: thresholdKey, factor_key: factorKey!)
            self.metadataPubKey = try thresholdKey.get_key_details().pub_key.getPublicKey(format: .EllipticCompress)

        } catch {
            
        }
    }

    private func newUser() async throws {
        guard let tkey = tkey else {
            throw CoreKitError.invalidTKey
        }
        guard let nodeDetails = nodeDetails else {
            throw CoreKitError.nodeDetailsMissing
        }

        let _ = try await tkey.reconstruct()

        
        // backup metadata share using factorKey
        // finding device share index
        var shareIndexes = try tkey.get_shares_indexes()
        shareIndexes.removeAll(where: { $0 == "1" })

        // TSS Module Initialize - create default tag
        // generate factor key or use oauthkey hash as factor
        let factorKey: String
        let descriptionTypeModule: FactorType

        let hashFactorKey = try Utilities.getHashedPrivateKey(postboxKey: self.oAuthKey!, clientID: option.web3AuthClientId)
        
        if option.disableHashFactor == false {
            factorKey = hashFactorKey
            descriptionTypeModule = FactorType.HashedShare
            
        } else {
            // random generate
            factorKey = try curveSecp256k1.SecretKey().serialize()
            descriptionTypeModule = FactorType.DeviceShare
            
            // delete exisiting hashFactor backupshare if available
            try await self.deleteMetadataShareBackup(factorKey: hashFactorKey)
        }

        // derive factor pub
        let factorPub = try curveSecp256k1.SecretKey(hex: factorKey).toPublic().serialize(compressed: false)

        // use input to create tag tss share
        let tssIndex = TssShareType.device

        let defaultTag = "default"
        try await TssModule.create_tagged_tss_share(threshold_key: tkey, tss_tag: defaultTag, deviceTssShare: nil, factorPub: factorPub, deviceTssIndex: tssIndex.rawValue, nodeDetails: nodeDetails, torusUtils: torusUtils)

        try TssModule.backup_share_with_factor_key(threshold_key: tkey, shareIndex: shareIndexes[0], factorKey: factorKey)
        // record share description
        let description = createCoreKitFactorDescription(module: descriptionTypeModule, tssIndex: tssIndex, dateAdded: Int(Date().timeIntervalSince1970))
        let jsonStr = try factorDescriptionToJsonStr(dataObj: description)
        try await tkey.add_share_description(key: factorPub, description: jsonStr)

        self.factorKey = factorKey
        self.deviceMetadataShareIndex = shareIndexes[0]
        
        self.metadataPubKey = try tkey.get_key_details().pub_key.getPublicKey(format: .EllipticCompress)
        
        // save as device factor if hashfactor is disable
        if option.disableHashFactor == true {
            try await setDeviceFactor(factorKey: factorKey)
        }
    }

    public func logout() async throws {
        // TODO how to clear all state
        self.factorKey = nil
        self.authSigs = nil
        self.sigs = nil
        
        self.tkey = nil
        self.metadataHostUrl = nil
        self.nodeDetails = nil
        self.nodeIndexes = nil
        
        self.verifier = nil
        self.verifierId = nil
        self.userInfo = [:]
        
        self.oAuthKey = nil
        self.metadataPubKey = nil
        self.deviceMetadataShareIndex = nil
        
    }

    public func inputFactor(factorKey: String) async throws {
        guard let threshold_key = tkey else {
            throw CoreKitError.invalidTKey
        }
        
        let allFactorPubs = try await self.getAllFactorPubs()
        let factorPub = try SecretKey(hex: factorKey).toPublic().serialize(compressed: true)
        if (!allFactorPubs.contains(factorPub)) {
            throw "Invalid factor \(factorKey)"
        }
        
        // input factor
        try await threshold_key.input_factor_key(factorKey: factorKey)

        // try using better methods ?
        self.deviceMetadataShareIndex = try await TssModule.find_device_share_index(threshold_key: threshold_key, factor_key: factorKey)
        
        // setup tkey ( assuming only 2 factor is required)
        let _ = try await threshold_key.reconstruct()
        let selectedTag = try TssModule.get_tss_tag(threshold_key: threshold_key)
        let _ = try await TssModule.get_tss_share(threshold_key: threshold_key, tss_tag: selectedTag, factorKey: factorKey)
        self.factorKey = factorKey
    }

    public func publicKey() async throws -> String {
        guard let threshold_key = tkey else {
            throw CoreKitError.invalidTKey
        }
        let selectedTag = try TssModule.get_tss_tag(threshold_key: threshold_key)

        return try await TssModule.get_tss_pub_key(threshold_key: threshold_key, tss_tag: selectedTag)
    }

    public func commitChanges() async throws {
        // create a copy syncMetadata
        guard let tkey = tkey else {
            throw CoreKitError.notInitialized
        }
        try await tkey.sync_local_metadata_transistions()
    }

    // To remove reset account function
    public func resetAccount() async throws {
        guard let postboxkey = self.oAuthKey else {
            throw CoreKitError.notLoggedIn
        }

        guard let threshold_key = tkey else {
            throw CoreKitError.invalidTKey
        }

        guard let _ = metadataHostUrl else {
            throw CoreKitError.invalidMetadataUrl
        }

        try await threshold_key.storage_layer_set_metadata(private_key: postboxkey, json: "{ \"message\": \"KEY_NOT_FOUND\" }")

        // reset state
        try await resetDeviceFactorStore()
        let _ = try await coreKitStorage.resetStore()
    }
}


// Device Factor Manipulation
extension MpcCoreKit {
    public func getDeviceFactor() async throws -> String {
        // getMetadataPublicKey compressed
        guard let metadataPubKey = self.metadataPubKey else {
            throw CoreKitError.metadataPubKeyUnavailable
        }
        
        let deviceFactorStorage = DeviceFactorStorage(storage: coreKitStorage)
        return try await deviceFactorStorage.getFactor(metadataPubKey: metadataPubKey)
    }
    
    public func setDeviceFactor(factorKey: String) async throws {
        guard let metadataPubKey = self.metadataPubKey else {
            throw CoreKitError.metadataPubKeyUnavailable
        }
        let deviceFactorStorage = DeviceFactorStorage(storage: coreKitStorage)
        try await deviceFactorStorage.setFactor(metadataPubKey: metadataPubKey, factorKey: factorKey)
    }
    
    internal func resetDeviceFactorStore() async throws {
        guard let metadataPubKey = self.metadataPubKey else {
            throw CoreKitError.metadataPubKeyUnavailable
        }
        try await coreKitStorage.set(key: metadataPubKey, payload: Data())
    }
    
}



extension MpcCoreKit {
    private func getMetadataShare() async throws -> ShareStore {
        let stores = try tkey!.get_all_share_stores_for_latest_polynomial()
        var share: ShareStore? = nil
        let length = try stores.length()
        for i in 0..<length {
            let store = try stores.getAt(index: i)
            let index = try store.share_index()
            if !index.elementsEqual("1") {
                share = store
            }
        }
        
        if share == nil {
            throw CoreKitError.notFound(msg: "No metadata share was found.")
        }
        
        return share!
    }
    
    private func deleteMetadataShareBackup(factorKey: String) async throws {
        var input: [String: Any] = [:]
        input.updateValue("SHARE_DELETED", forKey: "message")
        input.updateValue(Int(Date().timeIntervalSince1970), forKey: "dataAdded")
        var inputs: [String: [[String: Any]]] = [:]
        inputs.updateValue([input], forKey: "input")

        let payload = try JSONSerialization.data(withJSONObject: inputs)
        try tkey!.add_local_metadata_transitions(input_json: String(data: payload, encoding: .utf8)!, private_key: factorKey)
        if (!option.manualSync) {
            try await tkey!.sync_local_metadata_transistions()
        }
    }
    
    private func backupMetadataShare(factorKey: String) async throws {
        let metadataShare = try await getMetadataShare()
        
        try tkey!.add_local_metadata_transitions(input_json: metadataShare.toJsonString(), private_key: factorKey)
    }
    
    private func addFactorDescription (
        factorKey: String,
        shareDescription: FactorType,
        additionalMetadata: [String:String],
        updateMetadata: Bool = true
    ) async throws  {
        let tssIndex = try await TssModule.get_tss_share(threshold_key: self.tkey!, tss_tag: "default", factorKey: factorKey)
        let factorPub = try SecretKey(hex: factorKey).toPublic().serialize(compressed: false)
        
        var input: [String: Any] = [:]
        input.updateValue(shareDescription, forKey: "module")
        input.updateValue(Int(Date().timeIntervalSince1970), forKey: "dataAdded")
        input.updateValue(tssIndex, forKey: "tssIndex")
        for item in additionalMetadata {
            input.updateValue(item.value, forKey: item.key)
        }

        let payload = try JSONSerialization.data(withJSONObject: input)
        
        try await tkey!.add_share_description(key: factorPub, description: String(data: payload, encoding: .utf8)!, update_metadata: updateMetadata)
    }
    
    private func setupProvider() {
        // requires signing provider
    }
    
//    private func updateState(updates: CoreKitstate) async throws {
//        self.state.merge(with: updates)
////        let jsonState = try JSONEncoder().encode(state)
////        try await coreKitStorage.set(key: localstateKey, payload: jsonState)
//    }
    
    private func resetState() {
        self.tkey = nil
    }
    
    private func getOAuthKey(result: TorusKey) -> String {
        return TorusUtils.getPostboxKey(torusKey: result)
    }
    
    private func getSignatures(sessionData: TorusKey.SessionData) -> [[String: String]] {
        let signatures = sessionData.sessionTokenData.map { token in
            ["data": token!.token,
             "sig": token!.signature]
        }
        return signatures
    }
    
    private func getSigningSignatures() throws -> [String] {
        guard let sigs = self.authSigs else {
            throw CoreKitError.invalidAuthSignatures
        }
        return sigs
    }
    
    internal class AccessRequestParams: Codable {
        public var network: String
        public var client_id: String
        public var is_mpc_core_kit: String = "true"
        public var enable_gating: String = "true"
        
        public init(network: String, client_id: String) {
            self.network = network
            self.client_id = client_id
        }
    }
    
    private func featureRequest() async throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        
        let accessUrl = option.web3AuthNetwork.signerMap
        var request = try Utilities.makeUrlRequest(url: "\(accessUrl)/api/feature-access")
        let params = AccessRequestParams(network: option.web3AuthNetwork.name, client_id: option.web3AuthClientId)
        request.httpBody = try encoder.encode(params)
        let urlSession = URLSession(configuration: .default)
        let (val, _) = try await urlSession.data(for: request)
        return String(data: val, encoding: .utf8)!
    }
    
    private func getNonce() async throws {
        // requires tkey-mpc extension
        return;
    }
    
    private func logDecorator<T, U>(function: @escaping (T) -> U) -> (T) -> U {
        return { arg in
            print("Function called with argument: \(arg)")
            let result = function(arg)
            print("Function returned: \(result)")
            return result
        }
    }
}
