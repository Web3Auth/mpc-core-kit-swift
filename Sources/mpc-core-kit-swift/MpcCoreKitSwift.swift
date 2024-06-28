import Foundation
import CustomAuth
import FetchNodeDetails
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

    // TODO: Replace [String: Any] with [String: Codable], throughout
    internal var userInfo: [String: Any]?

    internal var oauthKey: String?
    internal var network: Web3AuthNetwork
    internal var option: CoreKitOptions

    internal var appState: CoreKitAppState

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

    private let localAppStateKey = "localAppState"

    // init
    // TODO: This should accept a param class instead
    public init(web3AuthClientId: String, web3AuthNetwork: Web3AuthNetwork, disableHashFactor: Bool = false, localStorage: ILocalStorage, manualSync: Bool = false) throws {
        if web3AuthClientId.isEmpty {
            throw CoreKitError.invalidInput
        }
        
        option = CoreKitOptions(disableHashFactor: disableHashFactor, Web3AuthClientId: web3AuthClientId, network: web3AuthNetwork, manualSync: manualSync) // TODO: This could be passed in instead
        
        appState = CoreKitAppState()

        network = web3AuthNetwork

        torusUtils = TorusUtils(enableOneKey: true, network: network.toTorusNetwork(), clientId: web3AuthClientId)

        nodeDetailsManager = NodeDetailManager(network: network.toTorusNetwork())

        coreKitStorage = CoreKitStorage(storeKey: storeKey, storage: localStorage)
    }

    public func updateAppState(state: CoreKitAppState) async throws {
        appState.merge(with: state)

        let jsonState = try JSONEncoder().encode(appState).bytes
        try await coreKitStorage.set(key: localAppStateKey, payload: jsonState)
    }

    public func getCurrentFactorKey() throws -> String {
        guard let factor = appState.factorKey else {
            throw CoreKitError.factorKeyUnavailable
        }
        return factor
    }

    public func getDeviceMetadataShareIndex() throws -> String {
        guard let shareIndex = appState.deviceMetadataShareIndex else {
            throw CoreKitError.notFound(msg: "share index not found")
        }
        return shareIndex
    }

    // TODO: This should accept a param class instead
    public func loginWithOAuth(loginProvider: LoginProviders, clientId: String, verifier: String, jwtParams: [String: String] = [:], redirectURL: String = "tdsdk://tdsdk/oauthCallback", browserRedirectURL: String = "https://scripts.toruswallet.io/redirect.html") async throws -> MpcKeyDetails {
        if loginProvider == .jwt && jwtParams.isEmpty {
            throw CoreKitError.notFound(msg: "jwt login should provide jwtParams")
        }

        let sub = SubVerifierDetails(loginType: .web,
                                     loginProvider: loginProvider,
                                     clientId: clientId,
                                     verifier: verifier,
                                     redirectURL: redirectURL,
                                     browserRedirectURL: browserRedirectURL,
                                     jwtParams: jwtParams
        )
        
        let customAuth = CustomAuth(web3AuthClientId: option.Web3AuthClientId, aggregateVerifierType: .singleLogin, aggregateVerifier: verifier, subVerifierDetails: [sub], network: network.toTorusNetwork(), enableOneKey: true)

        let userData = try await customAuth.triggerLogin()
        return try await login(userData: userData)
    }

    // mneomonic to share
    public func mnemonicToKey(shareMnemonic: String, format: String) throws -> String {
        // Assuming ShareSerializationModule.deserializeMnemonic returns Data
        let factorKey = try ShareSerializationModule.deserialize_share(threshold_key: tkey!, share: shareMnemonic, format: format)
        return factorKey
    }

    // share to mneomonic
    public func keyToMnemonic(factorKey: String, format: String) throws -> String {
        // Assuming ShareSerializationModule.deserializeMnemonic returns Data
        let mnemonic = try ShareSerializationModule.serialize_share(threshold_key: tkey!, share: factorKey, format: format)
        return mnemonic
    }

    public func loginWithJwt(verifier: String, verifierId: String, idToken: String, userInfo: [String: Any] = [:]) async throws -> MpcKeyDetails {
        let singleFactor = SingleFactorAuth(singleFactorAuthArgs: SingleFactorAuthArgs(web3AuthClientId: option.Web3AuthClientId, network: network))

        let torusKey = try await singleFactor.getTorusKey(loginParams: LoginParams(verifier: verifier, verifierId: verifierId, idToken: idToken))
        var modUserInfo = userInfo
        modUserInfo.updateValue(verifier, forKey: "verifier")
        modUserInfo.updateValue(verifierId, forKey: "verifierId")
        return try await login(userData: TorusKeyData(torusKey: torusKey, userInfo: modUserInfo))
    }

    public func getUserInfo() throws -> [String: Any] {
        guard let userInfo = userInfo else {
            throw CoreKitError.notLoggedIn
        }
        return userInfo
    }

    public func getKeyDetails() async throws -> MpcKeyDetails {
        if tkey == nil {
            throw CoreKitError.notInitialized
        }

        guard let finalKeyDetails = try tkey?.get_key_details() else {
            throw CoreKitError.keyDetailsNotFound
        }

        let tssTags = try TssModule.get_all_tss_tags(threshold_key: tkey!)
        if tssTags.isEmpty {
            throw CoreKitError.noTssTags
        }
        let tssTag = try TssModule.get_tss_tag(threshold_key: tkey!)
        let tssPubKey = try await TssModule.get_tss_pub_key(threshold_key: tkey!, tss_tag: tssTag)

        let factorsCount = try await getAllFactorPubs().count
        let keyDetails = MpcKeyDetails(
            tssPubKey: tssPubKey,
            metadataPubKey: try finalKeyDetails.pub_key.getPublicKey(format: PublicKeyEncoding.FullAddress),
            requiredFactors: finalKeyDetails.required_shares,
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
    private func login(userData: TorusKeyData) async throws -> MpcKeyDetails {
        oauthKey = userData.torusKey.oAuthKeyData?.privKey
        userInfo = userData.userInfo

        guard let verifierLocal = userData.userInfo["verifier"] as? String, let verifierIdLocal = userData.userInfo["verifierId"] as? String else {
            throw CoreKitError.invalidVerifierOrVerifierID
        }

        verifier = verifierLocal
        verifierId = verifierIdLocal

        // get from service provider/ torusUtils
        nodeIndexes = []

        let fnd = nodeDetailsManager
        let nodeDetails = try await fnd.getNodeDetails(verifier: verifierLocal, verifierID: verifierIdLocal)

        guard let host = nodeDetails.getTorusNodeEndpoints().first else {
            throw CoreKitError.invalidNode
        }
        guard let metadatahost = URL(string: host)?.host else {
            throw CoreKitError.invalidMetadataEndpoint
        }

        let metadataEndpoint = "https://" + metadatahost + "/metadata"

        metadataHostUrl = metadataEndpoint

        self.nodeDetails = nodeDetails

        tssEndpoints = nodeDetails.torusNodeTSSEndpoints

        guard let postboxkey = oauthKey else {
            throw CoreKitError.invalidPostboxKey
        }

        guard let sessionData = userData.torusKey.sessionData else {
            throw CoreKitError.invalidSessionData
        }

        let sessionTokenData = sessionData.sessionTokenData

        let signatures = sessionTokenData.map { token in
            ["data": Data(hex: token!.token).base64EncodedString(),
             "sig": token!.signature]
        }

        let sigs: [String] = try signatures.map { String(decoding: try JSONSerialization.data(withJSONObject: $0), as: UTF8.self) }

        authSigs = sigs

        // initialize tkey
        let storage_layer = try StorageLayer(enable_logging: true, host_url: metadataEndpoint, server_time_offset: 2)

        let service_provider = try ServiceProvider(enable_logging: true, postbox_key: postboxkey, useTss: true, verifier: verifier, verifierId: verifierId, nodeDetails: nodeDetails)

        let rss_comm = try RssComm()
        
        tkey = try ThresholdKey(
            storage_layer: storage_layer,
            service_provider: service_provider,
            enable_logging: true,
            manual_sync: option.manualSync,
            rss_comm: rss_comm)

        let key_details = try await tkey!.initialize(never_initialize_new_key: false, include_local_metadata_transitions: false)
        appState.metadataPubKey = try key_details.pub_key.getPublicKey(format: .EllipticCompress)
        
        if key_details.required_shares > 0 {
            try await existingUser()
        } else {
            try await newUser()
        }

        // to add tss pub details to corekit details
        let finalKeyDetails = try tkey!.get_key_details()
        let tssTags = try TssModule.get_all_tss_tags(threshold_key: tkey!)
        if tssTags.isEmpty {
            throw CoreKitError.noTssTags
        }
        let tssTag = try TssModule.get_tss_tag(threshold_key: tkey!)

        let tssPubKey = try await TssModule.get_tss_pub_key(threshold_key: tkey!, tss_tag: tssTag)

        return MpcKeyDetails(tssPubKey: tssPubKey, metadataPubKey: try finalKeyDetails.pub_key.getPublicKey(format: .EllipticCompress), requiredFactors: finalKeyDetails.required_shares, threshold: finalKeyDetails.threshold, shareDescriptions: finalKeyDetails.share_descriptions, totalShares: finalKeyDetails.total_shares, totalFactors: 0)
    }

    private func existingUser() async throws {
        guard tkey != nil else {
            throw CoreKitError.invalidTKey
        }

        // try check for hash factor
        if option.disableHashFactor == false {
            let factor = try Utilities.getHashedPrivateKey(postboxKey: oauthKey!, clientID: option.Web3AuthClientId)
            // TODO: factors need to be verified before insertion
            try await inputFactor(factorKey: factor)
            factorKey = factor
        } else {
            let factor = try await getDeviceFactor()
            // TODO: factors need to be verified before insertion
            try await inputFactor(factorKey: factor)
            factorKey = factor
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

        // TSS Module Initialize - create default tag
        // generate factor key or use oauthkey hash as factor
        let factorKey: String
        let descriptionTypeModule: FactorType
        
        if option.disableHashFactor == false {
            factorKey = try Utilities.getHashedPrivateKey(postboxKey: oauthKey!, clientID: option.Web3AuthClientId)
            descriptionTypeModule = FactorType.HashedShare

        } else {
            // random generate
            factorKey = try curveSecp256k1.SecretKey().serialize()
            descriptionTypeModule = FactorType.DeviceShare
        }

        // derive factor pub
        let factorPub = try curveSecp256k1.SecretKey(hex: factorKey).toPublic().serialize(compressed: false)

        // use input to create tag tss share
        let tssIndex = TssShareType.device

        let defaultTag = "default"
        try await TssModule.create_tagged_tss_share(threshold_key: tkey, tss_tag: defaultTag, deviceTssShare: nil, factorPub: factorPub, deviceTssIndex: tssIndex.rawValue, nodeDetails: nodeDetails, torusUtils: torusUtils)

        // backup metadata share using factorKey
        // finding device share index
        var shareIndexes = try tkey.get_shares_indexes()
        shareIndexes.removeAll(where: { $0 == "1" })

        try TssModule.backup_share_with_factor_key(threshold_key: tkey, shareIndex: shareIndexes[0], factorKey: factorKey)

        // record share description
        let description = createCoreKitFactorDescription(module: descriptionTypeModule, tssIndex: tssIndex)
        let jsonStr = try factorDescriptionToJsonStr(dataObj: description)
        try await tkey.add_share_description(key: factorPub, description: jsonStr)

        self.factorKey = factorKey
        let deviceMetadataShareIndex = try await TssModule.find_device_share_index(threshold_key: tkey, factor_key: factorKey)

        let metadataPubKey = try tkey.get_key_details().pub_key.getPublicKey(format: .EllipticCompress)
        try await updateAppState(state: CoreKitAppState(factorKey: factorKey, metadataPubKey: metadataPubKey, deviceMetadataShareIndex: deviceMetadataShareIndex))

        // save as device factor if hashfactor is disable
        if option.disableHashFactor == true {
            try await setDeviceFactor(factorKey: factorKey)
        }
    }

    public func logout() async throws {
        appState = CoreKitAppState()
        let jsonState = try JSONEncoder().encode(appState).bytes
        try await coreKitStorage.set(key: localAppStateKey, payload: jsonState)
    }

    public func inputFactor(factorKey: String) async throws {
        guard let threshold_key = tkey else {
            throw CoreKitError.invalidTKey
        }
        // input factor
        // TODO: factors need to be verified before insertion
        try await threshold_key.input_factor_key(factorKey: factorKey)

        // try using better methods ?
        let deviceMetadataShareIndex = try await TssModule.find_device_share_index(threshold_key: threshold_key, factor_key: factorKey)
        try await updateAppState(state: CoreKitAppState(deviceMetadataShareIndex: deviceMetadataShareIndex))

        // setup tkey ( assuming only 2 factor is required)
        let _ = try await threshold_key.reconstruct()

        let tssTags = try TssModule.get_all_tss_tags(threshold_key: tkey!)
        if tssTags.isEmpty {
            throw CoreKitError.noTssTags
        }
        let selectedTag = try TssModule.get_tss_tag(threshold_key: threshold_key)
        let _ = try await TssModule.get_tss_share(threshold_key: threshold_key, tss_tag: selectedTag, factorKey: factorKey)
        self.factorKey = factorKey
    }

    public func publicKey() async throws -> String {
        guard let threshold_key = tkey else {
            throw CoreKitError.invalidTKey
        }
        let tssTags = try TssModule.get_all_tss_tags(threshold_key: tkey!)
        if tssTags.isEmpty {
            throw CoreKitError.noTssTags
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
        guard let postboxkey = oauthKey else {
            throw CoreKitError.notLoggedIn
        }

        guard let threshold_key = tkey else {
            throw CoreKitError.invalidTKey
        }

        guard let _ = metadataHostUrl else {
            throw CoreKitError.invalidMetadataUrl
        }

        try await threshold_key.storage_layer_set_metadata(private_key: postboxkey, json: "{ \"message\": \"KEY_NOT_FOUND\" }")

        // reset appState
        try await resetDeviceFactorStore()
        try await coreKitStorage.set(key: localAppStateKey, payload: [:])

//        try await self.coreKitStorage.set(key: self.localAppStateKey, payload: [:])
    }
}


extension MpcCoreKit {
    public func getDeviceFactor() async throws -> String {
        // getMetadataPublicKey compressed
        guard let metadataPubKey = appState.metadataPubKey else {
            throw CoreKitError.metadataPubKeyUnavailable
        }

        let deviceFactorStorage = DeviceFactorStorage(storage: coreKitStorage)
        return try await deviceFactorStorage.getFactor(metadataPubKey: metadataPubKey)
    }

    public func setDeviceFactor(factorKey: String) async throws {
        guard let metadataPubKey = appState.metadataPubKey else {
            throw CoreKitError.metadataPubKeyUnavailable
        }
        let deviceFactorStorage = DeviceFactorStorage(storage: coreKitStorage)
        try await deviceFactorStorage.setFactor(metadataPubKey: metadataPubKey, factorKey: factorKey)
    }

    internal func resetDeviceFactorStore() async throws {
        guard let metadataPubKey = appState.metadataPubKey else {
            throw CoreKitError.metadataPubKeyUnavailable
        }
        try await coreKitStorage.set(key: metadataPubKey, payload: [:])
    }
}

