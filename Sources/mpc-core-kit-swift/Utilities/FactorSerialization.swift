import Foundation

#if canImport(tkey)
    import tkey
#endif

extension MpcCoreKit {
    public class FactorSerialization {
        public static func mnemonicToKey(tkey: ThresholdKey, shareMnemonic: String) throws -> String {
            return try ShareSerializationModule.deserialize_share(threshold_key: tkey, share: shareMnemonic)
        }
        
        public static func keyToMnemonic(tkey: ThresholdKey, shareHex: String) throws -> String {
            return try ShareSerializationModule.serialize_share(threshold_key: tkey, share: shareHex)
        }
    }
}
