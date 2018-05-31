module Test.Pos.Crypto.Gen
        (
        -- Protocol Magic Generator
          protocolMagics

        -- Sign Tag Generator
        , signTags

        -- Key Generators
        , keypairs
        , publicKeys
        , secretKeys
        , encryptedSecretKeys

        -- Redeem Key Generators
        , redeemKeypairs
        , redeemPublicKeys
        , redeemSecretKeys

        -- VSS Key Generators
        , vssKeyPairs
        , vssPublicKeys

        -- Proxy Cert and Key Generators
        , proxyCerts
        , proxySecretKeys
        , proxySignatures

        -- Signature Generators
        , signatures
        , signatureEncodeds
        , signeds
        , redeemSignatures

        -- Secret Generators
        , sharedSecretDatas
        , secrets
        , secretProofs

        -- Hash Generators
        , abstractHashes

        -- Passphrase Generators
        , passPhrases

        -- HD Generators
        , hDPassphrases
        , hDAddressPayloads
        ) where

import           Universum

import           Crypto.Hash
import qualified Data.ByteArray as ByteArray
import           Data.List.NonEmpty (fromList)
import           Hedgehog
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range

import           Pos.Binary.Class (Bi)
import           Pos.Crypto (AbstractHash (..), PassPhrase, abstractHash)
import           Pos.Crypto.Configuration (ProtocolMagic (..))
import           Pos.Crypto.HD (HDAddressPayload (..), HDPassphrase (..))
import           Pos.Crypto.Random (deterministic)
import           Pos.Crypto.SecretSharing (EncShare, Secret, SecretProof, VssKeyPair, VssPublicKey,
                                           deterministicVssKeyGen, genSharedSecret, toVssPublicKey)
import           Pos.Crypto.Signing (EncryptedSecretKey, ProxyCert, ProxySecretKey, ProxySignature,
                                     PublicKey, SafeSigner (..), SecretKey, SignTag (..), Signature,
                                     Signed, deterministicKeyGen, mkSigned, noPassEncrypt,
                                     proxySign, safeCreateProxyCert, safeCreatePsk, sign,
                                     signEncoded)
import           Pos.Crypto.Signing.Redeem (RedeemPublicKey, RedeemSecretKey, RedeemSignature,
                                            redeemDeterministicKeyGen, redeemSign)

----------------------------------------------------------------------------
-- Protocol Magic Generator
----------------------------------------------------------------------------

protocolMagics :: Gen ProtocolMagic
protocolMagics = ProtocolMagic <$> (Gen.int32 Range.constantBounded)

----------------------------------------------------------------------------
-- Sign Tag Generator
----------------------------------------------------------------------------

signTags :: Gen SignTag
signTags = Gen.element
        [ SignForTestingOnly
        , SignTx
        , SignRedeemTx
        , SignVssCert
        , SignUSProposal
        , SignCommitment
        , SignUSVote
        , SignMainBlock
        , SignMainBlockLight
        , SignMainBlockHeavy
        , SignProxySK
        ]

----------------------------------------------------------------------------
-- Key Generators
----------------------------------------------------------------------------

keypairs :: Gen (PublicKey, SecretKey)
keypairs = deterministicKeyGen <$> gen32Bytes

publicKeys :: Gen PublicKey
publicKeys =  fst <$> keypairs

secretKeys :: Gen SecretKey
secretKeys = snd <$> keypairs

encryptedSecretKeys :: Gen EncryptedSecretKey
encryptedSecretKeys = noPassEncrypt <$> secretKeys

----------------------------------------------------------------------------
-- Redeem Key Generators
----------------------------------------------------------------------------

redeemKeypairs :: Gen (Maybe (RedeemPublicKey, RedeemSecretKey))
redeemKeypairs = redeemDeterministicKeyGen <$> gen32Bytes

redeemPublicKeys :: Gen (RedeemPublicKey)
redeemPublicKeys = do
    rkp <- redeemKeypairs
    case rkp of
        Nothing      -> error "Error generating a RedeemPublicKey."
        Just (pk, _) -> return pk

redeemSecretKeys :: Gen (RedeemSecretKey)
redeemSecretKeys = do
    rkp <- redeemKeypairs
    case rkp of
        Nothing      -> error "Error generating a RedeemSecretKey."
        Just (_, sk) -> return sk

----------------------------------------------------------------------------
-- VSS Key Generators
----------------------------------------------------------------------------

vssKeyPairs :: Gen VssKeyPair
vssKeyPairs =  deterministicVssKeyGen <$> gen32Bytes

vssPublicKeys :: Gen VssPublicKey
vssPublicKeys = toVssPublicKey <$> vssKeyPairs

----------------------------------------------------------------------------
-- Proxy Cert and Key Generators
----------------------------------------------------------------------------

proxyCerts :: Bi w => ProtocolMagic -> Gen w -> Gen (ProxyCert w)
proxyCerts pm ws =
    safeCreateProxyCert pm <$> safeSigners <*> publicKeys <*> ws

proxySecretKeys :: Bi w => ProtocolMagic -> Gen w -> Gen (ProxySecretKey w)
proxySecretKeys pm ws =
    safeCreatePsk pm <$> safeSigners <*> publicKeys <*> ws

proxySignatures
    :: (Bi w, Bi a)
    => ProtocolMagic
    -> Gen a
    -> Gen w
    -> Gen (ProxySignature w a)
proxySignatures pm as ws = do
    st  <- signTags
    sk  <- secretKeys
    psk <- proxySecretKeys pm ws
    a   <- as
    return $ proxySign pm st sk psk a

----------------------------------------------------------------------------
-- Signature Generators
----------------------------------------------------------------------------

signatures :: Bi a => ProtocolMagic -> Gen a -> Gen (Signature a)
signatures pm as = sign pm <$> signTags <*> secretKeys <*> as

signatureEncodeds :: ProtocolMagic -> Gen ByteString -> Gen (Signature a)
signatureEncodeds pm bs =
    signEncoded pm <$> signTags <*> secretKeys <*> bs

signeds :: Bi a => ProtocolMagic -> Gen a -> Gen (Signed a)
signeds pm as =
    mkSigned pm <$> signTags <*> secretKeys <*> as

redeemSignatures
    ::  Bi a
    => ProtocolMagic
    -> Gen a
    -> Gen (RedeemSignature a)
redeemSignatures pm as =
    redeemSign pm <$> signTags <*> redeemSecretKeys <*> as

----------------------------------------------------------------------------
-- Secret Generators
----------------------------------------------------------------------------

sharedSecretDatas :: Gen (Secret, SecretProof, [(VssPublicKey, EncShare)])
sharedSecretDatas = do
    let numKeys = 128 :: Int
    parties <-
        Gen.integral (Range.constant 4 (fromIntegral numKeys)) :: Gen Integer
    threshold <- Gen.integral (Range.constant 2 (parties - 2)) :: Gen Integer
    vssKeys <- replicateM numKeys vssPublicKeys
    let ss = deterministic "ss" $ genSharedSecret threshold (fromList vssKeys)
    return ss

secrets :: Gen Secret
secrets = do
    (s, _, _) <- sharedSecretDatas
    return s

secretProofs :: Gen SecretProof
secretProofs = do
    (_, sp, _) <- sharedSecretDatas
    return sp

----------------------------------------------------------------------------
-- Hash Generators
----------------------------------------------------------------------------

abstractHashes :: Bi a => Gen a -> Gen (AbstractHash Blake2b_256 a)
abstractHashes as = abstractHash <$> as

----------------------------------------------------------------------------
-- Passphrase Generators
----------------------------------------------------------------------------

passPhrases :: Gen PassPhrase
passPhrases = ByteArray.pack <$> word8Lists
  where
    word8Lists :: Gen [Word8]
    word8Lists =
        Gen.list (Range.singleton 32) (Gen.word8 Range.constantBounded)

----------------------------------------------------------------------------
-- HD Generators
----------------------------------------------------------------------------

hDPassphrases :: Gen HDPassphrase
hDPassphrases = HDPassphrase <$> gen32Bytes

hDAddressPayloads :: Gen HDAddressPayload
hDAddressPayloads = HDAddressPayload <$> gen32Bytes

----------------------------------------------------------------------------
-- Helper Generators
----------------------------------------------------------------------------
genBytes :: Int -> Gen ByteString
genBytes n = Gen.bytes (Range.singleton n)

gen32Bytes :: Gen ByteString
gen32Bytes = genBytes 32

safeSigners :: Gen SafeSigner
safeSigners = FakeSigner <$> secretKeys
