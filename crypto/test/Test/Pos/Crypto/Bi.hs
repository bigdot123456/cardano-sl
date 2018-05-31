{-# LANGUAGE OverloadedStrings #-}

module Test.Pos.Crypto.Bi
    ( tests
    ) where

import           Universum

import           Cardano.Crypto.Wallet (xprv, xpub)

import qualified Data.ByteArray as ByteArray
import qualified Data.ByteString as BS

import           Hedgehog (Property)
import qualified Hedgehog as H

import           Pos.Aeson.Crypto ()
import           Pos.Crypto (PassPhrase, PublicKey (..), Secret, SecretKey (..), SecretProof,
                             deriveHDPassphrase, deterministicVssKeyGen, packHDAddressAttr,
                             redeemDeterministicKeyGen, toVssPublicKey)

import           Test.Pos.Crypto.Gen
import           Test.Pos.Crypto.TempHelpers (discoverGolden, discoverRoundTrip, eachOf,
                                              goldenTestBi, roundTripsAesonBuildable,
                                              roundTripsBiBuildable, roundTripsBiShow)

--------------------------------------------------------------------------------
-- PublicKey
--------------------------------------------------------------------------------

golden_PublicKey :: Property
golden_PublicKey = goldenTestBi pkey "test/golden/PublicKey"
  where
    Right pkey = PublicKey <$> xpub (getBytes 0 64)

roundTripPublicKeyBi :: Property
roundTripPublicKeyBi = eachOf 1000 publicKeys roundTripsBiBuildable

roundTripPublicKeyAeson :: Property
roundTripPublicKeyAeson = eachOf 1000 publicKeys roundTripsAesonBuildable

--------------------------------------------------------------------------------
-- SecretKey
--------------------------------------------------------------------------------

golden_SecretKey :: Property
golden_SecretKey = goldenTestBi skey "test/golden/SecretKey"
  where
    Right skey = SecretKey <$> xprv (getBytes 10 128)

roundTripSecretKeyBi :: Property
roundTripSecretKeyBi = eachOf 1000 secretKeys roundTripsBiBuildable

--------------------------------------------------------------------------------
-- EncryptedSecretKey
--------------------------------------------------------------------------------

{-
Currently cannot roundtrip test EncryptedSecretKey because one of its components,
XPrv, doesn't have an Eq instance. See Pos.Crypto.Signing.Types.Safe

golden_EncryptedSecretKey :: Property
golden_EncryptedSecretKey = do
    let Right skey = SecretKey <$> xprv (getBytes 10 128)
        let esky = EncryptedSecretKey xkey undefined
    goldenTestBi skey "test/golden/EncryptedSecretKey"

roundTripEncryptedSecretKeysBi :: Property
roundTripEncryptedSecretKeysBi = eachOf encryptedSecretKeys roundTripsBiBuildable
-}

--------------------------------------------------------------------------------
-- RedeemPublicKey
--------------------------------------------------------------------------------

golden_RedeemPublicKey :: Property
golden_RedeemPublicKey = goldenTestBi rpk "test/golden/RedeemPublicKey"
  where
    Just rpk = fst <$> redeemDeterministicKeyGen (getBytes 0 32)

roundTripRedeemPublicKeyBi :: Property
roundTripRedeemPublicKeyBi = eachOf 1000 redeemPublicKeys roundTripsBiBuildable

--------------------------------------------------------------------------------
-- RedeemSecretKey
--------------------------------------------------------------------------------

golden_RedeemSecretKey :: Property
golden_RedeemSecretKey = goldenTestBi rsk "test/golden/RedeemSecretKey"
  where
    Just rsk = snd <$> redeemDeterministicKeyGen (getBytes 0 32)

roundTripRedeemSecretKeyBi :: Property
roundTripRedeemSecretKeyBi = eachOf 1000 redeemSecretKeys roundTripsBiBuildable

--------------------------------------------------------------------------------
-- VssPublicKey
--------------------------------------------------------------------------------

golden_VssPublicKey :: Property
golden_VssPublicKey = goldenTestBi vpk "test/golden/VssPublicKey"
  where
    vpk = toVssPublicKey . deterministicVssKeyGen $ getBytes 0 32

roundTripVssPublicKeyBi :: Property
roundTripVssPublicKeyBi = eachOf 1000 vssPublicKeys roundTripsBiShow

--------------------------------------------------------------------------------
-- Secret
--------------------------------------------------------------------------------

-- | Not done because the constructor for the underlying `Point` type is not
--   exposed and there is no deterministic generation function
todo_golden_Secret :: Property
todo_golden_Secret = goldenTestBi
    (error "golden_Secret not yet defined" :: Secret)
    "test/golden/Secret"

roundTripSecretBi :: Property
roundTripSecretBi = eachOf 100 secrets roundTripsBiShow

--------------------------------------------------------------------------------
-- SecretProof
--------------------------------------------------------------------------------

-- | We have a similar problem for this
todo_golden_SecretProof :: Property
todo_golden_SecretProof = goldenTestBi
    (error "golden_SecretProof not yet defined" :: SecretProof)
    "test/golden/SecretProof"

roundTripSecretProofBi :: Property
roundTripSecretProofBi = eachOf 100 secretProofs roundTripsBiShow

--------------------------------------------------------------------------------
-- PassPhrase
--------------------------------------------------------------------------------

golden_PassPhrase :: Property
golden_PassPhrase = goldenTestBi passphrase "test/golden/PassPhrase"
  where
    -- PassPhrase has to be 32 bytes in length
    passphrase = ByteArray.pack (BS.unpack $ getBytes 3 32) :: PassPhrase

roundTripPassPhraseBi :: Property
roundTripPassPhraseBi = eachOf 1000 passPhrases roundTripsBiBuildable

--------------------------------------------------------------------------------
-- HDAddressPayload
--------------------------------------------------------------------------------

golden_HDAddressPayload :: Property
golden_HDAddressPayload = goldenTestBi hdap "test/golden/HDAddressPayload"
  where
    Right hdap =
        flip packHDAddressAttr [] . deriveHDPassphrase . PublicKey <$> xpub
            (getBytes 0 64)

roundTripHDAddressPayloadBi :: Property
roundTripHDAddressPayloadBi = eachOf 1000 hDAddressPayloads roundTripsBiShow

--------------------------------------------------------------------------------

getBytes :: Int -> Int -> ByteString
getBytes offset len = BS.take len $ BS.drop offset constantByteString

-- | Changing existing values in this string will break existing golden
-- tests, but it us OK to append more data to the end.
constantByteString :: ByteString
constantByteString =
    "Kmyw4lDSE5S4fSH6etNouiXezCyEjKc3tG4ja0kFjO8qzai26ZMPUEJfEy15ox5kJ0uKD\
    \bi7i6dLXkuesVZ9JfHgjrctsLFt2NvovXnchsOvX05Y6LohlTNt5mkPFhUoXu1EZSJTIy\
    \3fTU53b412r4AEusD7tcdRgH47yTr5hMO63bJnYBbmNperLHfiT1lP0MLQLh1J1DfoYBs\
    \auoJOzvtAgvjHo6UFttnK6vZ3Cknpuob6uMS2MkJKmuoQsqsAYcRDWbJ2Rgw4bm2ndTM4\
    \zFfuRDKvdrL6sDkuPNPYqxMWlqnXjSbU0eLtceZuKgXLHR8cdvsEvywt4JaZUQhnbq3Vl\
    \7nZqcXdoi4XGTCgSGcGp8N0SDVhvkVh0QF1RVpWPnOMyYISJvuaHfo1zXMdq9tEdtJfID"

--------------------------------------------------------------------------------

tests :: IO Bool
tests = (&&) <$> H.checkSequential $$discoverGolden
             <*> H.checkParallel $$discoverRoundTrip
