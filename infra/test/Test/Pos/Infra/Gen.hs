module Test.Pos.Infra.Gen
        (
        -- DHT Generators
          genDataMsg
        , genInvMsg
        , genMempoolMsg
        , genReqMsg
        , genResMsg
        , genDHTData
        , genDHTKey

        -- Slotting Generators
        , genEpochSlottingData
        , genSlottingData
        ) where

import           Universum

import           Hedgehog
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import           Data.Time.Units (Millisecond, Microsecond,
                                  fromMicroseconds)

import           Pos.Arbitrary.Core ()
import           Pos.Communication.Types.Relay (DataMsg (..), InvMsg (..),
                                                MempoolMsg (..), ReqMsg (..),
                                                ResMsg (..))
import           Pos.Core (EpochIndex (..), TimeDiff (..))
import           Pos.DHT (DHTData (..), DHTKey (..), bytesToDHTKey)
import           Pos.Slotting.Types (EpochSlottingData (..), SlottingData,
                                     createSlottingDataUnsafe)

----------------------------------------------------------------------------
-- DHT Generators
----------------------------------------------------------------------------

genInvMsg :: Gen a -> Gen (InvMsg a)
genInvMsg genA = InvMsg <$> genA

genReqMsg :: Gen (Maybe a) -> Gen (ReqMsg a)
genReqMsg genMA = ReqMsg <$> genMA

genResMsg :: Gen a -> Gen (ResMsg a)
genResMsg genA = ResMsg <$> genA <*> Gen.bool

genMempoolMsg :: Gen (MempoolMsg a)
genMempoolMsg = return MempoolMsg

genDataMsg :: Gen a -> Gen (DataMsg a)
genDataMsg genA = DataMsg <$> genA

genDHTKey :: Gen DHTKey
genDHTKey = do
    b <- gen32Bytes
    let k = bytesToDHTKey b :: Either String DHTKey
    case k of
        Left _   -> error "Failed to generate a DHTKey."
        Right dk -> return dk

genDHTData :: Gen DHTData
genDHTData = return $ DHTData ()

----------------------------------------------------------------------------
-- Slotting Generators
----------------------------------------------------------------------------

genEpochSlottingData :: Gen EpochSlottingData
genEpochSlottingData = EpochSlottingData <$> genMillisecond <*> genTimeDiff

genSlottingData :: Gen SlottingData
genSlottingData = createSlottingDataUnsafe <$> genMap
  where
    genMap :: Gen (Map EpochIndex EpochSlottingData)
    genMap = Gen.map Range.constantBounded genEpochIndexDataPair

genEpochIndexDataPair :: Gen (EpochIndex, EpochSlottingData)
genEpochIndexDataPair = do
    i <- genEpochIndex
    sd <- genEpochSlottingData
    return (i, sd)

----------------------------------------------------------------------------
-- Helper Generators
----------------------------------------------------------------------------

genBytes :: Int -> Gen ByteString
genBytes n = Gen.bytes (Range.singleton n)

gen32Bytes :: Gen ByteString
gen32Bytes = genBytes 32

genMillisecond :: Gen Millisecond
genMillisecond =
    fromMicroseconds <$> (toInteger <$> Gen.int Range.constantBounded)

genMicrosecond :: Gen Microsecond
genMicrosecond =
    fromMicroseconds <$> (toInteger <$> Gen.int Range.constantBounded)

-- TimeDiff is from core so this generator will be moved eventually.
genTimeDiff :: Gen TimeDiff
genTimeDiff = TimeDiff <$> genMicrosecond

-- EpochIndex is from core so this generator will be moved eventually.
genEpochIndex :: Gen EpochIndex
genEpochIndex = EpochIndex <$> Gen.word64 Range.constantBounded
