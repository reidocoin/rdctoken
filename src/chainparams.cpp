// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The PIVX developers
// Copyright (c) 2018 The RDCT developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "bignum.h"
#include "random.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

using namespace std;
using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

#include "chainparamsseeds.h"

/**
 * Main network
 */

//! Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress>& vSeedsOut, const SeedSpec6* data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7 * 24 * 60 * 60;
    for (unsigned int i = 0; i < count; i++) {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

//   What makes a good checkpoint block?
// + Is surrounded by blocks with reasonable timestamps
//   (no blocks before with a timestamp after, none after with
//    timestamp before)
// + Contains no strange transactions
static Checkpoints::MapCheckpoints mapCheckpoints =
    boost::assign::map_list_of
    (1, uint256("0x73c3ae7b97789ab6634b8204e2f7d5be4f0d8765443f8fad04042dd5908411fe"))
    (200, uint256("0x000000f44e9983594124f73594056af2ca0e79140a95f6973a69896905d052fb"))
    (500, uint256("0x0dae3b5e357a09d5efe73dd2f444f07fce9f703edb46385ebdb635f12cc18dfd"))
    (1000, uint256("0xf793a67f23bc96c174f4cf183b0d61cf51265e94a585fe06c8c9f0a5d938061f"))
    (5000, uint256("0xceaaf70ca45342d3651bc9e7b5129b3a735f74dce57608f0c85ba46d1167af2f"))
    (10000, uint256("0xa9313a5d3f0bf2c7e61f6555420abe107e5737c569b06c8689e87b80c3ecc14c"))
    (15000, uint256("0xdd567dcde2a313f2fa9dc5b4d94b50ed6132bec4f352122e66c18e0f6803cee8"))
    (20000, uint256("0x71e5dbbf9d196f11e5ea638e8aae70aaf602dc28614d8d0bb63e0fdc448f8b22"))
    (25000, uint256("0x23f4aca724243927f7006308bb934b5554a6614ac79b732cfa4a01ed4721e7fb"))
    (30000, uint256("0xbda2792598a7c601576bc32c3384b44751b68589402811dacf56389c099c6429"))
    (35000, uint256("0xa7829e9edf895a3ee572e801d8f0c30f6ab613fa00f18cc699d152a32309d61c"))
    (40000, uint256("0x2f3a0a5bd178b3f06d63b0e34eaf2140ab9ffb7f4ca721fa98a81fabd6d1e2c1"))
    (45000, uint256("0xf172337991fe3c23cbc8934c1ee93a118d1f5600b41e22094a7c4157f21f8d0b"))
    (50000, uint256("0xddb02f25072c531bc20280bfe4e788776c41336e81c1d627433182197603d661"))
    (100000, uint256("0xdb9755cde5bead196cf55cbfa02dae7c9ac2480a10640f2e79ac8d61e0cbc35b"))
    (150000, uint256("0x250ad64a7751ae939d6eafda3e39ea81f72bdfcbff17fc02b40f17cf60889408"))
    (200000, uint256("0x4cfdbad17342d7525ac1efceb33c9b4533ec867506a9acd36a2736f2a405fbdc"))
    (250000, uint256("0x611982ef6c6507d95030efbacb8f9b03b51b50b69581ceccd62a1f338954819e"))
    (300000, uint256("0x7a36f018bbcc8163700dd7e267a7c0b3ba3d61e68b1889420346b846157858ff"))
    (350000, uint256("0x233147d79169ccfccdd54c676f9e26554055c37fd49b6fc84e2ad3d7facdf626"))
    (400000, uint256("0x556cf2d42b095fdaf54063e27fc09cca7349e04170e948813be6306e9667dc5c"))
    (450000, uint256("0x8bbf04fb7f2a45e1953d1b4559f14705f8deb891079a0a94e66371c2d2e8a519"))
    (500000, uint256("0xac2ca5b5f5279055618ab6008be901375fc342cf253f765bcdac47ea805a581e"))
    (505775, uint256("0xb80b66d6199e74438221c99f5b55a461371b0abfd58a6e1dcdd55fd478c86e71"))
    (520000, uint256("0xd63d436570a07cc6ea256c2a2c5f05ad6bdaa5e2f2de3934bb2dc2771396c8f1"))
    (530000, uint256("0x6a050c2521bddfb83f78b097ed4c753c0cdaffb002e834d71d28ed6a3f2e0e7a"))
    (540000, uint256("0x4d9d59ceed1d3b129c90bdfc8fd3ff04d472a69a82d57494363bde62237d0645"))
    (550000, uint256("0x78918231eb989fd472b05e513fa6f27f2db476aecd653fd7f3db4dea18f73cba"))
    (560000, uint256("0xb29c9c1bd811e3744f9b10fb2cb58526aa731cacff5d5add435375c2778cba4f"))
    (570000, uint256("0x75268af020219932e9c9a85aac4cbca1709fd12798fb948782f91a6291be18a1"))
    (580000, uint256("0xa71450d60e5fe2bda15272e299b8d5d39361be82f90565ac1f11ae1ab2808ca3"))
    (590000, uint256("0xc69cdb4952e3ca910c13fca90ca0a16ab4819b19ada560b3dc8124d9e5ddbef0"))
    (590188, uint256("0xf3f6592144e3354b3d9cd870c57f7492117cf7b8fd49ed1550436308963360df"))
    (630000, uint256("0xc373cfa29da689252869ee61f1bd415d6fbf89fd132a7f6b5d9632d9229b7828"))
    (680000, uint256("0xf38b1256b4b418eb2ba1886138e0777921679e5c38f444e373d5624b095a0a2f"))
    (719775, uint256("0x10274773cc0a67ffad97656ea3709f72ef5e02debae7e718b88fdb98bd4a6181"))
    (750000, uint256("0x510ace7f19a9ce8e0b371fb249b2bcf2ca2dcd7d166688721c1bda422656c63c"))
    (779000, uint256("0x4bc2c516ebfed2d7178be5f1ca0fddf054eeb0dbc3910e7f47b1673bcb1a6d21"));

static const Checkpoints::CCheckpointData data = {
    &mapCheckpoints,
    1584399185,  // * UNIX timestamp of last checkpoint block
    1610582,        // * total number of transactions between genesis and last checkpoint
                 //   (the tx=... number in the SetBestChain debug.log lines)
    3000         // * estimated number of transactions per day after checkpoint
};

static Checkpoints::MapCheckpoints mapCheckpointsTestnet =
    boost::assign::map_list_of(0, uint256("0x001"));

static const Checkpoints::CCheckpointData dataTestnet = {
    &mapCheckpointsTestnet,
    1740710,
    0,
    250};

static Checkpoints::MapCheckpoints mapCheckpointsRegtest =
    boost::assign::map_list_of(0, uint256("0x001"));
static const Checkpoints::CCheckpointData dataRegtest = {
    &mapCheckpointsRegtest,
    1454124731,
    0,
    100};
class CMainParams : public CChainParams
{
public:
    CMainParams()
    {
        networkID = CBaseChainParams::MAIN;
        strNetworkID = "main";
        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */
        pchMessageStart[0] = 0xf0;
        pchMessageStart[1] = 0x23;
        pchMessageStart[2] = 0xcc;
        pchMessageStart[3] = 0xe6;
        vAlertPubKey = ParseHex("04a94fa4b884aa5435fa8e44e002380b931372dec4ca071a5d167c6129ce6a170991d9071c020ba4906c98a3c350a622b7d830fa94b0a57021596d106194d99dc4");
        nDefaultPort = 49846; // porta mainnet
        bnProofOfWorkLimit = ~uint256(0) >> 1; // RDCT starting difficulty is 1 / 2^12
        nSubsidyHalvingInterval = 1050000;
        nMaxReorganizationDepth = 100;
        nEnforceBlockUpgradeMajority = 750;
        nRejectBlockOutdatedMajority = 950;
        nToCheckBlockUpgradeMajority = 1000;
        nMinerThreads = 0;
        nTargetTimespan = 2 * 60; // RDCT coin: 2 minutes
        nTargetSpacing = 2 * 60;  // RDCT coin: 2 minutes
        nMaturity = 15;
        nMasternodeCountDrift = 20;
        nMaxMoneyOut = 25500000 * COIN;

        /** Height or Time Based Activations **/
        nLastPOWBlock = 200;
        nModifierUpdateBlock = 1; // we use the version 2 for RDCT

        const char* pszTimestamp = "Lendário Fundo Verde, de Stuhlberger, reabre após 10 anos para clientes da XP e Rico - InfoMoney";
        CMutableTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 0 * COIN;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime = 1537045200;
        genesis.nBits = 0x1e0ffff0;
        genesis.nNonce = 1529064;

		    hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("0x00000d794731fe98c6d703116f701b7437336832e49bbeb46d983e07e23bbb6e"));
        assert(genesis.hashMerkleRoot == uint256("0xedb2d2a03f5676ffdb180390996514caca485fed3890e27afb06f4feb8a6efcf"));

        // DNS Seeding
        vSeeds.push_back(CDNSSeedData("seed1.rdctoken.io", "seed1.rdctoken.io"));

        // RDCT coin addresses start with 'R'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 60);
        // RDCT coin script addresses start with '3'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 6);
        // RDCT coin private keys start with 'K'
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 46);
        // RDCT coin BIP32 pubkeys start with 'xpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        // RDCT coin BIP32 prvkeys start with 'xprv' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();
        // RDCT coin BIP44 coin type is '222' (0x800000de)
        // BIP44 coin type is from https://github.com/satoshilabs/slips/blob/master/slip-0044.md
        base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x00)(0x00)(0xde).convert_to_container<std::vector<unsigned char> >();

        convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = false;
        fAllowMinDifficultyBlocks = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fSkipProofOfWorkCheck = false;
        fTestnetToBeDeprecatedFieldRPC = false;
        fHeadersFirstSyncingActive = false;

        nPoolMaxTransactions = 3;
        strSporkKey = "043cadcd65fbac1c66f2067ce513f1ea0be0acb36af2c53518dcdb534bf5c1f8a0c14c28a47aaf4f26048121e32a35e39c4444a0dfd87292b403d689f51b2aa236";
        strMasternodePoolDummyAddress = "GSJVWUkt6HtSCY2SaJ2akeyJUg8bg1hW3S";
        nStartMasternodePayments = 1537466400; // 20/09/2018 15:00 -0300

        nBudget_Fee_Confirmations = 6; // Number of confirmations for the finalization fee
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return data;
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CMainParams
{
public:
    CTestNetParams()
    {
        networkID = CBaseChainParams::TESTNET;
        strNetworkID = "test";
        pchMessageStart[0] = 0x9a;
        pchMessageStart[1] = 0x20;
        pchMessageStart[2] = 0xd2;
        pchMessageStart[3] = 0x2c;
        vAlertPubKey = ParseHex("04be5ed545841909acdd0b620cfd5806a0f142c02d0ec01f0cb3c5674551cc474b00895e1974fbd09de17b137850092b967850afb0a6facbfbcc2528b582e41fb7");
        nDefaultPort = 17117;
        nEnforceBlockUpgradeMajority = 51;
        nRejectBlockOutdatedMajority = 75;
        nToCheckBlockUpgradeMajority = 100;
        nMinerThreads = 0;
        nTargetTimespan = 1 * 60; // RDCT coin: 1 day
        nTargetSpacing = 2 * 60;  // RDCT coin: 1 minute
        nLastPOWBlock = 200;
        nMaturity = 15;
        nMasternodeCountDrift = 4;
        nModifierUpdateBlock = 1;
        nMaxMoneyOut = 25000000 * COIN;

        //! Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTime = 1535835600;
        genesis.nNonce = 1853156;

        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("0x000006fcf37ffdec40c897eb9b1813914da37cc4612738b737658c59c14395f9"));

        vFixedSeeds.clear();
        vSeeds.clear();

        // Testnet RDCT coin addresses start with 'g'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 35);
        // Testnet RDCT coin script addresses start with '5' or '6'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 10);
        // Testnet private keys start with 'k'
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 108);
        // Testnet RDCT coin BIP32 pubkeys start with 'tpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        // Testnet RDCT coin BIP32 prvkeys start with 'tprv' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
        // Testnet RDCT BIP44 coin type is '1' (All coin's testnet default)
        base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x00)(0x00)(0x01).convert_to_container<std::vector<unsigned char> >();

        convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fAllowMinDifficultyBlocks = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        nPoolMaxTransactions = 2;
        strSporkKey = "04ff1765b5c2f5409e540e998133fbced768d3f5fee7da22ea906db467cb9f5d3f16ba5b11adb0eab7ce3ea032995636cdb6a4e6e40d5e418445f28b014cead9dc";
        strMasternodePoolDummyAddress = "gbJ4Qad4xc77PpLzMx6rUegAs6aUPWkcUq";
        nStartMasternodePayments = genesis.nTime + 86400; // 24 hours after genesis
        nBudget_Fee_Confirmations = 3; // Number of confirmations for the finalization fee. We have to make this very short
                                       // here because we only have a 8 block finalization window on testnet
    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataTestnet;
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CTestNetParams
{
public:
    CRegTestParams()
    {
        networkID = CBaseChainParams::REGTEST;
        strNetworkID = "regtest";
        strNetworkID = "regtest";
        pchMessageStart[0] = 0xaa;
        pchMessageStart[1] = 0x55;
        pchMessageStart[2] = 0x11;
        pchMessageStart[3] = 0xbb;
        nSubsidyHalvingInterval = 150;
        nEnforceBlockUpgradeMajority = 750;
        nRejectBlockOutdatedMajority = 950;
        nToCheckBlockUpgradeMajority = 1000;
        nMinerThreads = 1;
        nTargetTimespan = 24 * 60 * 60; // RDCT coin: 1 day
        nTargetSpacing = 2 * 60;        // RDCT coin: 1 minutes
        bnProofOfWorkLimit = ~uint256(0) >> 1;
        genesis.nTime = 1516926684;
        genesis.nBits = 0x1e0ffff0;
        genesis.nNonce = 769149;

        hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 23133;
        assert(hashGenesisBlock == uint256("0x0000001d71e19966939633980998c6741c1d9c33b101f9811bd3a0245d5be280"));

        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fAllowMinDifficultyBlocks = true;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;
    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataRegtest;
    }
};
static CRegTestParams regTestParams;

/**
 * Unit test
 */
class CUnitTestParams : public CMainParams, public CModifiableParams
{
public:
    CUnitTestParams()
    {
        networkID = CBaseChainParams::UNITTEST;
        strNetworkID = "unittest";
        nDefaultPort = 51478;
        vFixedSeeds.clear(); //! Unit test mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Unit test mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fAllowMinDifficultyBlocks = false;
        fMineBlocksOnDemand = true;
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        // UnitTest share the same checkpoints as MAIN
        return data;
    }

    //! Published setters to allow changing values in unit test cases
    virtual void setSubsidyHalvingInterval(int anSubsidyHalvingInterval) { nSubsidyHalvingInterval = anSubsidyHalvingInterval; }
    virtual void setEnforceBlockUpgradeMajority(int anEnforceBlockUpgradeMajority) { nEnforceBlockUpgradeMajority = anEnforceBlockUpgradeMajority; }
    virtual void setRejectBlockOutdatedMajority(int anRejectBlockOutdatedMajority) { nRejectBlockOutdatedMajority = anRejectBlockOutdatedMajority; }
    virtual void setToCheckBlockUpgradeMajority(int anToCheckBlockUpgradeMajority) { nToCheckBlockUpgradeMajority = anToCheckBlockUpgradeMajority; }
    virtual void setDefaultConsistencyChecks(bool afDefaultConsistencyChecks) { fDefaultConsistencyChecks = afDefaultConsistencyChecks; }
    virtual void setAllowMinDifficultyBlocks(bool afAllowMinDifficultyBlocks) { fAllowMinDifficultyBlocks = afAllowMinDifficultyBlocks; }
    virtual void setSkipProofOfWorkCheck(bool afSkipProofOfWorkCheck) { fSkipProofOfWorkCheck = afSkipProofOfWorkCheck; }
};
static CUnitTestParams unitTestParams;


static CChainParams* pCurrentParams = 0;

CModifiableParams* ModifiableParams()
{
    assert(pCurrentParams);
    assert(pCurrentParams == &unitTestParams);
    return (CModifiableParams*)&unitTestParams;
}

const CChainParams& Params()
{
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(CBaseChainParams::Network network)
{
    switch (network) {
    case CBaseChainParams::MAIN:
        return mainParams;
    case CBaseChainParams::TESTNET:
        return testNetParams;
    case CBaseChainParams::REGTEST:
        return regTestParams;
    case CBaseChainParams::UNITTEST:
        return unitTestParams;
    default:
        assert(false && "Unimplemented network");
        return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}
