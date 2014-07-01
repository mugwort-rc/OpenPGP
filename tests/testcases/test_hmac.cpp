#include <gtest/gtest.h>

#include "Hashes/HMAC.h"

#include "testvectors/hmac/hmac.h"

TEST(HMACTest, test_rfc2202){
    // 2. Test Cases for HMAC-MD5
    EXPECT_EQ(HMAC_MD5(std::string(16, 0x0b), "Hi There").digest(), unhexlify("9294727a3638bb1c13f48ef8158bfc9d"));
    EXPECT_EQ(HMAC_MD5("Jefe", "what do ya want for nothing?").digest(), unhexlify("750c783e6ab0b503eaa86e310a5db738"));
    EXPECT_EQ(HMAC_MD5(std::string(16, 0xaa), std::string(50, 0xdd)).digest(), unhexlify("56be34521d144c88dbb8c733f0e8b3f6"));
    EXPECT_EQ(HMAC_MD5(unhexlify("0102030405060708090a0b0c0d0e0f10111213141516171819"), std::string(50, 0xcd)).digest(), unhexlify("697eaf0aca3a3aea3a75164746ffaa79"));
    EXPECT_EQ(HMAC_MD5(std::string(16, 0x0c), "Test With Truncation").digest(), unhexlify("56461ef2342edc00f9bab995690efd4c"));
    EXPECT_EQ(HMAC_MD5(std::string(80, 0xaa), "Test Using Larger Than Block-Size Key - Hash Key First").digest(), unhexlify("6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd"));
    EXPECT_EQ(HMAC_MD5(std::string(80, 0xaa), "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data").digest(), unhexlify("6f630fad67cda0ee1fb1f562db3aa53e"));

    // 3. Test Cases for HMAC-SHA-1
    EXPECT_EQ(HMAC_SHA1(std::string(20, 0x0b), "Hi There").digest(), unhexlify("b617318655057264e28bc0b6fb378c8ef146be00"));
    EXPECT_EQ(HMAC_SHA1("Jefe", "what do ya want for nothing?").digest(), unhexlify("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"));
    EXPECT_EQ(HMAC_SHA1(std::string(20, 0xaa), std::string(50, 0xdd)).digest(), unhexlify("125d7342b9ac11cd91a39af48aa17b4f63f175d3"));
    EXPECT_EQ(HMAC_SHA1(unhexlify("0102030405060708090a0b0c0d0e0f10111213141516171819"), std::string(50, 0xcd)).digest(), unhexlify("4c9007f4026250c6bc8414f9bf50c86c2d7235da"));
    EXPECT_EQ(HMAC_SHA1(std::string(20, 0x0c), "Test With Truncation").digest(), unhexlify("4c1a03424b55e07fe7f27be1d58bb9324a9a5a04"));
    EXPECT_EQ(HMAC_SHA1(std::string(80, 0xaa), "Test Using Larger Than Block-Size Key - Hash Key First").digest(), unhexlify("aa4ae5e15272d00e95705637ce8a3b55ed402112"));
    EXPECT_EQ(HMAC_SHA1(std::string(80, 0xaa), "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data").digest(), unhexlify("e8e99d0f45237d786d6bbaa7965c7808bbff1a91"));
}

TEST(HMACTest, test_rfc2286){
    EXPECT_EQ(HMAC_RIPEMD160(std::string(20, 0x0b), "Hi There").digest(), unhexlify("24cb4bd67d20fc1a5d2ed7732dcc39377f0a5668"));
    EXPECT_EQ(HMAC_RIPEMD160("Jefe", "what do ya want for nothing?").digest(), unhexlify("dda6c0213a485a9e24f4742064a7f033b43c4069"));
    EXPECT_EQ(HMAC_RIPEMD160(std::string(20, 0xaa), std::string(50, 0xdd)).digest(), unhexlify("b0b105360de759960ab4f35298e116e295d8e7c1"));
    EXPECT_EQ(HMAC_RIPEMD160(unhexlify("0102030405060708090a0b0c0d0e0f10111213141516171819"), std::string(50, 0xcd)).digest(), unhexlify("d5ca862f4d21d5e610e18b4cf1beb97a4365ecf4"));
    EXPECT_EQ(HMAC_RIPEMD160(std::string(20, 0x0c), "Test With Truncation").digest(), unhexlify("7619693978f91d90539ae786500ff3d8e0518e39"));
    EXPECT_EQ(HMAC_RIPEMD160(std::string(80, 0xaa), "Test Using Larger Than Block-Size Key - Hash Key First").digest(), unhexlify("6466ca07ac5eac29e1bd523e5ada7605b791fd8b"));
    EXPECT_EQ(HMAC_RIPEMD160(std::string(80, 0xaa), "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data").digest(), unhexlify("69ea60798d71616cce5fd0871e23754cd75d5a0a"));
}

TEST(HMACTest, test_rfc4231){
    // 4.2. Test Case 1
    std::string TEST_CASE_1_KEY(20, 0x0b);
    std::string TEST_CASE_1_MSG = "Hi There";
    EXPECT_EQ(HMAC_SHA224(TEST_CASE_1_KEY, TEST_CASE_1_MSG).digest(), unhexlify("896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22"));
    EXPECT_EQ(HMAC_SHA256(TEST_CASE_1_KEY, TEST_CASE_1_MSG).digest(), unhexlify("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
    EXPECT_EQ(HMAC_SHA384(TEST_CASE_1_KEY, TEST_CASE_1_MSG).digest(), unhexlify("afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"));
    EXPECT_EQ(HMAC_SHA512(TEST_CASE_1_KEY, TEST_CASE_1_MSG).digest(), unhexlify("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"));

    // 4.3. Test Case 2
    std::string TEST_CASE_2_KEY = "Jefe";
    std::string TEST_CASE_2_MSG = "what do ya want for nothing?";
    EXPECT_EQ(HMAC_SHA224(TEST_CASE_2_KEY, TEST_CASE_2_MSG).digest(), unhexlify("a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44"));
    EXPECT_EQ(HMAC_SHA256(TEST_CASE_2_KEY, TEST_CASE_2_MSG).digest(), unhexlify("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
    EXPECT_EQ(HMAC_SHA384(TEST_CASE_2_KEY, TEST_CASE_2_MSG).digest(), unhexlify("af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649"));
    EXPECT_EQ(HMAC_SHA512(TEST_CASE_2_KEY, TEST_CASE_2_MSG).digest(), unhexlify("164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"));

    // 4.4. Test Case 3
    std::string TEST_CASE_3_KEY(20, 0xaa);
    std::string TEST_CASE_3_MSG(50, 0xdd);
    EXPECT_EQ(HMAC_SHA224(TEST_CASE_3_KEY, TEST_CASE_3_MSG).digest(), unhexlify("7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea"));
    EXPECT_EQ(HMAC_SHA256(TEST_CASE_3_KEY, TEST_CASE_3_MSG).digest(), unhexlify("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"));
    EXPECT_EQ(HMAC_SHA384(TEST_CASE_3_KEY, TEST_CASE_3_MSG).digest(), unhexlify("88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27"));
    EXPECT_EQ(HMAC_SHA512(TEST_CASE_3_KEY, TEST_CASE_3_MSG).digest(), unhexlify("fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb"));

    // 4.5. Test Case 4
    std::string TEST_CASE_4_KEY = unhexlify("0102030405060708090a0b0c0d0e0f10111213141516171819");
    std::string TEST_CASE_4_MSG(50, 0xcd);
    EXPECT_EQ(HMAC_SHA224(TEST_CASE_4_KEY, TEST_CASE_4_MSG).digest(), unhexlify("6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a"));
    EXPECT_EQ(HMAC_SHA256(TEST_CASE_4_KEY, TEST_CASE_4_MSG).digest(), unhexlify("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"));
    EXPECT_EQ(HMAC_SHA384(TEST_CASE_4_KEY, TEST_CASE_4_MSG).digest(), unhexlify("3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb"));
    EXPECT_EQ(HMAC_SHA512(TEST_CASE_4_KEY, TEST_CASE_4_MSG).digest(), unhexlify("b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd"));

    // 4.6. Test Case 5
    std::string TEST_CASE_5_KEY(20, 0x0c);
    std::string TEST_CASE_5_MSG = "Test With Truncation";
    EXPECT_EQ(HMAC_SHA224(TEST_CASE_5_KEY, TEST_CASE_5_MSG).digest().substr(0, 16), unhexlify("0e2aea68a90c8d37c988bcdb9fca6fa8"));
    EXPECT_EQ(HMAC_SHA256(TEST_CASE_5_KEY, TEST_CASE_5_MSG).digest().substr(0, 16), unhexlify("a3b6167473100ee06e0c796c2955552b"));
    EXPECT_EQ(HMAC_SHA384(TEST_CASE_5_KEY, TEST_CASE_5_MSG).digest().substr(0, 16), unhexlify("3abf34c3503b2a23a46efc619baef897"));
    EXPECT_EQ(HMAC_SHA512(TEST_CASE_5_KEY, TEST_CASE_5_MSG).digest().substr(0, 16), unhexlify("415fad6271580a531d4179bc891d87a6"));

    // 4.7. Test Case 6
    std::string TEST_CASE_6_KEY(131, 0xaa);
    std::string TEST_CASE_6_MSG = "Test Using Larger Than Block-Size Key - Hash Key First";
    EXPECT_EQ(HMAC_SHA224(TEST_CASE_6_KEY, TEST_CASE_6_MSG).digest(), unhexlify("95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e"));
    EXPECT_EQ(HMAC_SHA256(TEST_CASE_6_KEY, TEST_CASE_6_MSG).digest(), unhexlify("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"));
    EXPECT_EQ(HMAC_SHA384(TEST_CASE_6_KEY, TEST_CASE_6_MSG).digest(), unhexlify("4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952"));
    EXPECT_EQ(HMAC_SHA512(TEST_CASE_6_KEY, TEST_CASE_6_MSG).digest(), unhexlify("80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"));

    // 4.8. Test Case 7
    std::string TEST_CASE_7_KEY(131, 0xaa);
    std::string TEST_CASE_7_MSG = "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
    EXPECT_EQ(HMAC_SHA224(TEST_CASE_7_KEY, TEST_CASE_7_MSG).digest(), unhexlify("3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1"));
    EXPECT_EQ(HMAC_SHA256(TEST_CASE_7_KEY, TEST_CASE_7_MSG).digest(), unhexlify("9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"));
    EXPECT_EQ(HMAC_SHA384(TEST_CASE_7_KEY, TEST_CASE_7_MSG).digest(), unhexlify("6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e"));
    EXPECT_EQ(HMAC_SHA512(TEST_CASE_7_KEY, TEST_CASE_7_MSG).digest(), unhexlify("e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58"));

}

TEST(HMACTest, test_hmac_sha1){

    ASSERT_EQ(HMAC_SHA1_KEY.size(), HMAC_SHA1_MSG.size());
    ASSERT_EQ(HMAC_SHA1_MSG.size(), HMAC_SHA1_MAC.size());

    for (unsigned int i = 0; i < HMAC_SHA1_KEY.size(); ++i){
        auto digest = HMAC_SHA1(unhexlify(HMAC_SHA1_KEY[i]), unhexlify(HMAC_SHA1_MSG[i])).digest();
        auto mac = unhexlify(HMAC_SHA1_MAC[i]);
        EXPECT_EQ(digest.substr(0, mac.size()), mac);
    }
}

TEST(HMACTest, test_hmac_sha224){

    ASSERT_EQ(HMAC_SHA224_KEY.size(), HMAC_SHA224_MSG.size());
    ASSERT_EQ(HMAC_SHA224_MSG.size(), HMAC_SHA224_MAC.size());

    for (unsigned int i = 0; i < HMAC_SHA224_KEY.size(); ++i){
        auto digest = HMAC_SHA224(unhexlify(HMAC_SHA224_KEY[i]), unhexlify(HMAC_SHA224_MSG[i])).digest();
        auto mac = unhexlify(HMAC_SHA224_MAC[i]);
        EXPECT_EQ(digest.substr(0, mac.size()), mac);
    }
}

TEST(HMACTest, test_hmac_sha256){

    ASSERT_EQ(HMAC_SHA256_KEY.size(), HMAC_SHA256_MSG.size());
    ASSERT_EQ(HMAC_SHA256_MSG.size(), HMAC_SHA256_MAC.size());

    for (unsigned int i = 0; i < HMAC_SHA256_KEY.size(); ++i){
        auto digest = HMAC_SHA256(unhexlify(HMAC_SHA256_KEY[i]), unhexlify(HMAC_SHA256_MSG[i])).digest();
        auto mac = unhexlify(HMAC_SHA256_MAC[i]);
        EXPECT_EQ(digest.substr(0, mac.size()), mac);
    }
}

TEST(HMACTest, test_hmac_sha384){

    ASSERT_EQ(HMAC_SHA384_KEY.size(), HMAC_SHA384_MSG.size());
    ASSERT_EQ(HMAC_SHA384_MSG.size(), HMAC_SHA384_MAC.size());

    for (unsigned int i = 0; i < HMAC_SHA384_KEY.size(); ++i){
        auto digest = HMAC_SHA384(unhexlify(HMAC_SHA384_KEY[i]), unhexlify(HMAC_SHA384_MSG[i])).digest();
        auto mac = unhexlify(HMAC_SHA384_MAC[i]);
        EXPECT_EQ(digest.substr(0, mac.size()), mac);
    }
}

TEST(HMACTest, test_hmac_sha512){

    ASSERT_EQ(HMAC_SHA512_KEY.size(), HMAC_SHA512_MSG.size());
    ASSERT_EQ(HMAC_SHA512_MSG.size(), HMAC_SHA512_MAC.size());

    for (unsigned int i = 0; i < HMAC_SHA512_KEY.size(); ++i){
        auto digest = HMAC_SHA512(unhexlify(HMAC_SHA512_KEY[i]), unhexlify(HMAC_SHA512_MSG[i])).digest();
        auto mac = unhexlify(HMAC_SHA512_MAC[i]);
        EXPECT_EQ(digest.substr(0, mac.size()), mac);
    }
}
