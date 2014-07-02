#include <gtest/gtest.h>

#include "RNG/DRBG/HMAC.h"

#include "testvectors/drbg/hmac/no_reseed.h"
#include "testvectors/drbg/hmac/pr_false.h"
#include "testvectors/drbg/hmac/pr_true.h"

TEST(HMACDRBGTest, test_no_reseed_sha1){
    ASSERT_EQ(NO_RESEED_ENTROPY_SHA1.size(), NO_RESEED_NONCE_SHA1.size());
    ASSERT_EQ(NO_RESEED_NONCE_SHA1.size(), NO_RESEED_PERSONAL_SHA1.size());
    ASSERT_EQ(NO_RESEED_PERSONAL_SHA1.size(), NO_RESEED_ADDITIONAL1_SHA1.size());
    ASSERT_EQ(NO_RESEED_ADDITIONAL1_SHA1.size(), NO_RESEED_ADDITIONAL2_SHA1.size());
    ASSERT_EQ(NO_RESEED_ADDITIONAL2_SHA1.size(), NO_RESEED_RETURN_SHA1.size());

    for (unsigned int i = 0; i < NO_RESEED_ENTROPY_SHA1.size(); ++i){
        std::string
                entropy     = unhexlify(NO_RESEED_ENTROPY_SHA1[i]),
                nonce       = unhexlify(NO_RESEED_NONCE_SHA1[i]),
                personal    = unhexlify(NO_RESEED_PERSONAL_SHA1[i]),
                additional1 = unhexlify(NO_RESEED_ADDITIONAL1_SHA1[i]),
                additional2 = unhexlify(NO_RESEED_ADDITIONAL2_SHA1[i]),
                returnbits  = unhexlify(NO_RESEED_RETURN_SHA1[i]);

        HMAC_DRBG<HMAC_SHA1> drbg(entropy, nonce, personal);
        drbg.generate(returnbits.size(), additional1);
        EXPECT_EQ(drbg.generate(returnbits.size(), additional2), returnbits);
    }
}

TEST(HMACDRBGTest, test_no_reseed_sha224){
    ASSERT_EQ(NO_RESEED_ENTROPY_SHA224.size(), NO_RESEED_NONCE_SHA224.size());
    ASSERT_EQ(NO_RESEED_NONCE_SHA224.size(), NO_RESEED_PERSONAL_SHA224.size());
    ASSERT_EQ(NO_RESEED_PERSONAL_SHA224.size(), NO_RESEED_ADDITIONAL1_SHA224.size());
    ASSERT_EQ(NO_RESEED_ADDITIONAL1_SHA224.size(), NO_RESEED_ADDITIONAL2_SHA224.size());
    ASSERT_EQ(NO_RESEED_ADDITIONAL2_SHA224.size(), NO_RESEED_RETURN_SHA224.size());

    for (unsigned int i = 0; i < NO_RESEED_ENTROPY_SHA224.size(); ++i){
        std::string
                entropy     = unhexlify(NO_RESEED_ENTROPY_SHA224[i]),
                nonce       = unhexlify(NO_RESEED_NONCE_SHA224[i]),
                personal    = unhexlify(NO_RESEED_PERSONAL_SHA224[i]),
                additional1 = unhexlify(NO_RESEED_ADDITIONAL1_SHA224[i]),
                additional2 = unhexlify(NO_RESEED_ADDITIONAL2_SHA224[i]),
                returnbits  = unhexlify(NO_RESEED_RETURN_SHA224[i]);

        HMAC_DRBG<HMAC_SHA224> drbg(entropy, nonce, personal);
        drbg.generate(returnbits.size(), additional1);
        EXPECT_EQ(drbg.generate(returnbits.size(), additional2), returnbits);
    }
}

TEST(HMACDRBGTest, test_no_reseed_sha256){
    ASSERT_EQ(NO_RESEED_ENTROPY_SHA256.size(), NO_RESEED_NONCE_SHA256.size());
    ASSERT_EQ(NO_RESEED_NONCE_SHA256.size(), NO_RESEED_PERSONAL_SHA256.size());
    ASSERT_EQ(NO_RESEED_PERSONAL_SHA256.size(), NO_RESEED_ADDITIONAL1_SHA256.size());
    ASSERT_EQ(NO_RESEED_ADDITIONAL1_SHA256.size(), NO_RESEED_ADDITIONAL2_SHA256.size());
    ASSERT_EQ(NO_RESEED_ADDITIONAL2_SHA256.size(), NO_RESEED_RETURN_SHA256.size());

    for (unsigned int i = 0; i < NO_RESEED_ENTROPY_SHA256.size(); ++i){
        std::string
                entropy     = unhexlify(NO_RESEED_ENTROPY_SHA256[i]),
                nonce       = unhexlify(NO_RESEED_NONCE_SHA256[i]),
                personal    = unhexlify(NO_RESEED_PERSONAL_SHA256[i]),
                additional1 = unhexlify(NO_RESEED_ADDITIONAL1_SHA256[i]),
                additional2 = unhexlify(NO_RESEED_ADDITIONAL2_SHA256[i]),
                returnbits  = unhexlify(NO_RESEED_RETURN_SHA256[i]);

        HMAC_DRBG<HMAC_SHA256> drbg(entropy, nonce, personal);
        drbg.generate(returnbits.size(), additional1);
        EXPECT_EQ(drbg.generate(returnbits.size(), additional2), returnbits);
    }
}

TEST(HMACDRBGTest, test_no_reseed_sha384){
    ASSERT_EQ(NO_RESEED_ENTROPY_SHA384.size(), NO_RESEED_NONCE_SHA384.size());
    ASSERT_EQ(NO_RESEED_NONCE_SHA384.size(), NO_RESEED_PERSONAL_SHA384.size());
    ASSERT_EQ(NO_RESEED_PERSONAL_SHA384.size(), NO_RESEED_ADDITIONAL1_SHA384.size());
    ASSERT_EQ(NO_RESEED_ADDITIONAL1_SHA384.size(), NO_RESEED_ADDITIONAL2_SHA384.size());
    ASSERT_EQ(NO_RESEED_ADDITIONAL2_SHA384.size(), NO_RESEED_RETURN_SHA384.size());

    for (unsigned int i = 0; i < NO_RESEED_ENTROPY_SHA384.size(); ++i){
        std::string
                entropy     = unhexlify(NO_RESEED_ENTROPY_SHA384[i]),
                nonce       = unhexlify(NO_RESEED_NONCE_SHA384[i]),
                personal    = unhexlify(NO_RESEED_PERSONAL_SHA384[i]),
                additional1 = unhexlify(NO_RESEED_ADDITIONAL1_SHA384[i]),
                additional2 = unhexlify(NO_RESEED_ADDITIONAL2_SHA384[i]),
                returnbits  = unhexlify(NO_RESEED_RETURN_SHA384[i]);

        HMAC_DRBG<HMAC_SHA384> drbg(entropy, nonce, personal);
        drbg.generate(returnbits.size(), additional1);
        EXPECT_EQ(drbg.generate(returnbits.size(), additional2), returnbits);
    }
}

TEST(HMACDRBGTest, test_no_reseed_sha512){
    ASSERT_EQ(NO_RESEED_ENTROPY_SHA512.size(), NO_RESEED_NONCE_SHA512.size());
    ASSERT_EQ(NO_RESEED_NONCE_SHA512.size(), NO_RESEED_PERSONAL_SHA512.size());
    ASSERT_EQ(NO_RESEED_PERSONAL_SHA512.size(), NO_RESEED_ADDITIONAL1_SHA512.size());
    ASSERT_EQ(NO_RESEED_ADDITIONAL1_SHA512.size(), NO_RESEED_ADDITIONAL2_SHA512.size());
    ASSERT_EQ(NO_RESEED_ADDITIONAL2_SHA512.size(), NO_RESEED_RETURN_SHA512.size());

    for (unsigned int i = 0; i < NO_RESEED_ENTROPY_SHA512.size(); ++i){
        std::string
                entropy     = unhexlify(NO_RESEED_ENTROPY_SHA512[i]),
                nonce       = unhexlify(NO_RESEED_NONCE_SHA512[i]),
                personal    = unhexlify(NO_RESEED_PERSONAL_SHA512[i]),
                additional1 = unhexlify(NO_RESEED_ADDITIONAL1_SHA512[i]),
                additional2 = unhexlify(NO_RESEED_ADDITIONAL2_SHA512[i]),
                returnbits  = unhexlify(NO_RESEED_RETURN_SHA512[i]);

        HMAC_DRBG<HMAC_SHA512> drbg(entropy, nonce, personal);
        drbg.generate(returnbits.size(), additional1);
        EXPECT_EQ(drbg.generate(returnbits.size(), additional2), returnbits);
    }
}

TEST(HMACDRBGTest, test_pr_false_sha1){
    ASSERT_EQ(PR_FALSE_ENTROPY_SHA1.size(), PR_FALSE_NONCE_SHA1.size());
    ASSERT_EQ(PR_FALSE_NONCE_SHA1.size(), PR_FALSE_PERSONAL_SHA1.size());
    ASSERT_EQ(PR_FALSE_PERSONAL_SHA1.size(), PR_FALSE_RESEED_ENTROPY_SHA1.size());
    ASSERT_EQ(PR_FALSE_RESEED_ENTROPY_SHA1.size(), PR_FALSE_RESEED_ADDITIONAL_SHA1.size());
    ASSERT_EQ(PR_FALSE_RESEED_ADDITIONAL_SHA1.size(), PR_FALSE_ADDITIONAL1_SHA1.size());
    ASSERT_EQ(PR_FALSE_ADDITIONAL1_SHA1.size(), PR_FALSE_ADDITIONAL2_SHA1.size());
    ASSERT_EQ(PR_FALSE_ADDITIONAL2_SHA1.size(), PR_FALSE_RETURN_SHA1.size());

    for (unsigned int i = 0; i < PR_FALSE_ENTROPY_SHA1.size(); ++i){
        std::string
                entropy     = unhexlify(PR_FALSE_ENTROPY_SHA1[i]),
                nonce       = unhexlify(PR_FALSE_NONCE_SHA1[i]),
                personal    = unhexlify(PR_FALSE_PERSONAL_SHA1[i]),
                reseed_ent  = unhexlify(PR_FALSE_RESEED_ENTROPY_SHA1[i]),
                reseed_add  = unhexlify(PR_FALSE_RESEED_ADDITIONAL_SHA1[i]),
                additional1 = unhexlify(PR_FALSE_ADDITIONAL1_SHA1[i]),
                additional2 = unhexlify(PR_FALSE_ADDITIONAL2_SHA1[i]),
                returnbits  = unhexlify(PR_FALSE_RETURN_SHA1[i]);

        HMAC_DRBG<HMAC_SHA1> drbg(entropy, nonce, personal);
        drbg.reseed(reseed_ent, reseed_add);
        drbg.generate(returnbits.size(), additional1);
        EXPECT_EQ(drbg.generate(returnbits.size(), additional2), returnbits);
    }
}

TEST(HMACDRBGTest, test_pr_false_sha224){
    ASSERT_EQ(PR_FALSE_ENTROPY_SHA224.size(), PR_FALSE_NONCE_SHA224.size());
    ASSERT_EQ(PR_FALSE_NONCE_SHA224.size(), PR_FALSE_PERSONAL_SHA224.size());
    ASSERT_EQ(PR_FALSE_PERSONAL_SHA224.size(), PR_FALSE_RESEED_ENTROPY_SHA224.size());
    ASSERT_EQ(PR_FALSE_RESEED_ENTROPY_SHA224.size(), PR_FALSE_RESEED_ADDITIONAL_SHA224.size());
    ASSERT_EQ(PR_FALSE_RESEED_ADDITIONAL_SHA224.size(), PR_FALSE_ADDITIONAL1_SHA224.size());
    ASSERT_EQ(PR_FALSE_ADDITIONAL1_SHA224.size(), PR_FALSE_ADDITIONAL2_SHA224.size());
    ASSERT_EQ(PR_FALSE_ADDITIONAL2_SHA224.size(), PR_FALSE_RETURN_SHA224.size());

    for (unsigned int i = 0; i < PR_FALSE_ENTROPY_SHA224.size(); ++i){
        std::string
                entropy     = unhexlify(PR_FALSE_ENTROPY_SHA224[i]),
                nonce       = unhexlify(PR_FALSE_NONCE_SHA224[i]),
                personal    = unhexlify(PR_FALSE_PERSONAL_SHA224[i]),
                reseed_ent  = unhexlify(PR_FALSE_RESEED_ENTROPY_SHA224[i]),
                reseed_add  = unhexlify(PR_FALSE_RESEED_ADDITIONAL_SHA224[i]),
                additional1 = unhexlify(PR_FALSE_ADDITIONAL1_SHA224[i]),
                additional2 = unhexlify(PR_FALSE_ADDITIONAL2_SHA224[i]),
                returnbits  = unhexlify(PR_FALSE_RETURN_SHA224[i]);

        HMAC_DRBG<HMAC_SHA224> drbg(entropy, nonce, personal);
        drbg.reseed(reseed_ent, reseed_add);
        drbg.generate(returnbits.size(), additional1);
        EXPECT_EQ(drbg.generate(returnbits.size(), additional2), returnbits);
    }
}

TEST(HMACDRBGTest, test_pr_false_sha256){
    ASSERT_EQ(PR_FALSE_ENTROPY_SHA256.size(), PR_FALSE_NONCE_SHA256.size());
    ASSERT_EQ(PR_FALSE_NONCE_SHA256.size(), PR_FALSE_PERSONAL_SHA256.size());
    ASSERT_EQ(PR_FALSE_PERSONAL_SHA256.size(), PR_FALSE_RESEED_ENTROPY_SHA256.size());
    ASSERT_EQ(PR_FALSE_RESEED_ENTROPY_SHA256.size(), PR_FALSE_RESEED_ADDITIONAL_SHA256.size());
    ASSERT_EQ(PR_FALSE_RESEED_ADDITIONAL_SHA256.size(), PR_FALSE_ADDITIONAL1_SHA256.size());
    ASSERT_EQ(PR_FALSE_ADDITIONAL1_SHA256.size(), PR_FALSE_ADDITIONAL2_SHA256.size());
    ASSERT_EQ(PR_FALSE_ADDITIONAL2_SHA256.size(), PR_FALSE_RETURN_SHA256.size());

    for (unsigned int i = 0; i < PR_FALSE_ENTROPY_SHA256.size(); ++i){
        std::string
                entropy     = unhexlify(PR_FALSE_ENTROPY_SHA256[i]),
                nonce       = unhexlify(PR_FALSE_NONCE_SHA256[i]),
                personal    = unhexlify(PR_FALSE_PERSONAL_SHA256[i]),
                reseed_ent  = unhexlify(PR_FALSE_RESEED_ENTROPY_SHA256[i]),
                reseed_add  = unhexlify(PR_FALSE_RESEED_ADDITIONAL_SHA256[i]),
                additional1 = unhexlify(PR_FALSE_ADDITIONAL1_SHA256[i]),
                additional2 = unhexlify(PR_FALSE_ADDITIONAL2_SHA256[i]),
                returnbits  = unhexlify(PR_FALSE_RETURN_SHA256[i]);

        HMAC_DRBG<HMAC_SHA256> drbg(entropy, nonce, personal);
        drbg.reseed(reseed_ent, reseed_add);
        drbg.generate(returnbits.size(), additional1);
        EXPECT_EQ(drbg.generate(returnbits.size(), additional2), returnbits);
    }
}

TEST(HMACDRBGTest, test_pr_false_sha384){
    ASSERT_EQ(PR_FALSE_ENTROPY_SHA384.size(), PR_FALSE_NONCE_SHA384.size());
    ASSERT_EQ(PR_FALSE_NONCE_SHA384.size(), PR_FALSE_PERSONAL_SHA384.size());
    ASSERT_EQ(PR_FALSE_PERSONAL_SHA384.size(), PR_FALSE_RESEED_ENTROPY_SHA384.size());
    ASSERT_EQ(PR_FALSE_RESEED_ENTROPY_SHA384.size(), PR_FALSE_RESEED_ADDITIONAL_SHA384.size());
    ASSERT_EQ(PR_FALSE_RESEED_ADDITIONAL_SHA384.size(), PR_FALSE_ADDITIONAL1_SHA384.size());
    ASSERT_EQ(PR_FALSE_ADDITIONAL1_SHA384.size(), PR_FALSE_ADDITIONAL2_SHA384.size());
    ASSERT_EQ(PR_FALSE_ADDITIONAL2_SHA384.size(), PR_FALSE_RETURN_SHA384.size());

    for (unsigned int i = 0; i < PR_FALSE_ENTROPY_SHA384.size(); ++i){
        std::string
                entropy     = unhexlify(PR_FALSE_ENTROPY_SHA384[i]),
                nonce       = unhexlify(PR_FALSE_NONCE_SHA384[i]),
                personal    = unhexlify(PR_FALSE_PERSONAL_SHA384[i]),
                reseed_ent  = unhexlify(PR_FALSE_RESEED_ENTROPY_SHA384[i]),
                reseed_add  = unhexlify(PR_FALSE_RESEED_ADDITIONAL_SHA384[i]),
                additional1 = unhexlify(PR_FALSE_ADDITIONAL1_SHA384[i]),
                additional2 = unhexlify(PR_FALSE_ADDITIONAL2_SHA384[i]),
                returnbits  = unhexlify(PR_FALSE_RETURN_SHA384[i]);

        HMAC_DRBG<HMAC_SHA384> drbg(entropy, nonce, personal);
        drbg.reseed(reseed_ent, reseed_add);
        drbg.generate(returnbits.size(), additional1);
        EXPECT_EQ(drbg.generate(returnbits.size(), additional2), returnbits);
    }
}

TEST(HMACDRBGTest, test_pr_false_sha512){
    ASSERT_EQ(PR_FALSE_ENTROPY_SHA512.size(), PR_FALSE_NONCE_SHA512.size());
    ASSERT_EQ(PR_FALSE_NONCE_SHA512.size(), PR_FALSE_PERSONAL_SHA512.size());
    ASSERT_EQ(PR_FALSE_PERSONAL_SHA512.size(), PR_FALSE_RESEED_ENTROPY_SHA512.size());
    ASSERT_EQ(PR_FALSE_RESEED_ENTROPY_SHA512.size(), PR_FALSE_RESEED_ADDITIONAL_SHA512.size());
    ASSERT_EQ(PR_FALSE_RESEED_ADDITIONAL_SHA512.size(), PR_FALSE_ADDITIONAL1_SHA512.size());
    ASSERT_EQ(PR_FALSE_ADDITIONAL1_SHA512.size(), PR_FALSE_ADDITIONAL2_SHA512.size());
    ASSERT_EQ(PR_FALSE_ADDITIONAL2_SHA512.size(), PR_FALSE_RETURN_SHA512.size());

    for (unsigned int i = 0; i < PR_FALSE_ENTROPY_SHA512.size(); ++i){
        std::string
                entropy     = unhexlify(PR_FALSE_ENTROPY_SHA512[i]),
                nonce       = unhexlify(PR_FALSE_NONCE_SHA512[i]),
                personal    = unhexlify(PR_FALSE_PERSONAL_SHA512[i]),
                reseed_ent  = unhexlify(PR_FALSE_RESEED_ENTROPY_SHA512[i]),
                reseed_add  = unhexlify(PR_FALSE_RESEED_ADDITIONAL_SHA512[i]),
                additional1 = unhexlify(PR_FALSE_ADDITIONAL1_SHA512[i]),
                additional2 = unhexlify(PR_FALSE_ADDITIONAL2_SHA512[i]),
                returnbits  = unhexlify(PR_FALSE_RETURN_SHA512[i]);

        HMAC_DRBG<HMAC_SHA512> drbg(entropy, nonce, personal);
        drbg.reseed(reseed_ent, reseed_add);
        drbg.generate(returnbits.size(), additional1);
        EXPECT_EQ(drbg.generate(returnbits.size(), additional2), returnbits);
    }
}

TEST(HMACDRBGTest, test_pr_true_sha1){
    ASSERT_EQ(PR_TRUE_ENTROPY_SHA1.size(), PR_TRUE_NONCE_SHA1.size());
    ASSERT_EQ(PR_TRUE_NONCE_SHA1.size(), PR_TRUE_PERSONAL_SHA1.size());
    ASSERT_EQ(PR_TRUE_PERSONAL_SHA1.size(), PR_TRUE_ADDITIONAL1_SHA1.size());
    ASSERT_EQ(PR_TRUE_ADDITIONAL1_SHA1.size(), PR_TRUE_ADDITIONAL2_SHA1.size());
    ASSERT_EQ(PR_TRUE_ADDITIONAL2_SHA1.size(), PR_TRUE_PR_ENTROPY1_SHA1.size());
    ASSERT_EQ(PR_TRUE_PR_ENTROPY1_SHA1.size(), PR_TRUE_PR_ENTROPY2_SHA1.size());
    ASSERT_EQ(PR_TRUE_PR_ENTROPY2_SHA1.size(), PR_TRUE_RETURN_SHA1.size());

    for (unsigned int i = 0; i < PR_TRUE_ENTROPY_SHA1.size(); ++i){
        std::string
                entropy     = unhexlify(PR_TRUE_ENTROPY_SHA1[i]),
                nonce       = unhexlify(PR_TRUE_NONCE_SHA1[i]),
                personal    = unhexlify(PR_TRUE_PERSONAL_SHA1[i]),
                additional1 = unhexlify(PR_TRUE_ADDITIONAL1_SHA1[i]),
                additional2 = unhexlify(PR_TRUE_ADDITIONAL2_SHA1[i]),
                pr_entropy1 = unhexlify(PR_TRUE_PR_ENTROPY1_SHA1[i]),
                pr_entropy2 = unhexlify(PR_TRUE_PR_ENTROPY2_SHA1[i]),
                returnbits  = unhexlify(PR_TRUE_RETURN_SHA1[i]);

        HMAC_DRBG<HMAC_SHA1> drbg(entropy, nonce, personal);
        drbg.reseed(pr_entropy1, additional1);
        drbg.generate(returnbits.size());
        drbg.reseed(pr_entropy2, additional2);
        EXPECT_EQ(drbg.generate(returnbits.size()), returnbits);
    }
}

TEST(HMACDRBGTest, test_pr_true_sha224){
    ASSERT_EQ(PR_TRUE_ENTROPY_SHA224.size(), PR_TRUE_NONCE_SHA224.size());
    ASSERT_EQ(PR_TRUE_NONCE_SHA224.size(), PR_TRUE_PERSONAL_SHA224.size());
    ASSERT_EQ(PR_TRUE_PERSONAL_SHA224.size(), PR_TRUE_ADDITIONAL1_SHA224.size());
    ASSERT_EQ(PR_TRUE_ADDITIONAL1_SHA224.size(), PR_TRUE_ADDITIONAL2_SHA224.size());
    ASSERT_EQ(PR_TRUE_ADDITIONAL2_SHA224.size(), PR_TRUE_PR_ENTROPY1_SHA224.size());
    ASSERT_EQ(PR_TRUE_PR_ENTROPY1_SHA224.size(), PR_TRUE_PR_ENTROPY2_SHA224.size());
    ASSERT_EQ(PR_TRUE_PR_ENTROPY2_SHA224.size(), PR_TRUE_RETURN_SHA224.size());

    for (unsigned int i = 0; i < PR_TRUE_ENTROPY_SHA224.size(); ++i){
        std::string
                entropy     = unhexlify(PR_TRUE_ENTROPY_SHA224[i]),
                nonce       = unhexlify(PR_TRUE_NONCE_SHA224[i]),
                personal    = unhexlify(PR_TRUE_PERSONAL_SHA224[i]),
                additional1 = unhexlify(PR_TRUE_ADDITIONAL1_SHA224[i]),
                additional2 = unhexlify(PR_TRUE_ADDITIONAL2_SHA224[i]),
                pr_entropy1 = unhexlify(PR_TRUE_PR_ENTROPY1_SHA224[i]),
                pr_entropy2 = unhexlify(PR_TRUE_PR_ENTROPY2_SHA224[i]),
                returnbits  = unhexlify(PR_TRUE_RETURN_SHA224[i]);

        HMAC_DRBG<HMAC_SHA224> drbg(entropy, nonce, personal);
        drbg.reseed(pr_entropy1, additional1);
        drbg.generate(returnbits.size());
        drbg.reseed(pr_entropy2, additional2);
        EXPECT_EQ(drbg.generate(returnbits.size()), returnbits);
    }
}

TEST(HMACDRBGTest, test_pr_true_sha256){
    ASSERT_EQ(PR_TRUE_ENTROPY_SHA256.size(), PR_TRUE_NONCE_SHA256.size());
    ASSERT_EQ(PR_TRUE_NONCE_SHA256.size(), PR_TRUE_PERSONAL_SHA256.size());
    ASSERT_EQ(PR_TRUE_PERSONAL_SHA256.size(), PR_TRUE_ADDITIONAL1_SHA256.size());
    ASSERT_EQ(PR_TRUE_ADDITIONAL1_SHA256.size(), PR_TRUE_ADDITIONAL2_SHA256.size());
    ASSERT_EQ(PR_TRUE_ADDITIONAL2_SHA256.size(), PR_TRUE_PR_ENTROPY1_SHA256.size());
    ASSERT_EQ(PR_TRUE_PR_ENTROPY1_SHA256.size(), PR_TRUE_PR_ENTROPY2_SHA256.size());
    ASSERT_EQ(PR_TRUE_PR_ENTROPY2_SHA256.size(), PR_TRUE_RETURN_SHA256.size());

    for (unsigned int i = 0; i < PR_TRUE_ENTROPY_SHA256.size(); ++i){
        std::string
                entropy     = unhexlify(PR_TRUE_ENTROPY_SHA256[i]),
                nonce       = unhexlify(PR_TRUE_NONCE_SHA256[i]),
                personal    = unhexlify(PR_TRUE_PERSONAL_SHA256[i]),
                additional1 = unhexlify(PR_TRUE_ADDITIONAL1_SHA256[i]),
                additional2 = unhexlify(PR_TRUE_ADDITIONAL2_SHA256[i]),
                pr_entropy1 = unhexlify(PR_TRUE_PR_ENTROPY1_SHA256[i]),
                pr_entropy2 = unhexlify(PR_TRUE_PR_ENTROPY2_SHA256[i]),
                returnbits  = unhexlify(PR_TRUE_RETURN_SHA256[i]);

        HMAC_DRBG<HMAC_SHA256> drbg(entropy, nonce, personal);
        drbg.reseed(pr_entropy1, additional1);
        drbg.generate(returnbits.size());
        drbg.reseed(pr_entropy2, additional2);
        EXPECT_EQ(drbg.generate(returnbits.size()), returnbits);
    }
}

TEST(HMACDRBGTest, test_pr_true_sha384){
    ASSERT_EQ(PR_TRUE_ENTROPY_SHA384.size(), PR_TRUE_NONCE_SHA384.size());
    ASSERT_EQ(PR_TRUE_NONCE_SHA384.size(), PR_TRUE_PERSONAL_SHA384.size());
    ASSERT_EQ(PR_TRUE_PERSONAL_SHA384.size(), PR_TRUE_ADDITIONAL1_SHA384.size());
    ASSERT_EQ(PR_TRUE_ADDITIONAL1_SHA384.size(), PR_TRUE_ADDITIONAL2_SHA384.size());
    ASSERT_EQ(PR_TRUE_ADDITIONAL2_SHA384.size(), PR_TRUE_PR_ENTROPY1_SHA384.size());
    ASSERT_EQ(PR_TRUE_PR_ENTROPY1_SHA384.size(), PR_TRUE_PR_ENTROPY2_SHA384.size());
    ASSERT_EQ(PR_TRUE_PR_ENTROPY2_SHA384.size(), PR_TRUE_RETURN_SHA384.size());

    for (unsigned int i = 0; i < PR_TRUE_ENTROPY_SHA384.size(); ++i){
        std::string
                entropy     = unhexlify(PR_TRUE_ENTROPY_SHA384[i]),
                nonce       = unhexlify(PR_TRUE_NONCE_SHA384[i]),
                personal    = unhexlify(PR_TRUE_PERSONAL_SHA384[i]),
                additional1 = unhexlify(PR_TRUE_ADDITIONAL1_SHA384[i]),
                additional2 = unhexlify(PR_TRUE_ADDITIONAL2_SHA384[i]),
                pr_entropy1 = unhexlify(PR_TRUE_PR_ENTROPY1_SHA384[i]),
                pr_entropy2 = unhexlify(PR_TRUE_PR_ENTROPY2_SHA384[i]),
                returnbits  = unhexlify(PR_TRUE_RETURN_SHA384[i]);

        HMAC_DRBG<HMAC_SHA384> drbg(entropy, nonce, personal);
        drbg.reseed(pr_entropy1, additional1);
        drbg.generate(returnbits.size());
        drbg.reseed(pr_entropy2, additional2);
        EXPECT_EQ(drbg.generate(returnbits.size()), returnbits);
    }
}

TEST(HMACDRBGTest, test_pr_true_sha512){
    ASSERT_EQ(PR_TRUE_ENTROPY_SHA512.size(), PR_TRUE_NONCE_SHA512.size());
    ASSERT_EQ(PR_TRUE_NONCE_SHA512.size(), PR_TRUE_PERSONAL_SHA512.size());
    ASSERT_EQ(PR_TRUE_PERSONAL_SHA512.size(), PR_TRUE_ADDITIONAL1_SHA512.size());
    ASSERT_EQ(PR_TRUE_ADDITIONAL1_SHA512.size(), PR_TRUE_ADDITIONAL2_SHA512.size());
    ASSERT_EQ(PR_TRUE_ADDITIONAL2_SHA512.size(), PR_TRUE_PR_ENTROPY1_SHA512.size());
    ASSERT_EQ(PR_TRUE_PR_ENTROPY1_SHA512.size(), PR_TRUE_PR_ENTROPY2_SHA512.size());
    ASSERT_EQ(PR_TRUE_PR_ENTROPY2_SHA512.size(), PR_TRUE_RETURN_SHA512.size());

    for (unsigned int i = 0; i < PR_TRUE_ENTROPY_SHA512.size(); ++i){
        std::string
                entropy     = unhexlify(PR_TRUE_ENTROPY_SHA512[i]),
                nonce       = unhexlify(PR_TRUE_NONCE_SHA512[i]),
                personal    = unhexlify(PR_TRUE_PERSONAL_SHA512[i]),
                additional1 = unhexlify(PR_TRUE_ADDITIONAL1_SHA512[i]),
                additional2 = unhexlify(PR_TRUE_ADDITIONAL2_SHA512[i]),
                pr_entropy1 = unhexlify(PR_TRUE_PR_ENTROPY1_SHA512[i]),
                pr_entropy2 = unhexlify(PR_TRUE_PR_ENTROPY2_SHA512[i]),
                returnbits  = unhexlify(PR_TRUE_RETURN_SHA512[i]);

        HMAC_DRBG<HMAC_SHA512> drbg(entropy, nonce, personal);
        drbg.reseed(pr_entropy1, additional1);
        drbg.generate(returnbits.size());
        drbg.reseed(pr_entropy2, additional2);
        EXPECT_EQ(drbg.generate(returnbits.size()), returnbits);
    }
}
