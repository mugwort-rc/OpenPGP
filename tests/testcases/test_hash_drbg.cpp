#include <gtest/gtest.h>

#include "RNG/DRBG/Hash.h"

#include "testvectors/drbg/hash/no_reseed.h"
#include "testvectors/drbg/hash/pr_false.h"
#include "testvectors/drbg/hash/pr_true.h"

TEST(HashDRBGTest, test_no_reseed_sha1){
    ASSERT_EQ(HASH_DRBG_NO_RESEED_ENTROPY_SHA1.size(), HASH_DRBG_NO_RESEED_NONCE_SHA1.size());
    ASSERT_EQ(HASH_DRBG_NO_RESEED_NONCE_SHA1.size(), HASH_DRBG_NO_RESEED_PERSONAL_SHA1.size());
    ASSERT_EQ(HASH_DRBG_NO_RESEED_PERSONAL_SHA1.size(), HASH_DRBG_NO_RESEED_ADDITIONAL1_SHA1.size());
    ASSERT_EQ(HASH_DRBG_NO_RESEED_ADDITIONAL1_SHA1.size(), HASH_DRBG_NO_RESEED_ADDITIONAL2_SHA1.size());
    ASSERT_EQ(HASH_DRBG_NO_RESEED_ADDITIONAL2_SHA1.size(), HASH_DRBG_NO_RESEED_RETURN_SHA1.size());

    for (unsigned int i = 0; i < HASH_DRBG_NO_RESEED_ENTROPY_SHA1.size(); ++i){
        std::string
                entropy     = unhexlify(HASH_DRBG_NO_RESEED_ENTROPY_SHA1[i]),
                nonce       = unhexlify(HASH_DRBG_NO_RESEED_NONCE_SHA1[i]),
                personal    = unhexlify(HASH_DRBG_NO_RESEED_PERSONAL_SHA1[i]),
                additional1 = unhexlify(HASH_DRBG_NO_RESEED_ADDITIONAL1_SHA1[i]),
                additional2 = unhexlify(HASH_DRBG_NO_RESEED_ADDITIONAL2_SHA1[i]),
                returnbits  = unhexlify(HASH_DRBG_NO_RESEED_RETURN_SHA1[i]);

        Hash_DRBG_SHA1 drbg(entropy, nonce, personal);
        drbg.generate(returnbits.size(), additional1);
        EXPECT_EQ(drbg.generate(returnbits.size(), additional2), returnbits);
    }
}

TEST(HashDRBGTest, test_no_reseed_sha224){
    ASSERT_EQ(HASH_DRBG_NO_RESEED_ENTROPY_SHA224.size(), HASH_DRBG_NO_RESEED_NONCE_SHA224.size());
    ASSERT_EQ(HASH_DRBG_NO_RESEED_NONCE_SHA224.size(), HASH_DRBG_NO_RESEED_PERSONAL_SHA224.size());
    ASSERT_EQ(HASH_DRBG_NO_RESEED_PERSONAL_SHA224.size(), HASH_DRBG_NO_RESEED_ADDITIONAL1_SHA224.size());
    ASSERT_EQ(HASH_DRBG_NO_RESEED_ADDITIONAL1_SHA224.size(), HASH_DRBG_NO_RESEED_ADDITIONAL2_SHA224.size());
    ASSERT_EQ(HASH_DRBG_NO_RESEED_ADDITIONAL2_SHA224.size(), HASH_DRBG_NO_RESEED_RETURN_SHA224.size());

    for (unsigned int i = 0; i < HASH_DRBG_NO_RESEED_ENTROPY_SHA224.size(); ++i){
        std::string
                entropy     = unhexlify(HASH_DRBG_NO_RESEED_ENTROPY_SHA224[i]),
                nonce       = unhexlify(HASH_DRBG_NO_RESEED_NONCE_SHA224[i]),
                personal    = unhexlify(HASH_DRBG_NO_RESEED_PERSONAL_SHA224[i]),
                additional1 = unhexlify(HASH_DRBG_NO_RESEED_ADDITIONAL1_SHA224[i]),
                additional2 = unhexlify(HASH_DRBG_NO_RESEED_ADDITIONAL2_SHA224[i]),
                returnbits  = unhexlify(HASH_DRBG_NO_RESEED_RETURN_SHA224[i]);

        Hash_DRBG_SHA224 drbg(entropy, nonce, personal);
        drbg.generate(returnbits.size(), additional1);
        EXPECT_EQ(drbg.generate(returnbits.size(), additional2), returnbits);
    }
}

TEST(HashDRBGTest, test_no_reseed_sha256){
    ASSERT_EQ(HASH_DRBG_NO_RESEED_ENTROPY_SHA256.size(), HASH_DRBG_NO_RESEED_NONCE_SHA256.size());
    ASSERT_EQ(HASH_DRBG_NO_RESEED_NONCE_SHA256.size(), HASH_DRBG_NO_RESEED_PERSONAL_SHA256.size());
    ASSERT_EQ(HASH_DRBG_NO_RESEED_PERSONAL_SHA256.size(), HASH_DRBG_NO_RESEED_ADDITIONAL1_SHA256.size());
    ASSERT_EQ(HASH_DRBG_NO_RESEED_ADDITIONAL1_SHA256.size(), HASH_DRBG_NO_RESEED_ADDITIONAL2_SHA256.size());
    ASSERT_EQ(HASH_DRBG_NO_RESEED_ADDITIONAL2_SHA256.size(), HASH_DRBG_NO_RESEED_RETURN_SHA256.size());

    for (unsigned int i = 0; i < HASH_DRBG_NO_RESEED_ENTROPY_SHA256.size(); ++i){
        std::string
                entropy     = unhexlify(HASH_DRBG_NO_RESEED_ENTROPY_SHA256[i]),
                nonce       = unhexlify(HASH_DRBG_NO_RESEED_NONCE_SHA256[i]),
                personal    = unhexlify(HASH_DRBG_NO_RESEED_PERSONAL_SHA256[i]),
                additional1 = unhexlify(HASH_DRBG_NO_RESEED_ADDITIONAL1_SHA256[i]),
                additional2 = unhexlify(HASH_DRBG_NO_RESEED_ADDITIONAL2_SHA256[i]),
                returnbits  = unhexlify(HASH_DRBG_NO_RESEED_RETURN_SHA256[i]);

        Hash_DRBG_SHA256 drbg(entropy, nonce, personal);
        drbg.generate(returnbits.size(), additional1);
        EXPECT_EQ(drbg.generate(returnbits.size(), additional2), returnbits);
    }
}

TEST(HashDRBGTest, test_no_reseed_sha384){
    ASSERT_EQ(HASH_DRBG_NO_RESEED_ENTROPY_SHA384.size(), HASH_DRBG_NO_RESEED_NONCE_SHA384.size());
    ASSERT_EQ(HASH_DRBG_NO_RESEED_NONCE_SHA384.size(), HASH_DRBG_NO_RESEED_PERSONAL_SHA384.size());
    ASSERT_EQ(HASH_DRBG_NO_RESEED_PERSONAL_SHA384.size(), HASH_DRBG_NO_RESEED_ADDITIONAL1_SHA384.size());
    ASSERT_EQ(HASH_DRBG_NO_RESEED_ADDITIONAL1_SHA384.size(), HASH_DRBG_NO_RESEED_ADDITIONAL2_SHA384.size());
    ASSERT_EQ(HASH_DRBG_NO_RESEED_ADDITIONAL2_SHA384.size(), HASH_DRBG_NO_RESEED_RETURN_SHA384.size());

    for (unsigned int i = 0; i < HASH_DRBG_NO_RESEED_ENTROPY_SHA384.size(); ++i){
        std::string
                entropy     = unhexlify(HASH_DRBG_NO_RESEED_ENTROPY_SHA384[i]),
                nonce       = unhexlify(HASH_DRBG_NO_RESEED_NONCE_SHA384[i]),
                personal    = unhexlify(HASH_DRBG_NO_RESEED_PERSONAL_SHA384[i]),
                additional1 = unhexlify(HASH_DRBG_NO_RESEED_ADDITIONAL1_SHA384[i]),
                additional2 = unhexlify(HASH_DRBG_NO_RESEED_ADDITIONAL2_SHA384[i]),
                returnbits  = unhexlify(HASH_DRBG_NO_RESEED_RETURN_SHA384[i]);

        Hash_DRBG_SHA384 drbg(entropy, nonce, personal);
        drbg.generate(returnbits.size(), additional1);
        EXPECT_EQ(drbg.generate(returnbits.size(), additional2), returnbits);
    }
}

TEST(HashDRBGTest, test_no_reseed_sha512){
    ASSERT_EQ(HASH_DRBG_NO_RESEED_ENTROPY_SHA512.size(), HASH_DRBG_NO_RESEED_NONCE_SHA512.size());
    ASSERT_EQ(HASH_DRBG_NO_RESEED_NONCE_SHA512.size(), HASH_DRBG_NO_RESEED_PERSONAL_SHA512.size());
    ASSERT_EQ(HASH_DRBG_NO_RESEED_PERSONAL_SHA512.size(), HASH_DRBG_NO_RESEED_ADDITIONAL1_SHA512.size());
    ASSERT_EQ(HASH_DRBG_NO_RESEED_ADDITIONAL1_SHA512.size(), HASH_DRBG_NO_RESEED_ADDITIONAL2_SHA512.size());
    ASSERT_EQ(HASH_DRBG_NO_RESEED_ADDITIONAL2_SHA512.size(), HASH_DRBG_NO_RESEED_RETURN_SHA512.size());

    for (unsigned int i = 0; i < HASH_DRBG_NO_RESEED_ENTROPY_SHA512.size(); ++i){
        std::string
                entropy     = unhexlify(HASH_DRBG_NO_RESEED_ENTROPY_SHA512[i]),
                nonce       = unhexlify(HASH_DRBG_NO_RESEED_NONCE_SHA512[i]),
                personal    = unhexlify(HASH_DRBG_NO_RESEED_PERSONAL_SHA512[i]),
                additional1 = unhexlify(HASH_DRBG_NO_RESEED_ADDITIONAL1_SHA512[i]),
                additional2 = unhexlify(HASH_DRBG_NO_RESEED_ADDITIONAL2_SHA512[i]),
                returnbits  = unhexlify(HASH_DRBG_NO_RESEED_RETURN_SHA512[i]);

        Hash_DRBG_SHA512 drbg(entropy, nonce, personal);
        drbg.generate(returnbits.size(), additional1);
        EXPECT_EQ(drbg.generate(returnbits.size(), additional2), returnbits);
    }
}

TEST(HashDRBGTest, test_pr_false_sha1){
    ASSERT_EQ(HASH_DRBG_PR_FALSE_ENTROPY_SHA1.size(), HASH_DRBG_PR_FALSE_NONCE_SHA1.size());
    ASSERT_EQ(HASH_DRBG_PR_FALSE_NONCE_SHA1.size(), HASH_DRBG_PR_FALSE_PERSONAL_SHA1.size());
    ASSERT_EQ(HASH_DRBG_PR_FALSE_PERSONAL_SHA1.size(), HASH_DRBG_PR_FALSE_RESEED_ENTROPY_SHA1.size());
    ASSERT_EQ(HASH_DRBG_PR_FALSE_RESEED_ENTROPY_SHA1.size(), HASH_DRBG_PR_FALSE_RESEED_ADDITIONAL_SHA1.size());
    ASSERT_EQ(HASH_DRBG_PR_FALSE_RESEED_ADDITIONAL_SHA1.size(), HASH_DRBG_PR_FALSE_ADDITIONAL1_SHA1.size());
    ASSERT_EQ(HASH_DRBG_PR_FALSE_ADDITIONAL1_SHA1.size(), HASH_DRBG_PR_FALSE_ADDITIONAL2_SHA1.size());
    ASSERT_EQ(HASH_DRBG_PR_FALSE_ADDITIONAL2_SHA1.size(), HASH_DRBG_PR_FALSE_RETURN_SHA1.size());

    for (unsigned int i = 0; i < HASH_DRBG_PR_FALSE_ENTROPY_SHA1.size(); ++i){
        std::string
                entropy     = unhexlify(HASH_DRBG_PR_FALSE_ENTROPY_SHA1[i]),
                nonce       = unhexlify(HASH_DRBG_PR_FALSE_NONCE_SHA1[i]),
                personal    = unhexlify(HASH_DRBG_PR_FALSE_PERSONAL_SHA1[i]),
                reseed_ent  = unhexlify(HASH_DRBG_PR_FALSE_RESEED_ENTROPY_SHA1[i]),
                reseed_add  = unhexlify(HASH_DRBG_PR_FALSE_RESEED_ADDITIONAL_SHA1[i]),
                additional1 = unhexlify(HASH_DRBG_PR_FALSE_ADDITIONAL1_SHA1[i]),
                additional2 = unhexlify(HASH_DRBG_PR_FALSE_ADDITIONAL2_SHA1[i]),
                returnbits  = unhexlify(HASH_DRBG_PR_FALSE_RETURN_SHA1[i]);

        Hash_DRBG_SHA1 drbg(entropy, nonce, personal);
        drbg.reseed(reseed_ent, reseed_add);
        drbg.generate(returnbits.size(), additional1);
        EXPECT_EQ(drbg.generate(returnbits.size(), additional2), returnbits);
    }
}

TEST(HashDRBGTest, test_pr_false_sha224){
    ASSERT_EQ(HASH_DRBG_PR_FALSE_ENTROPY_SHA224.size(), HASH_DRBG_PR_FALSE_NONCE_SHA224.size());
    ASSERT_EQ(HASH_DRBG_PR_FALSE_NONCE_SHA224.size(), HASH_DRBG_PR_FALSE_PERSONAL_SHA224.size());
    ASSERT_EQ(HASH_DRBG_PR_FALSE_PERSONAL_SHA224.size(), HASH_DRBG_PR_FALSE_RESEED_ENTROPY_SHA224.size());
    ASSERT_EQ(HASH_DRBG_PR_FALSE_RESEED_ENTROPY_SHA224.size(), HASH_DRBG_PR_FALSE_RESEED_ADDITIONAL_SHA224.size());
    ASSERT_EQ(HASH_DRBG_PR_FALSE_RESEED_ADDITIONAL_SHA224.size(), HASH_DRBG_PR_FALSE_ADDITIONAL1_SHA224.size());
    ASSERT_EQ(HASH_DRBG_PR_FALSE_ADDITIONAL1_SHA224.size(), HASH_DRBG_PR_FALSE_ADDITIONAL2_SHA224.size());
    ASSERT_EQ(HASH_DRBG_PR_FALSE_ADDITIONAL2_SHA224.size(), HASH_DRBG_PR_FALSE_RETURN_SHA224.size());

    for (unsigned int i = 0; i < HASH_DRBG_PR_FALSE_ENTROPY_SHA224.size(); ++i){
        std::string
                entropy     = unhexlify(HASH_DRBG_PR_FALSE_ENTROPY_SHA224[i]),
                nonce       = unhexlify(HASH_DRBG_PR_FALSE_NONCE_SHA224[i]),
                personal    = unhexlify(HASH_DRBG_PR_FALSE_PERSONAL_SHA224[i]),
                reseed_ent  = unhexlify(HASH_DRBG_PR_FALSE_RESEED_ENTROPY_SHA224[i]),
                reseed_add  = unhexlify(HASH_DRBG_PR_FALSE_RESEED_ADDITIONAL_SHA224[i]),
                additional1 = unhexlify(HASH_DRBG_PR_FALSE_ADDITIONAL1_SHA224[i]),
                additional2 = unhexlify(HASH_DRBG_PR_FALSE_ADDITIONAL2_SHA224[i]),
                returnbits  = unhexlify(HASH_DRBG_PR_FALSE_RETURN_SHA224[i]);

        Hash_DRBG_SHA224 drbg(entropy, nonce, personal);
        drbg.reseed(reseed_ent, reseed_add);
        drbg.generate(returnbits.size(), additional1);
        EXPECT_EQ(drbg.generate(returnbits.size(), additional2), returnbits);
    }
}

TEST(HashDRBGTest, test_pr_false_sha256){
    ASSERT_EQ(HASH_DRBG_PR_FALSE_ENTROPY_SHA256.size(), HASH_DRBG_PR_FALSE_NONCE_SHA256.size());
    ASSERT_EQ(HASH_DRBG_PR_FALSE_NONCE_SHA256.size(), HASH_DRBG_PR_FALSE_PERSONAL_SHA256.size());
    ASSERT_EQ(HASH_DRBG_PR_FALSE_PERSONAL_SHA256.size(), HASH_DRBG_PR_FALSE_RESEED_ENTROPY_SHA256.size());
    ASSERT_EQ(HASH_DRBG_PR_FALSE_RESEED_ENTROPY_SHA256.size(), HASH_DRBG_PR_FALSE_RESEED_ADDITIONAL_SHA256.size());
    ASSERT_EQ(HASH_DRBG_PR_FALSE_RESEED_ADDITIONAL_SHA256.size(), HASH_DRBG_PR_FALSE_ADDITIONAL1_SHA256.size());
    ASSERT_EQ(HASH_DRBG_PR_FALSE_ADDITIONAL1_SHA256.size(), HASH_DRBG_PR_FALSE_ADDITIONAL2_SHA256.size());
    ASSERT_EQ(HASH_DRBG_PR_FALSE_ADDITIONAL2_SHA256.size(), HASH_DRBG_PR_FALSE_RETURN_SHA256.size());

    for (unsigned int i = 0; i < HASH_DRBG_PR_FALSE_ENTROPY_SHA256.size(); ++i){
        std::string
                entropy     = unhexlify(HASH_DRBG_PR_FALSE_ENTROPY_SHA256[i]),
                nonce       = unhexlify(HASH_DRBG_PR_FALSE_NONCE_SHA256[i]),
                personal    = unhexlify(HASH_DRBG_PR_FALSE_PERSONAL_SHA256[i]),
                reseed_ent  = unhexlify(HASH_DRBG_PR_FALSE_RESEED_ENTROPY_SHA256[i]),
                reseed_add  = unhexlify(HASH_DRBG_PR_FALSE_RESEED_ADDITIONAL_SHA256[i]),
                additional1 = unhexlify(HASH_DRBG_PR_FALSE_ADDITIONAL1_SHA256[i]),
                additional2 = unhexlify(HASH_DRBG_PR_FALSE_ADDITIONAL2_SHA256[i]),
                returnbits  = unhexlify(HASH_DRBG_PR_FALSE_RETURN_SHA256[i]);

        Hash_DRBG_SHA256 drbg(entropy, nonce, personal);
        drbg.reseed(reseed_ent, reseed_add);
        drbg.generate(returnbits.size(), additional1);
        EXPECT_EQ(drbg.generate(returnbits.size(), additional2), returnbits);
    }
}

TEST(HashDRBGTest, test_pr_false_sha384){
    ASSERT_EQ(HASH_DRBG_PR_FALSE_ENTROPY_SHA384.size(), HASH_DRBG_PR_FALSE_NONCE_SHA384.size());
    ASSERT_EQ(HASH_DRBG_PR_FALSE_NONCE_SHA384.size(), HASH_DRBG_PR_FALSE_PERSONAL_SHA384.size());
    ASSERT_EQ(HASH_DRBG_PR_FALSE_PERSONAL_SHA384.size(), HASH_DRBG_PR_FALSE_RESEED_ENTROPY_SHA384.size());
    ASSERT_EQ(HASH_DRBG_PR_FALSE_RESEED_ENTROPY_SHA384.size(), HASH_DRBG_PR_FALSE_RESEED_ADDITIONAL_SHA384.size());
    ASSERT_EQ(HASH_DRBG_PR_FALSE_RESEED_ADDITIONAL_SHA384.size(), HASH_DRBG_PR_FALSE_ADDITIONAL1_SHA384.size());
    ASSERT_EQ(HASH_DRBG_PR_FALSE_ADDITIONAL1_SHA384.size(), HASH_DRBG_PR_FALSE_ADDITIONAL2_SHA384.size());
    ASSERT_EQ(HASH_DRBG_PR_FALSE_ADDITIONAL2_SHA384.size(), HASH_DRBG_PR_FALSE_RETURN_SHA384.size());

    for (unsigned int i = 0; i < HASH_DRBG_PR_FALSE_ENTROPY_SHA384.size(); ++i){
        std::string
                entropy     = unhexlify(HASH_DRBG_PR_FALSE_ENTROPY_SHA384[i]),
                nonce       = unhexlify(HASH_DRBG_PR_FALSE_NONCE_SHA384[i]),
                personal    = unhexlify(HASH_DRBG_PR_FALSE_PERSONAL_SHA384[i]),
                reseed_ent  = unhexlify(HASH_DRBG_PR_FALSE_RESEED_ENTROPY_SHA384[i]),
                reseed_add  = unhexlify(HASH_DRBG_PR_FALSE_RESEED_ADDITIONAL_SHA384[i]),
                additional1 = unhexlify(HASH_DRBG_PR_FALSE_ADDITIONAL1_SHA384[i]),
                additional2 = unhexlify(HASH_DRBG_PR_FALSE_ADDITIONAL2_SHA384[i]),
                returnbits  = unhexlify(HASH_DRBG_PR_FALSE_RETURN_SHA384[i]);

        Hash_DRBG_SHA384 drbg(entropy, nonce, personal);
        drbg.reseed(reseed_ent, reseed_add);
        drbg.generate(returnbits.size(), additional1);
        EXPECT_EQ(drbg.generate(returnbits.size(), additional2), returnbits);
    }
}

TEST(HashDRBGTest, test_pr_false_sha512){
    ASSERT_EQ(HASH_DRBG_PR_FALSE_ENTROPY_SHA512.size(), HASH_DRBG_PR_FALSE_NONCE_SHA512.size());
    ASSERT_EQ(HASH_DRBG_PR_FALSE_NONCE_SHA512.size(), HASH_DRBG_PR_FALSE_PERSONAL_SHA512.size());
    ASSERT_EQ(HASH_DRBG_PR_FALSE_PERSONAL_SHA512.size(), HASH_DRBG_PR_FALSE_RESEED_ENTROPY_SHA512.size());
    ASSERT_EQ(HASH_DRBG_PR_FALSE_RESEED_ENTROPY_SHA512.size(), HASH_DRBG_PR_FALSE_RESEED_ADDITIONAL_SHA512.size());
    ASSERT_EQ(HASH_DRBG_PR_FALSE_RESEED_ADDITIONAL_SHA512.size(), HASH_DRBG_PR_FALSE_ADDITIONAL1_SHA512.size());
    ASSERT_EQ(HASH_DRBG_PR_FALSE_ADDITIONAL1_SHA512.size(), HASH_DRBG_PR_FALSE_ADDITIONAL2_SHA512.size());
    ASSERT_EQ(HASH_DRBG_PR_FALSE_ADDITIONAL2_SHA512.size(), HASH_DRBG_PR_FALSE_RETURN_SHA512.size());

    for (unsigned int i = 0; i < HASH_DRBG_PR_FALSE_ENTROPY_SHA512.size(); ++i){
        std::string
                entropy     = unhexlify(HASH_DRBG_PR_FALSE_ENTROPY_SHA512[i]),
                nonce       = unhexlify(HASH_DRBG_PR_FALSE_NONCE_SHA512[i]),
                personal    = unhexlify(HASH_DRBG_PR_FALSE_PERSONAL_SHA512[i]),
                reseed_ent  = unhexlify(HASH_DRBG_PR_FALSE_RESEED_ENTROPY_SHA512[i]),
                reseed_add  = unhexlify(HASH_DRBG_PR_FALSE_RESEED_ADDITIONAL_SHA512[i]),
                additional1 = unhexlify(HASH_DRBG_PR_FALSE_ADDITIONAL1_SHA512[i]),
                additional2 = unhexlify(HASH_DRBG_PR_FALSE_ADDITIONAL2_SHA512[i]),
                returnbits  = unhexlify(HASH_DRBG_PR_FALSE_RETURN_SHA512[i]);

        Hash_DRBG_SHA512 drbg(entropy, nonce, personal);
        drbg.reseed(reseed_ent, reseed_add);
        drbg.generate(returnbits.size(), additional1);
        EXPECT_EQ(drbg.generate(returnbits.size(), additional2), returnbits);
    }
}

TEST(HashDRBGTest, test_pr_true_sha1){
    ASSERT_EQ(HASH_DRBG_PR_TRUE_ENTROPY_SHA1.size(), HASH_DRBG_PR_TRUE_NONCE_SHA1.size());
    ASSERT_EQ(HASH_DRBG_PR_TRUE_NONCE_SHA1.size(), HASH_DRBG_PR_TRUE_PERSONAL_SHA1.size());
    ASSERT_EQ(HASH_DRBG_PR_TRUE_PERSONAL_SHA1.size(), HASH_DRBG_PR_TRUE_ADDITIONAL1_SHA1.size());
    ASSERT_EQ(HASH_DRBG_PR_TRUE_ADDITIONAL1_SHA1.size(), HASH_DRBG_PR_TRUE_ADDITIONAL2_SHA1.size());
    ASSERT_EQ(HASH_DRBG_PR_TRUE_ADDITIONAL2_SHA1.size(), HASH_DRBG_PR_TRUE_PR_ENTROPY1_SHA1.size());
    ASSERT_EQ(HASH_DRBG_PR_TRUE_PR_ENTROPY1_SHA1.size(), HASH_DRBG_PR_TRUE_PR_ENTROPY2_SHA1.size());
    ASSERT_EQ(HASH_DRBG_PR_TRUE_PR_ENTROPY2_SHA1.size(), HASH_DRBG_PR_TRUE_RETURN_SHA1.size());

    for (unsigned int i = 0; i < HASH_DRBG_PR_TRUE_ENTROPY_SHA1.size(); ++i){
        std::string
                entropy     = unhexlify(HASH_DRBG_PR_TRUE_ENTROPY_SHA1[i]),
                nonce       = unhexlify(HASH_DRBG_PR_TRUE_NONCE_SHA1[i]),
                personal    = unhexlify(HASH_DRBG_PR_TRUE_PERSONAL_SHA1[i]),
                additional1 = unhexlify(HASH_DRBG_PR_TRUE_ADDITIONAL1_SHA1[i]),
                additional2 = unhexlify(HASH_DRBG_PR_TRUE_ADDITIONAL2_SHA1[i]),
                pr_entropy1 = unhexlify(HASH_DRBG_PR_TRUE_PR_ENTROPY1_SHA1[i]),
                pr_entropy2 = unhexlify(HASH_DRBG_PR_TRUE_PR_ENTROPY2_SHA1[i]),
                returnbits  = unhexlify(HASH_DRBG_PR_TRUE_RETURN_SHA1[i]);

        Hash_DRBG_SHA1 drbg(entropy, nonce, personal);
        drbg.reseed(pr_entropy1, additional1);
        drbg.generate(returnbits.size());
        drbg.reseed(pr_entropy2, additional2);
        EXPECT_EQ(drbg.generate(returnbits.size()), returnbits);
    }
}

TEST(HashDRBGTest, test_pr_true_sha224){
    ASSERT_EQ(HASH_DRBG_PR_TRUE_ENTROPY_SHA224.size(), HASH_DRBG_PR_TRUE_NONCE_SHA224.size());
    ASSERT_EQ(HASH_DRBG_PR_TRUE_NONCE_SHA224.size(), HASH_DRBG_PR_TRUE_PERSONAL_SHA224.size());
    ASSERT_EQ(HASH_DRBG_PR_TRUE_PERSONAL_SHA224.size(), HASH_DRBG_PR_TRUE_ADDITIONAL1_SHA224.size());
    ASSERT_EQ(HASH_DRBG_PR_TRUE_ADDITIONAL1_SHA224.size(), HASH_DRBG_PR_TRUE_ADDITIONAL2_SHA224.size());
    ASSERT_EQ(HASH_DRBG_PR_TRUE_ADDITIONAL2_SHA224.size(), HASH_DRBG_PR_TRUE_PR_ENTROPY1_SHA224.size());
    ASSERT_EQ(HASH_DRBG_PR_TRUE_PR_ENTROPY1_SHA224.size(), HASH_DRBG_PR_TRUE_PR_ENTROPY2_SHA224.size());
    ASSERT_EQ(HASH_DRBG_PR_TRUE_PR_ENTROPY2_SHA224.size(), HASH_DRBG_PR_TRUE_RETURN_SHA224.size());

    for (unsigned int i = 0; i < HASH_DRBG_PR_TRUE_ENTROPY_SHA224.size(); ++i){
        std::string
                entropy     = unhexlify(HASH_DRBG_PR_TRUE_ENTROPY_SHA224[i]),
                nonce       = unhexlify(HASH_DRBG_PR_TRUE_NONCE_SHA224[i]),
                personal    = unhexlify(HASH_DRBG_PR_TRUE_PERSONAL_SHA224[i]),
                additional1 = unhexlify(HASH_DRBG_PR_TRUE_ADDITIONAL1_SHA224[i]),
                additional2 = unhexlify(HASH_DRBG_PR_TRUE_ADDITIONAL2_SHA224[i]),
                pr_entropy1 = unhexlify(HASH_DRBG_PR_TRUE_PR_ENTROPY1_SHA224[i]),
                pr_entropy2 = unhexlify(HASH_DRBG_PR_TRUE_PR_ENTROPY2_SHA224[i]),
                returnbits  = unhexlify(HASH_DRBG_PR_TRUE_RETURN_SHA224[i]);

        Hash_DRBG_SHA224 drbg(entropy, nonce, personal);
        drbg.reseed(pr_entropy1, additional1);
        drbg.generate(returnbits.size());
        drbg.reseed(pr_entropy2, additional2);
        EXPECT_EQ(drbg.generate(returnbits.size()), returnbits);
    }
}

TEST(HashDRBGTest, test_pr_true_sha256){
    ASSERT_EQ(HASH_DRBG_PR_TRUE_ENTROPY_SHA256.size(), HASH_DRBG_PR_TRUE_NONCE_SHA256.size());
    ASSERT_EQ(HASH_DRBG_PR_TRUE_NONCE_SHA256.size(), HASH_DRBG_PR_TRUE_PERSONAL_SHA256.size());
    ASSERT_EQ(HASH_DRBG_PR_TRUE_PERSONAL_SHA256.size(), HASH_DRBG_PR_TRUE_ADDITIONAL1_SHA256.size());
    ASSERT_EQ(HASH_DRBG_PR_TRUE_ADDITIONAL1_SHA256.size(), HASH_DRBG_PR_TRUE_ADDITIONAL2_SHA256.size());
    ASSERT_EQ(HASH_DRBG_PR_TRUE_ADDITIONAL2_SHA256.size(), HASH_DRBG_PR_TRUE_PR_ENTROPY1_SHA256.size());
    ASSERT_EQ(HASH_DRBG_PR_TRUE_PR_ENTROPY1_SHA256.size(), HASH_DRBG_PR_TRUE_PR_ENTROPY2_SHA256.size());
    ASSERT_EQ(HASH_DRBG_PR_TRUE_PR_ENTROPY2_SHA256.size(), HASH_DRBG_PR_TRUE_RETURN_SHA256.size());

    for (unsigned int i = 0; i < HASH_DRBG_PR_TRUE_ENTROPY_SHA256.size(); ++i){
        std::string
                entropy     = unhexlify(HASH_DRBG_PR_TRUE_ENTROPY_SHA256[i]),
                nonce       = unhexlify(HASH_DRBG_PR_TRUE_NONCE_SHA256[i]),
                personal    = unhexlify(HASH_DRBG_PR_TRUE_PERSONAL_SHA256[i]),
                additional1 = unhexlify(HASH_DRBG_PR_TRUE_ADDITIONAL1_SHA256[i]),
                additional2 = unhexlify(HASH_DRBG_PR_TRUE_ADDITIONAL2_SHA256[i]),
                pr_entropy1 = unhexlify(HASH_DRBG_PR_TRUE_PR_ENTROPY1_SHA256[i]),
                pr_entropy2 = unhexlify(HASH_DRBG_PR_TRUE_PR_ENTROPY2_SHA256[i]),
                returnbits  = unhexlify(HASH_DRBG_PR_TRUE_RETURN_SHA256[i]);

        Hash_DRBG_SHA256 drbg(entropy, nonce, personal);
        drbg.reseed(pr_entropy1, additional1);
        drbg.generate(returnbits.size());
        drbg.reseed(pr_entropy2, additional2);
        EXPECT_EQ(drbg.generate(returnbits.size()), returnbits);
    }
}

TEST(HashDRBGTest, test_pr_true_sha384){
    ASSERT_EQ(HASH_DRBG_PR_TRUE_ENTROPY_SHA384.size(), HASH_DRBG_PR_TRUE_NONCE_SHA384.size());
    ASSERT_EQ(HASH_DRBG_PR_TRUE_NONCE_SHA384.size(), HASH_DRBG_PR_TRUE_PERSONAL_SHA384.size());
    ASSERT_EQ(HASH_DRBG_PR_TRUE_PERSONAL_SHA384.size(), HASH_DRBG_PR_TRUE_ADDITIONAL1_SHA384.size());
    ASSERT_EQ(HASH_DRBG_PR_TRUE_ADDITIONAL1_SHA384.size(), HASH_DRBG_PR_TRUE_ADDITIONAL2_SHA384.size());
    ASSERT_EQ(HASH_DRBG_PR_TRUE_ADDITIONAL2_SHA384.size(), HASH_DRBG_PR_TRUE_PR_ENTROPY1_SHA384.size());
    ASSERT_EQ(HASH_DRBG_PR_TRUE_PR_ENTROPY1_SHA384.size(), HASH_DRBG_PR_TRUE_PR_ENTROPY2_SHA384.size());
    ASSERT_EQ(HASH_DRBG_PR_TRUE_PR_ENTROPY2_SHA384.size(), HASH_DRBG_PR_TRUE_RETURN_SHA384.size());

    for (unsigned int i = 0; i < HASH_DRBG_PR_TRUE_ENTROPY_SHA384.size(); ++i){
        std::string
                entropy     = unhexlify(HASH_DRBG_PR_TRUE_ENTROPY_SHA384[i]),
                nonce       = unhexlify(HASH_DRBG_PR_TRUE_NONCE_SHA384[i]),
                personal    = unhexlify(HASH_DRBG_PR_TRUE_PERSONAL_SHA384[i]),
                additional1 = unhexlify(HASH_DRBG_PR_TRUE_ADDITIONAL1_SHA384[i]),
                additional2 = unhexlify(HASH_DRBG_PR_TRUE_ADDITIONAL2_SHA384[i]),
                pr_entropy1 = unhexlify(HASH_DRBG_PR_TRUE_PR_ENTROPY1_SHA384[i]),
                pr_entropy2 = unhexlify(HASH_DRBG_PR_TRUE_PR_ENTROPY2_SHA384[i]),
                returnbits  = unhexlify(HASH_DRBG_PR_TRUE_RETURN_SHA384[i]);

        Hash_DRBG_SHA384 drbg(entropy, nonce, personal);
        drbg.reseed(pr_entropy1, additional1);
        drbg.generate(returnbits.size());
        drbg.reseed(pr_entropy2, additional2);
        EXPECT_EQ(drbg.generate(returnbits.size()), returnbits);
    }
}

TEST(HashDRBGTest, test_pr_true_sha512){
    ASSERT_EQ(HASH_DRBG_PR_TRUE_ENTROPY_SHA512.size(), HASH_DRBG_PR_TRUE_NONCE_SHA512.size());
    ASSERT_EQ(HASH_DRBG_PR_TRUE_NONCE_SHA512.size(), HASH_DRBG_PR_TRUE_PERSONAL_SHA512.size());
    ASSERT_EQ(HASH_DRBG_PR_TRUE_PERSONAL_SHA512.size(), HASH_DRBG_PR_TRUE_ADDITIONAL1_SHA512.size());
    ASSERT_EQ(HASH_DRBG_PR_TRUE_ADDITIONAL1_SHA512.size(), HASH_DRBG_PR_TRUE_ADDITIONAL2_SHA512.size());
    ASSERT_EQ(HASH_DRBG_PR_TRUE_ADDITIONAL2_SHA512.size(), HASH_DRBG_PR_TRUE_PR_ENTROPY1_SHA512.size());
    ASSERT_EQ(HASH_DRBG_PR_TRUE_PR_ENTROPY1_SHA512.size(), HASH_DRBG_PR_TRUE_PR_ENTROPY2_SHA512.size());
    ASSERT_EQ(HASH_DRBG_PR_TRUE_PR_ENTROPY2_SHA512.size(), HASH_DRBG_PR_TRUE_RETURN_SHA512.size());

    for (unsigned int i = 0; i < HASH_DRBG_PR_TRUE_ENTROPY_SHA512.size(); ++i){
        std::string
                entropy     = unhexlify(HASH_DRBG_PR_TRUE_ENTROPY_SHA512[i]),
                nonce       = unhexlify(HASH_DRBG_PR_TRUE_NONCE_SHA512[i]),
                personal    = unhexlify(HASH_DRBG_PR_TRUE_PERSONAL_SHA512[i]),
                additional1 = unhexlify(HASH_DRBG_PR_TRUE_ADDITIONAL1_SHA512[i]),
                additional2 = unhexlify(HASH_DRBG_PR_TRUE_ADDITIONAL2_SHA512[i]),
                pr_entropy1 = unhexlify(HASH_DRBG_PR_TRUE_PR_ENTROPY1_SHA512[i]),
                pr_entropy2 = unhexlify(HASH_DRBG_PR_TRUE_PR_ENTROPY2_SHA512[i]),
                returnbits  = unhexlify(HASH_DRBG_PR_TRUE_RETURN_SHA512[i]);

        Hash_DRBG_SHA512 drbg(entropy, nonce, personal);
        drbg.reseed(pr_entropy1, additional1);
        drbg.generate(returnbits.size());
        drbg.reseed(pr_entropy2, additional2);
        EXPECT_EQ(drbg.generate(returnbits.size()), returnbits);
    }
}
