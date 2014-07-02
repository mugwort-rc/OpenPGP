#ifndef __HASH_DRBG__
#define __HASH_DRBG__

#include <algorithm>

#include "../../common/includes.h"
#include "../../mpi.h"

#include "../../Hashes/Hashes.h"
#include "DRBG.h"

template <class Hash, const uint32_t seedlen>
class Hash_DRBG : public DRBG{
    protected:
        std::string Hash_df(const std::string &in, uint32_t no){
            std::string out;
            std::string no_str;
            for (uint8_t i = 0; i < 4; ++i){
                no_str += std::string(1, byte(no, i));
            }
            std::reverse(no_str.begin(), no_str.end());
            for (unsigned int i = 0; i < Hash::digestsize(); ++i){
                out += Hash(std::string(1, i+1) + no_str + in).digest();
            }
            return out.substr(0, no >> 3);
        }

        std::string hashgen(uint32_t no, const std::string &value){
            mpz_class data(hexlify(value), 16);
            std::string out;
            for (uint32_t i = 0; i < (no / Hash::digestsize()); ++i){
                out += Hash(to_bin(data)).digest();
                data += 1;
                data %= mod;
            }
            return out.substr(0, no);
        }

        std::string to_bin(const mpz_class &mpi){
            std::string out = unhexlify(to_hex(mpi));
            int diff = (seedlen >> 3) - out.size();
            if (diff > 0){
                out = std::string(diff, 0) + out;
            }
            return out;
        }

        std::string value;
        std::string constant;
        mpz_class   mod;

    public:
        Hash_DRBG(const std::string & entropy, const std::string & nonce, const std::string & personalization) :
            DRBG(),
            value(),
            constant(),
            mod(mpz_class(1) << seedlen)
        {
            std::string seed = entropy + nonce + personalization;
            value = Hash_df(seed, seedlen);
            constant = Hash_df(std::string(1, 0) + value, seedlen);
        }

        void reseed(const std::string & entropy, const std::string & additional=std::string()){
            std::string seed = std::string(1, 1) + value + entropy + additional;
            value = Hash_df(seed, seedlen);
            constant = Hash_df(std::string(1, 0) + value, seedlen);
            reseed_counter = 1;
        }

        std::string generate(unsigned int len, const std::string & additional=std::string()){
            if (!additional.empty()){
                mpz_class mpi(hexlify(value), 16);
                mpi += mpz_class(hexlify(Hash(std::string(1, 2) + value + additional).digest()), 16);
                mpi %= mod;
                value = to_bin(mpi);
            }
            std::string result = hashgen(len << 3, value);
            mpz_class mpi(hexlify(value), 16);
            mpi += mpz_class(hexlify(Hash(std::string(1, 3) + value).digest()), 16);
            mpi += mpz_class(hexlify(constant), 16);
            mpi += reseed_counter;
            mpi %= mod;
            value = to_bin(mpi);
            ++reseed_counter;
            return result;
        }

};

const uint32_t SHA1_SEEDLEN   = 440;
const uint32_t SHA224_SEEDLEN = 440;
const uint32_t SHA256_SEEDLEN = 440;
const uint32_t SHA384_SEEDLEN = 888;
const uint32_t SHA512_SEEDLEN = 888;

typedef Hash_DRBG<SHA1, SHA1_SEEDLEN> Hash_DRBG_SHA1;
typedef Hash_DRBG<SHA224, SHA224_SEEDLEN> Hash_DRBG_SHA224;
typedef Hash_DRBG<SHA256, SHA256_SEEDLEN> Hash_DRBG_SHA256;
typedef Hash_DRBG<SHA384, SHA384_SEEDLEN> Hash_DRBG_SHA384;
typedef Hash_DRBG<SHA512, SHA512_SEEDLEN> Hash_DRBG_SHA512;

#endif
