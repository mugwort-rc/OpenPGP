#ifndef __HMAC_DRBG__
#define __HMAC_DRBG__

#include "../../Hashes/HMAC.h"

template <class HMAC>
class HMAC_DRBG{
    protected:
        std::string hmac(const std::string & key, const std::string & value){
            return HMAC(key, value).digest();
        }

        std::string key;
        std::string value;

        unsigned int reseed_counter;

    public:
        HMAC_DRBG(const std::string & entropy, const std::string & nonce, const std::string & personalization) :
            key(),
            value(),
            reseed_counter(1)
        {
            std::string seed = entropy + nonce + personalization;
            typedef typename HMAC::Hash_t Hash_t;
            unsigned int len = Hash_t::digestsize() >> 3;
            key = std::string(len, 0);
            value = std::string(len, 1);
            update(seed);
        }

        void update(const std::string & entropy=std::string()){
            key = hmac(key, value + std::string(1, 0) + entropy);
            value = hmac(key, value);
            if (!entropy.empty()){
                key = hmac(key, value + std::string(1, 1) + entropy);
                value = hmac(key, value);
            }
        }

        void reseed(const std::string & entropy, const std::string & additional=std::string()){
            std::string seed = entropy + additional;
            update(seed);
            reseed_counter = 1;
        }

        std::string generate(unsigned int len, const std::string & additional=std::string()){
            if (!additional.empty()){
                update(additional);
            }
            std::string out;
            while (out.size() < len){
                value = hmac(key, value);
                out += value;
            }
            update(additional);
            ++reseed_counter;
            return out.substr(0, len);
        }

};

#endif
