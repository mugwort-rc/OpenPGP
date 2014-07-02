#ifndef __DRBG__
#define __DRBG__

#include <string>

class DRBG{
    protected:
        unsigned int reseed_counter;

    public:
        DRBG() :
            reseed_counter(1)
        {}
        virtual ~DRBG(){}

        virtual void reseed(const std::string &entropy, const std::string &additional=std::string()) = 0;
        virtual std::string generate(unsigned int len, const std::string &additional=std::string()) = 0;

};

#endif
