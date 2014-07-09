CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(OpenPGP)

SET(CMAKE_BINARY_DIR $(CMAKE_SOURCE_DIR)/build)

SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

SET(OpenPGP_SRCS
Encryptions/AES.cpp
Encryptions/Blowfish.cpp
Encryptions/CAST128.cpp
Encryptions/Camellia.cpp
Encryptions/DES.cpp
Encryptions/IDEA.cpp
Encryptions/SymAlg.cpp
Encryptions/TDES.cpp
Encryptions/Twofish.cpp
Hashes/Hash.cpp
Hashes/Hashes.cpp
Hashes/MD5.cpp
Hashes/RIPEMD160.cpp
Hashes/SHA1.cpp
Hashes/SHA2_Functions.cpp
Hashes/SHA224.cpp
Hashes/SHA256.cpp
Hashes/SHA384.cpp
Hashes/SHA512.cpp
PKA/DSA.cpp
PKA/ElGamal.cpp
PKA/PKA.cpp
PKA/RSA.cpp
Packets/Tag0.cpp
Packets/Tag1.cpp
Packets/Tag2.cpp
Packets/Tag3.cpp
Packets/Tag4.cpp
Packets/Tag5.cpp
Packets/Tag6.cpp
Packets/Tag7.cpp
Packets/Tag8.cpp
Packets/Tag9.cpp
Packets/Tag10.cpp
Packets/Tag11.cpp
Packets/Tag12.cpp
Packets/Tag13.cpp
Packets/Tag14.cpp
Packets/Tag17.cpp
Packets/Tag18.cpp
Packets/Tag19.cpp
Packets/TagX.cpp
Packets/packet.cpp
Packets/packets.cpp
Packets/s2k.cpp
RNG/BBS.cpp
Subpackets/Tag2Sub0.cpp
Subpackets/Tag2Sub1.cpp
Subpackets/Tag2Sub2.cpp
Subpackets/Tag2Sub3.cpp
Subpackets/Tag2Sub4.cpp
Subpackets/Tag2Sub5.cpp
Subpackets/Tag2Sub6.cpp
Subpackets/Tag2Sub7.cpp
Subpackets/Tag2Sub8.cpp
Subpackets/Tag2Sub9.cpp
Subpackets/Tag2Sub10.cpp
Subpackets/Tag2Sub11.cpp
Subpackets/Tag2Sub12.cpp
Subpackets/Tag2Sub13.cpp
Subpackets/Tag2Sub14.cpp
Subpackets/Tag2Sub15.cpp
Subpackets/Tag2Sub16.cpp
Subpackets/Tag2Sub17.cpp
Subpackets/Tag2Sub18.cpp
Subpackets/Tag2Sub19.cpp
Subpackets/Tag2Sub20.cpp
Subpackets/Tag2Sub21.cpp
Subpackets/Tag2Sub22.cpp
Subpackets/Tag2Sub23.cpp
Subpackets/Tag2Sub24.cpp
Subpackets/Tag2Sub25.cpp
Subpackets/Tag2Sub26.cpp
Subpackets/Tag2Sub27.cpp
Subpackets/Tag2Sub28.cpp
Subpackets/Tag2Sub29.cpp
Subpackets/Tag2Sub30.cpp
Subpackets/Tag2Sub31.cpp
Subpackets/Tag2Sub32.cpp
Subpackets/Tag17Sub1.cpp
Subpackets/subpacket.cpp
common/includes.cpp
common/integer.cpp
PGP.cpp
PGPSignedMessage.cpp
PKCS1.cpp
cfb.cpp
decrypt.cpp
encrypt.cpp
generatekey.cpp
mpi.cpp
pgptime.cpp
radix64.cpp
revoke.cpp
sigcalc.cpp
sign.cpp
verify.cpp
)

ADD_LIBRARY(${PROJECT_NAME} STATIC ${OpenPGP_SRCS})

SET(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
SET(${PROJECT_NAME}_SOURCE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Source Directories" FORCE)

ADD_SUBDIRECTORY(exec)
ADD_SUBDIRECTORY(tests)
