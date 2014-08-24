#include "pgpzlib.h"

#include <sstream>
#include <boost/iostreams/filtering_stream.hpp>
#include <boost/iostreams/filter/zlib.hpp>
#include <boost/iostreams/copy.hpp>

/* Compress from file source to file dest until EOF on source.
   def() returns Z_OK on success, Z_MEM_ERROR if memory could not be
   allocated for processing, Z_STREAM_ERROR if an invalid compression
   level is supplied, Z_VERSION_ERROR if the version of zlib.h and the
   version of the library linked do not match, or Z_ERRNO if there is
   an error reading or writing the files. */
int zlib_compress(const std::string & src, std::string & dst, int windowBits, int level)
{
    dst.clear(); // clear out destination

    boost::iostreams::filtering_ostream out;
    std::ostringstream oss;

    boost::iostreams::zlib_params zparam(
                level,
                boost::iostreams::zlib::deflated,
                windowBits  // window bits
                );

    out.push(boost::iostreams::zlib_compressor(zparam));
    out.push(oss);
    out.write(&src[0], src.size());
    boost::iostreams::close(out);

    dst = oss.str();
    return 0;
}

/* Decompress from file source to file dest until stream ends or EOF.
   inf() returns Z_OK on success, Z_MEM_ERROR if memory could not be
   allocated for processing, Z_DATA_ERROR if the deflate data is
   invalid or incomplete, Z_VERSION_ERROR if the version of zlib.h and
   the version of the library linked do not match, or Z_ERRNO if there
   is an error reading or writing the files. */
int zlib_decompress(const std::string & src, std::string & dst, int windowBits)
{
    dst.clear(); // clear out destination

    boost::iostreams::filtering_istream in;
    std::istringstream iss(src, std::ios::binary);

    boost::iostreams::zlib_params zparam(
                boost::iostreams::zlib::default_compression,
                boost::iostreams::zlib::deflated,
                windowBits  // window bits
                );

    in.push(boost::iostreams::zlib_decompressor(zparam));
    in.push(iss);

    std::ostringstream oss(std::ios::binary);
    boost::iostreams::copy(in, oss);

    dst = oss.str();
    return 0;
}
