#include "pgpbzip2.h"

#include <sstream>
#include <boost/iostreams/filtering_stream.hpp>
#include <boost/iostreams/filter/bzip2.hpp>
#include <boost/iostreams/copy.hpp>

int bz2_compress(const std::string & src, std::string & dst){
    dst.clear(); // clear out destination

    boost::iostreams::filtering_ostream out;
    std::ostringstream oss;

    out.push(boost::iostreams::bzip2_compressor());
    out.push(oss);
    out.write(&src[0], src.size());
    boost::iostreams::close(out);

    dst = oss.str();
    return 0;
}

int bz2_decompress(const std::string & src, std::string & dst){
    dst.clear(); // clear out destination

    boost::iostreams::filtering_istream in;
    std::istringstream iss(src, std::ios::binary);

    in.push(boost::iostreams::bzip2_decompressor());
    in.push(iss);

    std::ostringstream oss(std::ios::binary);
    boost::iostreams::copy(in, oss);

    dst = oss.str();
    return 0;
}
