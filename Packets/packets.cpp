#include "packets.h"

unsigned int partialBodyLen(uint8_t first_octet){
    return 1 << (first_octet & 0x1f);
}

std::string read_packet_header(std::string & data, uint8_t & tag, bool & format){
    uint8_t ctb = data[0];													    // Name "ctb" came from Version 2 [RFC 1991]
    if (!(ctb & 0x80)){
        std::cerr << "Warning: First bit of packet header is not 1." << std::endl;
//        throw std::runtime_error("Error: First bit of packet header MUST be 1.");
    }

    unsigned int length = 0;                                                    // length of the data without the header
    unsigned int remove = 1;                                                    // how much more stuff to remove from source string
    std::string packet;

    if (!(ctb & 0x40)){                                                         // Old length type RFC4880 sec 4.2.1
        format = false;
        tag = (ctb >> 2) & 15;                                                  // get tag value
		if (!(ctb & 3)){
            length = static_cast <uint8_t> (data[1]);
			remove += 1;
		}
		else if ((ctb & 3) == 1){
			length = toint(data.substr(1, 2), 256);
			remove += 2;
		}
		else if ((ctb & 3) == 2){
			length = toint(data.substr(2, 5), 256);
			remove += 5;
		}
		else if ((ctb & 3) == 3){                                               // indeterminate length; header is 1 octet long; packet continues until end of data
            length = data.size() - remove;
            remove += 0;
		}
    }
	else /*if (ctb & 0x40)*/{   												// New length type RFC4880 sec 4.2.2
		format = true;
		tag = ctb & 63;                                                         // get tag value
        uint8_t first_octet = static_cast <unsigned char> (data[1]);
		if (first_octet < 192){                                                 // 0 - 192
			length = first_octet;
			remove += 1;
		}
		else if ((192 <= first_octet) & (first_octet < 223)){                   // 193 - 8383
			length = toint(data.substr(1, 2), 256) - (192 << 8) + 192;
			remove += 2;
		}
		else if (first_octet == 255){                                           // 8384 - 4294967295
			length = toint(data.substr(2, 4), 256);
			remove += 5;
		}
		else if (224 <= first_octet){                                           // unknown
//			tag = -1;                                                           // partial
			length = partialBodyLen(first_octet);
			remove += 0;
		}
	}
	packet = data.substr(remove, length);								    	// Get packet
	data = data.substr(remove + length, data.size() - remove - length);		    // Remove packet from key
    return packet;
}

Packet::Ptr read_packet_raw(const bool format, const uint8_t tag, std::string & packet_data){
    Packet::Ptr out;
    switch (tag){
        case 0:
            throw std::runtime_error("Error: Tag number MUST NOT be 0.");
            break;
        case 1:
            out = std::make_shared<Tag1>();
            break;
        case 2:
            out = std::make_shared<Tag2>();
            break;
        case 3:
            out = std::make_shared<Tag3>();
            break;
        case 4:
            out = std::make_shared<Tag4>();
            break;
        case 5:
            out = std::make_shared<Tag5>();
            break;
        case 6:
            out = std::make_shared<Tag6>();
            break;
        case 7:
            out = std::make_shared<Tag7>();
            break;
        case 8:
            out = std::make_shared<Tag8>();
            break;
        case 9:
            out = std::make_shared<Tag9>();
            break;
        case 10:
            out = std::make_shared<Tag10>();
            break;
        case 11:
            out = std::make_shared<Tag11>();
            break;
        case 12:
            out = std::make_shared<Tag12>();
            break;
        case 13:
            out = std::make_shared<Tag13>();
            break;
        case 14:
            out = std::make_shared<Tag14>();
            break;
        case 17:
            out = std::make_shared<Tag17>();
            break;
        case 18:
            out = std::make_shared<Tag18>();
            break;
        case 19:
            out = std::make_shared<Tag19>();
            break;
        default:
            out = std::make_shared<TagX>();
//            throw std::runtime_error("Error: Tag not defined or reserved.");
            break;
    }
    out -> set_tag(tag);
    out -> set_format(format);
    out -> set_size(packet_data.size());
    out -> read(packet_data);
    return out;
}

Packet::Ptr read_packet(std::string & data){
    bool format;
    uint8_t tag;
    std::string packet_data = read_packet_header(data, tag, format);
    return read_packet_raw(format, tag, packet_data);
}
