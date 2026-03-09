#include "../include/parser/packet_parser.h"

#include <sstream>

// SRC_IP = 10.0.0.1
// DST_IP = 192.168.1.10
// SRC_PORT = 5000 
// DST_PORT = 80 
// PROTOCOL = TCP

bool parsePacket(std::string& input, PacketMetadata& packet) {

	std::istringstream iss(input);
	std::string token;

	// parse the input as a string
	while (iss >> token) {

		size_t pos = token.find("="); //size_t : big enough to hold the size of the thing in memory
		if (pos == std::string::npos) {
			continue;
		}

		std::string key = token.substr(0, pos);
		std::string value = token.substr(pos+1);

		if (key == "SRC_IP") {
			packet.SRC_IP = value;
		} else if (key == "DST_IP") {
			packet.DST_IP = value;
		}
		else if (key == "SRC_PORT") {
			packet.SRC_PORT = std::stoi(value);
		}
		else if (key == "DST_PORT") {
			packet.DST_PORT = std::stoi(value);
		}
		else if (key == "PROTOCOL") {
			packet.PROTOCOL = value;
		}
	}

	// return true if the packet is successfully parsed

	return (!packet.SRC_IP.empty() && !packet.DST_IP.empty() &&
		packet.SRC_PORT != -1 && packet.DST_PORT != -1 &&
		!packet.PROTOCOL.empty());

}