// define struct for one parsted packet
#pragma once

#include <string>

struct PacketMetadata {
	std::string SRC_IP;
	std::string DST_IP;
	int SRC_PORT  = -1;
	int DST_PORT  = -1;
	std::string PROTOCOL;
};