#pragma once
#include <string>
#include "firewall/packet_metadata.h"

bool parsePacket(std::string& input, PacketMetadata& packet);

