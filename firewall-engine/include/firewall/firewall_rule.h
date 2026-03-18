#pragma once
#include <string>

struct FirewallRule {
    int id = -1;
	std::string srcIP;
	std::string dstIP;
	int srcPort = -1;
	int dstPort = -1;
	std::string protocol;
    std::string action;   // ALLOW or DENY
};