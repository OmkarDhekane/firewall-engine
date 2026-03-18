#pragma once

#include <string>
#include <vector>

#include "firewall_rule.h"
#include "packet_metadata.h"

struct RuleDecision {
	std::string action;
	int matchingRuleId;
};

class RuleEngine {
public:
	RuleEngine();
	
	//load default rules existing in the system
	void loadDefaultRules();

	// evalute the packet against existing rules and return decision
	RuleDecision evaluate(const PacketMetadata& packet) const;

	// list all rules
	const std::vector<FirewallRule>& getRules() const;

private:
	
	std::vector<FirewallRule> rules;

	bool matchesRule(const FirewallRule& rule, const PacketMetadata& packet) const;
	bool matchIP(const std::string& ruleIP, const std::string& packetIP) const;
	bool matchPort(int rulePort, int packetPort) const;
	bool matchProtocol(const std::string& ruleProtocol, const std::string& packetProtocol) const;

};


