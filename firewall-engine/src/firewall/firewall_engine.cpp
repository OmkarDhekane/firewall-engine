#include "../include/firewall/firewall_engine.h"

// constructor
RuleEngine::RuleEngine() {
	loadDefaultRules();
}

// defintion of loadDefaultRules
void RuleEngine::loadDefaultRules() {
	rules.clear();


	// Rule 1: deny a specific source IP
	rules.push_back({1, "10.0.0.99", "*", -1, -1, "TCP","DENY"});
    
    // Rule 2: allow HTTP traffic
    rules.push_back({ 2, "*", "*", -1, 80, "TCP", "ALLOW" });

    // Rule 3: allow HTTPS traffic
    rules.push_back({ 3, "*", "*", -1, 443, "TCP", "ALLOW" });

    // Rule 4: allow DNS traffic over UDP
    rules.push_back({ 4, "*", "*", -1, 53, "UDP", "ALLOW" });

    // Rule 5: default deny everything else
    rules.push_back({ 5, "*", "*", -1, -1, "*", "DENY" });

}

// evalute
RuleDecision RuleEngine::evaluate(const PacketMetadata& packet) const {
    for (const auto& rule : rules) {
        if (matchesRule(rule, packet)) {
            return { rule.action, rule.id };
        }
    }

    return { "DENY", -1 };
}

// list rules
const std::vector<FirewallRule>& RuleEngine::getRules() const {
    return rules;
}

//match IP
bool RuleEngine::matchIP(const std::string& ruleIP, const std::string& packetIP) const {
    return ruleIP == "*" || ruleIP == packetIP;
}

//match Port
bool RuleEngine::matchPort(int rulePort, int packetPort) const {
    return rulePort == -1 || rulePort == packetPort;
}

//match Protocol
bool RuleEngine::matchProtocol(const std::string& ruleProtocol, const std::string& packetProtocol) const {
    return ruleProtocol == "*" || ruleProtocol == packetProtocol;
}

// match rule
bool RuleEngine::matchesRule(const FirewallRule& rule, const PacketMetadata& packet) const {
    return matchIP(rule.srcIP, packet.SRC_IP) &&
        matchIP(rule.dstIP, packet.DST_IP) &&
        matchPort(rule.srcPort, packet.SRC_PORT) &&
        matchPort(rule.dstPort, packet.DST_PORT) &&
        matchProtocol(rule.protocol, packet.PROTOCOL);
}
