#ifndef AGENT_SECURITY_AUDIT_H
#define AGENT_SECURITY_AUDIT_H

#include "agent_types.h"
#include "semantic.h"
#include "neurosymbolic.h"
#include <string>
#include <vector>

class SecurityAuditAgent {
public:
    SecurityAuditAgent(std::string candidatePassword, const PolicyConstraints& constraints,
                       std::string dictionaryPath = "dictionary.txt",
                       std::string breachCorpusPath = "");

    // Runs the 5-stage O-A-D-A-V loop
    bool execute();

    const ProfessionalSecurityReport& getRawReport() const { return rawReport; }
    const AgentActionReport& getReport() const { return report; }
    void renderReport() const;

private:
    std::string password;
    PolicyConstraints constraints;
    std::string dictPath;
    std::string breachPath;
    ProfessionalSecurityReport rawReport;
    AgentActionReport report;

    bool policyCompliant = false;
    bool dictionaryExposed = false;
    bool leetspeakVariantFound = false;
    bool dslBlacklistViolated = false;
    bool repeatedPatternFound = false;
    bool sequentialPatternFound = false;
    double entropyBits = 0.0;
    std::string strengthTier;
    std::string recommendedAction;

    // O-A-D-A-V Stages
    void observe();
    void analyze();
    void decide();
    void act();
    bool verify();
};

#endif // AGENT_SECURITY_AUDIT_H
