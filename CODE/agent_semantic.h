#ifndef AGENT_SEMANTIC_H
#define AGENT_SEMANTIC_H

#include "agent_types.h"
#include "ast.h"
#include "semantic.h"
#include <string>
#include <vector>

struct SemanticConflict {
    std::string type;
    std::string description;
    std::string recommendedCorrection;
};

class SemanticAgent {
public:
    explicit SemanticAgent(const PolicyAST& ast);

    // Runs the 5-stage O-A-D-A-V loop
    bool execute();

    const PolicyConstraints& getConstraints() const { return constraints; }
    const std::vector<SemanticConflict>& getConflicts() const { return conflicts; }
    const AgentActionReport& getReport() const { return report; }
    void renderReport() const;

private:
    const PolicyAST& ast;
    PolicyConstraints constraints;
    std::vector<SemanticConflict> conflicts;
    AgentActionReport report;

    // O-A-D-A-V Stages
    void observe();
    void analyze();
    void decide();
    void act();
    bool verify();
};

#endif // AGENT_SEMANTIC_H
