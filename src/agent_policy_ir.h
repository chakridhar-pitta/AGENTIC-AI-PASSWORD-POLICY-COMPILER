#ifndef AGENT_POLICY_IR_H
#define AGENT_POLICY_IR_H

#include "agent_types.h"
#include "ir.h"
#include "ast.h"
#include "semantic.h"
#include "automata.h"
#include <string>
#include <vector>
#include <memory>

struct IROptimizationRecord {
    std::string redundantConstraint;
    std::string optimizationApplied;
};

class PolicyIRAgent {
public:
    PolicyIRAgent(const PolicyConstraints& constraints, const PolicyAST& ast);

    // Runs the 5-stage O-A-D-A-V loop
    bool execute();

    const PolicyIR& getIR() const { return ir; }
    const std::vector<IROptimizationRecord>& getOptimizations() const { return optimizations; }
    const AgentActionReport& getReport() const { return report; }
    int getOriginalNodeCount() const { return originalNodeCount; }
    int getOptimizedNodeCount() const { return optimizedNodeCount; }
    bool isSemanticallyEquivalent() const { return semanticEquivalence; }
    std::shared_ptr<DFA> getSynthesizedDFA() const { return synthesizedDfa; }
    const AutomataMetrics& getAutomataMetrics() const { return automataMetrics; }
    void renderReport() const;

private:
    PolicyConstraints constraints;
    const PolicyAST& ast;
    PolicyIR ir;
    std::shared_ptr<DFA> synthesizedDfa;
    AutomataMetrics automataMetrics;
    std::vector<IROptimizationRecord> optimizations;
    AgentActionReport report;
    int originalNodeCount = 0;
    int optimizedNodeCount = 0;
    bool semanticEquivalence = true;

    // O-A-D-A-V Stages
    void observe();
    void analyze();
    void decide();
    void act();
    bool verify();
};

#endif // AGENT_POLICY_IR_H
