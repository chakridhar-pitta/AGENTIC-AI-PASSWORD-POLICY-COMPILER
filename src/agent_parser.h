#ifndef AGENT_PARSER_H
#define AGENT_PARSER_H

#include "agent_types.h"
#include "token.h"
#include "ast.h"
#include "parser.h"
#include <vector>
#include <memory>
#include <string>

class ParserAgent {
public:
    explicit ParserAgent(std::vector<Token> tokens, std::string humanPreApprovedChoice = "");

    // Runs the 5-stage O-A-D-A-V loop
    bool execute();

    const PolicyAST& getAST() const { return ast; }
    const AgentActionReport& getReport() const { return report; }
    bool wasRepaired() const { return autoRepaired; }
    bool needsHumanApproval() const { return report.humanApprovalRequired; }
    const std::vector<RepairCandidate>& getCandidates() const { return report.repairCandidates; }
    
    // Apply user selected candidate (e.g. "A" or "B")
    bool applyHumanApproval(const std::string& candidateId);

    void renderReport() const;

private:
    std::vector<Token> tokens;
    std::string humanChoice;
    PolicyAST ast;
    AgentActionReport report;
    bool autoRepaired = false;
    std::string repairSummary;

    // O-A-D-A-V Stages
    void observe();
    void analyze();
    void decide();
    void act();
    bool verify();

    // Syntax reasoning, candidate generation, and safety classification
    void evaluateSyntaxDefectsAndCandidates();
    bool validateCandidateStream(const std::vector<Token>& candTokens, PolicyAST& outAst);
};

#endif // AGENT_PARSER_H
