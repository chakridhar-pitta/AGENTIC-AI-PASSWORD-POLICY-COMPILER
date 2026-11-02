#ifndef AGENT_CODEGEN_H
#define AGENT_CODEGEN_H

#include "agent_types.h"
#include "semantic.h"
#include "ir.h"
#include "automata.h"
#include "bloom_filter.h"
#include "leetspeak.h"
#include <string>
#include <vector>
#include <memory>

struct SecurityCheckItem {
    std::string name;
    bool passed;
    std::string detail;
};

class CodegenAgent {
public:
    CodegenAgent(const PolicyConstraints& constraints,
                 std::string outputPath = "generated_validator.cpp",
                 std::shared_ptr<DFA> dfa = nullptr,
                 std::string dictionaryPath = "dictionary.txt",
                 std::string breachCorpusPath = "");

    // Runs the 5-stage O-A-D-A-V loop
    bool execute();

    void setSynthesizedDFA(std::shared_ptr<DFA> dfa) { synthesizedDfa = dfa; }
    std::shared_ptr<DFA> getSynthesizedDFA() const { return synthesizedDfa; }

    const std::vector<SecurityCheckItem>& getChecklist() const { return checklist; }
    const AgentActionReport& getReport() const { return report; }
    bool isGatePassed() const { return gatePassed; }
    const std::string& getOutputPath() const { return targetFile; }
    const StaticBloomBuilder& getBloomBuilder() const { return bloomBuilder; }
    void renderReport() const;

private:
    PolicyConstraints constraints;
    std::string targetFile;
    std::shared_ptr<DFA> synthesizedDfa;
    std::string dictPath;
    std::string breachPath;
    StaticBloomBuilder bloomBuilder;

    std::string generatedSource;
    std::vector<SecurityCheckItem> checklist;
    AgentActionReport report;
    bool gatePassed = false;

    // Substage AGENT-05-BREACH-FILTER-SYNTHESIZER
    bool runBreachFilterSynthesizer();

    // O-A-D-A-V Stages
    void observe();
    void analyze();
    void decide();
    void act();
    bool verify();

    // Secure generation & static analysis
    std::string synthesizeHardenedValidator();
    void runStaticSecurityAudit(const std::string& sourceCode);
};

#endif // AGENT_CODEGEN_H
