#ifndef AGENTIC_ORCHESTRATOR_H
#define AGENTIC_ORCHESTRATOR_H

#include "agent_types.h"
#include "agent_attack_detector.h"
#include "agent_lexer.h"
#include "agent_parser.h"
#include "agent_semantic.h"
#include "agent_policy_ir.h"
#include "agent_codegen.h"
#include "agent_validation.h"
#include "agent_security_audit.h"
#include "bloom_filter.h"
#include <string>
#include <vector>
#include <memory>

class AgenticOrchestrator {
public:
    AgenticOrchestrator();

    // Executes the entire 8-agent pipeline (Agent 0 to Agent 7) on a policy source string
    bool compilePolicy(const std::string& policySource,
                       const std::string& targetCppPath = "generated_validator.cpp",
                       const std::string& preApprovedRepair = "",
                       const std::string& dictionaryPath = "dictionary.txt",
                       const std::string& breachCorpusPath = "");

    // Runs live evaluation of a candidate password using Validation & Security Audit Agents
    void evaluatePassword(const std::string& password,
                          const std::string& dictionaryPath = "dictionary.txt",
                          const std::string& breachCorpusPath = "");

    // Runs automated PBL attack simulation suite and displays detection metrics
    bool runAttackSimulationBenchmark();

    // Renders the comprehensive Final Agentic Report
    void renderFinalReport() const;

    // Renders the full telemetry log containing all O-A-D-A-V steps across all agents
    void renderTelemetryLog() const;

    const PolicyConstraints& getCompiledConstraints() const { return finalConstraints; }
    bool isCompilationSuccessful() const { return compilationSuccess; }

private:
    std::vector<AgentTelemetryRecord> globalTelemetry;
    PolicyConstraints finalConstraints;
    bool compilationSuccess = false;
    AgentAttackDetector attackDetector;

    // Agent Reports
    AgentActionReport guardReport;
    AgentActionReport lexerReport;
    AgentActionReport parserReport;
    AgentActionReport semanticReport;
    AgentActionReport irReport;
    AgentActionReport codegenReport;
    AgentActionReport validationReport;

    int originalNodes = 0;
    int optimizedNodes = 0;
    bool semanticEquivalence = false;
    bool gate1Passed = false;
    bool gate2Passed = false;
    double testConformanceRate = 0.0;
    int testsTotal = 0;
    int testsPassed = 0;

    // Static Bloom Filter & Blocklist Metrics
    BloomParameters bloomParams;
    bool bloomSynthesized = false;
    size_t exactKeysCount = 0;
    size_t totalEmbeddedBytes = 0;
    size_t policyCompatibleKeys = 0;
    std::string activeDictPath;
    std::string activeBreachPath;

    void logTelemetry(const std::vector<AgentTelemetryRecord>& logs);
};

#endif // AGENTIC_ORCHESTRATOR_H
