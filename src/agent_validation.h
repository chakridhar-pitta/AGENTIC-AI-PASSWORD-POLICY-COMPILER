#ifndef AGENT_VALIDATION_H
#define AGENT_VALIDATION_H

#include "agent_types.h"
#include "semantic.h"
#include "bloom_filter.h"
#include "leetspeak.h"
#include <string>
#include <vector>

struct ValidationTestCase {
    std::string testName;
    std::string candidatePassword;
    bool expectedValid;
    bool actualValid;
    std::vector<std::string> actualViolations;
    bool testPassed;
};

struct BlocklistSecurityTestCase {
    std::string testName;
    std::string category;
    std::string details;
    bool passed;
};

class ValidationAgent {
public:
    explicit ValidationAgent(const PolicyConstraints& constraints,
                             std::string targetCppPath = "generated_validator.cpp",
                             std::string dictionaryPath = "dictionary.txt",
                             std::string breachCorpusPath = "");

    // Runs the 5-stage O-A-D-A-V loop
    bool execute();

    const std::vector<ValidationTestCase>& getTestMatrix() const { return testMatrix; }
    const std::vector<BlocklistSecurityTestCase>& getBlocklistTestMatrix() const { return blocklistTests; }
    const AgentActionReport& getReport() const { return report; }
    double getConformanceRate() const { return conformanceRate; }
    void renderReport() const;

    // Evaluates an arbitrary single password against the policy
    static bool evaluateSingle(const std::string& pwd, const PolicyConstraints& c, std::vector<std::string>& failures);

private:
    PolicyConstraints constraints;
    std::string targetFile;
    std::string dictPath;
    std::string breachPath;

    std::vector<ValidationTestCase> testMatrix;
    std::vector<BlocklistSecurityTestCase> blocklistTests;
    AgentActionReport report;
    double conformanceRate = 0.0;
    int blocklistTestsPassed = 0;

    // O-A-D-A-V Stages
    void observe();
    void analyze();
    void decide();
    void act();
    bool verify();

    // Test Oracle Synthesizers
    void synthesizeTestOracle();
    void runBlocklistSecurityTestSuite();
};

#endif // AGENT_VALIDATION_H
