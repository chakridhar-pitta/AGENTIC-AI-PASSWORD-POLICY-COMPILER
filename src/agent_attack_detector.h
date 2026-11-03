#ifndef AGENT_ATTACK_DETECTOR_H
#define AGENT_ATTACK_DETECTOR_H

#include "agent_types.h"
#include <string>
#include <vector>
#include <chrono>

// Comprehensive Agentic AI Attack Categories
enum class AttackCategory {
    NONE_BENIGN,
    POLICY_INJECTION_POLICY_BYPASS,  // Policy Injection / Policy-Bypass (Analogous to Prompt Injection in LLMs)
    SECURITY_DOWNGRADE,              // Adversarial weakening of policy below NIST/OWASP minimum safety baselines
    CODE_INJECTION_DSL_POISON,       // C++/Shell/Escape code embedded in blacklist/rule literals
    OUTPUT_BACKDOOR_HIDDEN_AGENDA,   // Synthesized code with hidden personal info exfiltration, network calls, file writes
    RESOURCE_EXHAUSTION_DOS          // Buffer overflow, oversized payload, ReDoS regex patterns
};

enum class ThreatRiskLevel {
    SAFE,       // Risk 0.0 - Benign legitimate policy
    LOW,        // Risk 1.0 - 3.9
    MEDIUM,     // Risk 4.0 - 6.9
    HIGH,       // Risk 7.0 - 8.9
    CRITICAL    // Risk 9.0 - 10.0
};

struct AttackAssessment {
    bool isAttack = false;
    AttackCategory category = AttackCategory::NONE_BENIGN;
    std::string categoryName = "BENIGN";
    ThreatRiskLevel riskLevel = ThreatRiskLevel::SAFE;
    double riskScore = 0.0; // 0.0 to 10.0
    std::string attackPatternDetected;
    std::string mitigationAction = "ALLOW";
    std::string explanation;
    double detectionLatencyMs = 0.0;
};

// Benchmark Test Case for Metric Calculations
struct AttackBenchmarkCase {
    std::string id;
    std::string name;
    AttackCategory expectedCategory;
    bool isMalicious; // true = Attack, false = Benign
    std::string payload;
    std::string description;
};

struct DetectionMetrics {
    int totalTests = 0;
    int truePositives = 0;   // Correctly detected and blocked attacks
    int trueNegatives = 0;   // Correctly allowed benign policies
    int falsePositives = 0;  // Benign policies mistakenly blocked
    int falseNegatives = 0;  // Attacks that evaded detection
    
    double precision = 0.0;       // TP / (TP + FP)
    double recall = 0.0;          // TP / (TP + FN) - Detection Rate
    double f1Score = 0.0;         // 2 * (Precision * Recall) / (Precision + Recall)
    double falsePositiveRate = 0.0; // FP / (FP + TN)
    double attackBlockRate = 0.0;   // Blocked Attacks / Detected Attacks (Target: 100%)
    double averageLatencyMs = 0.0;
};

class AgentAttackDetector {
public:
    AgentAttackDetector();

    // Inspects input policy before lexical tokenization (Agent 0: Policy Security Guard)
    AttackAssessment inspectPolicyInput(const std::string& input);

    // Inspects synthesized validator code for backdoors & hidden agendas (Gate #2)
    AttackAssessment inspectSynthesizedCode(const std::string& generatedCppCode);

    // Escapes special characters in string literals to prevent DSL injection poisoning
    static std::string sanitizeStringLiteral(const std::string& raw);

    // Runs full practical benchmark suite (28 test cases) and calculates detection metrics
    DetectionMetrics runBenchmarkSuite();

    // Returns standard pre-configured benchmark cases
    static std::vector<AttackBenchmarkCase> getBenchmarkCases();

    // Helper formatting methods
    static std::string categoryToString(AttackCategory cat);
    static std::string riskLevelToString(ThreatRiskLevel level);
    void printMetricsReport(const DetectionMetrics& metrics) const;

private:
    static std::string toLower(const std::string& s);
    static bool containsSubstring(const std::string& text, const std::string& needle);
    static bool matchesRegexPattern(const std::string& text, const std::string& regexStr);
};

#endif // AGENT_ATTACK_DETECTOR_H
