#ifndef AGENT_TYPES_H
#define AGENT_TYPES_H

#include <string>
#include <vector>
#include <chrono>
#include <iomanip>
#include <sstream>

enum class AgentStage {
    LexicalAnalysis,
    SyntaxAndAST,
    SemanticVerification,
    IROptimization,
    CodeSynthesis,
    RuntimeValidation,
    SecurityAudit
};

enum class AgentDecision {
    PROCEED,
    BLOCK,
    REPAIR_PROPOSED,
    REPAIR_APPLIED,
    HUMAN_APPROVAL_REQUIRED,
    OPTIMIZE,
    PASS_GATE,
    BLOCK_GATE,
    WARN
};

enum class RepairSafety {
    NONE,
    SAFE_DETERMINISTIC,
    AMBIGUOUS_NEEDS_HUMAN,
    UNSAFE_BLOCK
};

struct RepairCandidate {
    std::string id;            // e.g. "A", "B"
    std::string candidateText; // e.g. "require uppercase 1"
    std::string rationale;     // e.g. "Baseline policy: enforce at least 1 uppercase character"
    double confidence;         // e.g. 0.85
    bool grammarValid = false;
    bool astValid = false;
    bool semanticValid = false;

    RepairCandidate(std::string i = "", std::string text = "", std::string rat = "", double conf = 0.9)
        : id(std::move(i)), candidateText(std::move(text)), rationale(std::move(rat)), confidence(conf) {}
};

struct AgentTelemetryRecord {
    std::string agentId;
    std::string stage;
    std::string inputSummary;
    std::string observation;
    std::string decision;
    std::string actionTaken;
    std::string evidence;
    double confidence; // 0.0 to 1.0 (e.g. 0.99 = 99%)
    std::string resultStatus;
    std::string timestamp;

    static std::string currentTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto in_time_t = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
        std::stringstream ss;
        ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %H:%M:%S")
           << '.' << std::setfill('0') << std::setw(3) << ms.count();
        return ss.str();
    }
};

struct AgentActionReport {
    std::string agentName;
    std::string agentId;
    bool success;
    AgentDecision decision;
    double confidence;
    std::string issueDetected;
    std::string reason;
    std::string suggestedAction;
    std::vector<std::string> criticalFindings;
    std::vector<AgentTelemetryRecord> telemetryLogs;

    // Secure Autonomous Repair & Safety Classification
    RepairSafety safetyClassification = RepairSafety::NONE;
    std::vector<RepairCandidate> repairCandidates;
    bool humanApprovalRequired = false;
    std::string approvedCandidateId;

    AgentActionReport(const std::string& name = "", const std::string& id = "")
        : agentName(name), agentId(id), success(true), decision(AgentDecision::PROCEED), confidence(1.0) {}
};

#endif // AGENT_TYPES_H
