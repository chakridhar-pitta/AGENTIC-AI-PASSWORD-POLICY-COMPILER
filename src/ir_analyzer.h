#ifndef IR_ANALYZER_H
#define IR_ANALYZER_H

#include "ir.h"
#include "ast.h"
#include "semantic.h"
#include <vector>
#include <string>
#include <iostream>

struct RedundantRule {
    std::string ruleName;
    std::string originalValue;
    std::string updatedValue;
    std::string reason;
    bool isExactDuplicate;

    RedundantRule(std::string name = "", std::string orig = "", std::string upd = "",
                  std::string r = "", bool exact = false)
        : ruleName(name), originalValue(orig), updatedValue(upd), reason(r), isExactDuplicate(exact) {}
};

struct PolicyContradiction {
    std::string ruleName;
    std::string description;
    std::string expected;

    PolicyContradiction(std::string name = "", std::string desc = "", std::string exp = "")
        : ruleName(name), description(desc), expected(exp) {}
};

struct PolicyAnalysisReport {
    bool hasContradictions;
    std::vector<PolicyContradiction> contradictions;
    std::vector<RedundantRule> redundantRules;
    std::vector<std::string> restrictivenessWarnings;
    bool isSatisfiable;
    bool canCompile;
    int redundantCount;
    int contradictionCount;

    PolicyAnalysisReport()
        : hasContradictions(false), isSatisfiable(true), canCompile(true),
          redundantCount(0), contradictionCount(0) {}

    void print() const;
};

struct IRWarning {
    std::string message;
    IRWarning(std::string m = "") : message(m) {}
};

class PolicyAnalyzer {
public:
    // Core Static Policy Analysis (Major Change #4)
    static PolicyAnalysisReport analyze(const PolicyAST& ast, const PolicyConstraints& c, const PolicyIR& ir);

    // Legacy compatibility method
    static std::vector<IRWarning> analyze(const PolicyIR& ir);
};

// Legacy compatibility alias
typedef PolicyAnalyzer IRAnalyzer;

#endif
