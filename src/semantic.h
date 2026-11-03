#ifndef SEMANTIC_H
#define SEMANTIC_H

#include "ast.h"
#include "diagnostics.h"
#include <vector>
#include <string>
#include <map>

struct SemanticError {
    std::string message;
    SourcePos pos;

    SemanticError(std::string m = "", SourcePos p = SourcePos())
        : message(m), pos(p) {}
};

struct PolicyConstraints {
    int minLength;
    int maxLength;

    // Quantitative requirements
    int minUpper;
    int minLower;
    int minDigit;
    int minSpecial;

    // Legacy compatibility fields
    int requireUpper;
    int requireLower;
    int requireDigit;
    int requireSpecial;
    int noSpaces;

    // Pattern constraints
    int maxSequence;
    int maxRepeated;

    // Blacklist & Minimum Strength
    std::vector<std::string> blacklist;
    std::string minStrength;

    PolicyConstraints()
        : minLength(-1), maxLength(-1),
          minUpper(0), minLower(0), minDigit(0), minSpecial(0),
          requireUpper(-1), requireLower(-1), requireDigit(-1), requireSpecial(-1), noSpaces(-1),
          maxSequence(-1), maxRepeated(-1), minStrength("none") {}
};

class SemanticAnalyzer {
    std::vector<SemanticError> errs;
    std::vector<Diagnostic> diagnostics;
    PolicyConstraints constraints;

    // Tracking defined rules for duplicate detection (rule -> {value, SourcePos})
    std::map<std::string, std::pair<std::string, SourcePos>> definedRules;

public:
    void analyze(const PolicyAST& ast);

    const std::vector<SemanticError>& errors() const { return errs; }
    const std::vector<Diagnostic>& getDiagnostics() const { return diagnostics; }
    const PolicyConstraints& getConstraints() const { return constraints; }

    bool hasErrors() const { return !errs.empty(); }
};

#endif
