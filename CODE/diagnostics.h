#ifndef DIAGNOSTICS_H
#define DIAGNOSTICS_H

#include "token.h"
#include <string>
#include <vector>
#include <iostream>

// Standard Four Diagnostic Levels (Major Change #7)
enum class DiagLevel {
    Error,
    Warning,
    Info,
    Suggestion
};

struct CompilerDiagnostic {
    DiagLevel level;
    std::string ruleName;
    std::string message;
    std::string expected;
    std::string previousValue;
    std::string newValue;
    std::string suggestion;
    SourcePos pos;
    std::vector<std::string> contextLines;

    CompilerDiagnostic(
        DiagLevel l = DiagLevel::Info,
        std::string rule = "",
        std::string msg = "",
        std::string exp = "",
        std::string prev = "",
        std::string next = "",
        std::string sug = "",
        SourcePos p = SourcePos(),
        std::vector<std::string> ctx = {}
    ) : level(l), ruleName(rule), message(msg), expected(exp),
        previousValue(prev), newValue(next), suggestion(sug), pos(p), contextLines(ctx) {}
};

// Backward compatibility alias
typedef CompilerDiagnostic Diagnostic;

class DiagnosticsEngine {
public:
    static std::string levelToString(DiagLevel l);
    static void renderBox(const CompilerDiagnostic& diag, const std::vector<std::string>& sourceLines = {});
    static void renderSummary(int errors, int warnings, int infos, int suggestions);
};

#endif