#include "diagnostics.h"
#include <sstream>
#include <algorithm>
#include <iomanip>

using namespace std;

string DiagnosticsEngine::levelToString(DiagLevel l) {
    switch(l) {
        case DiagLevel::Error: return "ERROR";
        case DiagLevel::Warning: return "WARNING";
        case DiagLevel::Info: return "INFO";
        case DiagLevel::Suggestion: return "SUGGESTION";
    }
    return "UNKNOWN";
}

// Visual column width accounting for multi-byte UTF-8 characters
static int utf8VisualLength(const string& s) {
    int len = 0;
    for (size_t i = 0; i < s.length(); ) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x80) { i += 1; len += 1; }
        else if ((c & 0xE0) == 0xC0) { i += 2; len += 1; }
        else if ((c & 0xF0) == 0xE0) { i += 3; len += 1; }
        else if ((c & 0xF8) == 0xF0) { i += 4; len += 1; }
        else { i += 1; len += 1; }
    }
    return len;
}

void DiagnosticsEngine::renderBox(const CompilerDiagnostic& diag, const vector<string>& sourceLines) {
    string levelStr = levelToString(diag.level);

    // Icon per level
    string icon;
    switch(diag.level) {
        case DiagLevel::Error:      icon = "\u2717"; break; // ✗
        case DiagLevel::Warning:    icon = "\u26A0"; break; // ⚠
        case DiagLevel::Info:       icon = "\u2139"; break; // ℹ
        case DiagLevel::Suggestion: icon = "\U0001F4A1"; break; // 💡
    }

    // Determine context lines
    vector<string> ctx = diag.contextLines;
    if(ctx.empty() && diag.pos.line > 0 && diag.pos.line <= (int)sourceLines.size()) {
        ctx.push_back(sourceLines[diag.pos.line - 1]);
    }

    string posStr = "";
    if(diag.pos.line > 0) {
        posStr = "Line " + to_string(diag.pos.line) + ", Column " + to_string(diag.pos.col);
    }

    string fullMsg = icon + " " + diag.message;

    // Calculate box width dynamically
    int boxWidth = 42;
    if(!posStr.empty()) {
        boxWidth = max(boxWidth, utf8VisualLength(posStr) + 4);
    }
    for(const auto& line : ctx) {
        boxWidth = max(boxWidth, utf8VisualLength(line) + 4);
    }
    boxWidth = max(boxWidth, utf8VisualLength(fullMsg) + 4);

    if(!diag.previousValue.empty() && !diag.newValue.empty()) {
        boxWidth = max(boxWidth, utf8VisualLength("Previous value : " + diag.previousValue) + 4);
        boxWidth = max(boxWidth, utf8VisualLength("New value      : " + diag.newValue) + 4);
    }
    if(!diag.expected.empty()) {
        boxWidth = max(boxWidth, utf8VisualLength("Expected: " + diag.expected) + 4);
    }
    if(!diag.suggestion.empty()) {
        boxWidth = max(boxWidth, utf8VisualLength(diag.suggestion) + 4);
    }

    // Construct box border strings using standard Unicode Box Drawing
    string h = "";
    for(int i = 0; i < boxWidth; ++i) h += "\u2500";

    string topBorder = "\u250C" + h + "\u2510";
    string midBorder = "\u251C" + h + "\u2524";
    string botBorder = "\u2514" + h + "\u2518";
    string vBar      = "\u2502";

    auto printLine = [&](const string& text) {
        int vlen = utf8VisualLength(text);
        int pad = (boxWidth - 2) - vlen;
        if(pad < 0) pad = 0;
        cout << vBar << " " << text << string(pad, ' ') << " " << vBar << "\n";
    };

    cout << "\n" << topBorder << "\n";
    printLine(levelStr);
    cout << midBorder << "\n";

    if(!posStr.empty()) {
        printLine(posStr);
        printLine("");
    }

    for(const auto& line : ctx) {
        printLine(line);
    }
    if(!ctx.empty()) {
        printLine("");
    }

    printLine(fullMsg);

    if(diag.ruleName != "bounds_conflict" && !diag.previousValue.empty() && !diag.newValue.empty()) {
        printLine("");
        printLine("Previous value : " + diag.previousValue);
        printLine("New value      : " + diag.newValue);
    }

    if(diag.ruleName != "bounds_conflict" && !diag.expected.empty()) {
        printLine("");
        printLine("Expected: " + diag.expected);
    }

    if(!diag.suggestion.empty()) {
        printLine("");
        printLine("Suggestion:");
        printLine(diag.suggestion);
    }

    cout << botBorder << "\n";
}

void DiagnosticsEngine::renderSummary(int errors, int warnings, int infos, int suggestions) {
    cout << "\n[DIAGNOSTICS SUMMARY] ";
    cout << errors << " error(s), ";
    cout << warnings << " warning(s), ";
    cout << infos << " info(s), ";
    cout << suggestions << " suggestion(s)\n";
}