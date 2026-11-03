#include "ir_analyzer.h"
#include <map>
#include <algorithm>

using namespace std;

PolicyAnalysisReport PolicyAnalyzer::analyze(const PolicyAST& ast, const PolicyConstraints& c, const PolicyIR& ir)
{
    (void)ir;
    PolicyAnalysisReport report;
    map<string, string> seenRules;

    // --- 1. Redundancy & Duplicate Rule Analysis ---
    for(const auto& nodePtr : ast.nodes) {
        if(!nodePtr) continue;

        string ruleName = "";
        string valStr = "";

        switch(nodePtr->nodeType) {
            case ASTNodeType::LengthConstraint: {
                auto n = static_pointer_cast<LengthConstraintNode>(nodePtr);
                ruleName = (n->boundType == "min" ? "minLength" : "maxLength");
                valStr = to_string(n->length);
                break;
            }
            case ASTNodeType::CharacterConstraint: {
                auto n = static_pointer_cast<CharacterConstraintNode>(nodePtr);
                ruleName = "require " + n->charClass;
                valStr = to_string(n->minCount);
                break;
            }
            case ASTNodeType::PatternConstraint: {
                auto n = static_pointer_cast<PatternConstraintNode>(nodePtr);
                ruleName = "forbid " + n->patternType;
                valStr = to_string(n->threshold);
                break;
            }
            case ASTNodeType::DictionaryConstraint: {
                auto n = static_pointer_cast<DictionaryConstraintNode>(nodePtr);
                ruleName = "blacklist \"" + n->blacklistedWord + "\"";
                valStr = n->blacklistedWord;
                break;
            }
            case ASTNodeType::StrengthConstraint: {
                auto n = static_pointer_cast<StrengthConstraintNode>(nodePtr);
                ruleName = "strength";
                valStr = n->minimumLevel;
                break;
            }
        }

        if(ruleName.empty()) continue;

        if(seenRules.count(ruleName)) {
            string prevVal = seenRules[ruleName];
            bool exact = (prevVal == valStr);
            string reason = exact ? "Exact duplicate rule definition" : "Overridden by subsequent declaration";
            report.redundantRules.push_back(RedundantRule(ruleName, prevVal, valStr, reason, exact));
            seenRules[ruleName] = valStr;
        } else {
            seenRules[ruleName] = valStr;
        }
    }

    // --- 2. Contradiction & Satisfiability Analysis ---

    // A. Bounds conflict: minLength > maxLength
    if(c.minLength != -1 && c.maxLength != -1 && c.minLength > c.maxLength) {
        report.contradictions.push_back(PolicyContradiction(
            "bounds",
            "minLength (" + to_string(c.minLength) + ") exceeds maxLength (" + to_string(c.maxLength) + ")",
            "maxLength >= minLength"
        ));
    }

    // B. Character requirement capacity overflow
    int sumReq = max(0, c.minUpper) + max(0, c.minLower) + max(0, c.minDigit) + max(0, c.minSpecial);
    if(c.maxLength != -1 && sumReq > c.maxLength) {
        report.contradictions.push_back(PolicyContradiction(
            "capacity",
            "Sum of character requirements (" + to_string(sumReq) + ") exceeds maxLength (" + to_string(c.maxLength) + ")",
            "maxLength >= " + to_string(sumReq)
        ));
    }

    // C. Non-positive lengths
    if(c.minLength != -1 && c.minLength <= 0) {
        report.contradictions.push_back(PolicyContradiction(
            "minLength",
            "Invalid non-positive minimum length: " + to_string(c.minLength),
            "positive integer"
        ));
    }
    if(c.maxLength != -1 && c.maxLength <= 0) {
        report.contradictions.push_back(PolicyContradiction(
            "maxLength",
            "Invalid non-positive maximum length: " + to_string(c.maxLength),
            "positive integer"
        ));
    }

    // --- 3. Restrictiveness & Usability Profile ---
    if(c.minLength != -1 && c.maxLength != -1 && c.minLength == c.maxLength) {
        report.restrictivenessWarnings.push_back("Strict fixed-length policy (" + to_string(c.minLength) + " chars) significantly reduces keyspace flexibility.");
    }
    if(c.minLength > 64) {
        report.restrictivenessWarnings.push_back("Unusually restrictive minimum length (" + to_string(c.minLength) + " chars) may impede user adoption.");
    }
    if(c.minLength != -1 && c.minLength < 8) {
        report.restrictivenessWarnings.push_back("Minimum length (" + to_string(c.minLength) + ") is below standard NIST 800-63B recommendation (>= 8).");
    }
    if(c.minLength >= 12 && c.minUpper >= 1 && c.minLower >= 1 && c.minDigit >= 2 && c.minSpecial >= 1) {
        report.restrictivenessWarnings.push_back("Enterprise High-Security profile verified (satisfiable quantitative distribution).");
    }
    if(c.maxSequence != -1) {
        report.restrictivenessWarnings.push_back("Pattern optimization: Sequences >= " + to_string(c.maxSequence) + " chars will be filtered.");
    }
    if(c.maxRepeated != -1) {
        report.restrictivenessWarnings.push_back("Pattern optimization: Repetitions >= " + to_string(c.maxRepeated) + " chars will be filtered.");
    }
    if(!c.blacklist.empty()) {
        report.restrictivenessWarnings.push_back("Dictionary constraint: " + to_string(c.blacklist.size()) + " forbidden phrases active.");
    }

    // --- 4. Final Verdict Calculation ---
    report.contradictionCount = (int)report.contradictions.size();
    report.hasContradictions = (report.contradictionCount > 0);
    report.redundantCount = (int)report.redundantRules.size();
    report.isSatisfiable = !report.hasContradictions;
    report.canCompile = report.isSatisfiable;

    return report;
}

vector<IRWarning> PolicyAnalyzer::analyze(const PolicyIR& ir)
{
    vector<IRWarning> warnings;
    if(ir.length.minLength != -1 && ir.length.maxLength != -1 && ir.length.minLength == ir.length.maxLength) {
        warnings.push_back({"Password length is strictly fixed to " + to_string(ir.length.minLength) + " characters."});
    }
    if(ir.length.minLength != -1 && ir.length.minLength < 8) {
        warnings.push_back({"Minimum length (" + to_string(ir.length.minLength) + ") is below standard security threshold (>= 8)."});
    }
    return warnings;
}

void PolicyAnalysisReport::print() const {
    cout << "\n---------------------------------------------------------------\n";
    cout << "  POLICY ANALYSIS & OPTIMIZATION REPORT\n";
    cout << "---------------------------------------------------------------\n";
    cout << "Policy Analysis\n\n";

    if(!hasContradictions) {
        cout << "  [PASS] No contradictions\n";
    } else {
        cout << "  [FAIL] " << contradictionCount << " contradiction" << (contradictionCount > 1 ? "s" : "") << " detected:\n";
        for(const auto& cd : contradictions) {
            cout << "         * " << cd.description << " (Expected: " << cd.expected << ")\n";
        }
    }

    if(redundantCount == 0) {
        cout << "  [PASS] No redundant rules\n";
    } else {
        cout << "  [WARN] " << redundantCount << " redundant rule" << (redundantCount > 1 ? "s" : "") << ":\n";
        for(const auto& r : redundantRules) {
            if(r.isExactDuplicate) {
                cout << "         * Duplicate '" << r.ruleName << " " << r.originalValue << "' (pruned duplicate)\n";
            } else {
                cout << "         * Duplicate '" << r.ruleName << "': overridden (previous: " << r.originalValue << ", new: " << r.updatedValue << ")\n";
            }
        }
    }

    if(isSatisfiable) {
        cout << "  [PASS] All constraints satisfiable\n";
    } else {
        cout << "  [FAIL] Constraints unsatisfiable (no valid password exists)\n";
    }

    if(canCompile) {
        cout << "  [PASS] Policy can be compiled\n";
    } else {
        cout << "  [FAIL] Policy compilation blocked\n";
    }

    if(!restrictivenessWarnings.empty()) {
        cout << "\n  --- Security & Usability Profile ---\n";
        for(const auto& rw : restrictivenessWarnings) {
            cout << "  [INFO] " << rw << "\n";
        }
    }
    cout << "---------------------------------------------------------------\n";
}
