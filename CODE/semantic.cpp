#include "semantic.h"
#include <cstdlib>
#include <vector>
#include <string>
#include <algorithm>
#include <cctype>
#include <set>
#include <memory>

using namespace std;

void SemanticAnalyzer::analyze(const PolicyAST& ast) {
    errs.clear();
    diagnostics.clear();
    definedRules.clear();

    for(const auto& nodePtr : ast.nodes) {
        if(!nodePtr) continue;

        switch(nodePtr->nodeType) {
            case ASTNodeType::LengthConstraint: {
                auto n = static_pointer_cast<LengthConstraintNode>(nodePtr);
                string ruleName = (n->boundType == "min" ? "minLength" : "maxLength");
                string newValStr = to_string(n->length);

                // Duplicate rule check
                if(definedRules.count(ruleName)) {
                    string prevVal = definedRules[ruleName].first;
                    diagnostics.push_back(Diagnostic(
                        DiagLevel::Warning,
                        ruleName,
                        "Duplicate rule: " + ruleName,
                        "",
                        prevVal,
                        newValStr,
                        "Remove the duplicate rule or consolidate the constraints.",
                        n->pos,
                        {ruleName + " " + prevVal, ruleName + " " + newValStr}
                    ));
                }
                definedRules[ruleName] = {newValStr, n->pos};

                // Semantic validation on length
                if(n->boundType == "min") {
                    if(n->length <= 0) {
                        string msg = "Invalid minimum length: " + to_string(n->length);
                        string expected = "positive integer";
                        errs.push_back(SemanticError(msg + "\nExpected:\n" + expected, n->pos));
                        diagnostics.push_back(Diagnostic(
                            DiagLevel::Error,
                            ruleName,
                            msg,
                            expected,
                            "",
                            newValStr,
                            "Set minLength to a positive integer (e.g., minLength 8).",
                            n->pos,
                            {ruleName + " " + to_string(n->length)}
                        ));
                    } else {
                        constraints.minLength = n->length;
                    }
                } else if(n->boundType == "max") {
                    if(n->length <= 0) {
                        string msg = "Invalid maximum length: " + to_string(n->length);
                        string expected = "positive integer";
                        errs.push_back(SemanticError(msg + "\nExpected:\n" + expected, n->pos));
                        diagnostics.push_back(Diagnostic(
                            DiagLevel::Error,
                            ruleName,
                            msg,
                            expected,
                            "",
                            newValStr,
                            "Set maxLength to a positive integer greater than minLength",
                            n->pos
                        ));
                    } else {
                        constraints.maxLength = n->length;
                    }
                }
                break;
            }

            case ASTNodeType::CharacterConstraint: {
                auto n = static_pointer_cast<CharacterConstraintNode>(nodePtr);
                string ruleName = "require " + n->charClass;
                string newValStr = to_string(n->minCount);

                // Duplicate rule check
                if(definedRules.count(ruleName)) {
                    string prevVal = definedRules[ruleName].first;
                    diagnostics.push_back(Diagnostic(
                        DiagLevel::Warning,
                        ruleName,
                        "Duplicate rule: " + ruleName,
                        "",
                        prevVal,
                        newValStr,
                        "Remove redundant duplicate requirement.",
                        n->pos,
                        {ruleName + " " + prevVal, ruleName + " " + newValStr}
                    ));
                }
                definedRules[ruleName] = {newValStr, n->pos};

                // Semantic check: require <class> must be >= 1
                if(n->minCount <= 0) {
                    string capName = n->charClass;
                    if(!capName.empty()) capName[0] = (char)toupper((unsigned char)capName[0]);
                    string msg = capName + " requirement must be at least 1.";
                    errs.push_back(SemanticError(msg, n->pos));
                    diagnostics.push_back(Diagnostic(
                        DiagLevel::Error,
                        ruleName,
                        msg,
                        "positive integer (>= 1)",
                        "",
                        newValStr,
                        "Set requirement to 1 or higher, or omit the rule.",
                        n->pos,
                        {"require " + n->charClass + " " + to_string(n->minCount)}
                    ));
                    break;
                }

                if(n->charClass == "uppercase" || n->charClass == "upper") {
                    constraints.minUpper = n->minCount;
                    constraints.requireUpper = 1;
                } else if(n->charClass == "lowercase" || n->charClass == "lower") {
                    constraints.minLower = n->minCount;
                    constraints.requireLower = 1;
                } else if(n->charClass == "digit" || n->charClass == "digits") {
                    constraints.minDigit = n->minCount;
                    constraints.requireDigit = 1;
                } else if(n->charClass == "special" || n->charClass == "specials") {
                    constraints.minSpecial = n->minCount;
                    constraints.requireSpecial = 1;
                } else {
                    errs.push_back(SemanticError("Unknown character class requirement: '" + n->charClass + "'", n->pos));
                }
                break;
            }

            case ASTNodeType::PatternConstraint: {
                auto n = static_pointer_cast<PatternConstraintNode>(nodePtr);
                string ruleName = "forbid " + n->patternType;
                string newValStr = to_string(n->threshold);

                // Duplicate rule check
                if(definedRules.count(ruleName)) {
                    string prevVal = definedRules[ruleName].first;
                    diagnostics.push_back(Diagnostic(
                        DiagLevel::Warning,
                        ruleName,
                        "Duplicate rule: " + ruleName,
                        "",
                        prevVal,
                        newValStr,
                        "Remove redundant '" + ruleName + "' constraint",
                        n->pos
                    ));
                }
                definedRules[ruleName] = {newValStr, n->pos};

                // Semantic check: threshold must be >= 2 for sequence & repeated
                if(n->patternType == "sequence" || n->patternType == "repeated" ||
                   n->patternType == "sequences" || n->patternType == "consecutive") {
                    if(n->threshold < 2) {
                        string msg = "Pattern threshold for 'forbid " + n->patternType + "' must be at least 2.";
                        string expected = "integer >= 2";
                        errs.push_back(SemanticError(msg + "\nExpected:\n" + expected, n->pos));
                        diagnostics.push_back(Diagnostic(
                            DiagLevel::Error,
                            ruleName,
                            msg,
                            expected,
                            "",
                            newValStr,
                            "Set threshold to 2, 3, or higher",
                            n->pos
                        ));
                        break;
                    }
                }

                if(n->patternType == "spaces" || n->patternType == "space") {
                    constraints.noSpaces = n->threshold;
                } else if(n->patternType == "sequence" || n->patternType == "sequences") {
                    constraints.maxSequence = n->threshold;
                } else if(n->patternType == "repeated" || n->patternType == "consecutive") {
                    constraints.maxRepeated = n->threshold;
                } else {
                    errs.push_back(SemanticError("Unknown forbidden pattern target: '" + n->patternType + "'", n->pos));
                }
                break;
            }

            case ASTNodeType::DictionaryConstraint: {
                auto n = static_pointer_cast<DictionaryConstraintNode>(nodePtr);
                if(n->blacklistedWord.empty()) {
                    diagnostics.push_back(Diagnostic(
                        DiagLevel::Warning,
                        "blacklist",
                        "Empty blacklisted phrase ignored",
                        "non-empty string",
                        "",
                        "\"\"",
                        "Provide a non-empty string like \"password\"",
                        n->pos
                    ));
                } else {
                    constraints.blacklist.push_back(n->blacklistedWord);
                }
                break;
            }

            case ASTNodeType::StrengthConstraint: {
                auto n = static_pointer_cast<StrengthConstraintNode>(nodePtr);
                string lvl = n->minimumLevel;
                for(char& ch : lvl) ch = (char)tolower((unsigned char)ch);

                if(lvl != "weak" && lvl != "medium" && lvl != "strong" && lvl != "very strong" && lvl != "verystrong") {
                    diagnostics.push_back(Diagnostic(
                        DiagLevel::Warning,
                        "strength",
                        "Unrecognized strength tier: '" + n->minimumLevel + "'",
                        "weak, medium, strong, or very strong",
                        "",
                        n->minimumLevel,
                        "Defaulting target strength to 'strong'",
                        n->pos
                    ));
                    constraints.minStrength = "strong";
                } else {
                    constraints.minStrength = lvl;
                }
                break;
            }
        }
    }

    // --- High-Level Cross-Constraint Validation ---

    // 1. minLength cannot exceed maxLength
    if(constraints.minLength != -1 && constraints.maxLength != -1 &&
       constraints.minLength > constraints.maxLength)
    {
        string msg = "Minimum length exceeds maximum length";
        string expected = "maxLength >= " + to_string(constraints.minLength);
        string suggestion = "Set maxLength to " + to_string(constraints.minLength) + " or greater.";
        SourcePos conflictPos = definedRules.count("maxLength") ? definedRules["maxLength"].second : SourcePos(1, 1);
        errs.push_back(SemanticError(msg + "\nExpected:\n" + expected, conflictPos));
        diagnostics.push_back(Diagnostic(
            DiagLevel::Error,
            "bounds_conflict",
            msg,
            expected,
            to_string(constraints.minLength),
            to_string(constraints.maxLength),
            suggestion,
            conflictPos,
            {"minLength " + to_string(constraints.minLength), "maxLength " + to_string(constraints.maxLength)}
        ));
    }

    // 2. Sum of quantitative requirements cannot exceed maxLength
    int sumRequirements = max(0, constraints.minUpper) + max(0, constraints.minLower) +
                          max(0, constraints.minDigit) + max(0, constraints.minSpecial);

    if(constraints.maxLength != -1 && sumRequirements > constraints.maxLength) {
        string msg = "Unsatisfiable policy: Sum of required character counts (" + to_string(sumRequirements) +
                     ") exceeds maxLength (" + to_string(constraints.maxLength) + ")";
        string expected = "maxLength >= " + to_string(sumRequirements);
        errs.push_back(SemanticError(msg + "\nExpected:\n" + expected, SourcePos(0, 0)));
        diagnostics.push_back(Diagnostic(
            DiagLevel::Error,
            "capacity_overflow",
            msg,
            expected,
            to_string(constraints.maxLength),
            to_string(sumRequirements),
            "Decrease character count requirements or increase maxLength"
        ));
    }

    // 3. Warning if minLength is smaller than total required character classes
    if(constraints.minLength != -1 && sumRequirements > constraints.minLength) {
        diagnostics.push_back(Diagnostic(
            DiagLevel::Warning,
            "tightened_minimum",
            "Effective minimum length is " + to_string(sumRequirements) + 
            " due to character requirements, but minLength is currently " + to_string(constraints.minLength),
            "minLength >= " + to_string(sumRequirements),
            to_string(constraints.minLength),
            to_string(sumRequirements),
            "Consider explicitly setting minLength to at least " + to_string(sumRequirements)
        ));
    }
}
