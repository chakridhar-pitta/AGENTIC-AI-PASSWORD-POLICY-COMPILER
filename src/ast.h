#ifndef AST_H
#define AST_H

#include "token.h"
#include <string>
#include <vector>
#include <memory>

// Node category for Typed AST (MAJOR CHANGE #2)
enum class ASTNodeType {
    LengthConstraint,
    CharacterConstraint,
    PatternConstraint,
    DictionaryConstraint,
    StrengthConstraint
};

// Base AST Node
struct ASTNode {
    ASTNodeType nodeType;
    SourcePos pos;

    ASTNode(ASTNodeType t, SourcePos p = SourcePos()) : nodeType(t), pos(p) {}
    virtual ~ASTNode() {}
    virtual std::string toString() const = 0;
};

// 1. Length Constraint Node (e.g. minLength 12, maxLength 32)
struct LengthConstraintNode : public ASTNode {
    std::string boundType; // "min" or "max"
    int length;

    LengthConstraintNode(std::string bound, int len, SourcePos p = SourcePos())
        : ASTNode(ASTNodeType::LengthConstraint, p), boundType(bound), length(len) {}

    std::string toString() const override {
        return "LengthConstraint[" + boundType + ": " + std::to_string(length) + "]";
    }
};

// 2. Character Constraint Node (e.g. require uppercase 1, require digit 2)
struct CharacterConstraintNode : public ASTNode {
    std::string charClass; // "uppercase", "lowercase", "digit", "special"
    int minCount;

    CharacterConstraintNode(std::string cls, int count, SourcePos p = SourcePos())
        : ASTNode(ASTNodeType::CharacterConstraint, p), charClass(cls), minCount(count) {}

    std::string toString() const override {
        return "CharacterConstraint[" + charClass + " >= " + std::to_string(minCount) + "]";
    }
};

// 3. Pattern Constraint Node (e.g. forbid spaces, forbid sequence 3, forbid repeated 3)
struct PatternConstraintNode : public ASTNode {
    std::string patternType; // "spaces", "sequence", "repeated"
    int threshold;          // e.g. 3 (or 1 for spaces)

    PatternConstraintNode(std::string pType, int thresh = 1, SourcePos p = SourcePos())
        : ASTNode(ASTNodeType::PatternConstraint, p), patternType(pType), threshold(thresh) {}

    std::string toString() const override {
        return "PatternConstraint[forbid " + patternType + (threshold > 1 ? " threshold: " + std::to_string(threshold) : "") + "]";
    }
};

// 4. Dictionary Constraint Node (e.g. blacklist "password", blacklist "admin")
struct DictionaryConstraintNode : public ASTNode {
    std::string blacklistedWord;

    DictionaryConstraintNode(std::string word, SourcePos p = SourcePos())
        : ASTNode(ASTNodeType::DictionaryConstraint, p), blacklistedWord(word) {}

    std::string toString() const override {
        return "DictionaryConstraint[blacklist: \"" + blacklistedWord + "\"]";
    }
};

// 5. Strength Constraint Node (e.g. strength minimum strong)
struct StrengthConstraintNode : public ASTNode {
    std::string minimumLevel; // "weak", "medium", "strong", "very strong"

    StrengthConstraintNode(std::string level, SourcePos p = SourcePos())
        : ASTNode(ASTNodeType::StrengthConstraint, p), minimumLevel(level) {}

    std::string toString() const override {
        return "StrengthConstraint[minLevel: " + minimumLevel + "]";
    }
};

// Typed Policy AST Root
struct PolicyAST {
    std::vector<std::shared_ptr<ASTNode>> nodes;

    void addNode(std::shared_ptr<ASTNode> node) {
        nodes.push_back(node);
    }
};

// Backward-compatible alias for existing code
typedef PolicyAST ProgramNode;

#endif
