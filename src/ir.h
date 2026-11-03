#ifndef IR_H
#define IR_H

#include "semantic.h"
#include <vector>
#include <string>

// Sub-IR Module 1: Length Constraints
struct LengthIR {
    int minLength;
    int maxLength;
    LengthIR() : minLength(-1), maxLength(-1) {}
};

// Sub-IR Module 2: Character Class Constraints
struct CharacterClassIR {
    int minUpper;
    int minLower;
    int minDigit;
    int minSpecial;
    bool requireUpper;
    bool requireLower;
    bool requireDigit;
    bool requireSpecial;

    CharacterClassIR()
        : minUpper(0), minLower(0), minDigit(0), minSpecial(0),
          requireUpper(false), requireLower(false), requireDigit(false), requireSpecial(false) {}
};

// Sub-IR Module 3: Pattern Restrictions
struct PatternIR {
    bool forbidSpaces;
    int sequenceLimit;
    int repetitionLimit;

    PatternIR() : forbidSpaces(false), sequenceLimit(-1), repetitionLimit(-1) {}
};

// Sub-IR Module 4: Dictionary & Strength Requirements
struct SecurityIR {
    std::vector<std::string> blacklist;
    std::string strengthRequirement;

    SecurityIR() : strengthRequirement("none") {}
};

// Policy Intermediate Representation (Modular Policy IR 2.0)
struct PolicyIR {
    // Modular components
    LengthIR length;
    CharacterClassIR charClass;
    PatternIR pattern;
    SecurityIR security;

    // Direct named properties matching exact project specification
    int minLength;
    int maxLength;
    int uppercaseRequired;
    int lowercaseRequired;
    int minDigits;
    int minSpecial;
    bool forbidSpaces;
    int sequenceLimit;
    int repetitionLimit;
    std::vector<std::string> blacklist;
    std::string strengthRequirement;

    // Backward-compatible accessors
    bool requireUpper;
    bool requireLower;
    bool requireDigit;
    bool requireSpecial;
    bool noSpaces;
    int minUpper;
    int minLower;
    int minDigit;
    int maxSequence;
    int maxRepeated;
    std::string minStrength;

    PolicyIR();
    void syncFields();
};

PolicyIR buildIR(const PolicyConstraints& c);

#endif
