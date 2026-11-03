#ifndef NEURO_SYMBOLIC_H
#define NEURO_SYMBOLIC_H

#include "semantic.h"
#include <string>
#include <vector>
#include <set>
#include <iostream>

struct CharComposition {
    int uppercase;
    int lowercase;
    int digits;
    int special;
    int spaces;
    int length;
    int uniqueChars;

    CharComposition()
        : uppercase(0), lowercase(0), digits(0), special(0),
          spaces(0), length(0), uniqueChars(0) {}
};

struct PatternFindings {
    std::vector<std::string> repeatedChars;
    std::vector<std::string> repeatedSubstrings;
    std::vector<std::string> sequentialChars;
    std::vector<std::string> simpleSequences;
    std::vector<std::string> keyboardPatterns;

    bool hasAny() const {
        return !repeatedChars.empty() || !repeatedSubstrings.empty() ||
               !sequentialChars.empty() || !simpleSequences.empty() ||
               !keyboardPatterns.empty();
    }
};

struct DictionaryCheckResult {
    bool isCompromised;
    std::string matchedWord;
    std::string matchCategory; // Common Password, Custom Dictionary, Breach Corpus, Leetspeak Variant
    int totalDictionaryTerms;
    bool isLeetspeakVariant;
    std::string normalizedForm;
    std::string blocklistStatus; // "ACTIVE", "UNAVAILABLE", "CLEAN"
    bool dslBlacklistViolated;
    std::string dslMatchedToken;

    DictionaryCheckResult()
        : isCompromised(false), totalDictionaryTerms(0), isLeetspeakVariant(false),
          blocklistStatus("UNAVAILABLE"), dslBlacklistViolated(false) {}
};

struct EntropyEstimate {
    double entropyBits;
    int poolSize;
    std::string strengthRating;
    std::string advisory;

    EntropyEstimate()
        : entropyBits(0.0), poolSize(0), strengthRating("None") {}
};

struct ProfessionalSecurityReport {
    int score; // 0 - 10
    std::string tier;
    CharComposition composition;
    PatternFindings patterns;
    DictionaryCheckResult dictionary;
    EntropyEstimate entropy;
    std::vector<std::string> advisoryNotes;

    ProfessionalSecurityReport() : score(0), tier("Unrated") {}

    void print() const;
};

// Legacy compatibility struct
struct NSResult {
    int score;
    std::string level;
    std::vector<std::string> reasons;
};

class NeuroSymbolicEvaluator {
public:
    // Core Professional Security Analysis Engine
    static ProfessionalSecurityReport analyzeSecurity(
        const std::string& password,
        const PolicyConstraints& c,
        const std::string& customDictPath = "dictionary.txt",
        const std::string& breachCorpusPath = ""
    );

    // Legacy method maintained for backward compatibility
    static NSResult evaluate(
        const std::string& password,
        const PolicyConstraints& c
    );
};

#endif // NEURO_SYMBOLIC_H
