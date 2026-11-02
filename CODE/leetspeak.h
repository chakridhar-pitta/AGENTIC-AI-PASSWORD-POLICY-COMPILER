#ifndef LEETSPEAK_H
#define LEETSPEAK_H

#include <string>
#include <vector>
#include <map>
#include <iostream>
#include "bloom_filter.h"

// Record of an individual character substitution
struct SubstitutionRecord {
    size_t position;
    char originalChar;
    char normalizedChar;
    std::string ruleApplied;
};

// Distinct Security Classification Verdict
enum class BlocklistMatchVerdict {
    NO_MATCH,                   // Candidate is not in blocklist and does not match weak patterns
    EXACT_ORIGINAL_MATCH,       // Level 1: Canonical original candidate matches exact blocklist entry
    CASE_NORMALIZED_MATCH,      // Level 2: Case-insensitive normalized candidate matches exact entry
    LEETSPEAK_VARIANT_MATCH,    // Level 3: Controlled normalized candidate matches blocklist entry
    WEAK_PATTERN_MATCH,         // Level 4: Known weak root + trailing/leading numbers/symbols pattern
    SIMILARITY_MATCH,           // Level 5: High-probability typo/transposition of weak root
    DATASET_UNAVAILABLE         // Blocklist corpus missing or empty
};

// Analysis Output Container (Original candidate preserved unmodified)
struct LeetspeakAnalysisResult {
    std::string originalPassword;      // CONST / UNTOUCHED candidate password
    std::string canonicalOriginal;     // Lowercased, whitespace-trimmed original
    std::string normalizedPassword;    // Separate representation with ASCII leetspeak normalized
    std::vector<SubstitutionRecord> substitutions;
    bool hasSubstitutions = false;
    BlocklistMatchVerdict verdict = BlocklistMatchVerdict::NO_MATCH;
    int detectionLevel = 0;
    std::string detectionMethod;
    std::string matchedCategory;
    std::string matchedCanonicalKey;
    std::string verdictDescription;
    std::string securityRecommendation;
};

class ASCIILeetspeakAnalyzer {
public:
    // Normalizes candidate string into separate representation without modifying original
    static LeetspeakAnalysisResult analyze(const std::string& candidatePassword, const StaticBloomBuilder& blocklist);

    // Static normalization helper (returns normalized string & logs substitutions)
    static std::string normalizeCandidate(const std::string& rawCandidate, std::vector<SubstitutionRecord>& substitutions);

    // Standalone source code emission for target validator
    static std::string emitValidatorHelperCpp();

    // Mapping table documentation & accessor
    static const std::map<char, char>& getSubstitutionTable();

    // Unicode homoglyph scope note (NIST / ASVS compliance clarity)
    static std::string getUnicodeHomoglyphScopeNotice();
};

#endif // LEETSPEAK_H

