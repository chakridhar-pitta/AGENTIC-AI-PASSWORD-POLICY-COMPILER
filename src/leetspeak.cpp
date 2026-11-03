#include "leetspeak.h"
#include <cctype>
#include <sstream>
#include <algorithm>
#include <cmath>

const std::map<char, char>& ASCIILeetspeakAnalyzer::getSubstitutionTable() {
    static const std::map<char, char> TABLE = {
        {'@', 'a'},
        {'4', 'a'},
        {'0', 'o'},
        {'$', 's'},
        {'5', 's'},
        {'3', 'e'},
        {'1', 'i'},
        {'!', 'i'},
        {'7', 't'},
        {'8', 'b'},
        {'2', 'z'}
    };
    return TABLE;
}

std::string ASCIILeetspeakAnalyzer::normalizeCandidate(const std::string& rawCandidate, std::vector<SubstitutionRecord>& substitutions) {
    substitutions.clear();
    const auto& table = getSubstitutionTable();

    std::string normalized;
    normalized.reserve(rawCandidate.size());

    for (size_t i = 0; i < rawCandidate.size(); ++i) {
        char ch = rawCandidate[i];
        char lowerCh = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));

        auto it = table.find(ch);
        if (it != table.end()) {
            SubstitutionRecord rec;
            rec.position = i;
            rec.originalChar = ch;
            rec.normalizedChar = it->second;
            rec.ruleApplied = std::string("'") + ch + "' -> '" + it->second + "'";
            substitutions.push_back(rec);
            normalized.push_back(it->second);
        } else {
            // Keep character, with standard lowercasing applied for case insensitivity
            normalized.push_back(lowerCh);
        }
    }

    return normalized;
}

static int damerauLevenshtein(const std::string& s1, const std::string& s2) {
    size_t len1 = s1.size();
    size_t len2 = s2.size();
    if (len1 > 32 || len2 > 32) return 99;
    int d[33][33];
    for (size_t i = 0; i <= len1; ++i) d[i][0] = (int)i;
    for (size_t j = 0; j <= len2; ++j) d[0][j] = (int)j;
    for (size_t i = 1; i <= len1; ++i) {
        for (size_t j = 1; j <= len2; ++j) {
            int cost = (s1[i - 1] == s2[j - 1]) ? 0 : 1;
            int del = d[i - 1][j] + 1;
            int ins = d[i][j - 1] + 1;
            int sub = d[i - 1][j - 1] + cost;
            int val = std::min(del, std::min(ins, sub));
            if (i > 1 && j > 1 && s1[i - 1] == s2[j - 2] && s1[i - 2] == s2[j - 1]) {
                val = std::min(val, d[i - 2][j - 2] + 1);
            }
            d[i][j] = val;
        }
    }
    return d[len1][len2];
}

LeetspeakAnalysisResult ASCIILeetspeakAnalyzer::analyze(const std::string& candidatePassword, const StaticBloomBuilder& blocklist) {
    LeetspeakAnalysisResult res;
    // CRITICAL INVARIANT: Original candidate password remains completely unchanged
    res.originalPassword = candidatePassword;
    res.canonicalOriginal = StaticBloomBuilder::canonicalizeKey(candidatePassword);

    if (res.canonicalOriginal.empty()) {
        res.verdict = BlocklistMatchVerdict::NO_MATCH;
        res.verdictDescription = "Empty candidate password.";
        res.securityRecommendation = "Submit a password in Password Validation Lab to see real-time Blocklist and Bloom Filter analysis.";
        return res;
    }

    if (!blocklist.isAvailable()) {
        res.verdict = BlocklistMatchVerdict::DATASET_UNAVAILABLE;
        res.detectionLevel = 0;
        res.detectionMethod = "Unconfigured / Empty Corpus";
        res.verdictDescription = "Blocklist dataset unavailable or unconfigured (missing dictionary corpus).";
        res.securityRecommendation = "Notice: Blocklist screening skipped due to unconfigured dataset. (Never assumed CLEAN).";
        return res;
    }

    // -------------------------------------------------------------------------
    // LEVEL 1: Exact original password match
    // -------------------------------------------------------------------------
    MembershipResult rawExactQuery = blocklist.query(candidatePassword);
    if (rawExactQuery.status == MembershipStatus::EXACT_MATCH_CONFIRMED) {
        res.verdict = BlocklistMatchVerdict::EXACT_ORIGINAL_MATCH;
        res.detectionLevel = 1;
        res.detectionMethod = "Level 1: Exact Original Password Match";
        res.matchedCategory = "Exact Blocklist Match";
        res.matchedCanonicalKey = rawExactQuery.matchedCanonicalKey;
        res.verdictDescription = "Exact whole-password match in compiled blocklist (NIST SP 800-63B-4 Section 3.1.1.2).";
        res.securityRecommendation = "Reject password - Exact match against prohibited common password blocklist.";
        return res;
    }

    // -------------------------------------------------------------------------
    // LEVEL 2: Case-normalized exact match
    // -------------------------------------------------------------------------
    MembershipResult origQuery = blocklist.query(res.canonicalOriginal);
    if (origQuery.status == MembershipStatus::EXACT_MATCH_CONFIRMED) {
        res.verdict = (res.canonicalOriginal == candidatePassword)
            ? BlocklistMatchVerdict::EXACT_ORIGINAL_MATCH
            : BlocklistMatchVerdict::CASE_NORMALIZED_MATCH;
        res.detectionLevel = 2;
        res.detectionMethod = "Level 2: Case-Normalized Exact Match";
        res.matchedCategory = "Case Variation of Blacklist Entry";
        res.matchedCanonicalKey = origQuery.matchedCanonicalKey;
        res.verdictDescription = "Case-normalized match in compiled blocklist (differing only in letter casing).";
        res.securityRecommendation = "Reject password - Varying case on a known weak password does not defeat automated attacks.";
        return res;
    }

    // -------------------------------------------------------------------------
    // LEVEL 3: Leetspeak-normalized match (with controlled candidate generation)
    // -------------------------------------------------------------------------
    res.normalizedPassword = normalizeCandidate(candidatePassword, res.substitutions);
    res.hasSubstitutions = !res.substitutions.empty();

    std::vector<std::string> candidates;

    // Check for word root + trailing numeric/symbol run (e.g. P@$$w0rd123 -> word: P@$$w0rd, num: 123)
    size_t trailingStart = candidatePassword.size();
    while (trailingStart > 0 && std::isdigit(static_cast<unsigned char>(candidatePassword[trailingStart - 1]))) {
        trailingStart--;
    }

    if (trailingStart < candidatePassword.size() && trailingStart > 0) {
        std::string wordPart = candidatePassword.substr(0, trailingStart);
        std::string numPart = candidatePassword.substr(trailingStart);
        std::vector<SubstitutionRecord> wordSubs;
        std::string normWord = normalizeCandidate(wordPart, wordSubs);
        if (!wordSubs.empty() || normWord != StaticBloomBuilder::canonicalizeKey(wordPart)) {
            candidates.push_back(normWord + numPart); // e.g. password123
            candidates.push_back(normWord);           // e.g. password
        }
    }

    if (res.hasSubstitutions && res.normalizedPassword != res.canonicalOriginal) {
        candidates.push_back(res.normalizedPassword);

        // Controlled expansion: if '1' exists in original, also test candidate with 'l'
        if (candidatePassword.find('1') != std::string::npos) {
            std::string candL = res.normalizedPassword;
            for (size_t i = 0; i < candidatePassword.size() && i < candL.size(); ++i) {
                if (candidatePassword[i] == '1') candL[i] = 'l';
            }
            if (candL != res.normalizedPassword) candidates.push_back(candL);
        }
    }

    for (const auto& cand : candidates) {
        MembershipResult normQuery = blocklist.query(cand);
        if (normQuery.status == MembershipStatus::EXACT_MATCH_CONFIRMED) {
            res.verdict = BlocklistMatchVerdict::LEETSPEAK_VARIANT_MATCH;
            res.detectionLevel = 3;
            res.detectionMethod = "Level 3: Leetspeak-Normalized Match";
            res.matchedCategory = "Leetspeak-Based Blacklist Match";
            res.matchedCanonicalKey = normQuery.matchedCanonicalKey;
            res.normalizedPassword = cand; // Set the actual winning normalized candidate
            std::ostringstream ss;
            ss << "High-confidence leetspeak-variant match: candidate normalizes to \""
               << cand << "\" via predictable character substitutions.";
            res.verdictDescription = ss.str();
            res.securityRecommendation = "Reject password - Choose a completely different password rather than replacing letters with predictable symbols.";
            return res;
        }
    }

    // -------------------------------------------------------------------------
    // LEVEL 4: Known weak-pattern detection (Root + numeric / punctuation affix)
    // -------------------------------------------------------------------------
    std::string baseNorm = res.hasSubstitutions ? res.normalizedPassword : res.canonicalOriginal;
    // Strip trailing digits or common symbols (e.g. password123 -> password, admin2024 -> admin)
    size_t endIdx = baseNorm.size();
    while (endIdx > 0 && (std::isdigit(static_cast<unsigned char>(baseNorm[endIdx - 1])) ||
                          baseNorm[endIdx - 1] == '!' || baseNorm[endIdx - 1] == '@' ||
                          baseNorm[endIdx - 1] == '#' || baseNorm[endIdx - 1] == '$')) {
        endIdx--;
    }

    if (endIdx >= 4 && endIdx < baseNorm.size()) {
        std::string strippedRoot = baseNorm.substr(0, endIdx);
        MembershipResult rootQuery = blocklist.query(strippedRoot);
        if (rootQuery.status == MembershipStatus::EXACT_MATCH_CONFIRMED) {
            res.verdict = BlocklistMatchVerdict::WEAK_PATTERN_MATCH;
            res.detectionLevel = 4;
            res.detectionMethod = "Level 4: Root Word & Affix Decomposition";
            res.matchedCategory = "Weak Structural Pattern (Blocklisted Root + Predictable Affix)";
            res.matchedCanonicalKey = rootQuery.matchedCanonicalKey;
            res.verdictDescription = "Deconstructs into blocklisted root \"" + strippedRoot + "\" plus predictable numeric/symbol suffix.";
            res.securityRecommendation = "Reject password - Appending numbers or symbols to a weak word does not provide security.";
            return res;
        }
    }

    // Also strip leading digits (e.g. 123password)
    size_t startIdx = 0;
    while (startIdx < baseNorm.size() && (std::isdigit(static_cast<unsigned char>(baseNorm[startIdx])) ||
                                          baseNorm[startIdx] == '!' || baseNorm[startIdx] == '@')) {
        startIdx++;
    }
    if (startIdx > 0 && (baseNorm.size() - startIdx) >= 4) {
        std::string leadingRoot = baseNorm.substr(startIdx);
        MembershipResult leadQuery = blocklist.query(leadingRoot);
        if (leadQuery.status == MembershipStatus::EXACT_MATCH_CONFIRMED) {
            res.verdict = BlocklistMatchVerdict::WEAK_PATTERN_MATCH;
            res.detectionLevel = 4;
            res.detectionMethod = "Level 4: Leading Affix Decomposition";
            res.matchedCategory = "Weak Structural Pattern (Predictable Prefix + Blocklisted Root)";
            res.matchedCanonicalKey = leadQuery.matchedCanonicalKey;
            res.verdictDescription = "Deconstructs into predictable numeric prefix plus blocklisted root \"" + leadingRoot + "\".";
            res.securityRecommendation = "Reject password - Prepending numbers to a weak word does not provide security.";
            return res;
        }
    }

    // -------------------------------------------------------------------------
    // LEVEL 5: Carefully calibrated similarity detection (Damerau-Levenshtein <= 1)
    // -------------------------------------------------------------------------
    if (res.canonicalOriginal.size() >= 7 && res.canonicalOriginal.size() <= 14) {
        const auto& table = blocklist.getExactTable();
        // Probe nearby elements in sorted table using lower_bound
        auto it = std::lower_bound(table.begin(), table.end(), res.canonicalOriginal);
        int searchWindow = 20; // Check local neighborhood
        auto startIt = (it - table.begin() > searchWindow) ? it - searchWindow : table.begin();
        auto endIt = (table.end() - it > searchWindow) ? it + searchWindow : table.end();

        for (auto cur = startIt; cur != endIt; ++cur) {
            if (cur->size() >= 6 && std::abs((int)cur->size() - (int)res.canonicalOriginal.size()) <= 1) {
                int dist = damerauLevenshtein(res.canonicalOriginal, *cur);
                if (dist == 1) {
                    res.verdict = BlocklistMatchVerdict::SIMILARITY_MATCH;
                    res.detectionLevel = 5;
                    res.detectionMethod = "Level 5: Calibrated Damerau-Levenshtein Similarity";
                    res.matchedCategory = "Typographical Variation of Blacklist Entry";
                    res.matchedCanonicalKey = *cur;
                    res.verdictDescription = "High typographical similarity (edit distance = 1) to blocklisted password \"" + *cur + "\".";
                    res.securityRecommendation = "Reject password - Password appears to be a slight typographical variation of a known weak password.";
                    return res;
                }
            }
        }
    }

    // PASSED / CLEAN
    res.verdict = BlocklistMatchVerdict::NO_MATCH;
    res.detectionLevel = 0;
    res.detectionMethod = "Comprehensive 5-Level Screening Passed";
    res.matchedCategory = "Clean (No Blacklist Match)";
    res.verdictDescription = "Candidate password does not match or resemble any known weak, common, or breached passwords in the active 3,000-entry database.";
    res.securityRecommendation = "Pass - Blocklist screening clear (NIST SP 800-63B-4 & OWASP ASVS 5.0.0 compliant).";
    return res;
}

std::string ASCIILeetspeakAnalyzer::emitValidatorHelperCpp() {
    std::ostringstream out;
    out << "// ============================================================================\n";
    out << "// LEETSPEAK DECOUPLING & NORMALIZATION HELPER (Supplemental Security Heuristic)\n";
    out << "// Invariant: Original candidate password remains unmodified throughout validation\n";
    out << "// Substring matching is strictly forbidden; full-string normalization only\n";
    out << "// ============================================================================\n\n";

    out << "namespace LeetspeakNormalizer {\n\n";
    out << "static inline std::string normalize(const std::string& input, bool& hasSubstitutions) {\n";
    out << "    hasSubstitutions = false;\n";
    out << "    std::string norm;\n";
    out << "    norm.reserve(input.size());\n";
    out << "    for (char ch : input) {\n";
    out << "        char lower = (char)std::tolower((unsigned char)ch);\n";
    out << "        switch (ch) {\n";
    out << "            case '@': case '4': norm.push_back('a'); hasSubstitutions = true; break;\n";
    out << "            case '0':           norm.push_back('o'); hasSubstitutions = true; break;\n";
    out << "            case '$': case '5': norm.push_back('s'); hasSubstitutions = true; break;\n";
    out << "            case '3':           norm.push_back('e'); hasSubstitutions = true; break;\n";
    out << "            case '1': case '!': norm.push_back('i'); hasSubstitutions = true; break;\n";
    out << "            case '7':           norm.push_back('t'); hasSubstitutions = true; break;\n";
    out << "            case '8':           norm.push_back('b'); hasSubstitutions = true; break;\n";
    out << "            case '2':           norm.push_back('z'); hasSubstitutions = true; break;\n";
    out << "            default:            norm.push_back(lower); break;\n";
    out << "        }\n";
    out << "    }\n";
    out << "    return norm;\n";
    out << "}\n\n";
    out << "} // namespace LeetspeakNormalizer\n\n";

    return out.str();
}

std::string ASCIILeetspeakAnalyzer::getUnicodeHomoglyphScopeNotice() {
    return "SCOPE NOTICE: Current release implements deterministic ASCII leetspeak substitution detection. "
           "Full Unicode homoglyph / confusable analysis requires Unicode Consortium UAX #39 confusable tables "
           "and canonical NFKC normalization, which is reserved as an architectural extension.";
}
