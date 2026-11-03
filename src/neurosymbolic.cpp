#include "neurosymbolic.h"
#include "bloom_filter.h"
#include "leetspeak.h"
#include <cctype>
#include <cmath>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iomanip>

using namespace std;

static string toLowerStr(const string& s) {
    string r = s;
    for(char& ch : r) ch = (char)tolower((unsigned char)ch);
    return r;
}

ProfessionalSecurityReport NeuroSymbolicEvaluator::analyzeSecurity(
    const string& password,
    const PolicyConstraints& c,
    const string& customDictPath,
    const string& breachCorpusPath)
{
    ProfessionalSecurityReport rep;
    string pwdLower = toLowerStr(password);

    // ===============================================================
    // 1. CHARACTER COMPOSITION & LENGTH ANALYSIS
    // ===============================================================
    set<char> distinctChars;
    for(char ch : password) {
        distinctChars.insert(ch);
        if(isupper((unsigned char)ch)) rep.composition.uppercase++;
        else if(islower((unsigned char)ch)) rep.composition.lowercase++;
        else if(isdigit((unsigned char)ch)) rep.composition.digits++;
        else if(isspace((unsigned char)ch)) rep.composition.spaces++;
        else rep.composition.special++;
    }
    rep.composition.length = (int)password.size();
    rep.composition.uniqueChars = (int)distinctChars.size();

    // ===============================================================
    // 2. PATTERN DETECTION ENGINE
    // ===============================================================
    int len = (int)password.size();

    // A. Repeated Consecutive Characters (e.g. aaa, 111, @@@)
    for(int i = 0; i + 2 < len; i++) {
        if(password[i] == password[i+1] && password[i+1] == password[i+2]) {
            string r = password.substr(i, 3);
            if(find(rep.patterns.repeatedChars.begin(), rep.patterns.repeatedChars.end(), r) == rep.patterns.repeatedChars.end()) {
                rep.patterns.repeatedChars.push_back(r);
            }
        }
    }

    // B. Repeated Substrings (e.g. abcabc, passpass, 1212)
    for(int subLen = 2; subLen <= len / 2; subLen++) {
        for(int i = 0; i + 2 * subLen <= len; i++) {
            string s1 = pwdLower.substr(i, subLen);
            string s2 = pwdLower.substr(i + subLen, subLen);
            if(s1 == s2) {
                if(find(rep.patterns.repeatedSubstrings.begin(), rep.patterns.repeatedSubstrings.end(), s1) == rep.patterns.repeatedSubstrings.end()) {
                    rep.patterns.repeatedSubstrings.push_back(s1);
                }
            }
        }
    }

    // C. Sequential Characters (e.g. abc, cba, 123, 321)
    for(int i = 0; i + 2 < len; i++) {
        char c0 = pwdLower[i];
        char c1 = pwdLower[i+1];
        char c2 = pwdLower[i+2];

        if(c1 == c0 + 1 && c2 == c1 + 1) {
            string s = password.substr(i, 3);
            if(find(rep.patterns.sequentialChars.begin(), rep.patterns.sequentialChars.end(), s) == rep.patterns.sequentialChars.end()) {
                rep.patterns.sequentialChars.push_back(s);
            }
        }
        else if(c1 == c0 - 1 && c2 == c1 - 1) {
            string s = password.substr(i, 3);
            if(find(rep.patterns.sequentialChars.begin(), rep.patterns.sequentialChars.end(), s) == rep.patterns.sequentialChars.end()) {
                rep.patterns.sequentialChars.push_back(s);
            }
        }
    }

    // D. Simple Sequences (e.g. 012, 789, abc)
    static const vector<string> KNOWN_SEQUENCES = {
        "0123456789", "9876543210",
        "abcdefghijklmnopqrstuvwxyz", "zyxwvutsrqponmlkjihgfedcba"
    };

    for(const auto& seq : KNOWN_SEQUENCES) {
        for(size_t subLen = 3; subLen <= 6; subLen++) {
            for(size_t i = 0; i + subLen <= seq.size(); i++) {
                string sub = seq.substr(i, subLen);
                if(pwdLower.find(sub) != string::npos) {
                    if(find(rep.patterns.simpleSequences.begin(), rep.patterns.simpleSequences.end(), sub) == rep.patterns.simpleSequences.end()) {
                        rep.patterns.simpleSequences.push_back(sub);
                    }
                }
            }
        }
    }

    // E. Spatial Keyboard Walks (e.g. qwerty, asdf, zxcv, 1qaz)
    static const vector<string> KEYBOARD_ROWS = {
        "qwertyuiop", "asdfghjkl", "zxcvbnm",
        "poiuytrewq", "lkjhgfdsa", "mnbvcxz",
        "1234567890", "0987654321"
    };

    for(const auto& row : KEYBOARD_ROWS) {
        for(size_t i = 0; i + 3 <= row.size(); i++) {
            string walk = row.substr(i, 3);
            if(pwdLower.find(walk) != string::npos) {
                if(find(rep.patterns.keyboardPatterns.begin(), rep.patterns.keyboardPatterns.end(), walk) == rep.patterns.keyboardPatterns.end()) {
                    rep.patterns.keyboardPatterns.push_back(walk);
                }
            }
        }
    }

    // ===============================================================
    // 3. STANDARDS-ALIGNED BLOCKLIST SCREENING & LEETSPEAK ANALYSIS
    // (NIST SP 800-63B-4 Section 3.1.1.2 / OWASP ASVS 5.0.0 V6.2.8)
    // ===============================================================
    StaticBloomBuilder builder;
    builder.loadBuiltinCommon();
    if (!customDictPath.empty()) {
        builder.loadDictionaryFile(customDictPath);
    }
    if (!breachCorpusPath.empty()) {
        builder.loadBreachCorpusFile(breachCorpusPath);
    } else {
        if (!builder.loadBreachCorpusFile("data/breach_corpus.txt")) {
            if (!builder.loadBreachCorpusFile("breach_corpus.txt")) {
                builder.loadBreachCorpusFile("CODE/breach_corpus.txt");
            }
        }
    }
    builder.loadCuratedDatasets();

    bool built = builder.build();
    rep.dictionary.totalDictionaryTerms = (int)builder.getParameters().n;
    rep.dictionary.blocklistStatus = built ? "ACTIVE" : "UNAVAILABLE";

    if (!built) {
        rep.dictionary.isCompromised = false;
        rep.dictionary.matchCategory = "Blocklist Unavailable";
        rep.advisoryNotes.push_back("Notice: Password blocklist dataset unavailable or empty. (Not assumed clean).");
    } else {
        // Run decoupled leetspeak & whole-password analysis
        LeetspeakAnalysisResult leetRes = ASCIILeetspeakAnalyzer::analyze(password, builder);

        if (leetRes.verdict == BlocklistMatchVerdict::EXACT_ORIGINAL_MATCH) {
            rep.dictionary.isCompromised = true;
            rep.dictionary.matchedWord = leetRes.matchedCanonicalKey;
            rep.dictionary.matchCategory = "Exact Common Password Match (NIST SP 800-63B-4)";
            rep.advisoryNotes.push_back("Critical: Password exactly matches prohibited common/compromised password blocklist entry.");
        } else if (leetRes.verdict == BlocklistMatchVerdict::LEETSPEAK_VARIANT_MATCH) {
            rep.dictionary.isCompromised = true;
            rep.dictionary.isLeetspeakVariant = true;
            rep.dictionary.matchedWord = leetRes.matchedCanonicalKey;
            rep.dictionary.normalizedForm = leetRes.normalizedPassword;
            rep.dictionary.matchCategory = "Leetspeak Variant of Blocklisted Term";
            rep.advisoryNotes.push_back("Security finding: Candidate transforms into blocklisted term \"" +
                                        leetRes.normalizedPassword + "\" via predictable leetspeak substitutions.");
        } else {
            rep.dictionary.isCompromised = false;
            rep.dictionary.matchCategory = "Clean (No whole-password or leetspeak match)";
        }
    }

    // 4. Policy DSL Blacklist Check (Separate from NIST whole-password blocklist)
    for (const auto& bw : c.blacklist) {
        std::string bwLower = toLowerStr(bw);
        if (!bwLower.empty() && pwdLower.find(bwLower) != string::npos) {
            rep.dictionary.dslBlacklistViolated = true;
            rep.dictionary.dslMatchedToken = bw;
            rep.advisoryNotes.push_back("Policy violation: Contains explicit DSL blacklisted token: \"" + bw + "\".");
            break;
        }
    }

    // ===============================================================
    // 5. INFORMATION-THEORETIC ENTROPY ESTIMATE
    // ===============================================================
    int pool = 0;
    if(rep.composition.lowercase > 0) pool += 26;
    if(rep.composition.uppercase > 0) pool += 26;
    if(rep.composition.digits > 0)    pool += 10;
    if(rep.composition.special > 0)   pool += 33;
    if(rep.composition.spaces > 0)    pool += 1;
    if(pool == 0) pool = 1;

    rep.entropy.poolSize = pool;
    double rawEntropy = (double)len * (log((double)pool) / log(2.0));

    // Penalty deductions for patterns and dictionary matches
    double adjustedEntropy = rawEntropy;
    if(!rep.patterns.repeatedChars.empty()) adjustedEntropy -= 6.0;
    if(!rep.patterns.repeatedSubstrings.empty()) adjustedEntropy -= 8.0;
    if(!rep.patterns.sequentialChars.empty()) adjustedEntropy -= 5.0;
    if(!rep.patterns.simpleSequences.empty()) adjustedEntropy -= 5.0;
    if(!rep.patterns.keyboardPatterns.empty()) adjustedEntropy -= 8.0;
    if(rep.dictionary.isCompromised) adjustedEntropy -= 20.0;
    if(adjustedEntropy < 0.0) adjustedEntropy = 0.0;

    rep.entropy.entropyBits = adjustedEntropy;

    if(adjustedEntropy < 28.0) rep.entropy.strengthRating = "Very Weak (< 28 bits)";
    else if(adjustedEntropy < 45.0) rep.entropy.strengthRating = "Weak (28-44 bits)";
    else if(adjustedEntropy < 60.0) rep.entropy.strengthRating = "Moderate (45-59 bits)";
    else if(adjustedEntropy < 80.0) rep.entropy.strengthRating = "Strong (60-79 bits)";
    else rep.entropy.strengthRating = "Very Strong (>= 80 bits)";

    rep.entropy.advisory = "Estimated entropy is a theoretical measure of keyspace search complexity (L * log2(R)), not an absolute guarantee of password security.";

    // ===============================================================
    // 6. OVERALL SECURITY SCORING & ADVISORY NOTES
    // ===============================================================
    int score = 0;

    // Length contribution
    if(len >= 16) score += 3;
    else if(len >= 12) score += 2;
    else if(len >= 8) score += 1;
    else score -= 1;

    // Diversity contribution
    int classes = (rep.composition.lowercase > 0) + (rep.composition.uppercase > 0) +
                  (rep.composition.digits > 0) + (rep.composition.special > 0);
    score += classes;

    // Entropy contribution
    if(adjustedEntropy >= 75.0) score += 3;
    else if(adjustedEntropy >= 55.0) score += 2;
    else if(adjustedEntropy >= 35.0) score += 1;

    // Penalties
    if(!rep.patterns.repeatedChars.empty()) {
        score -= 2;
        rep.advisoryNotes.push_back("Repeated consecutive characters detected");
    }
    if(!rep.patterns.repeatedSubstrings.empty()) {
        score -= 2;
        rep.advisoryNotes.push_back("Repeated substrings detected (reduce redundancy)");
    }
    if(!rep.patterns.sequentialChars.empty() || !rep.patterns.simpleSequences.empty()) {
        score -= 2;
        rep.advisoryNotes.push_back("Sequential character/numeric sequences detected");
    }
    if(!rep.patterns.keyboardPatterns.empty()) {
        score -= 2;
        rep.advisoryNotes.push_back("Predictable keyboard-walk patterns detected");
    }
    if(rep.dictionary.isCompromised) {
        score = 0;
        rep.advisoryNotes.push_back("Compromised: matches blocklist entry '" + rep.dictionary.matchedWord + "'");
    }
    if(rep.dictionary.dslBlacklistViolated) {
        score = 0;
        rep.advisoryNotes.push_back("Violates explicit DSL policy blacklist: '" + rep.dictionary.dslMatchedToken + "'");
    }

    if(score < 0) score = 0;
    if(score > 10) score = 10;
    rep.score = score;

    if(score <= 2) rep.tier = "Very Weak";
    else if(score <= 4) rep.tier = "Weak";
    else if(score <= 7) rep.tier = "Medium";
    else if(score <= 9) rep.tier = "Strong";
    else rep.tier = "Very Strong";

    return rep;
}

NSResult NeuroSymbolicEvaluator::evaluate(const string& password, const PolicyConstraints& c)
{
    ProfessionalSecurityReport rep = analyzeSecurity(password, c);
    return {rep.score, rep.tier, rep.advisoryNotes};
}

void ProfessionalSecurityReport::print() const {
    cout << "\n===============================================================\n";
    cout << "  COMPREHENSIVE PASSWORD SECURITY ANALYSIS REPORT\n";
    cout << "===============================================================\n";

    cout << "Character composition:\n";
    cout << "Uppercase : " << composition.uppercase << "\n";
    cout << "Lowercase : " << composition.lowercase << "\n";
    cout << "Digits    : " << composition.digits << "\n";
    cout << "Special   : " << composition.special << "\n";

    cout << "\nLength:\n";
    cout << "Length : " << composition.length << " (Unique characters: " << composition.uniqueChars << ")\n";

    cout << "\nPatterns:\n";
    cout << "- repeated characters : ";
    if(patterns.repeatedChars.empty()) cout << "None\n";
    else {
        for(size_t i = 0; i < patterns.repeatedChars.size(); i++) {
            cout << "'" << patterns.repeatedChars[i] << "'" << (i + 1 < patterns.repeatedChars.size() ? ", " : "\n");
        }
    }

    cout << "- repeated substrings : ";
    if(patterns.repeatedSubstrings.empty()) cout << "None\n";
    else {
        for(size_t i = 0; i < patterns.repeatedSubstrings.size(); i++) {
            cout << "'" << patterns.repeatedSubstrings[i] << "'" << (i + 1 < patterns.repeatedSubstrings.size() ? ", " : "\n");
        }
    }

    cout << "- sequential chars    : ";
    if(patterns.sequentialChars.empty()) cout << "None\n";
    else {
        for(size_t i = 0; i < patterns.sequentialChars.size(); i++) {
            cout << "'" << patterns.sequentialChars[i] << "'" << (i + 1 < patterns.sequentialChars.size() ? ", " : "\n");
        }
    }

    cout << "- simple sequences    : ";
    if(patterns.simpleSequences.empty()) cout << "None\n";
    else {
        for(size_t i = 0; i < patterns.simpleSequences.size(); i++) {
            cout << "'" << patterns.simpleSequences[i] << "'" << (i + 1 < patterns.simpleSequences.size() ? ", " : "\n");
        }
    }

    cout << "- keyboard patterns   : ";
    if(patterns.keyboardPatterns.empty()) cout << "None\n";
    else {
        for(size_t i = 0; i < patterns.keyboardPatterns.size(); i++) {
            cout << "'" << patterns.keyboardPatterns[i] << "'" << (i + 1 < patterns.keyboardPatterns.size() ? ", " : "\n");
        }
    }

    cout << "\nBlocklist & Security Screening (NIST SP 800-63B-4):\n";
    if (dictionary.blocklistStatus == "UNAVAILABLE") {
        cout << "  Status : UNAVAILABLE / NOT CHECKED (Dataset unconfigured or empty)\n";
    } else if (!dictionary.isCompromised) {
        cout << "  Status : Clean (Screened against " << dictionary.totalDictionaryTerms << " unique keys via Static Bloom Filter + Exact Table)\n";
    } else {
        cout << "  Status : COMPROMISED (" << dictionary.matchCategory << " -> '" << dictionary.matchedWord << "'";
        if (dictionary.isLeetspeakVariant) {
            cout << ", Normalized Candidate: '" << dictionary.normalizedForm << "'";
        }
        cout << ")\n";
    }

    if (dictionary.dslBlacklistViolated) {
        cout << "  Policy DSL Blacklist: VIOLATION (Contains forbidden token -> '" << dictionary.dslMatchedToken << "')\n";
    }

    cout << "\nEntropy estimate:\n";
    cout << "  Estimated Entropy   : " << fixed << setprecision(1) << entropy.entropyBits << " bits (" << entropy.strengthRating << ")\n";
    cout << "  Character Pool Size : " << entropy.poolSize << "\n";
    cout << "  Advisory            : " << entropy.advisory << "\n";

    cout << "\nOverall Evaluation:\n";
    cout << "  Security Score      : " << score << " / 10\n";
    cout << "  Strength Tier       : " << tier << "\n";

    if(!advisoryNotes.empty()) {
        cout << "  Advisory Notes:\n";
        for(const auto& note : advisoryNotes) {
            cout << "    - " << note << "\n";
        }
    }
    cout << "===============================================================\n";
}
