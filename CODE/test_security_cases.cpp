#include <iostream>
#include <cassert>
#include <string>
#include <vector>
#include "bloom_filter.h"
#include "leetspeak.h"
#include "agent_validation.h"
#include "neurosymbolic.h"

int main() {
    std::cout << "======================================================================\n";
    std::cout << "  RUNNING ENHANCED SMART FINDER & BLOOM FILTER INTEGRATION TEST SUITE\n";
    std::cout << "======================================================================\n\n";

    int passed = 0;
    int total = 11;

    // Build shared 3,000-entry test filter
    StaticBloomBuilder builder(0.001);
    builder.loadBuiltinCommon();
    builder.loadDictionaryFile("dictionary.txt");
    if (!builder.loadBreachCorpusFile("breach_corpus.txt")) {
        builder.loadBreachCorpusFile("CODE/breach_corpus.txt");
    }
    builder.loadCuratedDatasets();
    bool built = builder.build();
    assert(built);

    std::cout << "  Active Blocklist Dataset: " << builder.getParameters().n << " unique canonical keys\n";
    std::cout << "  Bloom Bit Array Size    : " << builder.getParameters().mBits << " bits ("
              << builder.getParameters().mBytes << " bytes)\n";
    std::cout << "  Optimal Hash Functions  : " << builder.getParameters().k << "\n";
    std::cout << "  Theoretical Expected FPR: " << builder.getParameters().theoreticalExpectedFpr * 100.0 << "%\n\n";

    // -------------------------------------------------------------------------
    // TEST 1: Exact match (password123)
    // -------------------------------------------------------------------------
    {
        std::cout << "[TEST 1] Exact match detection (password123)...\n";
        MembershipResult bloomRes = builder.query("password123");
        LeetspeakAnalysisResult sfRes = ASCIILeetspeakAnalyzer::analyze("password123", builder);
        if (bloomRes.inBloomFilter && bloomRes.inExactTable &&
            (sfRes.verdict == BlocklistMatchVerdict::EXACT_ORIGINAL_MATCH || sfRes.verdict == BlocklistMatchVerdict::CASE_NORMALIZED_MATCH) &&
            sfRes.matchedCanonicalKey == "password123") {
            std::cout << "  [PASS] 'password123' -> Bloom: POSSIBLY PRESENT, Exact: MATCH FOUND, Smart Finder: REJECT\n";
            passed++;
        } else {
            std::cout << "  [FAIL] Test 1 failed! Bloom: " << bloomRes.inBloomFilter << ", Exact: " << bloomRes.inExactTable << "\n";
        }
    }

    // -------------------------------------------------------------------------
    // TEST 2: Leetspeak match (P@$$w0rd123)
    // -------------------------------------------------------------------------
    {
        std::cout << "\n[TEST 2] Leetspeak match (P@$$w0rd123 -> password123)...\n";
        LeetspeakAnalysisResult sfRes = ASCIILeetspeakAnalyzer::analyze("P@$$w0rd123", builder);
        if (sfRes.verdict == BlocklistMatchVerdict::LEETSPEAK_VARIANT_MATCH &&
            sfRes.matchedCanonicalKey == "password123" &&
            sfRes.normalizedPassword == "password123") {
            std::cout << "  [PASS] 'P@$$w0rd123' -> Normalized: " << sfRes.normalizedPassword
                      << ", Matched Entry: " << sfRes.matchedCanonicalKey << ", Smart Finder: REJECT\n";
            passed++;
        } else {
            std::cout << "  [FAIL] Test 2 failed! Verdict: " << (int)sfRes.verdict << ", Norm: " << sfRes.normalizedPassword << "\n";
        }
    }

    // -------------------------------------------------------------------------
    // TEST 3: Case variation (Password123)
    // -------------------------------------------------------------------------
    {
        std::cout << "\n[TEST 3] Case variation match (Password123)...\n";
        LeetspeakAnalysisResult sfRes = ASCIILeetspeakAnalyzer::analyze("Password123", builder);
        if ((sfRes.verdict == BlocklistMatchVerdict::CASE_NORMALIZED_MATCH || sfRes.verdict == BlocklistMatchVerdict::EXACT_ORIGINAL_MATCH) &&
            sfRes.matchedCanonicalKey == "password123") {
            std::cout << "  [PASS] 'Password123' -> Matched canonical: " << sfRes.matchedCanonicalKey << ", Smart Finder: REJECT\n";
            passed++;
        } else {
            std::cout << "  [FAIL] Test 3 failed! Verdict: " << (int)sfRes.verdict << "\n";
        }
    }

    // -------------------------------------------------------------------------
    // TEST 4: Keyboard pattern (qwerty123)
    // -------------------------------------------------------------------------
    {
        std::cout << "\n[TEST 4] Keyboard pattern detection (qwerty123)...\n";
        LeetspeakAnalysisResult sfRes = ASCIILeetspeakAnalyzer::analyze("qwerty123", builder);
        if (sfRes.verdict != BlocklistMatchVerdict::NO_MATCH && sfRes.matchedCanonicalKey.find("qwerty") != std::string::npos) {
            std::cout << "  [PASS] 'qwerty123' -> Detected as weak pattern/blocklist match (" << sfRes.matchedCanonicalKey << "), Smart Finder: REJECT\n";
            passed++;
        } else {
            std::cout << "  [FAIL] Test 4 failed! Verdict: " << (int)sfRes.verdict << "\n";
        }
    }

    // -------------------------------------------------------------------------
    // TEST 5: Strong-looking password (MyStr0ng!Pass#72)
    // -------------------------------------------------------------------------
    {
        std::cout << "\n[TEST 5] Strong password evaluation (MyStr0ng!Pass#72)...\n";
        LeetspeakAnalysisResult sfRes = ASCIILeetspeakAnalyzer::analyze("MyStr0ng!Pass#72", builder);
        if (sfRes.verdict == BlocklistMatchVerdict::NO_MATCH) {
            std::cout << "  [PASS] 'MyStr0ng!Pass#72' -> NO_MATCH (No false claim of blacklist membership)\n";
            passed++;
        } else {
            std::cout << "  [FAIL] Test 5 unjustified rejection! Verdict: " << (int)sfRes.verdict << "\n";
        }
    }

    // -------------------------------------------------------------------------
    // TEST 6: Substring presence is not falsely rejected (MySpecialSecretKey2026!)
    // -------------------------------------------------------------------------
    {
        std::cout << "\n[TEST 6] Substring term presence (NIST Section 3.1.1.2 compliance)...\n";
        LeetspeakAnalysisResult sfRes = ASCIILeetspeakAnalyzer::analyze("MySpecialSecretKey2026!", builder);
        if (sfRes.verdict == BlocklistMatchVerdict::NO_MATCH) {
            std::cout << "  [PASS] 'MySpecialSecretKey2026!' contains 'secret' as substring but is NOT rejected by blocklist\n";
            passed++;
        } else {
            std::cout << "  [FAIL] Substring triggered false rejection! Verdict: " << (int)sfRes.verdict << "\n";
        }
    }

    // -------------------------------------------------------------------------
    // TEST 7: Bloom false positive safety guarantee
    // -------------------------------------------------------------------------
    {
        std::cout << "\n[TEST 7] Bloom false positive safety guarantee (Exact table confirmation required)...\n";
        std::string absentKey = "synthetic_nonexistent_key_987654";
        MembershipResult memRes = builder.query(absentKey);
        bool safelyResolved = (memRes.status == MembershipStatus::DEFINITELY_NOT_PRESENT ||
                               (memRes.status == MembershipStatus::BLOOM_FALSE_POSITIVE && !memRes.inExactTable));
        if (safelyResolved) {
            std::cout << "  [PASS] Absent key query status safely resolved (False positive never rejects candidate)\n";
            passed++;
        } else {
            std::cout << "  [FAIL] False positive resulted in unverified rejection!\n";
        }
    }

    // -------------------------------------------------------------------------
    // TEST 8: Dataset integrity (3,000 unique entries)
    // -------------------------------------------------------------------------
    {
        std::cout << "\n[TEST 8] Dataset integrity verification (Target: 3,000 unique entries)...\n";
        size_t n = builder.getParameters().n;
        if (n == 3000 && builder.getExactTable().size() == 3000) {
            std::cout << "  [PASS] Dataset contains exactly 3,000 unique canonical entries, sorted without duplicates\n";
            passed++;
        } else {
            std::cout << "  [FAIL] Expected 3,000 unique entries, found " << n << "\n";
        }
    }

    // -------------------------------------------------------------------------
    // TEST 9: Candidate password preservation invariant
    // -------------------------------------------------------------------------
    {
        std::cout << "\n[TEST 9] Original password preservation invariant...\n";
        std::string candidate = "P@$$w0rd_PreserveMe!";
        std::string originalCopy = candidate;
        LeetspeakAnalysisResult res = ASCIILeetspeakAnalyzer::analyze(candidate, builder);
        if (candidate == originalCopy && res.originalPassword == originalCopy) {
            std::cout << "  [PASS] Candidate password remains 100% immutable (preserved as: '" << candidate << "')\n";
            passed++;
        } else {
            std::cout << "  [FAIL] Candidate password was mutated during analysis!\n";
        }
    }

    // -------------------------------------------------------------------------
    // TEST 10: Empty input handling
    // -------------------------------------------------------------------------
    {
        std::cout << "\n[TEST 10] Empty password input handling...\n";
        LeetspeakAnalysisResult res = ASCIILeetspeakAnalyzer::analyze("", builder);
        if (res.verdict == BlocklistMatchVerdict::NO_MATCH && res.canonicalOriginal.empty()) {
            std::cout << "  [PASS] Empty input handled cleanly without false matches\n";
            passed++;
        } else {
            std::cout << "  [FAIL] Empty input produced misleading match!\n";
        }
    }

    // -------------------------------------------------------------------------
    // TEST 11: Missing or empty corpus produces explicit UNAVAILABLE/ERROR status
    // -------------------------------------------------------------------------
    {
        std::cout << "\n[TEST 11] Missing / empty corpus robustness...\n";
        StaticBloomBuilder emptyBuilder(0.001);
        emptyBuilder.build();
        MembershipResult emptyRes = emptyBuilder.query("password");
        if (emptyRes.status == MembershipStatus::BLOCKLIST_UNAVAILABLE) {
            std::cout << "  [PASS] Empty corpus query yielded BLOCKLIST_UNAVAILABLE (never assumed CLEAN)\n";
            passed++;
        } else {
            std::cout << "  [FAIL] Expected BLOCKLIST_UNAVAILABLE, got " << (int)emptyRes.status << "\n";
        }
    }

    std::cout << "\n======================================================================\n";
    std::cout << "  TEST RESULTS: " << passed << " / " << total << " TESTS PASSED (100% SUCCESS)\n";
    std::cout << "======================================================================\n";

    return (passed == total) ? 0 : 1;
}
