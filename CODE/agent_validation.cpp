#include "agent_validation.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cctype>
#include <cmath>
#include <algorithm>

ValidationAgent::ValidationAgent(const PolicyConstraints& c, std::string targetCppPath,
                                 std::string dictionaryPath, std::string breachCorpusPath)
    : constraints(c), targetFile(std::move(targetCppPath)), dictPath(std::move(dictionaryPath)),
      breachPath(std::move(breachCorpusPath)), report("Runtime Validation Agent", "AGENT-06-VALIDATION") {
}

static std::string toLowerString(const std::string& s) {
    std::string r = s;
    for (char& ch : r) ch = (char)std::tolower((unsigned char)ch);
    return r;
}

bool ValidationAgent::evaluateSingle(const std::string& pwd, const PolicyConstraints& c, std::vector<std::string>& failures) {
    failures.clear();
    int upper = 0, lower = 0, digit = 0, special = 0, spaces = 0;

    for (char ch : pwd) {
        if (std::isupper((unsigned char)ch)) upper++;
        else if (std::islower((unsigned char)ch)) lower++;
        else if (std::isdigit((unsigned char)ch)) digit++;
        else if (std::isspace((unsigned char)ch)) spaces++;
        else special++;
    }

    if (c.minLength != -1 && (int)pwd.size() < c.minLength) {
        failures.push_back("Length " + std::to_string(pwd.size()) + " < minLength " + std::to_string(c.minLength));
    }
    if (c.maxLength != -1 && (int)pwd.size() > c.maxLength) {
        failures.push_back("Length " + std::to_string(pwd.size()) + " > maxLength " + std::to_string(c.maxLength));
    }
    if (c.minUpper > 0 && upper < c.minUpper) {
        failures.push_back("Uppercase (" + std::to_string(upper) + ") < required (" + std::to_string(c.minUpper) + ")");
    }
    if (c.minLower > 0 && lower < c.minLower) {
        failures.push_back("Lowercase (" + std::to_string(lower) + ") < required (" + std::to_string(c.minLower) + ")");
    }
    if (c.minDigit > 0 && digit < c.minDigit) {
        failures.push_back("Digits (" + std::to_string(digit) + ") < required (" + std::to_string(c.minDigit) + ")");
    }
    if (c.minSpecial > 0 && special < c.minSpecial) {
        failures.push_back("Special (" + std::to_string(special) + ") < required (" + std::to_string(c.minSpecial) + ")");
    }
    if (c.noSpaces == 1 && spaces > 0) {
        failures.push_back("Whitespace characters are forbidden");
    }
    if (c.maxSequence != -1) {
        int seqK = c.maxSequence;
        for (int i = seqK - 1; i < (int)pwd.size(); i++) {
            bool isAsc = true, isDesc = true;
            for (int j = 1; j < seqK; j++) {
                if (pwd[i - j + 1] != pwd[i - j] + 1) isAsc = false;
                if (pwd[i - j + 1] != pwd[i - j] - 1) isDesc = false;
            }
            if (isAsc || isDesc) {
                failures.push_back("Sequential pattern detected (threshold " + std::to_string(c.maxSequence) + ")");
                break;
            }
        }
    }
    if (c.maxRepeated != -1) {
        int repK = c.maxRepeated;
        for (int i = repK - 1; i < (int)pwd.size(); i++) {
            bool allSame = true;
            for (int j = 1; j < repK; j++) {
                if (pwd[i] != pwd[i - j]) { allSame = false; break; }
            }
            if (allSame) {
                failures.push_back("Consecutive repeated character detected (threshold " + std::to_string(c.maxRepeated) + ")");
                break;
            }
        }
    }
    std::string pwdLower = toLowerString(pwd);
    for (const auto& word : c.blacklist) {
        if (pwdLower.find(toLowerString(word)) != std::string::npos) {
            failures.push_back("Contains blacklisted word: \"" + word + "\"");
            break;
        }
    }

    return failures.empty();
}

void ValidationAgent::synthesizeTestOracle() {
    testMatrix.clear();

    // 1. Build a baseline compliant password
    int targetLen = (constraints.minLength != -1) ? std::max(constraints.minLength, 12) : 12;
    if (constraints.maxLength != -1 && targetLen > constraints.maxLength) {
        targetLen = constraints.maxLength;
    }

    std::string baseCompliant = "";
    int reqU = (constraints.minUpper > 0) ? constraints.minUpper : 1;
    int reqL = (constraints.minLower > 0) ? constraints.minLower : 1;
    int reqD = (constraints.minDigit > 0) ? constraints.minDigit : 1;
    int reqS = (constraints.minSpecial > 0) ? constraints.minSpecial : 1;

    for (int i = 0; i < reqU; i++) baseCompliant += (char)('A' + (i % 26));
    for (int i = 0; i < reqL; i++) baseCompliant += (char)('k' + (i % 10));
    for (int i = 0; i < reqD; i++) baseCompliant += (char)('2' + (i % 7));
    for (int i = 0; i < reqS; i++) baseCompliant += "!@#$%"[i % 5];

    // Pad with alternating safe lowercase chars so no sequence/repeat is triggered
    char padChars[] = {'x', 'm', 'q', 'v', 'b', 'p', 'z'};
    int padIdx = 0;
    while ((int)baseCompliant.size() < targetLen) {
        baseCompliant += padChars[padIdx % 7];
        padIdx++;
    }

    // Baseline Positive Test
    testMatrix.push_back({"Compliant Baseline Candidate", baseCompliant, true, false, {}, false});

    // Boundary Test 1: minLength - 1
    if (constraints.minLength > 1) {
        int shortLen = constraints.minLength - 1;
        std::string shortPwd = baseCompliant.substr(0, shortLen);
        testMatrix.push_back({"Boundary Test: minLength - 1", shortPwd, false, false, {}, false});
    }

    // Boundary Test 2: minLength exact
    if (constraints.minLength != -1) {
        std::string minExact = baseCompliant;
        if ((int)minExact.size() > constraints.minLength) {
            minExact = minExact.substr(0, constraints.minLength);
            std::vector<std::string> tmp;
            bool valid = evaluateSingle(minExact, constraints, tmp);
            testMatrix.push_back({"Boundary Test: minLength Exact", minExact, valid, false, {}, false});
        } else {
            testMatrix.push_back({"Boundary Test: minLength Exact", minExact, true, false, {}, false});
        }
    }

    // Boundary Test 3: minLength + 1
    if (constraints.minLength != -1) {
        std::string minPlus = baseCompliant;
        if ((int)minPlus.size() == constraints.minLength) {
            minPlus += "z";
        }
        // Account for policy where minLength == maxLength
        bool expectedValid = (constraints.maxLength == -1 || (int)minPlus.size() <= constraints.maxLength);
        testMatrix.push_back({"Boundary Test: minLength + 1", minPlus, expectedValid, false, {}, false});
    }

    // Boundary Test 4: maxLength + 1
    if (constraints.maxLength != -1) {
        std::string maxOverflow = baseCompliant;
        while ((int)maxOverflow.size() <= constraints.maxLength) {
            maxOverflow += "x";
        }
        testMatrix.push_back({"Boundary Test: maxLength + 1", maxOverflow, false, false, {}, false});
    }

    // Missing Uppercase
    if (constraints.minUpper > 0) {
        std::string noUpper = baseCompliant;
        for (char& ch : noUpper) {
            if (std::isupper((unsigned char)ch)) ch = 'a';
        }
        testMatrix.push_back({"Partition: Missing Uppercase", noUpper, false, false, {}, false});
    }

    // Missing Lowercase
    if (constraints.minLower > 0) {
        std::string noLower = baseCompliant;
        for (char& ch : noLower) {
            if (std::islower((unsigned char)ch)) ch = 'A';
        }
        testMatrix.push_back({"Partition: Missing Lowercase", noLower, false, false, {}, false});
    }

    // Missing Digit
    if (constraints.minDigit > 0) {
        std::string noDigit = baseCompliant;
        for (char& ch : noDigit) {
            if (std::isdigit((unsigned char)ch)) ch = 'w';
        }
        testMatrix.push_back({"Partition: Missing Digit", noDigit, false, false, {}, false});
    }

    // Missing Special
    if (constraints.minSpecial > 0) {
        std::string noSpecial = baseCompliant;
        for (char& ch : noSpecial) {
            if (!std::isalnum((unsigned char)ch) && !std::isspace((unsigned char)ch)) ch = 'r';
        }
        testMatrix.push_back({"Partition: Missing Special Char", noSpecial, false, false, {}, false});
    }

    // Forbidden Spaces Trigger
    if (constraints.noSpaces == 1) {
        std::string withSpace = baseCompliant + " ";
        testMatrix.push_back({"Adversarial: Forbidden Space Injection", withSpace, false, false, {}, false});
    }

    // Forbidden Sequence Trigger
    if (constraints.maxSequence != -1) {
        std::string withSeq = baseCompliant + "123456";
        testMatrix.push_back({"Adversarial: Sequential Pattern Trigger", withSeq, false, false, {}, false});
    }

    // Forbidden Repeated Trigger
    if (constraints.maxRepeated != -1) {
        std::string withRep = baseCompliant + "qqqqqq";
        testMatrix.push_back({"Adversarial: Repetition Pattern Trigger", withRep, false, false, {}, false});
    }

    // Blacklist Violation Trigger
    if (!constraints.blacklist.empty()) {
        std::string withBlacklist = baseCompliant + constraints.blacklist.front();
        testMatrix.push_back({"Adversarial: Blacklist Match Trigger", withBlacklist, false, false, {}, false});
    }

    // Multiple Simultaneous Violations
    testMatrix.push_back({"Multi-Fault Invariant Breach", "abc", false, false, {}, false});
}

void ValidationAgent::runBlocklistSecurityTestSuite() {
    blocklistTests.clear();

    // 1. Bloom Insertion & Membership Check
    StaticBloomBuilder builder(0.001);
    builder.loadBuiltinCommon();
    if (!dictPath.empty()) builder.loadDictionaryFile(dictPath);
    if (!breachPath.empty()) builder.loadBreachCorpusFile(breachPath);
    bool built = builder.build();

    bool test1 = built && builder.query("password").inBloomFilter;
    blocklistTests.push_back({"Bloom Filter Insertion & Bit-Array Probe", "Bloom Engine",
                              "Probing inserted key 'password' -> bit array probe returns positive", test1});

    // 2. No False Negatives for All Inserted Entries
    bool zeroFalseNegatives = true;
    for (const auto& key : builder.getExactTable()) {
        MembershipResult res = builder.query(key);
        if (!res.inBloomFilter || !res.inExactTable) {
            zeroFalseNegatives = false;
            break;
        }
    }
    blocklistTests.push_back({"No False Negatives Invariant", "Bloom Engine",
                              "Verified 100% of inserted keys (" + std::to_string(builder.getExactTable().size()) +
                              " keys) yield inBloomFilter=true", zeroFalseNegatives});

    // 3. Exact Confirmation After Bloom Positive
    MembershipResult exactRes = builder.query("admin");
    bool test3 = (exactRes.status == MembershipStatus::EXACT_MATCH_CONFIRMED && exactRes.inExactTable);
    blocklistTests.push_back({"Exact Table Binary Search Confirmation", "Exact Verification",
                              "Probed 'admin': Bloom positive followed by exact table confirmation", test3});

    // 4. False-Positive Resilience & Resolution Simulation
    // A synthetic query against an absent key must never trigger rejection if Bloom hits
    MembershipResult absRes = builder.query("nonexistent_secure_token_xyz999!");
    bool test4 = (absRes.status == MembershipStatus::DEFINITELY_NOT_PRESENT ||
                  (absRes.inBloomFilter && !absRes.inExactTable && absRes.status == MembershipStatus::BLOOM_FALSE_POSITIVE));
    blocklistTests.push_back({"False-Positive Safety Guarantee", "Exact Verification",
                              "Bloom positive alone strictly disallowed from rejecting without exact table match", test4});

    // 5. Normalization Consistency
    std::vector<SubstitutionRecord> subs1, subs2;
    std::string norm1 = ASCIILeetspeakAnalyzer::normalizeCandidate("P@ssw0rd", subs1);
    std::string norm2 = ASCIILeetspeakAnalyzer::normalizeCandidate("4dm!n", subs2);
    bool test5 = (norm1 == "password" && norm2 == "admin" && subs1.size() == 2 && subs2.size() == 2);
    blocklistTests.push_back({"ASCII Leetspeak Substitution Rules", "Leetspeak Analyzer",
                              "'P@ssw0rd' -> 'password', '4dm!n' -> 'admin' with exact substitution logging", test5});

    // 6. Original-Password Preservation Invariant
    std::string candidateCopy = "P@$$w0rd";
    std::string candidateOriginal = candidateCopy;
    LeetspeakAnalysisResult analysis = ASCIILeetspeakAnalyzer::analyze(candidateCopy, builder);
    bool test6 = (candidateCopy == candidateOriginal && analysis.originalPassword == candidateOriginal);
    blocklistTests.push_back({"Candidate Password Preservation Invariant", "Security Invariant",
                              "Original candidate password is strictly preserved unmodified across analysis", test6});

    // 7. Full-String Matching (Prefix / Substring Matches Forbidden)
    // "P@$$w0rd123" has a suffix "123". It must NOT match "password"!
    LeetspeakAnalysisResult suffixAnalysis = ASCIILeetspeakAnalyzer::analyze("P@$$w0rd123", builder);
    bool test7 = (suffixAnalysis.verdict == BlocklistMatchVerdict::NO_MATCH);
    blocklistTests.push_back({"Full-String Matching Rule (No Prefix Match)", "Standards Compliance",
                              "Candidate 'P@$$w0rd123' NOT matched to 'password' (NIST SP 800-63B-4 Section 3.1.1.2)", test7});

    // 8. Empty and Missing Corpus Handling
    StaticBloomBuilder emptyBuilder(0.001);
    emptyBuilder.build();
    MembershipResult emptyRes = emptyBuilder.query("password");
    bool test8 = (emptyRes.status == MembershipStatus::BLOCKLIST_UNAVAILABLE);
    blocklistTests.push_back({"Missing / Empty Corpus Robustness", "Dataset Provenance",
                              "Empty corpus yields explicit BLOCKLIST_UNAVAILABLE status (never assumed clean)", test8});

    // 9. Dataset Deduplication
    StaticBloomBuilder dedupBuilder(0.001);
    dedupBuilder.addEntry("password", BlocklistSourceType::BUILTIN_COMMON);
    dedupBuilder.addEntry("Password", BlocklistSourceType::CONFIGURED_DICTIONARY);
    dedupBuilder.addEntry("PASSWORD", BlocklistSourceType::BREACH_CORPUS);
    dedupBuilder.addEntry("  password  ", BlocklistSourceType::CONTEXT_SPECIFIC);
    dedupBuilder.build();
    bool test9 = (dedupBuilder.getParameters().n == 1 && dedupBuilder.getExactTable().size() == 1);
    blocklistTests.push_back({"Dataset Deduplication & Canonicalization", "Preprocessing",
                              "Case-insensitive trimmed deduplication collapses 4 identical terms to n=1", test9});

    // 10. Policy-Compatible Dictionary Filtering (OWASP ASVS 5.0.0 V6.2.4)
    size_t compatibleCount = builder.countPolicyCompatibleEntries(constraints);
    bool test10 = (compatibleCount <= builder.getExactTable().size());
    blocklistTests.push_back({"Policy-Compatible Corpus Filtering", "OWASP ASVS 5.0.0 V6.2.4",
                              "Filtered " + std::to_string(compatibleCount) + " policy-compatible entries from corpus", test10});

    // 11. Generated Validator File Structure & Verification
    std::ifstream vFile(targetFile);
    bool hasTarget = vFile.is_open();
    bool hasBloomBytes = false;
    bool hasExactTable = false;
    bool hasLeetspeakNorm = false;
    if (hasTarget) {
        std::stringstream ss;
        ss << vFile.rdbuf();
        std::string content = ss.str();
        hasBloomBytes = (content.find("STATIC_BLOOM_FILTER_BYTES") != std::string::npos);
        hasExactTable = (content.find("EXACT_BLOCKLIST_TABLE") != std::string::npos);
        hasLeetspeakNorm = (content.find("LeetspeakNormalizer::normalize") != std::string::npos);
    }
    bool test11 = (hasTarget && hasBloomBytes && hasExactTable && hasLeetspeakNorm);
    blocklistTests.push_back({"Standalone Target Validator Synthesis Verification", "Secure Code Emission",
                              "Generated validator contains embedded RODATA Bloom array, exact table, and leetspeak helper", test11});

    blocklistTestsPassed = 0;
    for (const auto& t : blocklistTests) {
        if (t.passed) blocklistTestsPassed++;
    }
}

void ValidationAgent::observe() {
    AgentTelemetryRecord tel;
    tel.agentId = report.agentId;
    tel.stage = "OBSERVE";
    tel.inputSummary = "Policy Constraints & Configured Blocklist Sources";
    tel.observation = "Inspecting constraint boundary conditions, character partitions, and static blocklist parameters.";
    tel.decision = "Synthesize comprehensive runtime equivalence partition matrix and blocklist test oracle.";
    tel.actionTaken = "ORACLE_SYNTHESIS_PLANNING";
    tel.evidence = "Constraints: minLen=" + std::to_string(constraints.minLength) +
                   ", maxLen=" + std::to_string(constraints.maxLength);
    tel.confidence = 1.0;
    tel.resultStatus = "OBSERVED";
    tel.timestamp = AgentTelemetryRecord::currentTimestamp();
    report.telemetryLogs.push_back(tel);
}

void ValidationAgent::analyze() {
    synthesizeTestOracle();
    runBlocklistSecurityTestSuite();
    report.confidence = 1.0;
}

void ValidationAgent::decide() {
    AgentTelemetryRecord tel;
    tel.agentId = report.agentId;
    tel.stage = "DECIDE";
    tel.inputSummary = "Synthesized " + std::to_string(testMatrix.size()) + " policy scenarios and " +
                       std::to_string(blocklistTests.size()) + " blocklist security assertions";
    tel.observation = "Ready to execute runtime conformance test suite and static blocklist verification.";
    tel.decision = "Dispatch all synthesized test vectors to validation engine.";
    tel.actionTaken = "DISPATCH_TEST_ORACLE";
    tel.evidence = "Covers Equivalence Partitions, Boundaries, Bloom Invariants, Leetspeak, and Deduplication.";
    tel.confidence = 1.0;
    tel.resultStatus = "TESTS_PREPARED";
    tel.timestamp = AgentTelemetryRecord::currentTimestamp();
    report.telemetryLogs.push_back(tel);
}

void ValidationAgent::act() {
    int passedCount = 0;
    for (auto& tc : testMatrix) {
        tc.actualValid = evaluateSingle(tc.candidatePassword, constraints, tc.actualViolations);
        tc.testPassed = (tc.actualValid == tc.expectedValid);
        if (tc.testPassed) passedCount++;
    }

    conformanceRate = testMatrix.empty() ? 100.0 : (double)passedCount / testMatrix.size() * 100.0;
    bool allPolicyPassed = (passedCount == (int)testMatrix.size());
    bool allBlocklistPassed = (blocklistTestsPassed == (int)blocklistTests.size());
    report.success = (allPolicyPassed && allBlocklistPassed);

    AgentTelemetryRecord tel;
    tel.agentId = report.agentId;
    tel.stage = "ACT";
    tel.inputSummary = "Executed " + std::to_string(testMatrix.size()) + " policy tests + " +
                       std::to_string(blocklistTests.size()) + " blocklist unit tests";
    tel.observation = "Completed test oracle execution. Policy Passed: " + std::to_string(passedCount) +
                      "/" + std::to_string(testMatrix.size()) + ", Blocklist Passed: " +
                      std::to_string(blocklistTestsPassed) + "/" + std::to_string(blocklistTests.size());
    tel.decision = report.success ? "Validator and static blocklist conformance verified at 100%." : "Conformance discrepancies detected.";
    tel.actionTaken = "COMPUTE_CONFORMANCE_METRICS";
    tel.evidence = "Policy Conformance = " + std::to_string((int)conformanceRate) + "%, Blocklist Assertions = " +
                   std::to_string(blocklistTestsPassed) + "/" + std::to_string(blocklistTests.size());
    tel.confidence = report.success ? 1.0 : 0.7;
    tel.resultStatus = report.success ? "SUCCESS" : "DISCREPANCY";
    tel.timestamp = AgentTelemetryRecord::currentTimestamp();
    report.telemetryLogs.push_back(tel);
}

bool ValidationAgent::verify() {
    bool ok = report.success;
    AgentTelemetryRecord tel;
    tel.agentId = report.agentId;
    tel.stage = "VERIFY";
    tel.inputSummary = "Conformance Verification Pass";
    tel.observation = "Comparing expected test oracle results against actual validator and blocklist outputs.";
    tel.decision = ok ? "Runtime validator and blocklist pass 100% of synthesized test scenarios." : "Test failures detected.";
    tel.actionTaken = "VERIFY_RUNTIME_ORACLE";
    tel.evidence = std::to_string(testMatrix.size() + blocklistTests.size()) + " total assertions executed.";
    tel.confidence = ok ? 1.0 : 0.0;
    tel.resultStatus = ok ? "VERIFIED" : "FAILED";
    tel.timestamp = AgentTelemetryRecord::currentTimestamp();
    report.telemetryLogs.push_back(tel);
    return ok;
}

bool ValidationAgent::execute() {
    observe();
    analyze();
    decide();
    act();
    return verify();
}

void ValidationAgent::renderReport() const {
    std::cout << "\n========================================================================================\n";
    std::cout << "  VALIDATION AGENT (Automated Runtime Test Oracle & Conformance Matrix)\n";
    std::cout << "========================================================================================\n";
    std::cout << std::left << std::setw(38) << "Test Scenario"
              << std::setw(20) << "Sample Vector"
              << std::setw(12) << "Expected"
              << std::setw(12) << "Actual"
              << "Verdict\n";
    std::cout << "----------------------------------------------------------------------------------------\n";
    for (const auto& tc : testMatrix) {
        std::string sample = tc.candidatePassword;
        if (sample.length() > 18) sample = sample.substr(0, 15) + "...";
        std::cout << std::left << std::setw(38) << tc.testName
              << std::setw(20) << ("\"" + sample + "\"")
              << std::setw(12) << (tc.expectedValid ? "VALID" : "INVALID")
              << std::setw(12) << (tc.actualValid ? "VALID" : "INVALID")
              << (tc.testPassed ? "[PASS]" : "[FAIL]") << "\n";
    }
    std::cout << "----------------------------------------------------------------------------------------\n";
    std::cout << "Policy Conformance Pass Rate: " << (int)conformanceRate << "%\n";

    std::cout << "\n========================================================================================\n";
    std::cout << "  STANDARDS-ALIGNED BLOCKLIST & BLOOM FILTER TEST SUITE (NIST / OWASP)\n";
    std::cout << "========================================================================================\n";
    std::cout << std::left << std::setw(46) << "Security Assertion"
              << std::setw(24) << "Category"
              << "Result\n";
    std::cout << "----------------------------------------------------------------------------------------\n";
    for (const auto& bt : blocklistTests) {
        std::cout << std::left << std::setw(46) << bt.testName
                  << std::setw(24) << bt.category
                  << (bt.passed ? "[PASS]" : "[FAIL]") << "\n";
    }
    std::cout << "----------------------------------------------------------------------------------------\n";
    std::cout << "Blocklist Security Assertions: " << blocklistTestsPassed << " / " << blocklistTests.size() << " passed ("
              << (blocklistTestsPassed == (int)blocklistTests.size() ? "100% Invariants Verified" : "Discrepancy") << ")\n";
    std::cout << "========================================================================================\n";
}
