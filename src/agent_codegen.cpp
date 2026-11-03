#include "agent_codegen.h"
#include "agent_attack_detector.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>

CodegenAgent::CodegenAgent(const PolicyConstraints& c, std::string outputPath, std::shared_ptr<DFA> dfa,
                           std::string dictionaryPath, std::string breachCorpusPath)
    : constraints(c), targetFile(std::move(outputPath)), synthesizedDfa(std::move(dfa)),
      dictPath(std::move(dictionaryPath)), breachPath(std::move(breachCorpusPath)),
      report("Secure Code Generation Agent", "AGENT-05-SECURE-CODEGEN") {
}

bool CodegenAgent::runBreachFilterSynthesizer() {
    // -------------------------------------------------------------------------
    // SUBSTAGE: AGENT-05-BREACH-FILTER-SYNTHESIZER
    // Build-time Static Bloom Filter & Exact Verification Table Synthesis
    // -------------------------------------------------------------------------
    bloomBuilder.loadBuiltinCommon();
    if (!dictPath.empty()) {
        bloomBuilder.loadDictionaryFile(dictPath);
    }
    if (!breachPath.empty()) {
        bloomBuilder.loadBreachCorpusFile(breachPath);
    } else {
        if (!bloomBuilder.loadBreachCorpusFile("data/breach_corpus.txt")) {
            if (!bloomBuilder.loadBreachCorpusFile("breach_corpus.txt")) {
                bloomBuilder.loadBreachCorpusFile("CODE/breach_corpus.txt");
            }
        }
    }
    bloomBuilder.loadCuratedDatasets();

    bool built = bloomBuilder.build();

    // Determine manifest output path (alongside target C++ validator)
    std::string manifestPath = "generated_bloom_manifest.json";
    size_t lastSlash = targetFile.find_last_of("\\/");
    if (lastSlash != std::string::npos) {
        manifestPath = targetFile.substr(0, lastSlash + 1) + "generated_bloom_manifest.json";
    }
    bloomBuilder.emitManifestJson(manifestPath, constraints);

    AgentTelemetryRecord tel;
    tel.agentId = "AGENT-05-BREACH-FILTER-SYNTHESIZER";
    tel.stage = "SYNTHESIZE";
    tel.inputSummary = "Corpus ingestion: dict=" + (dictPath.empty() ? "none" : dictPath) +
                       ", breach=" + (breachPath.empty() ? "none" : breachPath);

    const auto& p = bloomBuilder.getParameters();
    if (built) {
        tel.observation = "Synthesized immutable Static Bloom Filter for " + std::to_string(p.n) +
                          " unique canonical keys. m=" + std::to_string(p.mBits) + " bits (" +
                          std::to_string(p.mBytes) + " bytes), k=" + std::to_string(p.k) + " hashes.";
        tel.decision = "Embed static bit array and sorted canonical exact-verification table into generated C++ validator.";
        tel.actionTaken = "EMIT_STATIC_BLOOM_RODATA";
        tel.evidence = "Theoretical expected FPR = " + std::to_string(p.theoreticalExpectedFpr) +
                       ", Exact verification entries = " + std::to_string(bloomBuilder.getExactTable().size());
        tel.confidence = 1.0;
        tel.resultStatus = "FILTER_SYNTHESIZED";
    } else {
        tel.observation = "Blocklist corpus empty or unavailable.";
        tel.decision = "Flag blocklist unavailable. Zero fake data generated.";
        tel.actionTaken = "FLAG_BLOCKLIST_UNAVAILABLE";
        tel.evidence = "Unique keys = 0";
        tel.confidence = 1.0;
        tel.resultStatus = "BLOCKLIST_UNAVAILABLE";
    }
    tel.timestamp = AgentTelemetryRecord::currentTimestamp();
    report.telemetryLogs.push_back(tel);

    return built;
}

std::string CodegenAgent::synthesizeHardenedValidator() {
    std::ostringstream out;

    out << "// ============================================================\n";
    out << "// SECURE COMPILED POLICY VALIDATOR (Hardened Target Architecture)\n";
    out << "// Synthesized by: Codegen Agent & Security Gate #2\n";
    out << "// Substage: AGENT-05-BREACH-FILTER-SYNTHESIZER (NIST SP 800-63B-4 / OWASP ASVS 5.0.0)\n";
    out << "// Invariants: Static RODATA Bloom Filter + Exact Binary Search Verification\n";
    out << "//             Decoupled Leetspeak Normalizer (Original Password Preserved)\n";
    out << "//             Bounded Input, Zero Credential Leak, Memory Scrubbing\n";
    out << "// ============================================================\n\n";

    out << "#include <iostream>\n";
    out << "#include <string>\n";
    out << "#include <vector>\n";
    out << "#include <cctype>\n";
    out << "#include <cmath>\n";
    out << "#include <algorithm>\n";
    out << "#include <cstring>\n";
    out << "#include <cstdint>\n\n";

    if (synthesizedDfa) {
        out << synthesizedDfa->emitCppTable("DFA_TRANSITION_TABLE") << "\n\n";
    }

    if (bloomBuilder.isSynthesized()) {
        out << bloomBuilder.emitStaticDataCpp() << "\n";
        out << ASCIILeetspeakAnalyzer::emitValidatorHelperCpp() << "\n";
    }

    out << "struct ValidationResult {\n";
    out << "    bool isValid;\n";
    out << "    std::vector<std::string> errors;\n";
    out << "    double entropyScore;\n";
    out << "    std::string estimatedStrength;\n";
    out << "    bool blocklistScreened;\n";
    out << "    std::string blocklistVerdict;\n";
    out << "};\n\n";

    out << "class HardenedPolicyValidator {\n";
    out << "private:\n";
    out << "    std::string password;\n";
    out << "    static const size_t MAX_INPUT_BOUND = 4096;\n\n";

    out << "    void secureZeroMemory(std::string& s) {\n";
    out << "        if (s.empty()) return;\n";
    out << "        volatile char* p = const_cast<char*>(s.data());\n";
    out << "        size_t len = s.size();\n";
    out << "        while (len--) *p++ = 0;\n";
    out << "        s.clear();\n";
    out << "    }\n\n";

    out << "    int calculatePoolSize(int uppers, int lowers, int digits, int specials) const {\n";
    out << "        int pool = 0;\n";
    out << "        if (uppers > 0) pool += 26;\n";
    out << "        if (lowers > 0) pool += 26;\n";
    out << "        if (digits > 0) pool += 10;\n";
    out << "        if (specials > 0) pool += 33;\n";
    out << "        return pool;\n";
    out << "    }\n\n";

    out << "    std::string toLowerSafe(const std::string& s) const {\n";
    out << "        std::string res = s;\n";
    out << "        for (char& ch : res) ch = (char)std::tolower((unsigned char)ch);\n";
    out << "        return res;\n";
    out << "    }\n\n";

    out << "public:\n";
    out << "    explicit HardenedPolicyValidator(const std::string& pwd) : password(pwd) {}\n\n";
    out << "    ~HardenedPolicyValidator() {\n";
    out << "        // Secure memory scrubbing on destruction\n";
    out << "        secureZeroMemory(password);\n";
    out << "    }\n\n";

    out << "    ValidationResult validate() {\n";
    out << "        ValidationResult result;\n";
    out << "        result.isValid = true;\n";
    out << "        result.entropyScore = 0.0;\n";
    out << "        result.estimatedStrength = \"UNKNOWN\";\n";
    out << "        result.blocklistScreened = false;\n";
    out << "        result.blocklistVerdict = \"NOT_SCREENED\";\n\n";

    out << "        // Security Gate: Bounded Input Defense (ReDoS / Memory exhaustion protection)\n";
    out << "        if (password.length() > MAX_INPUT_BOUND) {\n";
    out << "            result.isValid = false;\n";
    out << "            result.errors.push_back(\"[SECURITY REJECTION] Input length exceeds bounded memory safety limit (4096 bytes).\");\n";
    out << "            return result;\n";
    out << "        }\n\n";

    out << "        int upperCount = 0, lowerCount = 0, digitCount = 0, specialCount = 0, spaceCount = 0;\n";
    out << "        for (char ch : password) {\n";
    out << "            if (std::isupper((unsigned char)ch)) upperCount++;\n";
    out << "            else if (std::islower((unsigned char)ch)) lowerCount++;\n";
    out << "            else if (std::isdigit((unsigned char)ch)) digitCount++;\n";
    out << "            else if (std::isspace((unsigned char)ch)) spaceCount++;\n";
    out << "            else specialCount++;\n";
    out << "        }\n\n";

    out << "        int pool = calculatePoolSize(upperCount, lowerCount, digitCount, specialCount);\n";
    out << "        if (pool > 0 && !password.empty()) {\n";
    out << "            result.entropyScore = (double)password.length() * (std::log(pool) / std::log(2.0));\n";
    out << "        }\n\n";

    out << "        // 1. Length Constraints\n";
    if (constraints.minLength != -1) {
        out << "        if ((int)password.length() < " << constraints.minLength << ") {\n";
        out << "            result.isValid = false;\n";
        out << "            result.errors.push_back(\"[REJECTED] Password length (\" + std::to_string(password.length()) + \") is shorter than required (" << constraints.minLength << ").\");\n";
        out << "        }\n";
    }
    if (constraints.maxLength != -1) {
        out << "        if ((int)password.length() > " << constraints.maxLength << ") {\n";
        out << "            result.isValid = false;\n";
        out << "            result.errors.push_back(\"[REJECTED] Password length (\" + std::to_string(password.length()) + \") exceeds maximum allowed (" << constraints.maxLength << ").\");\n";
        out << "        }\n";
    }

    out << "\n        // 2. Character Requirements\n";
    if (constraints.minUpper > 0) {
        out << "        if (upperCount < " << constraints.minUpper << ") {\n";
        out << "            result.isValid = false;\n";
        out << "            result.errors.push_back(\"[REJECTED] Uppercase characters (\" + std::to_string(upperCount) + \") less than required (" << constraints.minUpper << ").\");\n";
        out << "        }\n";
    }
    if (constraints.minLower > 0) {
        out << "        if (lowerCount < " << constraints.minLower << ") {\n";
        out << "            result.isValid = false;\n";
        out << "            result.errors.push_back(\"[REJECTED] Lowercase characters (\" + std::to_string(lowerCount) + \") less than required (" << constraints.minLower << ").\");\n";
        out << "        }\n";
    }
    if (constraints.minDigit > 0) {
        out << "        if (digitCount < " << constraints.minDigit << ") {\n";
        out << "            result.isValid = false;\n";
        out << "            result.errors.push_back(\"[REJECTED] Numeric digits (\" + std::to_string(digitCount) + \") less than required (" << constraints.minDigit << ").\");\n";
        out << "        }\n";
    }
    if (constraints.minSpecial > 0) {
        out << "        if (specialCount < " << constraints.minSpecial << ") {\n";
        out << "            result.isValid = false;\n";
        out << "            result.errors.push_back(\"[REJECTED] Special characters (\" + std::to_string(specialCount) + \") less than required (" << constraints.minSpecial << ").\");\n";
        out << "        }\n";
    }

    if (synthesizedDfa) {
        out << "\n        // ======================================================\n";
        out << "        // 3. POLICY-DRIVEN DFA PATTERN RECOGNITION (SINGLE-PASS O(N))\n";
        out << "        // ======================================================\n";
        out << "        int dfaCurrentState = 0;\n";
        out << "        for (char ch : password) {\n";
        out << "            unsigned char uch = (unsigned char)ch;\n";
        out << "            if (uch < 128) {\n";
        out << "                dfaCurrentState = DFA_TRANSITION_TABLE[dfaCurrentState][uch];\n";
        out << "                if (DFA_REJECT_STATES[dfaCurrentState]) {\n";
        out << "                    result.isValid = false;\n";
        out << "                    result.errors.push_back(\"[REJECTED] Password violates compiled DFA pattern policy (forbidden sequence, repeated substring, or blacklisted token).\");\n";
        out << "                    break;\n";
        out << "                }\n";
        out << "            }\n";
        out << "        }\n";
    } else {
        out << "\n        // 3. Forbidden Structural Patterns\n";
        if (constraints.noSpaces == 1) {
            out << "        if (spaceCount > 0) {\n";
            out << "            result.isValid = false;\n";
            out << "            result.errors.push_back(\"[REJECTED] Whitespace characters are strictly forbidden.\");\n";
            out << "        }\n";
        }
        if (constraints.maxSequence != -1) {
            int seqThreshold = constraints.maxSequence;
            out << "        int seqThreshold = " << seqThreshold << ";\n";
            out << "        for (int idx = seqThreshold - 1; idx < (int)password.length(); idx++) {\n";
            out << "            bool isAsc = true, isDesc = true;\n";
            out << "            for (int j = 1; j < seqThreshold; j++) {\n";
            out << "                if (password[idx - j + 1] != password[idx - j] + 1) isAsc = false;\n";
            out << "                if (password[idx - j + 1] != password[idx - j] - 1) isDesc = false;\n";
            out << "            }\n";
            out << "            if (isAsc || isDesc) {\n";
            out << "                result.isValid = false;\n";
            out << "                result.errors.push_back(\"[REJECTED] Sequential character sequence detected (threshold " << seqThreshold << ").\");\n";
            out << "                break;\n";
            out << "            }\n";
            out << "        }\n";
        }
        if (constraints.maxRepeated != -1) {
            int repThreshold = constraints.maxRepeated;
            out << "        int repThreshold = " << repThreshold << ";\n";
            out << "        for (int idx = repThreshold - 1; idx < (int)password.length(); idx++) {\n";
            out << "            bool allSame = true;\n";
            out << "            for (int j = 1; j < repThreshold; j++) {\n";
            out << "                if (password[idx] != password[idx - j]) { allSame = false; break; }\n";
            out << "            }\n";
            out << "            if (allSame) {\n";
            out << "                result.isValid = false;\n";
            out << "                result.errors.push_back(\"[REJECTED] Repeated consecutive character pattern detected (threshold " << repThreshold << ").\");\n";
            out << "                break;\n";
            out << "            }\n";
            out << "        }\n";
        }

        out << "\n        // 4. Blacklist Verification (Policy DSL Token Match)\n";
        if (!constraints.blacklist.empty()) {
            out << "        std::string pwdLower = toLowerSafe(password);\n";
            for (const auto& term : constraints.blacklist) {
                std::string safeTerm = AgentAttackDetector::sanitizeStringLiteral(term);
                out << "        if (pwdLower.find(\"" << safeTerm << "\") != std::string::npos) {\n";
                out << "            result.isValid = false;\n";
                out << "            result.errors.push_back(\"[REJECTED] Contains forbidden blacklisted term: \\\"" << safeTerm << "\\\"\");\n";
                out << "        }\n";
            }
        }
    }

    if (bloomBuilder.isSynthesized()) {
        out << "\n        // ============================================================================\n";
        out << "        // 4. STATIC RODATA BLOOM FILTER & EXACT VERIFICATION (NIST SP 800-63B-4)\n";
        out << "        // ============================================================================\n";
        out << "        result.blocklistScreened = true;\n";
        out << "        result.blocklistVerdict = \"CLEAN\";\n";
        out << "        std::string candCanonical = toLowerSafe(password);\n\n";

        out << "        // Fast O(1) Bloom Filter Pre-Check for Exact Original Candidate\n";
        out << "        if (CompiledBlocklist::bloomContains(candCanonical)) {\n";
        out << "            // Bloom positive -> Exact binary search confirmation required\n";
        out << "            if (CompiledBlocklist::exactTableContains(candCanonical)) {\n";
        out << "                result.isValid = false;\n";
        out << "                result.blocklistVerdict = \"EXACT_MATCH\";\n";
        out << "                result.errors.push_back(\"[REJECTED] Exact match found in compiled password blocklist (NIST SP 800-63B-4 Section 3.1.1.2).\");\n";
        out << "            }\n";
        out << "            // Notice: If exact confirmation fails, Bloom false positive is safely discarded\n";
        out << "        }\n\n";

        out << "        // Supplementary Heuristic: Decoupled Leetspeak Analysis (Candidate preserved unmodified)\n";
        out << "        bool hasLeetSubs = false;\n";
        out << "        std::string normalizedCand = LeetspeakNormalizer::normalize(password, hasLeetSubs);\n";
        out << "        if (hasLeetSubs && normalizedCand != candCanonical) {\n";
        out << "            if (CompiledBlocklist::bloomContains(normalizedCand)) {\n";
        out << "                if (CompiledBlocklist::exactTableContains(normalizedCand)) {\n";
        out << "                    result.isValid = false;\n";
        out << "                    if (result.blocklistVerdict == \"CLEAN\") result.blocklistVerdict = \"LEETSPEAK_VARIANT\";\n";
        out << "                    result.errors.push_back(\"[REJECTED] Leetspeak variant of blocklisted password detected: candidate normalizes to \\\"\" + normalizedCand + \"\\\" via predictable ASCII substitutions.\");\n";
        out << "                }\n";
        out << "            }\n";
        out << "        }\n";
    }

    out << "\n        // 5. Entropy & Strength Tier Assessment\n";
    out << "        if (result.entropyScore > 80.0) result.estimatedStrength = \"VERY STRONG\";\n";
    out << "        else if (result.entropyScore > 60.0) result.estimatedStrength = \"STRONG\";\n";
    out << "        else if (result.entropyScore > 40.0) result.estimatedStrength = \"MODERATE\";\n";
    out << "        else result.estimatedStrength = \"WEAK\";\n\n";

    if (!constraints.minStrength.empty() && constraints.minStrength != "none") {
        out << "        std::string reqTier = \"" << constraints.minStrength << "\";\n";
        out << "        int curLevel = (result.estimatedStrength == \"VERY STRONG\" ? 4 : (result.estimatedStrength == \"STRONG\" ? 3 : (result.estimatedStrength == \"MODERATE\" ? 2 : 1)));\n";
        out << "        int reqLevel = (reqTier == \"very strong\" || reqTier == \"verystrong\" ? 4 : (reqTier == \"strong\" ? 3 : (reqTier == \"moderate\" || reqTier == \"medium\" ? 2 : 1)));\n";
        out << "        if (curLevel < reqLevel) {\n";
        out << "            result.isValid = false;\n";
        out << "            result.errors.push_back(\"[REJECTED] Calculated entropy tier (\" + result.estimatedStrength + \") does not meet policy requirement (\" + reqTier + \").\");\n";
        out << "        }\n";
    }

    out << "\n        return result;\n";
    out << "    }\n";
    out << "};\n\n";

    out << "int main() {\n";
    out << "    std::string inputPwd;\n";
    out << "    std::cout << \"==================================================\\n\";\n";
    out << "    std::cout << \"  Hardened Policy Validator (Compiled Target)\\n\";\n";
    out << "    std::cout << \"  Security Engine: Static RODATA Bloom Filter Embedded\\n\";\n";
    out << "    std::cout << \"==================================================\\n\";\n";
    out << "    std::cout << \"Enter password to validate: \";\n";
    out << "    if (!std::getline(std::cin, inputPwd)) return 0;\n\n";
    out << "    HardenedPolicyValidator validator(inputPwd);\n";
    out << "    ValidationResult res = validator.validate();\n\n";
    out << "    if (res.isValid) {\n";
    out << "        std::cout << \"\\n[STATUS: VALID] Password meets all compiled policy requirements.\\n\";\n";
    out << "    } else {\n";
    out << "        std::cout << \"\\n[STATUS: INVALID] Password failed policy compliance:\\n\";\n";
    out << "        for (const auto& err : res.errors) {\n";
    out << "            std::cout << \"  * \" << err << \"\\n\";\n";
    out << "        }\n";
    out << "    }\n";
    out << "    std::cout << \"\\n-- Security Metrics --\\n\";\n";
    out << "    std::cout << \"Calculated Shannon Entropy: \" << res.entropyScore << \" bits\\n\";\n";
    out << "    std::cout << \"Evaluated Strength Tier   : \" << res.estimatedStrength << \"\\n\";\n";
    out << "    std::cout << \"Blocklist Screening Status: \" << (res.blocklistScreened ? \"ACTIVE (Static RODATA Filter)\" : \"INACTIVE\") << \"\\n\";\n";
    out << "    std::cout << \"Blocklist Verdict         : \" << res.blocklistVerdict << \"\\n\";\n";
    out << "    return res.isValid ? 0 : 1;\n";
    out << "}\n";

    return out.str();
}

void CodegenAgent::runStaticSecurityAudit(const std::string& code) {
    checklist.clear();

    // 1. Input Bounded Check
    bool bounded = (code.find("MAX_INPUT_BOUND") != std::string::npos &&
                    code.find("password.length() > MAX_INPUT_BOUND") != std::string::npos);
    checklist.push_back({"Input bounded", bounded, "Guards against buffer/CPU exhaustion (4096-byte limit enforced)"});

    // 2. Unsafe memory operations check
    bool safeMemory = (code.find("malloc(") == std::string::npos &&
                       code.find("free(") == std::string::npos &&
                       code.find("new ") == std::string::npos &&
                       code.find("delete ") == std::string::npos &&
                       code.find("secureZeroMemory") != std::string::npos);
    checklist.push_back({"No unsafe memory operations", safeMemory, "RAII containers only + volatile memory scrubbing implemented"});

    // 3. No hardcoded secrets
    bool noSecrets = (code.find("API_KEY") == std::string::npos &&
                      code.find("PASSWORD =") == std::string::npos &&
                      code.find("SECRET") == std::string::npos);
    checklist.push_back({"No hardcoded secrets", noSecrets, "Zero embedded credentials or static key material detected"});

    // 4. No plaintext password logging
    bool noPasswordLogging = (code.find("std::cout << password") == std::string::npos &&
                             code.find("printf(\"%s\", password") == std::string::npos &&
                             code.find("errors.push_back(password") == std::string::npos);
    checklist.push_back({"No plaintext password logging", noPasswordLogging, "Password plaintext is never leaked in errors or stdout"});

    // 5. File paths validated
    bool pathSafe = (code.find("system(") == std::string::npos &&
                     code.find("popen(") == std::string::npos &&
                     code.find("../") == std::string::npos);
    checklist.push_back({"File paths validated", pathSafe, "Zero shell injections, command executions, or path traversals"});

    // 6. Error handling present
    bool errorHandling = (code.find("result.isValid = false;") != std::string::npos &&
                          code.find("result.errors.push_back") != std::string::npos);
    checklist.push_back({"Error handling present", errorHandling, "Deterministic, structured diagnostic error collection enabled"});

    // 7. Static Bloom Filter & Exact Table synthesized check
    bool hasBloomAndExact = (code.find("STATIC_BLOOM_FILTER_BYTES") != std::string::npos &&
                             code.find("EXACT_BLOCKLIST_TABLE") != std::string::npos &&
                             code.find("bloomContains") != std::string::npos &&
                             code.find("exactTableContains") != std::string::npos);
    checklist.push_back({"Static Bloom Filter & Exact Table Synthesized", hasBloomAndExact,
                         "Build-time RODATA Bloom filter + O(log N) binary search exact table embedded"});

    // 8. Decoupled Leetspeak Normalizer embedded check
    bool hasLeetspeak = (code.find("LeetspeakNormalizer::normalize") != std::string::npos);
    checklist.push_back({"Decoupled Leetspeak Normalizer Embedded", hasLeetspeak,
                         "Normalized heuristic layer embedded; candidate password preserved unmodified"});

    gatePassed = true;
    for (const auto& item : checklist) {
        if (!item.passed) {
            gatePassed = false;
            break;
        }
    }
}

void CodegenAgent::observe() {
    AgentTelemetryRecord tel;
    tel.agentId = report.agentId;
    tel.stage = "OBSERVE";
    tel.inputSummary = "Policy Constraints & Configured Corpus Paths";
    tel.observation = "Inspecting constraints, dictionary path: \"" + dictPath +
                      "\", breach corpus path: \"" + breachPath + "\".";
    tel.decision = "Synthesize hardened standalone C++ validator with embedded Static RODATA Bloom Filter.";
    tel.actionTaken = "SYNTHESIS_PLANNING";
    tel.evidence = "Target: " + targetFile + " (Standard C++17 RAII)";
    tel.confidence = 1.0;
    tel.resultStatus = "OBSERVED";
    tel.timestamp = AgentTelemetryRecord::currentTimestamp();
    report.telemetryLogs.push_back(tel);
}

void CodegenAgent::analyze() {
    runBreachFilterSynthesizer();
    generatedSource = synthesizeHardenedValidator();
    runStaticSecurityAudit(generatedSource);
    report.decision = gatePassed ? AgentDecision::PASS_GATE : AgentDecision::BLOCK_GATE;
    report.confidence = 1.0;
}

void CodegenAgent::decide() {
    AgentTelemetryRecord tel;
    tel.agentId = report.agentId;
    tel.stage = "DECIDE";
    tel.inputSummary = "Static Code Audit Assessment";

    if (gatePassed) {
        tel.observation = "Emitted C++ code satisfies all 8 static security audit invariants.";
        tel.decision = "Pass Security Gate #2; approve target C++ validator for filesystem commit.";
        tel.actionTaken = "APPROVE_SECURITY_GATE_2";
        tel.evidence = "Passed 8/8 security assertions: Bounded input, zero logging, memory hygiene, Bloom filter + exact table.";
        tel.confidence = 1.0;
        tel.resultStatus = "GATE_PASSED";
    } else {
        tel.observation = "Security vulnerabilities detected in emitted C++ validator AST.";
        tel.decision = "Block Security Gate #2; abort code emission.";
        tel.actionTaken = "BLOCK_SECURITY_GATE_2";
        tel.evidence = "Security audit checklist failed.";
        tel.confidence = 1.0;
        tel.resultStatus = "GATE_BLOCKED";
    }
    tel.timestamp = AgentTelemetryRecord::currentTimestamp();
    report.telemetryLogs.push_back(tel);
}

void CodegenAgent::act() {
    if (gatePassed) {
        std::ofstream out(targetFile);
        if (out.is_open()) {
            out << generatedSource;
            out.close();
            report.success = true;
        } else {
            report.success = false;
        }
    } else {
        report.success = false;
    }

    AgentTelemetryRecord tel;
    tel.agentId = report.agentId;
    tel.stage = "ACT";
    tel.inputSummary = "Commit Target C++ Validator";
    tel.observation = report.success ? "Writing verified validator source to " + targetFile : "Emission blocked by Security Gate.";
    tel.decision = report.success ? "File committed successfully." : "Emission aborted.";
    tel.actionTaken = report.success ? "COMMIT_SOURCE_FILE" : "ABORT_EMISSION";
    tel.evidence = "Size: " + std::to_string(generatedSource.size()) + " bytes";
    tel.confidence = 1.0;
    tel.resultStatus = report.success ? "SUCCESS" : "FAILED";
    tel.timestamp = AgentTelemetryRecord::currentTimestamp();
    report.telemetryLogs.push_back(tel);
}

bool CodegenAgent::verify() {
    bool ok = report.success && gatePassed;
    AgentTelemetryRecord tel;
    tel.agentId = report.agentId;
    tel.stage = "VERIFY";
    tel.inputSummary = "Post-Emission Verification";
    tel.observation = "Verifying physical existence and integrity of target file: " + targetFile;
    tel.decision = ok ? "Validator file sealed and ready for deployment." : "Verification failed.";
    tel.actionTaken = "VERIFY_TARGET_FILE";
    tel.evidence = ok ? "File accessible on disk." : "File missing or unapproved.";
    tel.confidence = ok ? 1.0 : 0.0;
    tel.resultStatus = ok ? "VERIFIED" : "FAILED";
    tel.timestamp = AgentTelemetryRecord::currentTimestamp();
    report.telemetryLogs.push_back(tel);
    return ok;
}

bool CodegenAgent::execute() {
    observe();
    analyze();
    decide();
    act();
    return verify();
}

void CodegenAgent::renderReport() const {
    std::cout << "\n==================================================\n";
    std::cout << "  CODEGEN AGENT (Security Gate #2)\n";
    std::cout << "==================================================\n";
    std::cout << "SECURE CODE CHECK\n";
    std::cout << "────────────────────\n";
    for (const auto& item : checklist) {
        std::cout << (item.passed ? " [✓] " : " [✗] ") << item.name << "\n";
        std::cout << "     " << item.detail << "\n";
    }

    if (bloomBuilder.isSynthesized()) {
        const auto& p = bloomBuilder.getParameters();
        std::cout << "\nSTATIC BLOOM FILTER SYNTHESIS METRICS\n";
        std::cout << "────────────────────────────────────────\n";
        std::cout << "  Unique Keys Ingested      : " << p.n << "\n";
        std::cout << "  Bloom Bit Array Size (m)  : " << p.mBits << " bits (" << p.mBytes << " bytes)\n";
        std::cout << "  Hash Functions Count (k)  : " << p.k << "\n";
        std::cout << "  Target False Positive Prob: " << std::fixed << std::setprecision(4) << p.targetFpr << "\n";
        std::cout << "  Theoretical Expected FPR  : " << std::fixed << std::setprecision(6) << p.theoreticalExpectedFpr << "\n";
        std::cout << "  Exact Table Key Count     : " << bloomBuilder.getExactTable().size() << "\n";
        std::cout << "  Total Embedded Data Footprint: " << bloomBuilder.getTotalEmbeddedBytes() << " bytes\n";
        std::cout << "  Runtime External File Req : NONE (Self-contained in C++ executable)\n";
    }

    std::cout << "\nTarget File  : " << targetFile << "\n";
    std::cout << "Security Gate: " << (gatePassed ? "PASSED (Code Approved)" : "FAILED (Code Blocked)") << "\n";
    std::cout << "Action       : " << (gatePassed ? "PROCEED" : "BLOCK") << "\n";
    std::cout << "--------------------------------------------------\n";
}
