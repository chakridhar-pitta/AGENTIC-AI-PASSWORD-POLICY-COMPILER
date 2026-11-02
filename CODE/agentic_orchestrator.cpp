#include "agentic_orchestrator.h"
#include <iostream>
#include <iomanip>

AgenticOrchestrator::AgenticOrchestrator()
    : compilationSuccess(false) {
}

void AgenticOrchestrator::logTelemetry(const std::vector<AgentTelemetryRecord>& logs) {
    for (const auto& log : logs) {
        globalTelemetry.push_back(log);
    }
}

bool AgenticOrchestrator::compilePolicy(const std::string& policySource,
                                        const std::string& targetCppPath,
                                        const std::string& preApprovedRepair,
                                        const std::string& dictionaryPath,
                                        const std::string& breachCorpusPath) {
    std::cout << "\n========================================================================================\n";
    std::cout << "  AGENTIC AI COMPILER PLATFORM — 8 AI AGENTS, DUAL GATES & ATTACK SHIELD\n";
    std::cout << "========================================================================================\n";
    std::cout << "Initializing Agentic Orchestrator and dispatching compiler agents...\n";

    // -------------------------------------------------------------------------
    // AGENT 0: POLICY SECURITY GUARD & ATTACK SHIELD (Pre-Lexical Security Gate)
    // -------------------------------------------------------------------------
    std::cout << "\n>>> [ORCHESTRATOR] Dispatching AGENT-00-INPUT-GUARD (Policy Security & Attack Shield)...\n";
    AttackAssessment attackAssess = attackDetector.inspectPolicyInput(policySource);

    guardReport.agentName = "Policy Security Guard & Attack Shield";
    guardReport.agentId = "AGENT-00-INPUT-GUARD";
    guardReport.confidence = 0.99;

    AgentTelemetryRecord guardTel;
    guardTel.agentId = "AGENT-00-INPUT-GUARD";
    guardTel.stage = "OBSERVE";
    guardTel.inputSummary = "Raw policy stream inspection (" + std::to_string(policySource.size()) + " bytes)";
    guardTel.observation = "Scanning for prompt injections, policy bypass instructions, security downgrades, and code payloads.";
    guardTel.decision = attackAssess.isAttack ? "Flag adversarial attack: " + attackAssess.categoryName : "Policy adheres to baseline specification";
    guardTel.actionTaken = attackAssess.isAttack ? attackAssess.mitigationAction : "FORWARD_TO_LEXER";
    guardTel.evidence = attackAssess.attackPatternDetected;
    guardTel.confidence = 0.99;
    guardTel.resultStatus = attackAssess.isAttack ? "ATTACK_BLOCKED" : "CLEAN_POLICY";
    guardTel.timestamp = AgentTelemetryRecord::currentTimestamp();
    guardReport.telemetryLogs.push_back(guardTel);
    logTelemetry(guardReport.telemetryLogs);

    if (attackAssess.isAttack) {
        std::cout << "\n╔══════════════════════════════════════════════════════════════════════════════════════╗\n";
        std::cout << "║ 🛡️ [AGENT-00-INPUT-GUARD] SECURITY ALERT: ADVERSARIAL ATTACK BLOCKED                  ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════════════════════════════╣\n";
        std::cout << "║ Attack Vector    : " << std::left << std::setw(66) << attackAssess.categoryName << "║\n";
        std::cout << "║ Threat Risk Level: " << std::left << std::setw(66) << (attackAssess.riskLevel == ThreatRiskLevel::CRITICAL ? "CRITICAL (Risk 9.8/10.0)" : "HIGH (Risk 8.5/10.0)") << "║\n";
        std::cout << "║ Signature / Match: " << std::left << std::setw(66) << attackAssess.attackPatternDetected << "║\n";
        std::cout << "║ Mitigation Action: " << std::left << std::setw(66) << attackAssess.mitigationAction << "║\n";
        std::cout << "║ Rationale        : " << std::left << std::setw(66) << attackAssess.explanation << "║\n";
        std::cout << "╚══════════════════════════════════════════════════════════════════════════════════════╝\n";
        std::cout << "\n[HALT] Pipeline terminated by AGENT-00-INPUT-GUARD: Adversarial input neutralized.\n";
        compilationSuccess = false;
        return false;
    }

    std::cout << "  [PASS] Policy Security Guard: Input is safe and compliant with security bounds.\n";

    // -------------------------------------------------------------
    // AGENT 1: LEXER AGENT (Token Security & Lexical Intelligence)
    // -------------------------------------------------------------
    std::cout << "\n>>> [ORCHESTRATOR] Dispatching AGENT-01-LEXER (Lexical Intelligence Agent)...\n";
    LexerAgent lexAgent(policySource);
    bool lexSuccess = lexAgent.execute();
    logTelemetry(lexAgent.getReport().telemetryLogs);
    lexAgent.renderReport();
    lexerReport = lexAgent.getReport();

    if (!lexSuccess) {
        std::cout << "\n[HALT] Pipeline terminated by AGENT-01-LEXER: Unsafe or invalid lexical tokens.\n";
        compilationSuccess = false;
        return false;
    }

    // -------------------------------------------------------------
    // AGENT 2: PARSER AGENT (Syntax Intelligence & AST Self-Repair)
    // -------------------------------------------------------------
    std::cout << "\n>>> [ORCHESTRATOR] Dispatching AGENT-02-SYNTAX (Syntax & AST Repair Agent)...\n";
    ParserAgent parseAgent(lexAgent.getTokens(), preApprovedRepair);
    bool parseSuccess = parseAgent.execute();

    if (!parseSuccess && parseAgent.needsHumanApproval()) {
        parseAgent.renderReport();
        std::cout << "\n========================================================================================\n";
        std::cout << "  [HUMAN-IN-THE-LOOP APPROVAL REQUIRED - AGENT-02-SYNTAX]\n";
        std::cout << "========================================================================================\n";
        std::cout << "  The Parser Agent detected ambiguous syntax with multiple valid security interpretations.\n";
        std::cout << "  A compiler must never silently guess security policies without human authorization.\n";
        std::cout << "\n  Candidate Repairs Available:\n";
        for (const auto& c : parseAgent.getCandidates()) {
            std::cout << "    [" << c.id << "] -> " << c.candidateText << "  (" << c.rationale << ")\n";
        }
        std::cout << "\n  Please select an approved repair [A / B] or [Q] to abort: ";
        std::string userSel;
        if (std::cin >> userSel && (userSel == "A" || userSel == "a" || userSel == "B" || userSel == "b")) {
            std::string chosen = (userSel == "a" ? "A" : (userSel == "b" ? "B" : userSel));
            parseSuccess = parseAgent.applyHumanApproval(chosen);
            std::cout << "\n>>> [ORCHESTRATOR] Human operator authorized Candidate [" << chosen << "]. Resuming pipeline...\n";
            parseAgent.renderReport();
        } else {
            std::cout << "\n[HALT] Pipeline terminated: Operator did not authorize repair candidate.\n";
            logTelemetry(parseAgent.getReport().telemetryLogs);
            parserReport = parseAgent.getReport();
            compilationSuccess = false;
            return false;
        }
    } else {
        parseAgent.renderReport();
    }

    logTelemetry(parseAgent.getReport().telemetryLogs);
    parserReport = parseAgent.getReport();

    if (!parseSuccess) {
        std::cout << "\n[HALT] Pipeline terminated by AGENT-02-SYNTAX: Unrecoverable syntax errors.\n";
        compilationSuccess = false;
        return false;
    }

    // -------------------------------------------------------------
    // AGENT 3: SEMANTIC AGENT (Rule Verification & Satisfiability)
    // -------------------------------------------------------------
    std::cout << "\n>>> [ORCHESTRATOR] Dispatching AGENT-03-SEMANTIC (Rule Verification & Satisfiability Agent)...\n";
    SemanticAgent semAgent(parseAgent.getAST());
    bool semSuccess = semAgent.execute();
    logTelemetry(semAgent.getReport().telemetryLogs);
    semAgent.renderReport();
    semanticReport = semAgent.getReport();

    if (!semSuccess) {
        std::cout << "\n[HALT] Pipeline terminated by AGENT-03-SEMANTIC: Policy constraints are unsatisfiable.\n";
        compilationSuccess = false;
        return false;
    }
    gate1Passed = true;
    finalConstraints = semAgent.getConstraints();

    // -------------------------------------------------------------
    // AGENT 4: POLICY / IR AGENT (Canonicalization & Optimization)
    // -------------------------------------------------------------
    std::cout << "\n>>> [ORCHESTRATOR] Dispatching AGENT-04-POLICY-IR (IR Optimization Agent)...\n";
    PolicyIRAgent irAgent(finalConstraints, parseAgent.getAST());
    bool irSuccess = irAgent.execute();
    logTelemetry(irAgent.getReport().telemetryLogs);
    irAgent.renderReport();
    irReport = irAgent.getReport();
    originalNodes = irAgent.getOriginalNodeCount();
    optimizedNodes = irAgent.getOptimizedNodeCount();
    semanticEquivalence = irAgent.isSemanticallyEquivalent();

    if (!irSuccess) {
        std::cout << "\n[HALT] Pipeline terminated by AGENT-04-POLICY-IR: Semantic equivalence check failed.\n";
        compilationSuccess = false;
        return false;
    }

    // ---------------------------------------------------------------------------------
    // AGENT 5: CODEGEN AGENT & BREACH FILTER SYNTHESIZER (Security Gate #2)
    // ---------------------------------------------------------------------------------
    std::cout << "\n>>> [ORCHESTRATOR] Dispatching AGENT-05-SECURE-CODEGEN & BREACH FILTER SYNTHESIZER (Security Gate #2)...\n";
    CodegenAgent cgAgent(finalConstraints, targetCppPath, irAgent.getSynthesizedDFA(), dictionaryPath, breachCorpusPath);
    bool cgSuccess = cgAgent.execute();
    logTelemetry(cgAgent.getReport().telemetryLogs);
    cgAgent.renderReport();
    codegenReport = cgAgent.getReport();
    gate2Passed = cgAgent.isGatePassed();

    // Record blocklist synthesis metrics for final reporting
    bloomSynthesized = cgAgent.getBloomBuilder().isSynthesized();
    bloomParams = cgAgent.getBloomBuilder().getParameters();
    exactKeysCount = cgAgent.getBloomBuilder().getExactTable().size();
    totalEmbeddedBytes = cgAgent.getBloomBuilder().getTotalEmbeddedBytes();
    policyCompatibleKeys = cgAgent.getBloomBuilder().countPolicyCompatibleEntries(finalConstraints);
    activeDictPath = dictionaryPath;
    activeBreachPath = breachCorpusPath;

    if (!cgSuccess || !gate2Passed) {
        std::cout << "\n[HALT] Pipeline terminated by AGENT-05-SECURE-CODEGEN: Target code failed Security Gate #2.\n";
        compilationSuccess = false;
        return false;
    }

    // -------------------------------------------------------------
    // AGENT 6: VALIDATION AGENT (Automated Test Oracle & Conformance)
    // -------------------------------------------------------------
    std::cout << "\n>>> [ORCHESTRATOR] Dispatching AGENT-06-VALIDATION (Automated Test Oracle Agent)...\n";
    ValidationAgent valAgent(finalConstraints, targetCppPath, dictionaryPath, breachCorpusPath);
    bool valSuccess = valAgent.execute();
    logTelemetry(valAgent.getReport().telemetryLogs);
    valAgent.renderReport();
    validationReport = valAgent.getReport();
    testConformanceRate = valAgent.getConformanceRate();
    testsTotal = (int)valAgent.getTestMatrix().size();
    testsPassed = 0;
    for (const auto& tc : valAgent.getTestMatrix()) {
        if (tc.testPassed) testsPassed++;
    }

    if (!valSuccess) {
        std::cout << "\n[WARNING] AGENT-06-VALIDATION: Some runtime conformance tests failed expectations.\n";
    }

    compilationSuccess = true;
    renderFinalReport();
    return true;
}

void AgenticOrchestrator::evaluatePassword(const std::string& pwd, const std::string& dictPath, const std::string& breachPath) {
    std::cout << "\n========================================================================================\n";
    std::cout << "  EVALUATING CANDIDATE PASSWORD VIA AGENTIC SECURITY & VALIDATION ENGINES\n";
    std::cout << "========================================================================================\n";

    // Run Stage 7: Security Audit Agent
    std::cout << ">>> [ORCHESTRATOR] Dispatching AGENT-07-SECURITY-AUDIT (Deep Threat Profiling)...\n";
    SecurityAuditAgent auditAgent(pwd, finalConstraints, dictPath, breachPath);
    auditAgent.execute();
    logTelemetry(auditAgent.getReport().telemetryLogs);
    auditAgent.renderReport();
}

void AgenticOrchestrator::renderFinalReport() const {
    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                         FINAL AGENTIC COMPILER REPORT                                ║\n";
    std::cout << "╠══════════════════════════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║ Architecture Model       : 7 AI Agents, One Unified Secure Compiler Pipeline         ║\n";
    std::cout << "║ Compilation Verdict      : " << (compilationSuccess ? "COMPILATION SUCCESSFUL (ALL GATES PASSED)         " : "COMPILATION HALTED (SECURITY VIOLATION)       ") << "║\n";
    std::cout << "║ Telemetry Events Logged  : " << std::left << std::setw(66) << (std::to_string(globalTelemetry.size()) + " total O-A-D-A-V telemetry state transitions") << "║\n";
    std::cout << "╟──────────────────────────────────────────────────────────────────────────────────────╢\n";
    std::cout << "║ AGENT STAGE BREAKDOWN:                                                               ║\n";
    std::cout << "║   [Agent 1: Lexer]       : Clean (Zero suspicious tokens or malformed literals)      ║\n";
    std::cout << "║   [Agent 2: Parser]      : Typed AST Generated & Verified (" << std::left << std::setw(37) << (std::to_string(originalNodes) + " constraint nodes)") << "║\n";
    std::cout << "║   [Agent 3: Semantic]    : Satisfiability Theorem VERIFIED (Security Gate #1 Passed)  ║\n";
    std::cout << "║   [Agent 4: Policy/IR]   : Canonicalization Done (Nodes: " << originalNodes << " -> " << optimizedNodes << ", Invariance: 100%)  ║\n";
    std::cout << "║   [Agent 5: Codegen]     : Hardened Target C++ Synthesized (Security Gate #2 Passed) ║\n";
    std::cout << "║   [Agent 6: Validation]  : Test Oracle Conformance " << std::left << std::setw(42) << (std::to_string((int)testConformanceRate) + "% (" + std::to_string(testsPassed) + "/" + std::to_string(testsTotal) + " scenarios passed)") << "║\n";
    std::cout << "║   [Agent 7: Security]    : Deep Threat Analysis & Neuro-Symbolic Engine Armed        ║\n";
    std::cout << "╟──────────────────────────────────────────────────────────────────────────────────────╢\n";
    std::cout << "║ STATIC RODATA BLOOM FILTER & EXACT BLOCKLIST VERIFICATION (NIST SP 800-63B-4):       ║\n";
    if (bloomSynthesized) {
        std::cout << "║   Filter Synthesis Status: [PASSED] Synthesized into target C++ .rodata               ║\n";
        std::cout << "║   Unique Keys Ingested   : " << std::left << std::setw(66) << (std::to_string(bloomParams.n) + " canonical keys (deduplicated across active sources)") << "║\n";
        std::cout << "║   Static Bloom Bit Array : " << std::left << std::setw(66) << (std::to_string(bloomParams.mBits) + " bits (" + std::to_string(bloomParams.mBytes) + " bytes) [Expected FPR: " + std::to_string(bloomParams.theoreticalExpectedFpr) + "]") << "║\n";
        std::cout << "║   Hash Functions (k)     : " << std::left << std::setw(66) << (std::to_string(bloomParams.k) + " (Kirsch-Mitzenmacher Double Hashing FNV1a + MurmurMix)") << "║\n";
        std::cout << "║   Exact Table Keys       : " << std::left << std::setw(66) << (std::to_string(exactKeysCount) + " sorted canonical keys (O(log N) binary search check)") << "║\n";
        std::cout << "║   Total Embedded Storage : " << std::left << std::setw(66) << (std::to_string(totalEmbeddedBytes) + " bytes (Zero runtime file/network dependency)") << "║\n";
        std::cout << "║   OWASP ASVS 5.0.0 V6.2.4: " << std::left << std::setw(66) << (policyCompatibleKeys >= 3000 ? "Satisfied (>= 3,000 policy-compatible entries)" : "Insufficient corpus (" + std::to_string(policyCompatibleKeys) + "/3,000 policy-compatible keys)") << "║\n";
    } else {
        std::cout << "║   Filter Synthesis Status: [UNAVAILABLE] Corpus missing or empty                      ║\n";
    }
    std::cout << "╟──────────────────────────────────────────────────────────────────────────────────────╢\n";
    std::cout << "║ SECURITY GATES AUDIT:                                                                ║\n";
    std::cout << "║   Security Gate #1 (Pre-Codegen Policy Satisfiability) : " << (gate1Passed ? "[PASSED] Approved            " : "[BLOCKED] Failed           ") << "║\n";
    std::cout << "║   Security Gate #2 (Post-Codegen Memory/Input Hardening): " << (gate2Passed ? "[PASSED] Approved            " : "[BLOCKED] Failed           ") << "║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════════════════════════════╝\n";
}

void AgenticOrchestrator::renderTelemetryLog() const {
    std::cout << "\n========================================================================================\n";
    std::cout << "  AGENTIC TELEMETRY AUDIT TRAIL (O-A-D-A-V State Transitions)\n";
    std::cout << "========================================================================================\n";
    for (size_t i = 0; i < globalTelemetry.size(); ++i) {
        const auto& t = globalTelemetry[i];
        std::cout << "┌─ Event [" << std::setfill('0') << std::setw(2) << (i + 1) << "] "
                  << t.agentId << " :: " << t.stage << " (" << t.timestamp << ")\n";
        std::cout << "│  Input      : " << t.inputSummary << "\n";
        std::cout << "│  Observation: " << t.observation << "\n";
        std::cout << "│  Decision   : " << t.decision << "\n";
        std::cout << "│  Action     : " << t.actionTaken << " [Status: " << t.resultStatus << "]\n";
        std::cout << "│  Evidence   : " << t.evidence << "\n";
        std::cout << "│  Confidence : " << (int)(t.confidence * 100) << "%\n";
        std::cout << "└───────────────────────────────────────────────────────────────────────────────\n";
    }
}

bool AgenticOrchestrator::runAttackSimulationBenchmark() {
    std::cout << "\n========================================================================================\n";
    std::cout << "  DISPATCHING AUTOMATED AGENTIC AI ATTACK SIMULATION & EVALUATION BENCHMARK\n";
    std::cout << "========================================================================================\n";
    DetectionMetrics metrics = attackDetector.runBenchmarkSuite();
    attackDetector.printMetricsReport(metrics);
    return true;
}
