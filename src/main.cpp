#include <algorithm>
#include <cctype>
#include <cstdio>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#ifdef _WIN32
#include <direct.h>
#define MKDIR_ONE(d) _mkdir(d)
#else
#include <sys/stat.h>
#define MKDIR_ONE(d) mkdir(d, 0755)
#endif

#include "agent_attack_detector.h"
#include "agent_codegen.h"
#include "agent_lexer.h"
#include "agent_parser.h"
#include "agent_policy_ir.h"
#include "agent_security_audit.h"
#include "agent_semantic.h"
#include "agent_types.h"
#include "agent_validation.h"
#include "agentic_orchestrator.h"
#include "ast.h"
#include "diagnostics.h"
#include "token.h"

using namespace std;

static string readAll(const string &path) {
  ifstream in(path.c_str());
  ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

static string escapeJson(const string &s) {
  ostringstream o;
  for (char c : s) {
    if (c == '\"') {
      o << "\\\"";
    } else if (c == '\\') {
      o << "\\\\";
    } else if (c == '\b') {
      o << "\\b";
    } else if (c == '\f') {
      o << "\\f";
    } else if (c == '\n') {
      o << "\\n";
    } else if (c == '\r') {
      o << "\\r";
    } else if (c == '\t') {
      o << "\\t";
    } else if ((unsigned char)c < 32) {
      o << "\\u" << hex << setw(4) << setfill('0')
        << (int)(unsigned char)c << dec;
    } else {
      o << c;
    }
  }
  return o.str();
}

static void ensureDir(const string &path) {
  if (path.empty())
    return;
  string cur;
  for (size_t i = 0; i < path.size(); ++i) {
    char c = path[i];
    if (c == '/' || c == '\\') {
      if (!cur.empty() && cur != "." && cur[cur.size() - 1] != ':')
        MKDIR_ONE(cur.c_str());
    }
    cur += c;
  }
  if (!cur.empty() && cur != "." && cur[cur.size() - 1] != ':')
    MKDIR_ONE(cur.c_str());
}

static const char *riskLevelName(ThreatRiskLevel level) {
  switch (level) {
  case ThreatRiskLevel::SAFE:
    return "SAFE";
  case ThreatRiskLevel::LOW:
    return "LOW";
  case ThreatRiskLevel::MEDIUM:
    return "MEDIUM";
  case ThreatRiskLevel::HIGH:
    return "HIGH";
  case ThreatRiskLevel::CRITICAL:
    return "CRITICAL";
  default:
    return "UNKNOWN";
  }
}

static int runStageMode(const string &stage, const string &policySource,
                        const string &outDir, const string &approvedRepair,
                        const string &dictPath, const string &breachPath) {
  ensureDir(outDir);

  if (stage == "guard") {
    AgentAttackDetector attackDetector;
    AttackAssessment attackAssess =
        attackDetector.inspectPolicyInput(policySource);

    string guardReportPath = outDir + "/guard_report.json";
    ofstream gr(guardReportPath.c_str());
    gr << "{\n"
       << "  \"isAttack\": " << (attackAssess.isAttack ? "true" : "false")
       << ",\n"
       << "  \"categoryName\": \"" << escapeJson(attackAssess.categoryName)
       << "\",\n"
       << "  \"riskLevel\": \"" << riskLevelName(attackAssess.riskLevel)
       << "\",\n"
       << "  \"attackPatternDetected\": \""
       << escapeJson(attackAssess.attackPatternDetected) << "\",\n"
       << "  \"mitigationAction\": \""
       << escapeJson(attackAssess.mitigationAction) << "\",\n"
       << "  \"explanation\": \"" << escapeJson(attackAssess.explanation)
       << "\"\n"
       << "}\n";
    gr.close();

    string stageResultPath = outDir + "/stage_result.json";
    ofstream sr(stageResultPath.c_str());
    sr << "{\n"
       << "  \"stage\": \"guard\",\n"
       << "  \"ok\": " << (attackAssess.isAttack ? "false" : "true") << ",\n"
       << "  \"decision\": \"" << (attackAssess.isAttack ? "BLOCK" : "PASS")
       << "\",\n"
       << "  \"artifact_file\": \"guard_report.json\"\n"
       << "}\n";
    sr.close();

    return attackAssess.isAttack ? 1 : 0;
  }

  if (stage == "lex") {
    LexerAgent lexAgent(policySource);
    bool lexSuccess = lexAgent.execute();

    string tokensPath = outDir + "/tokens.json";
    ofstream tf(tokensPath.c_str());
    tf << "[\n";
    const auto &toks = lexAgent.getTokens();
    for (size_t i = 0; i < toks.size(); ++i) {
      tf << "  {\"type\": \"" << tokenTypeName(toks[i].type)
         << "\", \"lexeme\": \"" << escapeJson(toks[i].lexeme)
         << "\", \"line\": " << toks[i].pos.line
         << ", \"col\": " << toks[i].pos.col << "}"
         << (i + 1 < toks.size() ? ",\n" : "\n");
    }
    tf << "]\n";
    tf.close();

    string stageResultPath = outDir + "/stage_result.json";
    ofstream sr(stageResultPath.c_str());
    sr << "{\n"
       << "  \"stage\": \"lex\",\n"
       << "  \"ok\": " << (lexSuccess ? "true" : "false") << ",\n"
       << "  \"decision\": \"" << (lexSuccess ? "PROCEED" : "BLOCK") << "\",\n"
       << "  \"artifact_file\": \"tokens.json\"\n"
       << "}\n";
    sr.close();

    return lexSuccess ? 0 : 1;
  }

  if (stage == "parse") {
    LexerAgent lexAgent(policySource);
    if (!lexAgent.execute()) {
      ofstream astFile((outDir + "/ast.json").c_str());
      astFile << "{\"nodeCount\": 0, \"nodes\": []}\n";
      astFile.close();

      ofstream sr((outDir + "/stage_result.json").c_str());
      sr << "{\n"
         << "  \"stage\": \"parse\",\n"
         << "  \"ok\": false,\n"
         << "  \"decision\": \"BLOCK\",\n"
         << "  \"artifact_file\": \"ast.json\"\n"
         << "}\n";
      sr.close();
      return 1;
    }

    ParserAgent parseAgent(lexAgent.getTokens(), approvedRepair);
    bool parseSuccess = parseAgent.execute();

    if (!parseSuccess && parseAgent.needsHumanApproval()) {
      ofstream astFile((outDir + "/ast.json").c_str());
      astFile << "{\"nodeCount\": 0, \"nodes\": []}\n";
      astFile.close();

      ofstream sr((outDir + "/stage_result.json").c_str());
      sr << "{\n"
         << "  \"stage\": \"parse\",\n"
         << "  \"ok\": false,\n"
         << "  \"decision\": \"NEEDS_HUMAN\",\n"
         << "  \"artifact_file\": \"ast.json\",\n"
         << "  \"candidates\": [\n";
      const auto &cands = parseAgent.getCandidates();
      for (size_t i = 0; i < cands.size(); ++i) {
        sr << "    {\n"
           << "      \"id\": \"" << escapeJson(cands[i].id) << "\",\n"
           << "      \"candidateText\": \""
           << escapeJson(cands[i].candidateText) << "\",\n"
           << "      \"rationale\": \"" << escapeJson(cands[i].rationale)
           << "\",\n"
           << "      \"confidence\": " << cands[i].confidence << "\n"
           << "    }" << (i + 1 < cands.size() ? ",\n" : "\n");
      }
      sr << "  ]\n"
         << "}\n";
      sr.close();
      return 20;
    }

    if (!parseSuccess) {
      ofstream astFile((outDir + "/ast.json").c_str());
      astFile << "{\"nodeCount\": 0, \"nodes\": []}\n";
      astFile.close();

      ofstream sr((outDir + "/stage_result.json").c_str());
      sr << "{\n"
         << "  \"stage\": \"parse\",\n"
         << "  \"ok\": false,\n"
         << "  \"decision\": \"BLOCK\",\n"
         << "  \"artifact_file\": \"ast.json\"\n"
         << "}\n";
      sr.close();
      return 1;
    }

    const PolicyAST &ast = parseAgent.getAST();
    ofstream astFile((outDir + "/ast.json").c_str());
    astFile << "{\n"
            << "  \"nodeCount\": " << ast.nodes.size() << ",\n"
            << "  \"nodes\": [\n";
    for (size_t i = 0; i < ast.nodes.size(); ++i) {
      const auto &n = ast.nodes[i];
      astFile << "    {\n"
              << "      \"line\": " << n->pos.line << ",\n"
              << "      \"col\": " << n->pos.col << ",\n"
              << "      \"repr\": \"" << escapeJson(n->toString()) << "\"";
      if (n->nodeType == ASTNodeType::LengthConstraint) {
        auto lc = dynamic_pointer_cast<LengthConstraintNode>(n);
        if (lc) {
          astFile << ",\n      \"nodeType\": \"LengthConstraint\",\n"
                  << "      \"boundType\": \"" << escapeJson(lc->boundType)
                  << "\",\n"
                  << "      \"length\": " << lc->length;
        }
      } else if (n->nodeType == ASTNodeType::CharacterConstraint) {
        auto cc = dynamic_pointer_cast<CharacterConstraintNode>(n);
        if (cc) {
          astFile << ",\n      \"nodeType\": \"CharacterConstraint\",\n"
                  << "      \"charClass\": \"" << escapeJson(cc->charClass)
                  << "\",\n"
                  << "      \"minCount\": " << cc->minCount;
        }
      } else if (n->nodeType == ASTNodeType::PatternConstraint) {
        auto pc = dynamic_pointer_cast<PatternConstraintNode>(n);
        if (pc) {
          astFile << ",\n      \"nodeType\": \"PatternConstraint\",\n"
                  << "      \"patternType\": \"" << escapeJson(pc->patternType)
                  << "\",\n"
                  << "      \"threshold\": " << pc->threshold;
        }
      } else if (n->nodeType == ASTNodeType::DictionaryConstraint) {
        auto dc = dynamic_pointer_cast<DictionaryConstraintNode>(n);
        if (dc) {
          astFile << ",\n      \"nodeType\": \"DictionaryConstraint\",\n"
                  << "      \"blacklistedWord\": \""
                  << escapeJson(dc->blacklistedWord) << "\"";
        }
      } else if (n->nodeType == ASTNodeType::StrengthConstraint) {
        auto sc = dynamic_pointer_cast<StrengthConstraintNode>(n);
        if (sc) {
          astFile << ",\n      \"nodeType\": \"StrengthConstraint\",\n"
                  << "      \"minimumLevel\": \""
                  << escapeJson(sc->minimumLevel) << "\"";
        }
      }
      astFile << "\n    }" << (i + 1 < ast.nodes.size() ? ",\n" : "\n");
    }
    astFile << "  ]\n"
            << "}\n";
    astFile.close();

    ofstream sr((outDir + "/stage_result.json").c_str());
    sr << "{\n"
       << "  \"stage\": \"parse\",\n"
       << "  \"ok\": true,\n"
       << "  \"decision\": \"PROCEED\",\n"
       << "  \"artifact_file\": \"ast.json\"\n"
       << "}\n";
    sr.close();
    return 0;
  }

  if (stage == "semantic") {
    LexerAgent lexAgent(policySource);
    if (!lexAgent.execute())
      return 1;
    ParserAgent parseAgent(lexAgent.getTokens(), approvedRepair);
    if (!parseAgent.execute()) {
      if (parseAgent.needsHumanApproval())
        return 20;
      return 1;
    }

    SemanticAgent semAgent(parseAgent.getAST());
    bool semSuccess = semAgent.execute();
    const PolicyConstraints &c = semAgent.getConstraints();

    string constraintsPath = outDir + "/constraints.json";
    ofstream cf(constraintsPath.c_str());
    cf << "{\n"
       << "  \"minLength\": " << c.minLength << ",\n"
       << "  \"maxLength\": " << c.maxLength << ",\n"
       << "  \"minUpper\": " << c.minUpper << ",\n"
       << "  \"minLower\": " << c.minLower << ",\n"
       << "  \"minDigit\": " << c.minDigit << ",\n"
       << "  \"minSpecial\": " << c.minSpecial << ",\n"
       << "  \"noSpaces\": " << c.noSpaces << ",\n"
       << "  \"maxSequence\": " << c.maxSequence << ",\n"
       << "  \"maxRepeated\": " << c.maxRepeated << ",\n"
       << "  \"minStrength\": \"" << escapeJson(c.minStrength) << "\",\n"
       << "  \"blacklist\": [";
    for (size_t i = 0; i < c.blacklist.size(); ++i) {
      cf << "\"" << escapeJson(c.blacklist[i]) << "\""
         << (i + 1 < c.blacklist.size() ? ", " : "");
    }
    cf << "]\n"
       << "}\n";
    cf.close();

    ofstream sr((outDir + "/stage_result.json").c_str());
    sr << "{\n"
       << "  \"stage\": \"semantic\",\n"
       << "  \"ok\": " << (semSuccess ? "true" : "false") << ",\n"
       << "  \"decision\": \"" << (semSuccess ? "APPROVE" : "REJECT") << "\",\n"
       << "  \"artifact_file\": \"constraints.json\"\n"
       << "}\n";
    sr.close();
    return semSuccess ? 0 : 1;
  }

  if (stage == "ir") {
    LexerAgent lexAgent(policySource);
    if (!lexAgent.execute())
      return 1;
    ParserAgent parseAgent(lexAgent.getTokens(), approvedRepair);
    if (!parseAgent.execute()) {
      if (parseAgent.needsHumanApproval())
        return 20;
      return 1;
    }
    SemanticAgent semAgent(parseAgent.getAST());
    if (!semAgent.execute())
      return 1;

    PolicyIRAgent irAgent(semAgent.getConstraints(), parseAgent.getAST());
    bool irSuccess = irAgent.execute();
    const PolicyIR &ir = irAgent.getIR();

    string irPath = outDir + "/ir.json";
    ofstream irf(irPath.c_str());
    irf << "{\n"
        << "  \"originalNodeCount\": " << irAgent.getOriginalNodeCount()
        << ",\n"
        << "  \"optimizedNodeCount\": " << irAgent.getOptimizedNodeCount()
        << ",\n"
        << "  \"semanticEquivalence\": "
        << (irAgent.isSemanticallyEquivalent() ? "true" : "false") << ",\n"
        << "  \"length\": {\"minLength\": " << ir.length.minLength
        << ", \"maxLength\": " << ir.length.maxLength << "},\n"
        << "  \"charClass\": {\"minUpper\": " << ir.charClass.minUpper
        << ", \"minLower\": " << ir.charClass.minLower
        << ", \"minDigit\": " << ir.charClass.minDigit
        << ", \"minSpecial\": " << ir.charClass.minSpecial << "},\n"
        << "  \"pattern\": {\"forbidSpaces\": "
        << (ir.pattern.forbidSpaces ? "true" : "false")
        << ", \"sequenceLimit\": " << ir.pattern.sequenceLimit
        << ", \"repetitionLimit\": " << ir.pattern.repetitionLimit << "},\n"
        << "  \"security\": {\"strengthRequirement\": \""
        << escapeJson(ir.security.strengthRequirement)
        << "\", \"blacklist\": [";
    for (size_t i = 0; i < ir.security.blacklist.size(); ++i) {
      irf << "\"" << escapeJson(ir.security.blacklist[i]) << "\""
          << (i + 1 < ir.security.blacklist.size() ? ", " : "");
    }
    irf << "]}\n"
        << "}\n";
    irf.close();

    ofstream sr((outDir + "/stage_result.json").c_str());
    sr << "{\n"
       << "  \"stage\": \"ir\",\n"
       << "  \"ok\": " << (irSuccess ? "true" : "false") << ",\n"
       << "  \"decision\": \"" << (irSuccess ? "PROCEED" : "BLOCK") << "\",\n"
       << "  \"artifact_file\": \"ir.json\"\n"
       << "}\n";
    sr.close();
    return irSuccess ? 0 : 1;
  }

  if (stage == "codegen") {
    LexerAgent lexAgent(policySource);
    if (!lexAgent.execute())
      return 1;
    ParserAgent parseAgent(lexAgent.getTokens(), approvedRepair);
    if (!parseAgent.execute()) {
      if (parseAgent.needsHumanApproval())
        return 20;
      return 1;
    }
    SemanticAgent semAgent(parseAgent.getAST());
    if (!semAgent.execute())
      return 1;
    PolicyIRAgent irAgent(semAgent.getConstraints(), parseAgent.getAST());
    if (!irAgent.execute())
      return 1;

    string targetCpp = outDir + "/validator.cpp";
    CodegenAgent cgAgent(semAgent.getConstraints(), targetCpp,
                         irAgent.getSynthesizedDFA(), dictPath, breachPath);
    bool cgSuccess = cgAgent.execute();
    bool gate2 = cgAgent.isGatePassed();
    bool ok = cgSuccess && gate2;

    remove((outDir + "/generated_bloom_manifest.json").c_str());

    ofstream sr((outDir + "/stage_result.json").c_str());
    sr << "{\n"
       << "  \"stage\": \"codegen\",\n"
       << "  \"ok\": " << (ok ? "true" : "false") << ",\n"
       << "  \"decision\": \"" << (ok ? "PROCEED" : "BLOCK") << "\",\n"
       << "  \"artifact_file\": \"validator.cpp\"\n"
       << "}\n";
    sr.close();
    return ok ? 0 : 1;
  }

  if (stage == "test") {
    LexerAgent lexAgent(policySource);
    if (!lexAgent.execute())
      return 1;
    ParserAgent parseAgent(lexAgent.getTokens(), approvedRepair);
    if (!parseAgent.execute()) {
      if (parseAgent.needsHumanApproval())
        return 20;
      return 1;
    }
    SemanticAgent semAgent(parseAgent.getAST());
    if (!semAgent.execute())
      return 1;
    PolicyIRAgent irAgent(semAgent.getConstraints(), parseAgent.getAST());
    if (!irAgent.execute())
      return 1;

    string targetCpp = outDir + "/validator.cpp";
    bool createdTmp = false;
    {
      ifstream testV(targetCpp.c_str());
      if (!testV.is_open()) {
        CodegenAgent cgAgent(semAgent.getConstraints(), targetCpp,
                             irAgent.getSynthesizedDFA(), dictPath, breachPath);
        cgAgent.execute();
        createdTmp = true;
      }
    }

    ValidationAgent valAgent(semAgent.getConstraints(), targetCpp, dictPath,
                             breachPath);
    valAgent.execute();

    if (createdTmp) {
      remove(targetCpp.c_str());
    }
    remove((outDir + "/generated_bloom_manifest.json").c_str());

    int testsTotal = (int)valAgent.getTestMatrix().size();
    int testsPassed = 0;
    for (const auto &tc : valAgent.getTestMatrix()) {
      if (tc.testPassed)
        testsPassed++;
    }
    bool allPassed = (testsPassed == testsTotal && testsTotal > 0);

    string testReportPath = outDir + "/test_report.json";
    ofstream tr(testReportPath.c_str());
    tr << "{\n"
       << "  \"conformance_rate\": " << valAgent.getConformanceRate() << ",\n"
       << "  \"tests_total\": " << testsTotal << ",\n"
       << "  \"tests_passed\": " << testsPassed << ",\n"
       << "  \"all_passed\": " << (allPassed ? "true" : "false") << ",\n"
       << "  \"test_cases\": [\n";
    const auto &matrix = valAgent.getTestMatrix();
    for (size_t i = 0; i < matrix.size(); ++i) {
      tr << "    {\n"
         << "      \"test_name\": \"" << escapeJson(matrix[i].testName)
         << "\",\n"
         << "      \"candidate_password\": \""
         << escapeJson(matrix[i].candidatePassword) << "\",\n"
         << "      \"expected_valid\": "
         << (matrix[i].expectedValid ? "true" : "false") << ",\n"
         << "      \"actual_valid\": "
         << (matrix[i].actualValid ? "true" : "false") << ",\n"
         << "      \"test_passed\": "
         << (matrix[i].testPassed ? "true" : "false") << "\n"
         << "    }" << (i + 1 < matrix.size() ? ",\n" : "\n");
    }
    tr << "  ]\n"
       << "}\n";
    tr.close();

    ofstream sr((outDir + "/stage_result.json").c_str());
    sr << "{\n"
       << "  \"stage\": \"test\",\n"
       << "  \"ok\": " << (allPassed ? "true" : "false") << ",\n"
       << "  \"decision\": \"" << (allPassed ? "PASS" : "FAIL") << "\",\n"
       << "  \"artifact_file\": \"test_report.json\"\n"
       << "}\n";
    sr.close();
    return allPassed ? 0 : 1;
  }

  if (stage == "audit") {
    LexerAgent lexAgent(policySource);
    if (!lexAgent.execute())
      return 1;
    ParserAgent parseAgent(lexAgent.getTokens(), approvedRepair);
    if (!parseAgent.execute()) {
      if (parseAgent.needsHumanApproval())
        return 20;
      return 1;
    }
    SemanticAgent semAgent(parseAgent.getAST());
    if (!semAgent.execute())
      return 1;
    PolicyIRAgent irAgent(semAgent.getConstraints(), parseAgent.getAST());
    if (!irAgent.execute())
      return 1;

    string targetCpp = outDir + "/validator.cpp";
    bool createdTmp = false;
    {
      ifstream testV(targetCpp.c_str());
      if (!testV.is_open()) {
        createdTmp = true;
      }
    }
    string cgTarget =
        createdTmp ? (outDir + "/.tmp_audit_validator.cpp") : targetCpp;
    CodegenAgent cgAgent(semAgent.getConstraints(), cgTarget,
                         irAgent.getSynthesizedDFA(), dictPath, breachPath);
    cgAgent.execute();
    if (createdTmp) {
      remove(cgTarget.c_str());
    }
    remove((outDir + "/generated_bloom_manifest.json").c_str());
    bool gate2 = cgAgent.isGatePassed();
    const auto &checklist = cgAgent.getChecklist();

    string auditReportPath = outDir + "/audit_report.json";
    ofstream ar(auditReportPath.c_str());
    ar << "{\n"
       << "  \"gate2_passed\": " << (gate2 ? "true" : "false") << ",\n"
       << "  \"decision\": \"" << (gate2 ? "APPROVE" : "BLOCK") << "\",\n"
       << "  \"checklist\": [\n";
    for (size_t i = 0; i < checklist.size(); ++i) {
      ar << "    {\n"
         << "      \"name\": \"" << escapeJson(checklist[i].name) << "\",\n"
         << "      \"passed\": " << (checklist[i].passed ? "true" : "false")
         << ",\n"
         << "      \"detail\": \"" << escapeJson(checklist[i].detail) << "\"\n"
         << "    }" << (i + 1 < checklist.size() ? ",\n" : "\n");
    }
    ar << "  ]\n"
       << "}\n";
    ar.close();

    ofstream sr((outDir + "/stage_result.json").c_str());
    sr << "{\n"
       << "  \"stage\": \"audit\",\n"
       << "  \"ok\": " << (gate2 ? "true" : "false") << ",\n"
       << "  \"decision\": \"" << (gate2 ? "APPROVE" : "REJECT") << "\",\n"
       << "  \"artifact_file\": \"audit_report.json\"\n"
       << "}\n";
    sr.close();
    return gate2 ? 0 : 1;
  }

  cerr << "[ERROR] Unknown stage: " << stage << "\n";
  return 1;
}

int main(int argc, char *argv[]) {
  string stage = "";
  string outDir = "";
  string policyPath = "";
  bool showTelemetry = false;
  string cliPassword = "";
  string dictPath = "dictionary.txt";
  string breachPath = "";
  string approvedRepair = "";
  bool simulateAttacks = false;

  for (int i = 1; i < argc; ++i) {
    string arg = argv[i];
    if (arg == "--simulate-attacks") {
      simulateAttacks = true;
    } else if (arg == "--stage" && i + 1 < argc) {
      stage = argv[++i];
    } else if (arg == "--policy" && i + 1 < argc) {
      policyPath = argv[++i];
    } else if (arg == "--out-dir" && i + 1 < argc) {
      outDir = argv[++i];
    } else if (arg == "--approve-repair" && i + 1 < argc) {
      approvedRepair = argv[++i];
    } else if (arg == "--telemetry") {
      showTelemetry = true;
    } else if (arg == "--password" && i + 1 < argc) {
      cliPassword = argv[++i];
    } else if (arg == "--dictionary" && i + 1 < argc) {
      dictPath = argv[++i];
    } else if (arg == "--breach-corpus" && i + 1 < argc) {
      breachPath = argv[++i];
    } else if (arg.rfind("--", 0) != 0 && policyPath.empty()) {
      policyPath = arg;
    }
  }

  // Direct attack simulation mode
  if (simulateAttacks) {
    cout << "=================================================================="
            "======================\n";
    cout << "  AGENTIC AI PASSWORD POLICY COMPILER (Version 3.0 Enterprise)\n";
    cout << "  Architecture: 7 Specialized AI Compiler Agents | Dual Security "
            "Gates | Telemetry Log\n";
    cout << "  Enhancement : Static RODATA Bloom Filter + Exact Verification + "
            "Leetspeak Analysis\n";
    cout << "=================================================================="
            "======================\n";
    AgenticOrchestrator orchestrator;
    orchestrator.runAttackSimulationBenchmark();
    return 0;
  }

  // Dictionary and breach path resolution
  if (breachPath.empty()) {
    ifstream dbf("data/breach_corpus.txt");
    if (dbf.is_open())
      breachPath = "data/breach_corpus.txt";
    else {
      ifstream bf("breach_corpus.txt");
      if (bf.is_open())
        breachPath = "breach_corpus.txt";
      else {
        ifstream cbf("CODE/breach_corpus.txt");
        if (cbf.is_open())
          breachPath = "CODE/breach_corpus.txt";
      }
    }
  }

  if (dictPath == "dictionary.txt") {
    ifstream ddf("data/dictionary.txt");
    if (ddf.is_open())
      dictPath = "data/dictionary.txt";
    else {
      ifstream df("dictionary.txt");
      if (!df.is_open()) {
        ifstream cdf("CODE/dictionary.txt");
        if (cdf.is_open())
          dictPath = "CODE/dictionary.txt";
      }
    }
  }

  if (policyPath.empty()) {
    cout << "Usage  : policy_compiler <policyfile> [options]\n";
    cout << "         policy_compiler --simulate-attacks\n";
    cout << "         policy_compiler --stage "
            "<guard|lex|parse|semantic|ir|codegen|test|audit> --policy <file> "
            "--out-dir <dir> [--approve-repair X]\n";
    cout << "Options:\n";
    cout << "  --simulate-attacks       Run automated PBL attack simulation "
            "suite & detection metrics\n";
    cout << "  --stage <name>           Execute single pipeline stage (guard, "
            "lex, parse, semantic, ir, codegen, test, audit)\n";
    cout << "  --policy <path>          Path to policy file\n";
    cout << "  --out-dir <path>         Output directory for stage artifacts\n";
    cout << "  --telemetry              Display full O-A-D-A-V agent telemetry "
            "event trail\n";
    cout << "  --password <pwd>         Directly evaluate candidate password "
            "non-interactively\n";
    cout << "  --dictionary <path>      Specify custom dictionary (default: "
            "dictionary.txt)\n";
    cout << "  --breach-corpus <path>   Specify optional breach corpus dataset "
            "(e.g. breach_corpus.txt)\n";
    cout << "  --approve-repair <X>     Pre-approve ambiguous repair candidate "
            "(e.g. A or B)\n";
    return 0;
  }

  ifstream chk(policyPath.c_str());
  if (!chk) {
    string fallbackTestPath = "tests/" + policyPath;
    ifstream chk2(fallbackTestPath.c_str());
    if (chk2) {
      policyPath = fallbackTestPath;
    } else {
      cout << "[ERROR] Cannot open policy file: " << policyPath << "\n";
      return 1;
    }
  }

  string policySource = readAll(policyPath);

  // Stage mode dispatch
  if (!stage.empty()) {
    if (outDir.empty()) {
      cerr << "[ERROR] --out-dir is required in stage mode\n";
      return 1;
    }
    return runStageMode(stage, policySource, outDir, approvedRepair, dictPath,
                        breachPath);
  }

  // Default interactive / full-compilation pipeline mode
  cout << "===================================================================="
          "====================\n";
  cout << "  AGENTIC AI PASSWORD POLICY COMPILER (Version 3.0 Enterprise)\n";
  cout << "  Architecture: 7 Specialized AI Compiler Agents | Dual Security "
          "Gates | Telemetry Log\n";
  cout << "  Enhancement : Static RODATA Bloom Filter + Exact Verification + "
          "Leetspeak Analysis\n";
  cout << "===================================================================="
          "====================\n";

  // Initialize Agentic Orchestrator
  AgenticOrchestrator orchestrator;

  // Run full 7-Agent Compilation Pipeline with routed dictionary and breach
  // corpus paths
  bool success =
      orchestrator.compilePolicy(policySource, "generated_validator.cpp",
                                 approvedRepair, dictPath, breachPath);

  if (showTelemetry) {
    orchestrator.renderTelemetryLog();
  }

  if (!success) {
    cout << "\n[HALT] Agentic compilation terminated due to security or "
            "constraint violations.\n";
    return 1;
  }

  // Password Evaluation Phase
  if (!cliPassword.empty()) {
    orchestrator.evaluatePassword(cliPassword, dictPath, breachPath);
    return 0;
  }

  // Interactive Password Evaluation Loop
  cout << "\n=================================================================="
          "======================\n";
  cout << "  INTERACTIVE EVALUATION LAB (Testing Candidate Passwords against "
          "Compiled Policy)\n";
  cout << "===================================================================="
          "====================\n";
  cout << "Enter candidate passwords to test against the policy (type "
          "'telemetry' for audit log, 'exit' to quit):\n";

  string inputLine;
  while (true) {
    cout << "\nEnter password to evaluate > ";
    if (!getline(cin, inputLine))
      break;
    if (inputLine.empty())
      continue;
    if (inputLine == "exit" || inputLine == "quit") {
      cout << "Exiting Agentic Compiler Platform. Goodbye!\n";
      break;
    }
    if (inputLine == "telemetry") {
      orchestrator.renderTelemetryLog();
      continue;
    }

    orchestrator.evaluatePassword(inputLine, dictPath, breachPath);
  }

  return 0;
}
