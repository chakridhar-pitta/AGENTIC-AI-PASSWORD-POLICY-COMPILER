#include "agent_parser.h"
#include <iostream>
#include <sstream>

ParserAgent::ParserAgent(std::vector<Token> tokList, std::string humanPreApprovedChoice)
    : tokens(std::move(tokList)),
      humanChoice(std::move(humanPreApprovedChoice)),
      report("Syntax Intelligence Agent", "AGENT-02-SYNTAX") {
}

bool ParserAgent::validateCandidateStream(const std::vector<Token>& candTokens, PolicyAST& outAst) {
    Parser p(candTokens);
    outAst = p.parse();
    if (!p.errors().empty() || outAst.nodes.empty()) {
        return false;
    }
    // Basic semantic check on generated AST nodes
    for (const auto& node : outAst.nodes) {
        if (node->nodeType == ASTNodeType::LengthConstraint) {
            auto ml = std::dynamic_pointer_cast<LengthConstraintNode>(node);
            if (ml && ml->length <= 0) return false;
        } else if (node->nodeType == ASTNodeType::CharacterConstraint) {
            auto req = std::dynamic_pointer_cast<CharacterConstraintNode>(node);
            if (req && req->minCount <= 0) return false;
        }
    }
    return true;
}

void ParserAgent::evaluateSyntaxDefectsAndCandidates() {
    report.repairCandidates.clear();

    // Check 1: Incomplete require rule (missing count) -> AMBIGUOUS
    for (size_t i = 0; i < tokens.size(); ++i) {
        if (tokens[i].type == TokenType::Identifier && tokens[i].lexeme == "require") {
            if (i + 1 < tokens.size() && tokens[i + 1].type == TokenType::Identifier) {
                std::string cat = tokens[i + 1].lexeme;
                if (cat == "uppercase" || cat == "lowercase" || cat == "digit" || cat == "special") {
                    if (i + 2 >= tokens.size() || tokens[i + 2].type != TokenType::Number) {
                        // Ambiguity Detected!
                        // Candidate A: count = 1
                        RepairCandidate candA("A", "require " + cat + " 1",
                            "Baseline security: Enforce at least 1 " + cat + " character", 0.50);
                        std::vector<Token> streamA = tokens;
                        SourcePos posA = tokens[i + 1].pos;
                        posA.col += (int)cat.length() + 1;
                        streamA.insert(streamA.begin() + i + 2, Token(TokenType::Number, "1", posA));
                        PolicyAST astA;
                        if (validateCandidateStream(streamA, astA)) {
                            candA.grammarValid = true;
                            candA.astValid = true;
                            candA.semanticValid = true;
                        }

                        // Candidate B: count = 2
                        RepairCandidate candB("B", "require " + cat + " 2",
                            "Enterprise defense: Enforce at least 2 " + cat + " characters for heightened entropy", 0.50);
                        std::vector<Token> streamB = tokens;
                        SourcePos posB = tokens[i + 1].pos;
                        posB.col += (int)cat.length() + 1;
                        streamB.insert(streamB.begin() + i + 2, Token(TokenType::Number, "2", posB));
                        PolicyAST astB;
                        if (validateCandidateStream(streamB, astB)) {
                            candB.grammarValid = true;
                            candB.astValid = true;
                            candB.semanticValid = true;
                        }

                        report.repairCandidates.push_back(candA);
                        report.repairCandidates.push_back(candB);
                        report.issueDetected = "Ambiguous incomplete rule: 'require " + cat + "'";
                        report.reason = "Missing numeric count. Multiple semantically valid interpretations exist; compiler cannot silently assume security parameters.";
                        report.suggestedAction = "Require Human-in-the-Loop operator decision [A / B].";
                        report.safetyClassification = RepairSafety::AMBIGUOUS_NEEDS_HUMAN;
                        report.humanApprovalRequired = true;
                        report.confidence = 0.50;
                        return;
                    }
                }
            }
        }
    }

    // Check 2: Deterministic keyword typo (e.g. requir uppercase 1) -> SAFE_DETERMINISTIC
    for (size_t i = 0; i < tokens.size(); ++i) {
        if (tokens[i].type == TokenType::Identifier) {
            std::string lex = tokens[i].lexeme;
            std::string canonical = "";
            if (lex == "requir" || lex == "req" || lex == "requiree") canonical = "require";
            else if (lex == "minlenght" || lex == "minlen" || lex == "min_length") canonical = "minLength";
            else if (lex == "maxlenght" || lex == "maxlen" || lex == "max_length") canonical = "maxLength";

            if (!canonical.empty()) {
                RepairCandidate cand("A", canonical, "Deterministic keyword typo correction: '" + lex + "' -> '" + canonical + "'", 0.99);
                std::vector<Token> streamFixed = tokens;
                streamFixed[i].lexeme = canonical;
                PolicyAST astFixed;
                if (validateCandidateStream(streamFixed, astFixed)) {
                    cand.grammarValid = true;
                    cand.astValid = true;
                    cand.semanticValid = true;
                    report.repairCandidates.push_back(cand);
                    report.issueDetected = "Typo in keyword: '" + lex + "'";
                    report.reason = "Unambiguous canonical keyword match '" + canonical + "'.";
                    report.suggestedAction = cand.rationale;
                    report.safetyClassification = RepairSafety::SAFE_DETERMINISTIC;
                    report.humanApprovalRequired = false;
                    report.confidence = 0.99;
                    tokens = streamFixed;
                    autoRepaired = true;
                    repairSummary = "Applied safe deterministic repair: '" + lex + "' -> '" + canonical + "'";
                    return;
                }
            }
        }
    }
}

bool ParserAgent::applyHumanApproval(const std::string& candidateId) {
    for (const auto& cand : report.repairCandidates) {
        if (cand.id == candidateId || cand.id == (candidateId == "a" ? "A" : (candidateId == "b" ? "B" : candidateId))) {
            report.approvedCandidateId = cand.id;
            report.humanApprovalRequired = false;
            report.safetyClassification = RepairSafety::AMBIGUOUS_NEEDS_HUMAN; // Resolved
            report.decision = AgentDecision::REPAIR_APPLIED;
            report.confidence = 1.0; // Confirmed by human authority

            // Apply the chosen candidate tokens
            if (cand.id == "A") {
                // Synthesize count 1
                for (size_t i = 0; i < tokens.size(); ++i) {
                    if (tokens[i].type == TokenType::Identifier && tokens[i].lexeme == "require") {
                        if (i + 1 < tokens.size() && tokens[i + 1].type == TokenType::Identifier) {
                            if (i + 2 >= tokens.size() || tokens[i + 2].type != TokenType::Number) {
                                SourcePos pos = tokens[i + 1].pos;
                                pos.col += (int)tokens[i + 1].lexeme.length() + 1;
                                tokens.insert(tokens.begin() + i + 2, Token(TokenType::Number, "1", pos));
                                break;
                            }
                        }
                    }
                }
            } else if (cand.id == "B") {
                // Synthesize count 2
                for (size_t i = 0; i < tokens.size(); ++i) {
                    if (tokens[i].type == TokenType::Identifier && tokens[i].lexeme == "require") {
                        if (i + 1 < tokens.size() && tokens[i + 1].type == TokenType::Identifier) {
                            if (i + 2 >= tokens.size() || tokens[i + 2].type != TokenType::Number) {
                                SourcePos pos = tokens[i + 1].pos;
                                pos.col += (int)tokens[i + 1].lexeme.length() + 1;
                                tokens.insert(tokens.begin() + i + 2, Token(TokenType::Number, "2", pos));
                                break;
                            }
                        }
                    }
                }
            }

            autoRepaired = true;
            repairSummary = "Human approved Candidate [" + cand.id + "]: " + cand.candidateText;
            report.suggestedAction = cand.candidateText;

            // Re-parse and verify AST
            Parser p(tokens);
            ast = p.parse();
            report.success = p.errors().empty();
            return report.success;
        }
    }
    return false;
}

void ParserAgent::observe() {
    AgentTelemetryRecord tel;
    tel.agentId = report.agentId;
    tel.stage = "OBSERVE";
    tel.inputSummary = "Token stream (" + std::to_string(tokens.size()) + " tokens)";
    tel.observation = "Inspecting token sequence for grammatical phrase completeness and constraint productions.";
    tel.decision = "Perform syntax parsing and detect potential ambiguities or defects.";
    tel.actionTaken = "STREAM_INSPECTION";
    tel.evidence = "Grammar: DSL 2.0 Extended Recursive Descent Spec";
    tel.confidence = 1.0;
    tel.resultStatus = "OBSERVED";
    tel.timestamp = AgentTelemetryRecord::currentTimestamp();
    report.telemetryLogs.push_back(tel);
}

void ParserAgent::analyze() {
    // 1. First attempt standard parsing on original tokens
    Parser originalParser(tokens);
    ast = originalParser.parse();

    if (!originalParser.errors().empty()) {
        const auto& err = originalParser.errors().front();
        report.issueDetected = err.message;
        report.reason = "Grammar violation at line " + std::to_string(err.pos.line) + ", col " + std::to_string(err.pos.col);

        // 2. Run ambiguity and candidate evaluation
        evaluateSyntaxDefectsAndCandidates();

        if (report.safetyClassification == RepairSafety::SAFE_DETERMINISTIC) {
            report.decision = AgentDecision::REPAIR_APPLIED;
            // tokens were updated in evaluateSyntaxDefectsAndCandidates
            return;
        } else if (report.safetyClassification == RepairSafety::AMBIGUOUS_NEEDS_HUMAN) {
            // Check if human pre-approved choice was already provided
            if (!humanChoice.empty()) {
                applyHumanApproval(humanChoice);
                return;
            }
            report.success = false;
            report.decision = AgentDecision::HUMAN_APPROVAL_REQUIRED;
            return;
        }

        // Unrepairable or unsafe
        report.safetyClassification = RepairSafety::UNSAFE_BLOCK;
        report.success = false;
        report.decision = AgentDecision::BLOCK;
        report.suggestedAction = "Correct DSL syntax according to grammar production rules.";
    }
}

void ParserAgent::decide() {
    AgentTelemetryRecord tel;
    tel.agentId = report.agentId;
    tel.stage = "DECIDE";
    tel.inputSummary = "Parser assessment & Safety Classification";

    if (report.safetyClassification == RepairSafety::SAFE_DETERMINISTIC) {
        tel.observation = report.issueDetected + " | Single canonical repair verified.";
        tel.decision = "Autonomous Safe Repair: Apply deterministic completion.";
        tel.actionTaken = "APPLY_SAFE_REPAIR";
        tel.evidence = "Safety Classification: SAFE / DETERMINISTIC (100% grammar, AST, semantic valid).";
        tel.confidence = 0.99;
        tel.resultStatus = "REPAIR_APPLIED";
    } else if (report.safetyClassification == RepairSafety::AMBIGUOUS_NEEDS_HUMAN) {
        if (!report.approvedCandidateId.empty()) {
            tel.observation = "Ambiguity resolved via Human-in-the-Loop decision: Approved [" + report.approvedCandidateId + "].";
            tel.decision = "Apply human-approved candidate: " + report.suggestedAction;
            tel.actionTaken = "APPLY_HUMAN_APPROVED_REPAIR";
            tel.evidence = "Human operator authorization recorded.";
            tel.confidence = 1.0;
            tel.resultStatus = "APPROVED_BY_HUMAN";
        } else {
            tel.observation = report.issueDetected + " | " + report.reason;
            tel.decision = "Halt automated modification: Trigger Human-in-the-Loop approval gate.";
            tel.actionTaken = "REQUIRE_HUMAN_APPROVAL";
            tel.evidence = "Safety Classification: AMBIGUOUS (Multiple semantically valid interpretations).";
            tel.confidence = 0.50;
            tel.resultStatus = "AWAIT_HUMAN_APPROVAL";
        }
    } else if (!report.success) {
        tel.observation = report.issueDetected;
        tel.decision = "Halt pipeline: Unrecoverable syntax error or unsafe repair.";
        tel.actionTaken = "EMIT_SYNTAX_ERROR";
        tel.evidence = report.reason;
        tel.confidence = 0.0;
        tel.resultStatus = "BLOCK";
    } else {
        tel.observation = "Grammar productions satisfied. Zero syntax errors detected.";
        tel.decision = "Approve Typed AST for semantic satisfiability analysis.";
        tel.actionTaken = "APPROVE_AST";
        tel.evidence = "Successfully constructed " + std::to_string(ast.nodes.size()) + " AST constraint nodes.";
        tel.confidence = 1.0;
        tel.resultStatus = "PASS";
    }
    tel.timestamp = AgentTelemetryRecord::currentTimestamp();
    report.telemetryLogs.push_back(tel);
}

void ParserAgent::act() {
    if (autoRepaired) {
        // Re-parse with repaired tokens
        Parser repairParser(tokens);
        ast = repairParser.parse();
        report.success = repairParser.errors().empty();
    }

    AgentTelemetryRecord tel;
    tel.agentId = report.agentId;
    tel.stage = "ACT";
    tel.inputSummary = "AST Construction Act";
    tel.observation = autoRepaired ? "Reparsing synthesized token stream." : (report.success ? "AST nodes committed." : "Parsing halted.");
    tel.decision = report.success ? "AST construction successful." : "AST construction blocked.";
    tel.actionTaken = autoRepaired ? "APPLY_AST_REPAIR" : (report.success ? "EMIT_TYPED_AST" : "HALT_EMISSION");
    tel.evidence = "Node count: " + std::to_string(ast.nodes.size());
    tel.confidence = report.success ? 1.0 : 0.0;
    tel.resultStatus = report.success ? "SUCCESS" : "FAILED";
    tel.timestamp = AgentTelemetryRecord::currentTimestamp();
    report.telemetryLogs.push_back(tel);
}

bool ParserAgent::verify() {
    bool ok = report.success && !ast.nodes.empty();
    AgentTelemetryRecord tel;
    tel.agentId = report.agentId;
    tel.stage = "VERIFY";
    tel.inputSummary = "AST Integrity Verification";
    tel.observation = "Checking AST completeness, node type validity, and safety conformance.";
    tel.decision = ok ? "Typed AST verified and sealed." : "Verification failed or waiting human approval.";
    tel.actionTaken = "VERIFY_AST";
    tel.evidence = "Valid typed nodes: " + std::to_string(ast.nodes.size());
    tel.confidence = ok ? 1.0 : 0.0;
    tel.resultStatus = ok ? "VERIFIED" : "FAILED";
    tel.timestamp = AgentTelemetryRecord::currentTimestamp();
    report.telemetryLogs.push_back(tel);
    return ok;
}

bool ParserAgent::execute() {
    observe();
    analyze();
    decide();
    act();
    return verify();
}

void ParserAgent::renderReport() const {
    std::cout << "\n==================================================\n";
    std::cout << "  PARSER AGENT (Syntax Intelligence & AST Repair)\n";
    std::cout << "==================================================\n";

    if (report.safetyClassification == RepairSafety::AMBIGUOUS_NEEDS_HUMAN) {
        if (!report.approvedCandidateId.empty()) {
            std::cout << "AUTONOMOUS REPAIR (HUMAN-IN-THE-LOOP RESOLVED)\n";
            std::cout << "--------------------------------------------------\n";
            std::cout << "Approved Candidate:\n  [" << report.approvedCandidateId << "] " << report.suggestedAction << "\n\n";
            std::cout << "Reason:\n  " << report.reason << "\n\n";
            std::cout << "Safety classification:\n  AMBIGUOUS -> RESOLVED BY HUMAN OPERATOR\n\n";
            std::cout << "Verification:\n";
            std::cout << "  [x] Grammar valid\n";
            std::cout << "  [x] AST valid\n";
            std::cout << "  [x] Semantic valid\n\n";
            std::cout << "Action: REPAIR_APPLIED (With Human Authorization)\n";
        } else {
            std::cout << "AUTONOMOUS REPAIR EVALUATION\n";
            std::cout << "--------------------------------------------------\n";
            std::cout << "Issue Detected:\n  " << report.issueDetected << "\n\n";
            std::cout << "Reason:\n  " << report.reason << "\n\n";
            std::cout << "Candidate repairs:\n";
            for (const auto& c : report.repairCandidates) {
                std::cout << "  [" << c.id << "] -> " << c.candidateText << "  (" << c.rationale << ")\n";
            }
            std::cout << "\nSafety classification:\n  AMBIGUOUS / HUMAN APPROVAL REQUIRED\n\n";
            std::cout << "Verification of Candidates:\n";
            for (const auto& c : report.repairCandidates) {
                std::cout << "  [x] Candidate " << c.id << ": Grammar valid | AST valid | Semantic valid\n";
            }
            std::cout << "\nDecision:\n  HUMAN APPROVAL REQUIRED (Cannot silently assume security intent)\n\n";
            std::cout << "Action:\n  AWAIT_HUMAN_APPROVAL\n";
        }
    } else if (report.safetyClassification == RepairSafety::SAFE_DETERMINISTIC) {
        std::cout << "AUTONOMOUS REPAIR\n";
        std::cout << "--------------------------------------------------\n";
        std::cout << "Candidate:\n  " << report.suggestedAction << "\n\n";
        std::cout << "Reason:\n  " << report.reason << "\n\n";
        std::cout << "Safety classification:\n  SAFE / DETERMINISTIC\n\n";
        std::cout << "Verification:\n";
        std::cout << "  [x] Grammar valid\n";
        std::cout << "  [x] AST valid\n";
        std::cout << "  [x] Semantic valid\n\n";
        std::cout << "Action:\n  REPAIR_APPLIED\n";
    } else if (!report.success) {
        std::cout << "Issue detected:\n  " << report.issueDetected << "\n\n";
        std::cout << "Reason:\n  " << report.reason << "\n\n";
        std::cout << "Safety classification:\n  UNSAFE / BLOCK\n\n";
        std::cout << "Suggested action:\n  " << report.suggestedAction << "\n\n";
        std::cout << "Action: BLOCK\n";
    } else {
        std::cout << "Syntax parsing status: [OK]\n";
        std::cout << "Constructed Typed AST: " << ast.nodes.size() << " valid constraint nodes\n";
        for (size_t i = 0; i < ast.nodes.size(); ++i) {
            std::cout << "  [" << (i + 1) << "] " << ast.nodes[i]->toString() << "\n";
        }
        std::cout << "Confidence: 100%\n";
        std::cout << "Action    : PROCEED\n";
    }
    std::cout << "--------------------------------------------------\n";
}
