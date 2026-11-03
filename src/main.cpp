#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <cctype>
#include <algorithm>

#include "agentic_orchestrator.h"
#include "diagnostics.h"

using namespace std;

static string readAll(const string& path)
{
    ifstream in(path);
    ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

int main(int argc, char* argv[])
{
    cout << "========================================================================================\n";
    cout << "  AGENTIC AI PASSWORD POLICY COMPILER (Version 3.0 Enterprise)\n";
    cout << "  Architecture: 7 Specialized AI Compiler Agents | Dual Security Gates | Telemetry Log\n";
    cout << "  Enhancement : Static RODATA Bloom Filter + Exact Verification + Leetspeak Analysis\n";
    cout << "========================================================================================\n";

    if (argc < 2)
    {
        cout << "Usage  : policy_compiler <policyfile> [options]\n";
        cout << "         policy_compiler --simulate-attacks\n";
        cout << "Options:\n";
        cout << "  --simulate-attacks       Run automated PBL attack simulation suite & detection metrics\n";
        cout << "  --telemetry              Display full O-A-D-A-V agent telemetry event trail\n";
        cout << "  --password <pwd>         Directly evaluate candidate password non-interactively\n";
        cout << "  --dictionary <path>      Specify custom dictionary (default: dictionary.txt)\n";
        cout << "  --breach-corpus <path>   Specify optional breach corpus dataset (e.g. breach_corpus.txt)\n";
        cout << "  --approve-repair <X>     Pre-approve ambiguous repair candidate (e.g. A or B)\n";
        return 0;
    }

    // Direct attack simulation mode
    for (int i = 1; i < argc; ++i) {
        if (string(argv[i]) == "--simulate-attacks") {
            AgenticOrchestrator orchestrator;
            orchestrator.runAttackSimulationBenchmark();
            return 0;
        }
    }

    string policyPath = argv[1];
    bool showTelemetry = false;
    string cliPassword = "";
    string dictPath = "dictionary.txt";
    string breachPath = "";
    string approvedRepair = "";

    for (int i = 2; i < argc; ++i) {
        string arg = argv[i];
        if (arg == "--telemetry") {
            showTelemetry = true;
        } else if (arg == "--password" && i + 1 < argc) {
            cliPassword = argv[++i];
        } else if (arg == "--dictionary" && i + 1 < argc) {
            dictPath = argv[++i];
        } else if (arg == "--breach-corpus" && i + 1 < argc) {
            breachPath = argv[++i];
        } else if (arg == "--approve-repair" && i + 1 < argc) {
            approvedRepair = argv[++i];
        }
    }

    if (breachPath.empty()) {
        ifstream dbf("data/breach_corpus.txt");
        if (dbf.is_open()) breachPath = "data/breach_corpus.txt";
        else {
            ifstream bf("breach_corpus.txt");
            if (bf.is_open()) breachPath = "breach_corpus.txt";
            else {
                ifstream cbf("CODE/breach_corpus.txt");
                if (cbf.is_open()) breachPath = "CODE/breach_corpus.txt";
            }
        }
    }

    if (dictPath == "dictionary.txt") {
        ifstream ddf("data/dictionary.txt");
        if (ddf.is_open()) dictPath = "data/dictionary.txt";
        else {
            ifstream df("dictionary.txt");
            if (!df.is_open()) {
                ifstream cdf("CODE/dictionary.txt");
                if (cdf.is_open()) dictPath = "CODE/dictionary.txt";
            }
        }
    }

    ifstream chk(policyPath);
    if (!chk)
    {
        string fallbackTestPath = "tests/" + policyPath;
        ifstream chk2(fallbackTestPath);
        if (chk2) {
            policyPath = fallbackTestPath;
        } else {
            cout << "[ERROR] Cannot open policy file: " << policyPath << "\n";
            return 1;
        }
    }

    string policySource = readAll(policyPath);

    // Initialize Agentic Orchestrator
    AgenticOrchestrator orchestrator;

    // Run full 7-Agent Compilation Pipeline with routed dictionary and breach corpus paths
    bool success = orchestrator.compilePolicy(policySource, "generated_validator.cpp", approvedRepair, dictPath, breachPath);

    if (showTelemetry) {
        orchestrator.renderTelemetryLog();
    }

    if (!success) {
        cout << "\n[HALT] Agentic compilation terminated due to security or constraint violations.\n";
        return 1;
    }

    // Password Evaluation Phase
    if (!cliPassword.empty()) {
        orchestrator.evaluatePassword(cliPassword, dictPath, breachPath);
        return 0;
    }

    // Interactive Password Evaluation Loop
    cout << "\n========================================================================================\n";
    cout << "  INTERACTIVE EVALUATION LAB (Testing Candidate Passwords against Compiled Policy)\n";
    cout << "========================================================================================\n";
    cout << "Enter candidate passwords to test against the policy (type 'telemetry' for audit log, 'exit' to quit):\n";

    string inputLine;
    while (true) {
        cout << "\nEnter password to evaluate > ";
        if (!getline(cin, inputLine)) break;
        if (inputLine.empty()) continue;
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
