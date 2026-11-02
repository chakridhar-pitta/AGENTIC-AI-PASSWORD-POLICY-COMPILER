#ifndef AUTOMATA_H
#define AUTOMATA_H

#include <string>
#include <vector>
#include <map>
#include <set>
#include <memory>

struct NFAState {
    int id = 0;
    bool isMatch = false;
    std::map<char, std::vector<int>> transitions;
    std::vector<int> eps;
};

class NFA {
public:
    int startState = 0;
    std::vector<NFAState> states;

    // Methods to construct sub-automata
    static NFA buildLiteral(const std::string& str);
    static NFA buildRepeatedChar(int threshold);
    static NFA buildAscendingSequence(int threshold);
    static NFA buildDescendingSequence(int threshold);
    static NFA unionAll(const std::vector<NFA>& nfas);
};

struct DFAState {
    int id = 0;
    bool isRejectState = false;
    int transitions[128];

    DFAState() {
        for (int i = 0; i < 128; ++i) {
            transitions[i] = 0;
        }
    }
};

class DFA {
public:
    int startState = 0;
    std::vector<DFAState> states;
    int rawDfaStateCount = 0;

    static DFA fromNFA(const NFA& nfa);
    DFA minimizeHopcroft() const;
    bool simulate(const std::string& input) const;
    std::string emitCppTable(const std::string& tableName = "DFA_TRANSITION_TABLE") const;
};

struct AutomataMetrics {
    int nfaStateCount = 0;
    int rawDfaStateCount = 0;
    int minDfaStateCount = 0;
    double compressionRatio = 0.0;
};

// Computes epsilon closure of a set of NFA states
std::set<int> computeEpsilonClosure(const NFA& nfa, const std::set<int>& states);

#endif // AUTOMATA_H

