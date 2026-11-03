#include "automata.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <queue>
#include <cctype>

std::set<int> computeEpsilonClosure(const NFA& nfa, const std::set<int>& states) {
    std::set<int> closure = states;
    std::vector<int> stack(states.begin(), states.end());

    while (!stack.empty()) {
        int u = stack.back();
        stack.pop_back();

        if (u >= 0 && u < (int)nfa.states.size()) {
            for (int v : nfa.states[u].eps) {
                if (closure.insert(v).second) {
                    stack.push_back(v);
                }
            }
        }
    }
    return closure;
}

NFA NFA::buildLiteral(const std::string& str) {
    NFA nfa;
    if (str.empty()) {
        NFAState s;
        s.id = 0;
        s.isMatch = true;
        nfa.states.push_back(s);
        nfa.startState = 0;
        return nfa;
    }

    int len = (int)str.size();
    nfa.states.resize(len + 1);
    for (int i = 0; i <= len; ++i) {
        nfa.states[i].id = i;
        nfa.states[i].isMatch = false;
    }

    for (int i = 0; i < len; ++i) {
        char ch = str[i];
        char lowerCh = (char)std::tolower((unsigned char)ch);
        char upperCh = (char)std::toupper((unsigned char)ch);

        nfa.states[i].transitions[lowerCh].push_back(i + 1);
        if (lowerCh != upperCh) {
            nfa.states[i].transitions[upperCh].push_back(i + 1);
        }
    }

    nfa.states[len].isMatch = true;
    for (int c = 32; c <= 126; ++c) {
        nfa.states[len].transitions[(char)c].push_back(len);
    }
    nfa.startState = 0;
    return nfa;
}

NFA NFA::buildRepeatedChar(int threshold) {
    NFA nfa;
    if (threshold <= 1) {
        NFAState s0, s1;
        s0.id = 0; s0.isMatch = false;
        s1.id = 1; s1.isMatch = true;
        for (int c = 32; c <= 126; ++c) {
            s0.transitions[(char)c].push_back(1);
            s1.transitions[(char)c].push_back(1);
        }
        nfa.states = { s0, s1 };
        nfa.startState = 0;
        return nfa;
    }

    NFAState s0, s1;
    s0.id = 0; s0.isMatch = false;
    s1.id = 1; s1.isMatch = true;
    for (int c = 32; c <= 126; ++c) {
        s1.transitions[(char)c].push_back(1);
    }
    nfa.states.push_back(s0);
    nfa.states.push_back(s1);

    int nextId = 2;
    for (int c = 32; c <= 126; ++c) {
        int prev = 0;
        for (int step = 1; step < threshold; ++step) {
            int curr = nextId++;
            NFAState st;
            st.id = curr;
            st.isMatch = false;
            nfa.states.push_back(st);
            nfa.states[prev].transitions[(char)c].push_back(curr);
            prev = curr;
        }
        nfa.states[prev].transitions[(char)c].push_back(1);
    }

    nfa.startState = 0;
    return nfa;
}

NFA NFA::buildAscendingSequence(int threshold) {
    NFA nfa;
    if (threshold <= 1) {
        return buildRepeatedChar(threshold);
    }

    NFAState s0, s1;
    s0.id = 0; s0.isMatch = false;
    s1.id = 1; s1.isMatch = true;
    for (int c = 32; c <= 126; ++c) {
        s1.transitions[(char)c].push_back(1);
    }
    nfa.states.push_back(s0);
    nfa.states.push_back(s1);

    int nextId = 2;
    for (int c = 32; c <= 126 - (threshold - 1); ++c) {
        int prev = 0;
        for (int step = 0; step < threshold - 1; ++step) {
            char stepChar = (char)(c + step);
            int curr = nextId++;
            NFAState st;
            st.id = curr;
            st.isMatch = false;
            nfa.states.push_back(st);
            nfa.states[prev].transitions[stepChar].push_back(curr);
            prev = curr;
        }
        char lastChar = (char)(c + threshold - 1);
        nfa.states[prev].transitions[lastChar].push_back(1);
    }

    nfa.startState = 0;
    return nfa;
}

NFA NFA::buildDescendingSequence(int threshold) {
    NFA nfa;
    if (threshold <= 1) {
        return buildRepeatedChar(threshold);
    }

    NFAState s0, s1;
    s0.id = 0; s0.isMatch = false;
    s1.id = 1; s1.isMatch = true;
    for (int c = 32; c <= 126; ++c) {
        s1.transitions[(char)c].push_back(1);
    }
    nfa.states.push_back(s0);
    nfa.states.push_back(s1);

    int nextId = 2;
    for (int c = 32 + (threshold - 1); c <= 126; ++c) {
        int prev = 0;
        for (int step = 0; step < threshold - 1; ++step) {
            char stepChar = (char)(c - step);
            int curr = nextId++;
            NFAState st;
            st.id = curr;
            st.isMatch = false;
            nfa.states.push_back(st);
            nfa.states[prev].transitions[stepChar].push_back(curr);
            prev = curr;
        }
        char lastChar = (char)(c - (threshold - 1));
        nfa.states[prev].transitions[lastChar].push_back(1);
    }

    nfa.startState = 0;
    return nfa;
}

NFA NFA::unionAll(const std::vector<NFA>& nfas) {
    NFA combined;
    NFAState start;
    start.id = 0;
    start.isMatch = false;

    // Self-loop on start state for all alphabet characters to match patterns anywhere in string
    for (int c = 32; c <= 126; ++c) {
        start.transitions[(char)c].push_back(0);
    }
    combined.states.push_back(start);
    combined.startState = 0;

    for (const auto& sub : nfas) {
        if (sub.states.empty()) continue;
        int offset = (int)combined.states.size();

        for (const auto& st : sub.states) {
            NFAState newSt;
            newSt.id = st.id + offset;
            newSt.isMatch = st.isMatch;

            for (const auto& tr : st.transitions) {
                for (int target : tr.second) {
                    newSt.transitions[tr.first].push_back(target + offset);
                }
            }
            for (int ep : st.eps) {
                newSt.eps.push_back(ep + offset);
            }
            combined.states.push_back(newSt);
        }

        // Epsilon transition from combined start state to sub-automata start state
        combined.states[0].eps.push_back(sub.startState + offset);
    }

    return combined;
}

DFA DFA::fromNFA(const NFA& nfa) {
    DFA dfa;
    if (nfa.states.empty()) return dfa;

    std::set<int> initialSet = computeEpsilonClosure(nfa, { nfa.startState });
    std::map<std::set<int>, int> subsetToId;
    std::vector<std::set<int>> worklist;

    dfa.startState = 0;
    subsetToId[initialSet] = 0;
    worklist.push_back(initialSet);

    int canonicalRejectId = -1;

    DFAState s0;
    s0.id = 0;
    s0.isRejectState = false;
    for (int s : initialSet) {
        if (s >= 0 && s < (int)nfa.states.size() && nfa.states[s].isMatch) {
            s0.isRejectState = true;
            canonicalRejectId = 0;
            break;
        }
    }
    dfa.states.push_back(s0);

    size_t worklistIdx = 0;
    while (worklistIdx < worklist.size()) {
        std::set<int> U = worklist[worklistIdx++];
        int uId = subsetToId[U];

        if (dfa.states[uId].isRejectState) {
            for (int c = 0; c < 128; ++c) {
                dfa.states[uId].transitions[c] = uId;
            }
            continue;
        }

        for (int c = 32; c <= 126; ++c) {
            char ch = (char)c;
            std::set<int> moveSet;

            for (int s : U) {
                if (s >= 0 && s < (int)nfa.states.size()) {
                    auto it = nfa.states[s].transitions.find(ch);
                    if (it != nfa.states[s].transitions.end()) {
                        for (int nextS : it->second) {
                            moveSet.insert(nextS);
                        }
                    }
                }
            }

            std::set<int> closure = computeEpsilonClosure(nfa, moveSet);
            if (closure.empty()) {
                dfa.states[uId].transitions[c] = 0;
            } else {
                bool isMatchClosure = false;
                for (int s : closure) {
                    if (s >= 0 && s < (int)nfa.states.size() && nfa.states[s].isMatch) {
                        isMatchClosure = true;
                        break;
                    }
                }

                if (isMatchClosure) {
                    if (canonicalRejectId == -1) {
                        canonicalRejectId = (int)dfa.states.size();
                        DFAState rejectState;
                        rejectState.id = canonicalRejectId;
                        rejectState.isRejectState = true;
                        for (int i = 0; i < 128; ++i) {
                            rejectState.transitions[i] = canonicalRejectId;
                        }
                        dfa.states.push_back(rejectState);
                    }
                    dfa.states[uId].transitions[c] = canonicalRejectId;
                } else {
                    auto itFound = subsetToId.find(closure);
                    if (itFound == subsetToId.end()) {
                        int nextId = (int)dfa.states.size();
                        subsetToId[closure] = nextId;

                        DFAState nextState;
                        nextState.id = nextId;
                        nextState.isRejectState = false;
                        dfa.states.push_back(nextState);
                        worklist.push_back(closure);
                        dfa.states[uId].transitions[c] = nextId;
                    } else {
                        dfa.states[uId].transitions[c] = itFound->second;
                    }
                }
            }
        }

        // Total deterministic completion for non-printable characters (< 32 and 127)
        for (int c = 0; c < 128; ++c) {
            if (c < 32 || c > 126) {
                dfa.states[uId].transitions[c] = 0;
            }
        }
    }

    dfa.rawDfaStateCount = (int)dfa.states.size();
    return dfa;
}

DFA DFA::minimizeHopcroft() const {
    int n = (int)states.size();
    if (n <= 1) {
        DFA copy = *this;
        copy.rawDfaStateCount = n;
        return copy;
    }

    std::set<int> F;
    std::set<int> nonF;
    for (int i = 0; i < n; ++i) {
        if (states[i].isRejectState) {
            F.insert(i);
        } else {
            nonF.insert(i);
        }
    }

    // Edge cases: all states accept or all states reject
    if (F.empty() || nonF.empty()) {
        DFA minDfa;
        minDfa.startState = 0;
        minDfa.rawDfaStateCount = n;
        DFAState s0;
        s0.id = 0;
        s0.isRejectState = !F.empty();
        for (int c = 0; c < 128; ++c) s0.transitions[c] = 0;
        minDfa.states.push_back(s0);
        return minDfa;
    }

    std::vector<std::set<int>> P = { F, nonF };
    std::vector<std::set<int>> W = { F };

    while (!W.empty()) {
        std::set<int> A = W.back();
        W.pop_back();

        for (int c = 32; c <= 126; ++c) {
            // Find all states that transition on c into A
            std::set<int> X;
            for (int s = 0; s < n; ++s) {
                int dest = states[s].transitions[c];
                if (A.find(dest) != A.end()) {
                    X.insert(s);
                }
            }

            if (X.empty()) continue;

            std::vector<std::set<int>> nextP;
            for (const auto& Y : P) {
                std::set<int> Y1;
                std::set<int> Y2;
                for (int s : Y) {
                    if (X.find(s) != X.end()) {
                        Y1.insert(s);
                    } else {
                        Y2.insert(s);
                    }
                }

                if (!Y1.empty() && !Y2.empty()) {
                    nextP.push_back(Y1);
                    nextP.push_back(Y2);

                    auto itW = std::find(W.begin(), W.end(), Y);
                    if (itW != W.end()) {
                        W.erase(itW);
                        W.push_back(Y1);
                        W.push_back(Y2);
                    } else {
                        if (Y1.size() <= Y2.size()) {
                            W.push_back(Y1);
                        } else {
                            W.push_back(Y2);
                        }
                    }
                } else {
                    nextP.push_back(Y);
                }
            }
            P = std::move(nextP);
        }
    }

    int k = (int)P.size();
    // Reorder partition blocks so block containing startState is at index 0
    int startBlock = 0;
    for (int i = 0; i < k; ++i) {
        if (P[i].find(startState) != P[i].end()) {
            startBlock = i;
            break;
        }
    }
    if (startBlock != 0) {
        std::swap(P[0], P[startBlock]);
    }

    std::vector<int> stateToBlock(n, 0);
    for (int i = 0; i < k; ++i) {
        for (int s : P[i]) {
            stateToBlock[s] = i;
        }
    }

    DFA minDfa;
    minDfa.startState = 0;
    minDfa.rawDfaStateCount = (rawDfaStateCount > 0) ? rawDfaStateCount : n;
    minDfa.states.resize(k);

    for (int i = 0; i < k; ++i) {
        minDfa.states[i].id = i;
        int rep = *P[i].begin();
        minDfa.states[i].isRejectState = states[rep].isRejectState;

        for (int c = 0; c < 128; ++c) {
            int origTarget = states[rep].transitions[c];
            if (origTarget >= 0 && origTarget < n) {
                minDfa.states[i].transitions[c] = stateToBlock[origTarget];
            } else {
                minDfa.states[i].transitions[c] = 0;
            }
        }
    }

    return minDfa;
}

bool DFA::simulate(const std::string& input) const {
    if (states.empty()) return false;
    int curr = startState;
    if (curr >= 0 && curr < (int)states.size() && states[curr].isRejectState) {
        return true;
    }

    for (char ch : input) {
        unsigned char uch = static_cast<unsigned char>(ch);
        if (uch < 128) {
            curr = states[curr].transitions[uch];
            if (curr >= 0 && curr < (int)states.size() && states[curr].isRejectState) {
                return true;
            }
        }
    }
    return (curr >= 0 && curr < (int)states.size() && states[curr].isRejectState);
}

std::string DFA::emitCppTable(const std::string& tableName) const {
    std::ostringstream ss;
    int minStates = (int)states.size();
    int rawStates = (rawDfaStateCount > 0) ? rawDfaStateCount : minStates;
    double ratio = (rawStates > 0) ? (((double)(rawStates - minStates) / (double)rawStates) * 100.0) : 0.0;
    std::string tbl = tableName.empty() ? "DFA_TRANSITION_TABLE" : tableName;

    ss << "// Auto-generated Minimized DFA Transition Matrix (Hopcroft Optimized)\n";
    ss << "// Compression: " << rawStates << " -> " << minStates << " (" << std::fixed << std::setprecision(2) << ratio << "%)\n";
    ss << "static const int DFA_STATE_COUNT = " << minStates << ";\n";
    ss << "static const int " << tbl << "[DFA_STATE_COUNT][128] = {\n";
    for (int i = 0; i < minStates; ++i) {
        ss << "    { ";
        for (int c = 0; c < 128; ++c) {
            ss << states[i].transitions[c];
            if (c < 127) ss << ", ";
        }
        ss << " }";
        if (i < minStates - 1) ss << ",";
        ss << "\n";
    }
    ss << "};\n";
    ss << "static const bool DFA_REJECT_STATES[DFA_STATE_COUNT] = { ";
    for (int i = 0; i < minStates; ++i) {
        ss << (states[i].isRejectState ? "true" : "false");
        if (i < minStates - 1) ss << ", ";
    }
    ss << " };\n";
    return ss.str();
}
