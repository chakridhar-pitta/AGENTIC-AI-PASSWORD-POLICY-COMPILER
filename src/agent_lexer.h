#ifndef AGENT_LEXER_H
#define AGENT_LEXER_H

#include "agent_types.h"
#include "token.h"
#include "lexer.h"
#include <string>
#include <vector>

class LexerAgent {
public:
    explicit LexerAgent(std::string rawSource);

    // Runs the 5-stage O-A-D-A-V loop
    bool execute();

    const std::vector<Token>& getTokens() const { return tokens; }
    const AgentActionReport& getReport() const { return report; }
    void renderReport() const;

private:
    std::string source;
    std::vector<Token> tokens;
    AgentActionReport report;

    // O-A-D-A-V Stages
    void observe();
    void analyze();
    void decide();
    void act();
    bool verify();

    // Helper algorithms
    static int levenshteinDistance(const std::string& s1, const std::string& s2);
    std::string findClosestKeyword(const std::string& unknownWord) const;
};

#endif // AGENT_LEXER_H
