#ifndef PARSER_H
#define PARSER_H

#include "token.h"
#include "ast.h"
#include <vector>
#include <string>
#include <memory>

struct ParseError {
    std::string message;
    SourcePos pos;
    ParseError(std::string m = "", SourcePos p = SourcePos()) : message(m), pos(p) {}
};

class Parser {
public:
    explicit Parser(std::vector<Token> tokens);

    PolicyAST parse();
    const std::vector<ParseError>& errors() const { return errs; }

private:
    std::vector<Token> ts;
    size_t k = 0;
    std::vector<ParseError> errs;

    const Token& cur() const;
    bool match(TokenType t);
    const Token& consume(TokenType t, const std::string& msg);
    void skipNewlines();

    std::shared_ptr<ASTNode> parseRule();
    std::string parseValue();
};

#endif
