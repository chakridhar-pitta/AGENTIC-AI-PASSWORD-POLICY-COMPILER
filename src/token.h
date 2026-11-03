#ifndef TOKEN_H
#define TOKEN_H

#include <string>

enum class TokenType {
    Identifier,
    Number,
    Boolean,
    String,
    LBracket,
    RBracket,
    Comma,
    Newline,
    End,
    Unknown
};

struct SourcePos {
    int line;
    int col;
    SourcePos(int l = 1, int c = 1) : line(l), col(c) {}
};

struct Token {
    TokenType type;
    std::string lexeme;
    SourcePos pos;
    Token(TokenType t = TokenType::Unknown, std::string l = "", SourcePos p = SourcePos())
        : type(t), lexeme(l), pos(p) {}
};

inline std::string tokenTypeName(TokenType t) {
    switch(t) {
        case TokenType::Identifier: return "Identifier";
        case TokenType::Number:     return "Number";
        case TokenType::Boolean:    return "Boolean";
        case TokenType::String:     return "String";
        case TokenType::Newline:    return "Newline";
        case TokenType::End:        return "End";
        default:                    return "Unknown";
    }
}

#endif
