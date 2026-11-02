#include "parser.h"

using namespace std;

Parser::Parser(vector<Token> tokens) : ts(move(tokens)) {}

const Token& Parser::cur() const {
    if(k >= ts.size()) return ts.back();
    return ts[k];
}

bool Parser::match(TokenType t) {
    if(cur().type == t) { 
        k++; 
        return true; 
    }
    return false;
}

const Token& Parser::consume(TokenType t, const string& msg) {
    if(cur().type == t) 
        return ts[k++];

    errs.push_back(ParseError(msg, cur().pos));
    return ts[k]; // recovery: return current
}

void Parser::skipNewlines() {
    while(cur().type == TokenType::Newline) 
        k++;
}

string Parser::parseValue() {
    if(cur().type == TokenType::Number)   
        return ts[k++].lexeme;

    if(cur().type == TokenType::Boolean)  
        return ts[k++].lexeme;

    if(cur().type == TokenType::String)
        return ts[k++].lexeme;

    if(cur().type == TokenType::Identifier)
        return ts[k++].lexeme;

    errs.push_back(ParseError("Expected value (number, boolean, string, or identifier)", cur().pos));
    k++; // consume something to recover
    return "";
}

shared_ptr<ASTNode> Parser::parseRule() {
    Token firstTok = consume(TokenType::Identifier, "Expected rule keyword (identifier)");
    SourcePos startPos = firstTok.pos;

    // DSL 2.0: 'require' <category> <count>
    if (firstTok.lexeme == "require" && cur().type == TokenType::Identifier) {
        Token catTok = consume(TokenType::Identifier, "Expected category (uppercase, lowercase, digit, special)");
        Token countTok = consume(TokenType::Number, "Missing numeric count for 'require " + catTok.lexeme + "'. Expected explicit count (e.g. 1 or 2).");
        int count = 1;
        try { count = stoi(countTok.lexeme); } catch(...) { count = 1; }
        if (cur().type == TokenType::Newline) k++;
        return make_shared<CharacterConstraintNode>(catTok.lexeme, count, startPos);
    }

    // DSL 2.0: 'forbid' <category> [threshold]
    if (firstTok.lexeme == "forbid" && cur().type == TokenType::Identifier) {
        Token catTok = consume(TokenType::Identifier, "Expected forbidden target (spaces, sequence, repeated)");
        int val = 1;
        if (cur().type == TokenType::Number) {
            try { val = stoi(consume(TokenType::Number, "Expected numeric threshold").lexeme); } catch(...) { val = 3; }
        }
        if (cur().type == TokenType::Newline) k++;
        return make_shared<PatternConstraintNode>(catTok.lexeme, val, startPos);
    }

    // DSL 2.0: 'blacklist' <string_or_identifier> or 'blacklist' '[' ... ']'
    if (firstTok.lexeme == "blacklist") {
        if (cur().type == TokenType::LBracket) {
            consume(TokenType::LBracket, "Expected '['");
            string firstWord = "";
            while (cur().type != TokenType::RBracket && cur().type != TokenType::End) {
                while (cur().type == TokenType::Newline) k++;
                if (cur().type == TokenType::String || cur().type == TokenType::Identifier) {
                    string w = cur().lexeme;
                    k++;
                    if (firstWord.empty()) firstWord = w;
                } else if (cur().type == TokenType::Comma) {
                    k++;
                } else if (cur().type != TokenType::RBracket) {
                    k++;
                }
                while (cur().type == TokenType::Newline) k++;
            }
            if (cur().type == TokenType::RBracket) consume(TokenType::RBracket, "Expected ']'");
            if (cur().type == TokenType::Newline) k++;
            return make_shared<DictionaryConstraintNode>(firstWord, startPos);
        }
        string word = "";
        if (cur().type == TokenType::String) {
            word = consume(TokenType::String, "Expected quoted string to blacklist").lexeme;
        } else if (cur().type == TokenType::Identifier) {
            word = consume(TokenType::Identifier, "Expected string to blacklist").lexeme;
        } else {
            errs.push_back(ParseError("Expected string literal (e.g. \"password\") for blacklist", cur().pos));
            k++;
        }
        if (cur().type == TokenType::Newline) k++;
        return make_shared<DictionaryConstraintNode>(word, startPos);
    }

    // DSL 2.0: 'strength' 'minimum' <level>
    if (firstTok.lexeme == "strength") {
        if (cur().type == TokenType::Identifier && cur().lexeme == "minimum") {
            consume(TokenType::Identifier, "Expected 'minimum'");
        }
        string level = "strong";
        if (cur().type == TokenType::Identifier) {
            level = consume(TokenType::Identifier, "Expected strength level (weak, medium, strong)").lexeme;
        } else {
            errs.push_back(ParseError("Expected strength level (weak, medium, strong)", cur().pos));
            k++;
        }
        if (cur().type == TokenType::Newline) k++;
        return make_shared<StrengthConstraintNode>(level, startPos);
    }

    // Legacy rules mapping to Typed AST Nodes
    string value = parseValue();
    if(cur().type == TokenType::Newline) 
        k++;

    if(firstTok.lexeme == "minLength") {
        int v = 0; try { v = stoi(value); } catch(...) { v = 0; }
        return make_shared<LengthConstraintNode>("min", v, startPos);
    }
    if(firstTok.lexeme == "maxLength") {
        int v = 0; try { v = stoi(value); } catch(...) { v = 0; }
        return make_shared<LengthConstraintNode>("max", v, startPos);
    }
    if(firstTok.lexeme == "requireUpper") {
        int count = (value == "true" ? 1 : 0);
        return make_shared<CharacterConstraintNode>("uppercase", count, startPos);
    }
    if(firstTok.lexeme == "requireLower") {
        int count = (value == "true" ? 1 : 0);
        return make_shared<CharacterConstraintNode>("lowercase", count, startPos);
    }
    if(firstTok.lexeme == "requireDigit") {
        int count = (value == "true" ? 1 : 0);
        return make_shared<CharacterConstraintNode>("digit", count, startPos);
    }
    if(firstTok.lexeme == "requireSpecial") {
        int count = (value == "true" ? 1 : 0);
        return make_shared<CharacterConstraintNode>("special", count, startPos);
    }
    if(firstTok.lexeme == "noSpaces") {
        int count = (value == "true" ? 1 : 0);
        return make_shared<PatternConstraintNode>("spaces", count, startPos);
    }

    // Unknown legacy rule: emit parse error but return null
    errs.push_back(ParseError("Unrecognized rule keyword: '" + firstTok.lexeme + "'", startPos));
    return nullptr;
}

PolicyAST Parser::parse() {
    PolicyAST prog;
    skipNewlines();

    while(cur().type != TokenType::End) {

        if(cur().type == TokenType::Newline) { 
            skipNewlines(); 
            continue; 
        }

        if(cur().type == TokenType::Unknown) {
            errs.push_back(ParseError("Unknown token in input: " + cur().lexeme, cur().pos));

            while(cur().type != TokenType::Newline && 
                  cur().type != TokenType::End) 
                k++;

            if(cur().type == TokenType::Newline) 
                k++;

            continue;
        }

        shared_ptr<ASTNode> node = parseRule();
        if(node) {
            prog.addNode(node);
        }
        skipNewlines();
    }

    return prog;
}
