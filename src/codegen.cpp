#include "codegen.h"
#include "agent_codegen.h"

void CodeGenerator::generate(const PolicyConstraints& c, const std::string& outputPath, std::shared_ptr<DFA> synthesizedDfa) {
    // Shared generation path: delegates to CodegenAgent to ensure 100% identical security logic
    CodegenAgent agent(c, outputPath, synthesizedDfa);
    agent.execute();
}
