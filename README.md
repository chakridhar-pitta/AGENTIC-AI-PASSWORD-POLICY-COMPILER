# Agentic AI Password Policy Compiler (Enterprise v3.0)

<p align="center">
  <img src="docs/images/nitw_crest_official.png" alt="NIT Warangal Crest" width="160" />
</p>

A university compiler-design project featuring an 8-stage Agentic AI compiler pipeline, attack simulation suite, and intelligent password policy enforcement engine.

## Core Pillars
- **Agentic AI**: 7 specialized autonomous compiler agents + orchestrator + dual security gates + O-A-D-A-V telemetry audit trails.
- **Attack Simulation**: Automated attack detection suite testing 28 real-world vectors (prompt injection, policy bypass, downgrade attacks, DSL/C++ code injection, DoS) with quantitative confusion matrix evaluation.
- **Intelligent AI**: Neuro-symbolic multi-factor policy verification, Leetspeak variant detection, and static RODATA Bloom filtering.

---

## Architectural Design & Pipeline

The system architecture and multi-agent interaction flow are documented in `docs/images/`:
- **Overall System Architecture**: [`docs/images/Architecture Diagram.png`](docs/images/Architecture%20Diagram.png)
- **Agentic Pipeline**: [`docs/images/Architectural Pipeline.png`](docs/images/Architectural%20Pipeline.png)
- **Module Interaction Flow**: [`docs/images/Module Interaction Flow.png`](docs/images/Module%20Interaction%20Flow.png)
- **Evolutionary Architecture Comparison**: [`docs/images/Existing_and_Proposed_Architecture.png`](docs/images/Existing_and_Proposed_Architecture.png)

---

## Building the Compiler

Build the compiler and test suite from `CODE/` using `g++` (C++14 or higher):

### Main Compiler (`policy_compiler.exe`)
```bash
g++ -std=c++14 -O2 -I CODE \
  CODE/agent_attack_detector.cpp \
  CODE/agent_codegen.cpp \
  CODE/agent_lexer.cpp \
  CODE/agent_parser.cpp \
  CODE/agent_policy_ir.cpp \
  CODE/agent_security_audit.cpp \
  CODE/agent_semantic.cpp \
  CODE/agent_validation.cpp \
  CODE/agentic_orchestrator.cpp \
  CODE/automata.cpp \
  CODE/bloom_filter.cpp \
  CODE/codegen.cpp \
  CODE/diagnostics.cpp \
  CODE/ir.cpp \
  CODE/ir_analyzer.cpp \
  CODE/leetspeak.cpp \
  CODE/lexer.cpp \
  CODE/main.cpp \
  CODE/neurosymbolic.cpp \
  CODE/parser.cpp \
  CODE/semantic.cpp \
  -o policy_compiler.exe
```

### Test Suite (`test_security_cases.exe`)
```bash
g++ -std=c++14 -O2 -I CODE \
  CODE/test_security_cases.cpp \
  CODE/bloom_filter.cpp \
  CODE/leetspeak.cpp \
  -o test_security_cases.exe
```

---

## Usage

### 1. Compile a Policy File & Evaluate Password
```bash
./policy_compiler.exe CODE/policy_dsl2.txt --password "Test@1234"
```

### 2. Run Attack Simulation Suite
```bash
./policy_compiler.exe --simulate-attacks
```

### 3. Run Security & Smart Finder Test Suite
```bash
./test_security_cases.exe
```

---

## Regenerating Validator and Bloom Manifest

`generated_validator.cpp` and `generated_bloom_manifest.json` are auto-generated compiler artifacts and are intentionally excluded from git tracking.

To regenerate them at any time, run the compiler against any valid policy DSL file:
```bash
./policy_compiler.exe CODE/policy_dsl2.txt
```
This dispatches the codegen agent (Security Gate #2), synthesizing:
- `generated_validator.cpp`: Contains the minimized DFA state transition table and standalone C++ validator logic.
- `generated_bloom_manifest.json`: Contains the static RODATA Bloom filter parameters, bit array size, hash seeds, and dataset ingestion metrics.

---

## Dataset Generation

The weak password corpus and pattern datasets are maintained under `CODE/datasets/` and `CODE/breach_corpus.txt`. To re-curate or update the corpus:
```bash
python CODE/tools/generate_dataset_curation.py
```
This deduplicates and writes exactly 3,000 unique keys into `CODE/datasets/`, `CODE/breach_corpus.txt`, and exports `CODE/dataset_bundle.js`.
