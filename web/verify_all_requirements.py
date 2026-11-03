import sys, re
sys.stdout.reconfigure(encoding='utf-8')

# Read Enhanced_Compiler.html
with open('web/Enhanced_Compiler.html', 'r', encoding='utf-8') as f:
    html = f.read()

# Verify all the prompt requirements directly:
# 1. Verbose Agent 04 message removed
assert "Semantic Equivalence: <strong>VERIFIED (100% Invariance)</strong>" not in html
assert "Original nodes: 12 → Optimized nodes: 11" not in html
print("Check 1 PASSED: Verbose AGENT-04 telemetry message completely removed.")

# 2. Simplified Agent 04 status exists
assert "Agent 04 — Policy optimization completed." in html
print("Check 2 PASSED: Meaningful status 'Agent 04 — Policy optimization completed.' is visible.")

# 3. Duplicate inputs removed, passwordInput is the single input
pwd_inputs = re.findall(r'<input[^>]+type=[\'"]password[\'"][^>]*>', html)
assert len(pwd_inputs) == 1 and 'id="passwordInput"' in pwd_inputs[0]
print(f"Check 3 PASSED: Exactly 1 password input in the app ({pwd_inputs[0]}).")

# 4. Import options removed from Bloom Filter
assert "manifestFileInput" not in html
assert "Admin: Import Manifest" not in html
print("Check 4 PASSED: Import Options removed from Bloom Filter UI.")

# 5. Broken Import button in CodeGen removed
assert "validatorCppInput" not in html
print("Check 5 PASSED: Unnecessary Import controls in CodeGen removed.")

# 6. AST & IR display focused
assert 'id="astTreeDisplay"' in html
assert 'id="irTreeDisplay"' in html
assert '🌳 Abstract Syntax Tree (AST)' in html
assert '⚡ Intermediate Representation (IR)' in html
print("Check 6 PASSED: AST and IR visualization properly structured and focused.")

# 7. DFA State diagram SVG present
assert 'id="dfaStateDiagramSvg"' in html
assert 'id="node_q0"' in html
assert 'id="node_scan"' in html
assert 'id="node_accept"' in html
assert 'id="node_trap"' in html
print("Check 7 PASSED: Clean vector DFA State Diagram present with q0, q_scan, q_acc, and q_trap.")

# 8. Intelligent Blocklist check item in Validation Lab
assert 'id="chk-blocklist"' in html
assert 'id="chk-blocklist-badge"' in html
print("Check 8 PASSED: Intelligent Blocklist check present in Validation Lab checklist.")

# 9. Blocklist & Bloom Filter panel simplified
assert 'id="syncOverallStatusBadge"' in html
assert 'id="sfStatusBadge"' in html
assert 'id="bfFilterBadge"' in html
assert 'id="bfExactBadge"' in html
print("Check 9 PASSED: Blocklist & Bloom Filter panel contains clean, synchronized status badges.")

print("\nAll 9 Structural and Syntactic Checks PASSED!")

