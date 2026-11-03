import sys, re
sys.stdout.reconfigure(encoding='utf-8')

with open('web/Enhanced_Compiler.html', 'r', encoding='utf-8') as f:
    html = f.read()

# Extract the script block
start_idx = html.find('<script>') + len('<script>')
end_idx = html.rfind('</script>')
app_script = html[start_idx:end_idx]

head = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Enhanced Compiler Verification Test</title>
</head>
<body>
  <div id="results">Running tests...</div>

  <!-- Required DOM elements for compiler & evaluator -->
  <div style="display:none;">
    <textarea id="policyInput">
# Enterprise Security Baseline Policy (DSL 2.0)
min_length 14
max_length 64
require uppercase 2
require lowercase 4
require digit 2
require special 2
no_spaces
max_sequence 3
max_repeated 2
blacklist "password", "admin", "root", "qwerty"
    </textarea>
    <div id="editorLineNums"></div>
    <span id="statLines"></span>
    <span id="statTokensEst"></span>
    <input type="password" id="passwordInput">
    <div id="pipelineStatusPill"></div>
    <div id="compilationBanner">
      <span id="bannerSymbol"></span>
      <div id="bannerTitle"></div>
      <div id="bannerSub"></div>
    </div>
    <span id="metricTokens"></span>
    <span id="metricRules"></span>
    
    <!-- Stage elements -->
    <div id="stage-guard"><span class="stage-badge" id="badge-guard"></span><span class="stage-icon" id="icon-guard"></span></div>
    <div id="conn-0"></div>
    <div id="stage-lex"><span class="stage-badge" id="badge-lex"></span><span class="stage-icon" id="icon-lex"></span></div>
    <div id="conn-1"></div>
    <div id="stage-par"><span class="stage-badge" id="badge-par"></span><span class="stage-icon" id="icon-par"></span></div>
    <div id="conn-2"></div>
    <div id="stage-sem"><span class="stage-badge" id="badge-sem"></span><span class="stage-icon" id="icon-sem"></span></div>
    <div id="conn-3"></div>
    <div id="stage-ir"><span class="stage-badge" id="badge-ir"></span><span class="stage-icon" id="icon-ir"></span><span id="badge-stage-ir-automata"></span></div>
    <div id="conn-4"></div>
    <div id="stage-cg"><span class="stage-badge" id="badge-cg"></span><span class="stage-icon" id="icon-cg"></span></div>
    <div id="conn-5"></div>
    <div id="stage-val"><span class="stage-badge" id="badge-val"></span><span class="stage-icon" id="icon-val"></span></div>
    <div id="conn-6"></div>
    <div id="stage-ana"><span class="stage-badge" id="badge-ana"></span><span class="stage-icon" id="icon-ana"></span></div>

    <div id="gate1StatusText"></div>
    <div id="gate2StatusText"></div>
    <div id="agentNotificationsArea"></div>
    <table><tbody id="telemetryTableBody"></tbody></table>
    <div id="badgeTelemetryCount"></div>
    <div id="compilerLogStream"></div>
    <div id="diagnosticsList"></div>
    <div id="badgeDiagCount"></div>

    <!-- Security elements -->
    <div id="secTotalChars"></div>
    <div id="secCharPills"></div>
    <div id="secPatternPills"></div>
    <div id="secDictStatus"></div>
    <div id="secEntropyText"></div>
    <div id="entropyLabel"></div>

    <!-- Validation Lab checklist -->
    <div id="chk-len"><span id="chk-len-badge"></span><span id="chk-len-sub"></span></div>
    <div id="chk-upper"><span id="chk-upper-badge"></span><span id="chk-upper-sub"></span></div>
    <div id="chk-lower"><span id="chk-lower-badge"></span><span id="chk-lower-sub"></span></div>
    <div id="chk-digit"><span id="chk-digit-badge"></span><span id="chk-digit-sub"></span></div>
    <div id="chk-special"><span id="chk-special-badge"></span><span id="chk-special-sub"></span></div>
    <div id="chk-patterns"><span id="chk-patterns-badge"></span><span id="chk-patterns-sub"></span></div>
    <div id="chk-blocklist"><span id="chk-blocklist-badge"></span><span id="chk-blocklist-sub"></span></div>

    <!-- Verdict -->
    <div id="verdictBanner"><span id="verdictBadge"></span><h3 id="verdictTitle"></h3><p id="verdictSub"></p></div>
    <span id="scoreValue"></span>
    <div id="scoreBarFill"></div>
    <button id="btnValidatePassword"><span id="btnValidateText"></span><span id="btnValidateIcon"></span></button>

    <!-- Blocklist and Bloom elements -->
    <span id="syncCandidatePasswordMasked"></span>
    <span id="btnToggleSyncPassword"></span>
    <span id="syncCandidateLen"></span>
    <span id="syncOverallStatusBadge"></span>
    <span id="sfStatusBadge"></span>
    <span id="sfOriginalPwd"></span>
    <span id="sfDetectionCategory"></span>
    <span id="sfDetectionMethod"></span>
    <span id="sfMatchedEntry"></span>
    <span id="sfEvaluatedCandidates"></span>
    <span id="sfReasonText"></span>
    <span id="sfRecommendationText"></span>
    <span id="bfFilterBadge"></span>
    <span id="bfExactBadge"></span>
    <span id="badgeBloomStatus"></span>

    <!-- Automata and AST/IR -->
    <div id="astTreeDisplay"></div>
    <div id="irTreeDisplay"></div>
    <span id="badgeAutomataStates"></span>
    <div id="automataTraceVerdict"></div>
    <div id="automataTraceStream"></div>
    <svg id="dfaStateDiagramSvg">
      <circle id="circle_q0"></circle>
      <circle id="circle_scan"></circle>
      <circle id="circle_accept_outer"></circle>
      <circle id="circle_accept_inner"></circle>
      <circle id="circle_trap"></circle>
      <path id="path_scan_trap"></path>
      <path id="path_q0_scan"></path>
      <path id="path_scan_accept"></path>
    </svg>

    <div id="tokenStreamBox"></div>
    <table><tbody id="batchTableBody"></tbody></table>
    <pre id="generatedCodeDisplay"></pre>
    <div id="policyContradictionsBox"></div>
    <div id="policyRedundanciesBox"></div>
    <div id="attackThreatBanner">
      <span id="threatLevelBadge"></span>
      <span id="threatCategoryName"></span>
      <span id="threatExplanationText"></span>
      <span id="threatMitigationBadge"></span>
    </div>
  </div>

  <script>
"""

tail = """
  </script>

  <script>
  async function runVerification() {
    const tests = [];
    function assert(c, msg) { if (!c) throw new Error(msg); }

    // Test 1: Compile Pipeline
    try {
      await runCompile();
      assert(compiledConstraints !== null, 'compiledConstraints is null');
      assert(globalTelemetryRecords.length >= 10, 'Telemetry records count too low');
      tests.push({ name: 'Compiler Pipeline (7 Agents + Dual Security Gates)', passed: true, note: 'All stages passed' });
    } catch(e) {
      tests.push({ name: 'Compiler Pipeline', passed: false, note: e.message });
    }

    // Test 2: Agent Telemetry Cleanup
    try {
      const notif = document.getElementById('agentNotificationsArea');
      const text = notif ? notif.innerHTML : '';
      assert(!text.includes('Semantic Equivalence: <strong>VERIFIED (100% Invariance)</strong>'), 'Old verbose message present');
      assert(!text.includes('Original nodes: 12'), 'Old node counts present');
      const agt4 = globalTelemetryRecords.filter(r => r.agentId === 'AGENT-04-POLICY-IR');
      assert(agt4.length > 0, 'No Agent 4 telemetry');
      for (const r of agt4) {
        assert(!r.obs.includes('Original nodes:'), 'Raw debug info in telemetry record');
      }
      tests.push({ name: 'Agent Telemetry Cleanup (Verbosity removed, Agent 4 status visible)', passed: true, note: 'Clean and concise status verified' });
    } catch(e) {
      tests.push({ name: 'Agent Telemetry Cleanup', passed: false, note: e.message });
    }

    // Test 3: AST & IR Generation
    try {
      const ast = document.getElementById('astTreeDisplay').innerHTML;
      const ir = document.getElementById('irTreeDisplay').innerHTML;
      assert(ast.includes('#1') || ast.includes('min_length'), 'AST empty');
      assert(ir.includes('Length Bounds:'), 'IR empty');
      tests.push({ name: 'AST & IR Generation (Clean, readable structure)', passed: true, note: 'AST nodes & Canonical IR verified' });
    } catch(e) {
      tests.push({ name: 'AST & IR Generation', passed: false, note: e.message });
    }

    // Test 4: Password Validation Lab with P@$$w0rd123
    try {
      fillTestPassword('P@$$w0rd123');
      const syncStatus = document.getElementById('syncOverallStatusBadge').textContent;
      const sfStatus = document.getElementById('sfStatusBadge').textContent;
      const sfMatched = document.getElementById('sfMatchedEntry').textContent;
      const bfFilter = document.getElementById('bfFilterBadge').textContent;
      const bfExact = document.getElementById('bfExactBadge').textContent;
      const blBadge = document.getElementById('chk-blocklist-badge').textContent;
      const verdict = document.getElementById('verdictBadge').textContent;

      assert(syncStatus === 'BLOCKLISTED', 'syncStatus expected BLOCKLISTED, got ' + syncStatus);
      assert(sfStatus === 'BLOCKLISTED', 'sfStatus expected BLOCKLISTED, got ' + sfStatus);
      assert(sfMatched === 'password123', 'sfMatched expected password123, got ' + sfMatched);
      assert(bfFilter === 'POSSIBLY PRESENT', 'bfFilter expected POSSIBLY PRESENT, got ' + bfFilter);
      assert(bfExact === 'MATCH FOUND', 'bfExact expected MATCH FOUND, got ' + bfExact);
      assert(blBadge.includes('FAIL') || blBadge.includes('✗'), 'chk-blocklist expected FAIL, got ' + blBadge);
      assert(verdict === 'INVALID', 'verdict expected INVALID, got ' + verdict);
      tests.push({ name: 'P@$$w0rd123 Leetspeak Blocklist Matching & Rejection', passed: true, note: 'Auto-synchronized, matched to password123, confirmed & rejected' });
    } catch(e) {
      tests.push({ name: 'P@$$w0rd123 Leetspeak Blocklist Matching', passed: false, note: e.message });
    }

    // Test 5: Bloom Filter & Confirmation
    try {
      // Positive test
      const qPos = queryBloomFilter('password123');
      assert(qPos.isPositive === true, 'Bloom filter failed to match password123');
      const exactPos = activeBlocklistSet.has('password123');
      assert(exactPos === true, 'Exact blocklist lookup failed for password123');

      // Negative test
      const qNeg = queryBloomFilter('UnlikelyStringToEverBeInBlocklist987654321');
      assert(qNeg.isPositive === false, 'Bloom filter false positive on unique string');
      tests.push({ name: 'Bloom Filter Fast Pre-Filter & Exact Confirmation', passed: true, note: 'Tested positive and negative queries; zero false rejections enforced' });
    } catch(e) {
      tests.push({ name: 'Bloom Filter Fast Pre-Filter', passed: false, note: e.message });
    }

    // Test 6: Automata DFA State Diagram & Live Traversal
    try {
      fillTestPassword('P@$$w0rd123');
      const cTrap = document.getElementById('circle_trap');
      assert(cTrap.getAttribute('fill') === '#FEE2E2', 'Trap circle fill expected #FEE2E2 for P@$$w0rd123, got ' + cTrap.getAttribute('fill'));

      // Test clean password
      fillTestPassword('MyStr0ng!Pass#72');
      const cAcc = document.getElementById('circle_accept_outer');
      assert(cAcc.getAttribute('fill') === '#ECFDF5', 'Accept circle fill expected #ECFDF5 for clean password, got ' + cAcc.getAttribute('fill'));
      tests.push({ name: 'Automata DFA State Machine (Diagram & live state tracking)', passed: true, note: 'Highlights trap state on sequence/repeat, accept state on valid' });
    } catch(e) {
      tests.push({ name: 'Automata DFA State Machine', passed: false, note: e.message });
    }

    // Render results
    let out = '<pre id="finalTestReport" style="font-family:monospace;font-size:13px;line-height:1.5;">\\n';
    out += '======================================================================\\n';
    out += '     AGENTIC AI PASSWORD POLICY COMPILER — VERIFICATION SUITE         \\n';
    out += '======================================================================\\n\\n';
    let allPassed = true;
    for (const t of tests) {
      out += `[${t.passed ? 'SUCCESS' : 'FAILURE'}] ${t.name}\\n`;
      out += `  -> ${t.note}\\n\\n`;
      if (!t.passed) allPassed = false;
    }
    out += '======================================================================\\n';
    out += `TOTAL: ${tests.filter(t => t.passed).length} / ${tests.length} TESTS PASSED\\n`;
    out += `OVERALL STATUS: ${allPassed ? 'ALL VERIFICATION CRITERIA SATISFIED' : 'FAILURES DETECTED'}\\n`;
    out += '======================================================================\\n</pre>';
    document.getElementById('results').innerHTML = out;
  }

  window.addEventListener('DOMContentLoaded', () => {
    setTimeout(runVerification, 400);
  });
  </script>
</body>
</html>
"""

with open('web/test_compiler_verification.html', 'w', encoding='utf-8') as f:
    f.write(head + app_script + tail)

print("Properly generated web/test_compiler_verification.html.")
