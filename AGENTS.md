# AI Agent Work Guidelines for Aetheris

## Phase Execution Workflow

Every phase follows this strict cycle:

1. **Multi-Agent Investigation** — Launch 2+ parallel subagents to analyze the codebase
   - Each agent independently identifies issues from different perspectives
   - Agents return structured findings with file/line references
2. **Implement Fixes** — Human/AI lead reads findings, implements all fixes
3. **Test** — `cargo check --workspace` + relevant crate tests must pass
   - Run ALL applicable tests, not just the ones related to the change
   - Compilation must be clean (zero errors, zero warnings)
4. **Multi-Agent Review** — Launch 2+ parallel subagents to review ALL changes
   - Must verify correctness, no regressions, edge cases, test coverage
   - Return structured review: ✅ APPROVED / ⚠️ WARNINGS / ❌ ISSUES
   - Fixes applied in previous iterations must be re-verified
5. **Iterate** — If any reviewer returns ❌ ISSUES or unresolved ⚠️ WARNINGS:
   - Go back to step 2 (implement fixes for issues found in review)
   - Then step 3 (test again)
   - Then **MUST go back to step 4 (multi-agent review again)** to verify fixes
   - Repeat this full loop (2→3→4→5→2→3→4→5→...) until ALL reviewers return ✅ APPROVED with zero ❌ ISSUES
   - ⚠️ CRITICAL: Never skip step 4 after a fix iteration. Every fix batch must be re-reviewed.
6. **Commit** — Only after ALL reviewers pass with zero blocking issues

## Principles

- **Do NOT write code during investigation/review** — only read, analyze, report
- **Be maximally critical** — it's easier to tone down harsh feedback than to catch what was missed
- **Phase isolation** — never modify files outside the current phase's scope
- **Verify everything** — compile + test after every fix batch, no exceptions
- **Chinese OK** for design discussions, but code + docs stay in English
