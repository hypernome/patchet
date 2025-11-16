# Experimental Results Summary

**Generated:** 2025-11-16T15:11:09.632569

## Security Evaluation

### Overall Results

| Metric | OAuth Baseline | Agentic JWT |
|--------|---------------|-------------|
| Threats Tested | 12 | 12 |
| Attacks Blocked | 0 (0%) | 12 (100%) |
| Attacks Succeeded | 12 | 0 |

### Individual Threat Results

#### T1: Agent Identity Spoofing
- **OAuth:** ✗ Succeeded
- **A-JWT:** ✓ Blocked
- **Detection:** A2: Registration First Security Model

#### T10: Intent Origin Forgery
- **OAuth:** ✗ Succeeded
- **A-JWT:** ✓ Blocked
- **Detection:** A9: Cryptographic Delegation Chains, A10: Workflow Execution Logging

#### T11: Delegation Chain Manipulation
- **OAuth:** ✗ Succeeded
- **A-JWT:** ✓ Blocked
- **Detection:** A9: Cryptographic Delegation Chains, A6:  Proof of Possession

#### T12: Agent Configuration Exposure
- **OAuth:** ✗ Succeeded
- **A-JWT:** ✓ Blocked
- **Detection:** A1: Agent Checksum Verification, A2: Registration First Security Model

#### T2: Token Replay Attacks
- **OAuth:** ✗ Succeeded
- **A-JWT:** ✓ Blocked
- **Detection:** A6:  Proof of Possession

#### T3: Shim Library Impersonation
- **OAuth:** ✗ Succeeded
- **A-JWT:** ✓ Blocked
- **Detection:** A1: Agent Checksum Verification, A2: Registration First Security Model

#### T4: Runtime Code Modification
- **OAuth:** ✗ Succeeded
- **A-JWT:** ✓ Blocked
- **Detection:** A1: Agent Checksum Verification, A12: Prompt Integrity Validation

#### T5: Prompt Injection Attacks
- **OAuth:** ✗ Succeeded
- **A-JWT:** ✓ Blocked
- **Detection:** A12: Prompt Integrity Validation

#### T6: Workflow Definition Tampering
- **OAuth:** ✗ Succeeded
- **A-JWT:** ✓ Blocked
- **Detection:** A8: Workflow Validation, A11: Agent Registration Versioning

#### T7: Cross-Agent Privilege Escalation
- **OAuth:** ✗ Succeeded
- **A-JWT:** ✓ Blocked
- **Detection:** A3, A7, A8

#### T8: Workflow Step Bypass
- **OAuth:** ✗ Succeeded
- **A-JWT:** ✓ Blocked
- **Detection:** A8: Workflow Validation, A10: Workflow Execution Logging

#### T9: Scope Inflation
- **OAuth:** ✗ Succeeded
- **A-JWT:** ✓ Blocked
- **Detection:** A7: Cryptographic Intent Token Binding, A8: Workflow Validation


## Performance Evaluation

### Token Minting

| Metric | OAuth | A-JWT | Overhead |
|--------|-------|-------|----------|
| Total | 2.1ms | 4.2ms | +2.1ms |

### End-to-End Workflow

| Metric | OAuth | A-JWT | Overhead |
|--------|-------|-------|----------|
| Total | 696ms | 1433ms | +736.7ms (105.8%) |

## Files Generated

1. `results.json` - Raw experimental data
2. `performance_metrics.json` - LangSmith timing data
3. `tables.tex` - LaTeX tables for paper
4. `summary_report.md` - This file

## Next Steps

1. **Review Results:** Check this summary for any anomalies
2. **Update Paper:** Insert LaTeX tables into Section VI
3. **Verify Claims:** Ensure all paper claims match these results
4. **Reproducibility:** Package test code and data for reviewers
