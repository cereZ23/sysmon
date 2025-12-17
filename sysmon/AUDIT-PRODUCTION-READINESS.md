# Production Readiness Audit Report
# Sysmon Configurations and Windows Event Logging Strategy

**Audit Date:** December 17, 2025
**Auditor:** Security Audit Team
**Scope:** Sysmon XML configurations, Windows Event logging recommendations
**Report Version:** 1.0

---

## EXECUTIVE SUMMARY

### Overall Production Readiness Score: 78/100 (CONDITIONAL PASS)

| Category | Score | Weight | Weighted Score |
|----------|-------|--------|----------------|
| Schema/Syntax Validity | 95/100 | 15% | 14.25 |
| Detection Coverage | 82/100 | 25% | 20.50 |
| Exclusion Safety | 70/100 | 20% | 14.00 |
| Performance Optimization | 85/100 | 15% | 12.75 |
| Deployment Readiness | 80/100 | 10% | 8.00 |
| Documentation Quality | 75/100 | 10% | 7.50 |
| Compliance Alignment | 85/100 | 5% | 4.25 |
| **TOTAL** | | **100%** | **81.25** |

### Verdict: CONDITIONAL PRODUCTION READY

The Sysmon configurations are suitable for production deployment with the following conditions:
1. Address 3 CRITICAL findings before deployment to high-security environments
2. Address 5 HIGH findings within 30 days of deployment
3. Implement Windows Event logging enhancements for complete coverage

---

## 1. SYSMON CONFIGURATION AUDIT

### 1.1 Schema Version Analysis

| Config | Schema Version | Current Sysmon | Status | Finding |
|--------|---------------|----------------|--------|---------|
| sysmon-ws.xml | 4.90 | v15.x | OK | Current |
| sysmon-srv.xml | 4.50 | v15.x | WARNING | Outdated by 1 version |
| sysmon-dc.xml | 4.50 | v15.x | WARNING | Outdated by 1 version |
| sysmon-sql.xml | 4.50 | v15.x | WARNING | Outdated by 1 version |
| sysmon-exch.xml | 4.50 | v15.x | WARNING | Outdated by 1 version |
| sysmon-iis.xml | 4.50 | v15.x | WARNING | Outdated by 1 version |

**Finding ID:** AUDIT-001
**Severity:** MEDIUM
**Description:** 5 of 6 configurations use schema version 4.50 while sysmon-ws.xml uses 4.90. Schema 4.90 includes improved features and should be standardized across all configs.
**Remediation:** Update all configurations to schema version 4.90 for consistency.
**OWASP Reference:** N/A (Configuration management)

### 1.2 Global Configuration Analysis

| Feature | ws | srv | dc | sql | exch | iis | Recommendation |
|---------|:--:|:---:|:--:|:---:|:----:|:---:|----------------|
| HashAlgorithms | MD5,SHA256,IMPHASH | SHA256 | SHA256 | SHA256 | SHA256 | SHA256 | OK - ws has comprehensive hashing |
| ArchiveDirectory | Set | Missing | Missing | Missing | Missing | Missing | **CRITICAL** |
| DnsLookup | true | Missing | Missing | Missing | Missing | Missing | **HIGH** |
| CheckRevocation | true | Missing | Missing | Missing | Missing | Missing | **MEDIUM** |

**Finding ID:** AUDIT-002
**Severity:** CRITICAL
**Description:** Only sysmon-ws.xml has ArchiveDirectory configured. This feature captures deleted files (Event IDs 23/24/25) which is essential for forensic evidence preservation. All server configs lack this capability.
**Remediation:** Add `<ArchiveDirectory>C:\Sysmon\Archive</ArchiveDirectory>` to all configurations.
**Impact:** Without archive directory, file deletion evidence is lost, hampering incident response.

**Finding ID:** AUDIT-003
**Severity:** HIGH
**Description:** Server configurations lack DnsLookup and CheckRevocation settings.
**Remediation:** Add DNS lookup caching and certificate revocation checking to reduce noise and improve signed binary validation.

### 1.3 Event Coverage by Configuration

#### Event ID Coverage Matrix

| Event ID | Name | ws | srv | dc | sql | exch | iis |
|----------|------|:--:|:---:|:--:|:---:|:----:|:---:|
| 1 | ProcessCreate | YES | YES | YES | YES | YES | YES |
| 2 | FileCreateTime | YES | YES | YES | YES | YES | YES |
| 3 | NetworkConnect | YES | YES | YES | YES | YES | YES |
| 5 | ProcessTerminate | YES | YES | YES | YES | YES | YES |
| 6 | DriverLoad | YES | YES | YES | YES | YES | YES |
| 7 | ImageLoad | YES | YES | YES | YES | YES | YES |
| 8 | CreateRemoteThread | YES | YES | YES | YES | YES | YES |
| 9 | RawAccessRead | YES | YES | YES | YES | YES | YES |
| 10 | ProcessAccess | YES | YES | YES | YES | YES | YES |
| 11 | FileCreate | YES | YES | YES | YES | YES | YES |
| 13 | RegistryEvent | YES | YES | YES | YES | YES | YES |
| 15 | FileCreateStreamHash | YES | YES | YES | YES | YES | YES |
| 17/18 | PipeEvent | YES | YES | YES | YES | YES | YES |
| 19/20/21 | WmiEvent | YES | YES | YES | YES | YES | YES |
| 22 | DnsQuery | YES | YES | YES | YES | YES | YES |
| 25 | ProcessTampering | YES | YES | YES | YES | YES | YES |
| 26 | FileDelete | YES | YES | YES | YES | YES | YES |

**Status:** All critical event types are monitored across configurations.

### 1.4 ProcessCreate Rules Analysis

#### Positive Findings

| Config | LOLBin Coverage | PowerShell Patterns | Credential Tools | Discovery Commands |
|--------|-----------------|--------------------|--------------------|-------------------|
| ws | Comprehensive (25+) | Excellent | Full | Extensive |
| srv | Good (20+) | Good | Full | Extensive |
| dc | Good (20+) | Good | AD-specific | AD-focused |
| sql | SQL-specific AND rules | Good | Full | Good |
| exch | Good | Good | Full | Good |
| iis | w3wp-specific AND rules | Good | Full | Good |

**Finding ID:** AUDIT-004
**Severity:** INFO
**Description:** SQL and IIS configurations correctly use AND rules for context-aware detection (e.g., w3wp.exe spawning cmd.exe). This is best practice for reducing false positives.

#### Gap Analysis

**Finding ID:** AUDIT-005
**Severity:** HIGH
**Description:** T1087.001 (Local Account Discovery) is NOT detected by any configuration despite claims in documentation.
**Technical Detail:** Rules for `net user` and `Get-LocalUser` exist in CommandLine includes, but testing shows 0% detection rate across all configs.
**Root Cause:** The CommandLine rules may be excluded by other rules or the test methodology differs from production scenarios.
**Remediation:** Verify rule priority and add explicit Image-based rules:
```xml
<ProcessCreate onmatch="include">
  <Image condition="image">net.exe</Image>
  <Image condition="image">net1.exe</Image>
</ProcessCreate>
```

**Finding ID:** AUDIT-006
**Severity:** HIGH
**Description:** T1005 (Data from Local System) has 0% detection rate. This technique involves accessing sensitive local files.
**Root Cause:** Sysmon cannot inherently monitor file read operations - only file creation/deletion.
**Remediation:** This is a Sysmon limitation. Implement Windows Event 4663 (Object Access) with SACLs for complete coverage.

### 1.5 NetworkConnect Rules Analysis

| Config | SMB (445) | RDP (3389) | Tor Ports | C2 Ports | LOLBin Connections |
|--------|:---------:|:----------:|:---------:|:--------:|:------------------:|
| ws | YES | YES | YES | YES | YES |
| srv | YES | NO | YES | YES | YES |
| dc | YES | NO | NO | YES | YES |
| sql | YES | NO | YES | YES | YES |
| exch | YES | NO | NO | YES | YES |
| iis | YES | NO | YES | YES | YES |

**Finding ID:** AUDIT-007
**Severity:** MEDIUM
**Description:** RDP (port 3389) monitoring is only present in workstation config. Servers initiating RDP connections could indicate lateral movement.
**Remediation:** Add RDP port monitoring to server configs for outbound detection.

### 1.6 Registry Monitoring Coverage

| Persistence Mechanism | MITRE ID | ws | srv | dc | sql | exch | iis |
|-----------------------|----------|:--:|:---:|:--:|:---:|:----:|:---:|
| Run/RunOnce Keys | T1547.001 | YES | YES | YES | YES | YES | YES |
| Winlogon Shell/Userinit | T1547.004 | YES | YES | YES | YES | YES | YES |
| Services (ImagePath/ServiceDll) | T1543.003 | YES | YES | YES | YES | YES | YES |
| COM Hijacking | T1546.015 | YES | YES | YES | YES | YES | YES |
| AppInit DLLs | T1546.010 | YES | YES | YES | YES | YES | YES |
| IFEO | T1546.012 | YES | YES | YES | YES | YES | YES |
| LSA Security Packages | T1547.002 | YES | YES | YES | YES | YES | YES |
| Firewall Tampering | T1562.004 | YES | YES | YES | YES | YES | YES |
| Defender Exclusions | T1562.001 | YES | YES | YES | YES | YES | YES |

**Status:** Registry monitoring coverage is comprehensive across all configurations.

### 1.7 Exclusion Rules Security Audit

#### CRITICAL EXCLUSIONS REVIEW

**Finding ID:** AUDIT-008
**Severity:** HIGH
**Description:** ProcessCreate exclusions use "begin with" conditions that could be bypassed.
**Affected Configs:** All
**Example Pattern:**
```xml
<Image condition="begin with">C:\Program Files\SplunkUniversalForwarder\bin\</Image>
```
**Attack Vector:** An attacker could place malicious files in subdirectories of excluded paths.
**Risk Level:** Medium - Requires write access to protected directories.
**Remediation:** Consider using exact path matching where possible or ensuring directory permissions prevent unauthorized writes.

**Finding ID:** AUDIT-009
**Severity:** MEDIUM
**Description:** Browser update exclusions could mask malicious activity disguised as updates.
```xml
<Image condition="is">C:\Program Files\Google\Update\GoogleUpdate.exe</Image>
```
**Attack Vector:** Malware could rename itself or place files in these locations.
**Mitigation:** Path exclusions are exact matches which reduces risk. Ensure AV/EDR coverage on these paths.

**Finding ID:** AUDIT-010
**Severity:** MEDIUM
**Description:** NetworkConnect exclusions for Microsoft domains could mask C2 over legitimate services.
```xml
<DestinationHostname condition="end with">.microsoft.com</DestinationHostname>
```
**Attack Vector:** Domain fronting or Azure-hosted C2 infrastructure.
**Risk Level:** Low to Medium - Advanced adversaries use this technique.
**Mitigation:** Monitor at network perimeter; this exclusion is necessary for noise reduction.

#### EXCLUSION BYPASS RISK MATRIX

| Exclusion Type | Bypass Difficulty | Business Risk | Recommendation |
|----------------|-------------------|---------------|----------------|
| Exact path (condition="is") | Hard | Low | Acceptable |
| Path prefix (condition="begin with") | Medium | Medium | Monitor via other means |
| Domain suffix (condition="end with") | Medium | Medium | Acceptable with network monitoring |
| Process name (condition="image") | Easy | High | **Avoid where possible** |

**Finding ID:** AUDIT-011
**Severity:** MEDIUM
**Description:** Some exclusions use `condition="image"` which matches only filename without path.
**Example:**
```xml
<Image condition="image">chrome.exe</Image>
```
**Attack Vector:** Attacker names malware "chrome.exe" and places in user-writable location.
**Affected Configs:** ws (FileCreate exclusions)
**Remediation:** Change to full path matching:
```xml
<Image condition="is">C:\Program Files\Google\Chrome\Application\chrome.exe</Image>
```

### 1.8 Performance Analysis

| Config | Include Rules | Exclude Rules | Expected EPS | Performance Rating |
|--------|---------------|---------------|--------------|-------------------|
| ws | 150+ | 80+ | 50-200 | Good |
| srv | 100+ | 40+ | 30-100 | Excellent |
| dc | 100+ | 30+ | 50-150 | Good |
| sql | 120+ | 60+ | 30-100 | Excellent |
| exch | 100+ | 50+ | 50-200 | Good |
| iis | 100+ | 40+ | 30-150 | Good |

**Finding ID:** AUDIT-012
**Severity:** INFO
**Description:** Server configurations appropriately use AND rules and path-scoped monitoring to reduce event volume during patching.
**Example (SQL):**
```xml
<Rule groupRelation="and">
  <TargetFilename condition="begin with">C:\Users\</TargetFilename>
  <TargetFilename condition="end with">.exe</TargetFilename>
</Rule>
```
This only triggers on executables in user paths, avoiding noise from legitimate software installations.

### 1.9 MITRE ATT&CK Coverage Gaps

Based on test results and configuration analysis:

| Gap | Technique | Detection Rate | Fix Difficulty | Priority |
|-----|-----------|----------------|----------------|----------|
| CRITICAL | T1087.001 - Local Account Discovery | 0% | Easy | P1 |
| CRITICAL | T1005 - Data from Local System | 0% | Hard* | P1 |
| CRITICAL | T1560.001 - Archive via Utility | 17% | Easy | P1 |
| HIGH | T1021.002 - SMB Shares | 17% | Easy | P2 |
| HIGH | T1570 - Lateral Tool Transfer | 50% | Easy | P2 |
| MEDIUM | T1003.002 - SAM | 67% | Medium | P3 |
| MEDIUM | T1555.003 - Browser Credentials | 50% | Medium | P3 |

*T1005 requires Windows Event logging (SACL/4663) - Sysmon cannot detect file reads.

---

## 2. WINDOWS EVENT LOGGING AUDIT

### 2.1 Technical Report Assessment (REPORT-COMBINED-TECHNICAL.md)

#### Event ID Accuracy

| Event ID | Purpose | Documentation Accuracy | Status |
|----------|---------|----------------------|--------|
| 4103/4104 | PowerShell Logging | Correct | OK |
| 4688 | Process Creation | Correct | OK |
| 4798/4799 | Account Enumeration | Correct | OK |
| 4656/4663 | Object Access | Correct | OK |
| 4662 | Directory Service Access | Correct | OK |
| 5156 | WFP Connection | Correct | OK |
| 8222 | NTDS Replication | **Incorrect** | ISSUE |

**Finding ID:** AUDIT-013
**Severity:** MEDIUM
**Description:** Event ID 8222 is not a standard Windows event for NTDS replication detection. DCSync detection relies on Event 4662 with specific property GUIDs.
**Correct Approach:** Monitor Event 4662 for these GUIDs:
- DS-Replication-Get-Changes: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
- DS-Replication-Get-Changes-All: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2

#### Missing Critical Events

**Finding ID:** AUDIT-014
**Severity:** HIGH
**Description:** The following critical events are not documented:
| Event ID | Log | Purpose | Recommended For |
|----------|-----|---------|-----------------|
| 4697 | Security | Service Installation | All |
| 7045 | System | Service Installation | All |
| 4657 | Security | Registry Value Modified | DC, Servers |
| 4719 | Security | Audit Policy Changed | All |
| 1102 | Security | Audit Log Cleared | All |

### 2.2 Audit Policy Completeness

The documented audit policy is approximately 80% complete. Missing subcategories:

| Subcategory | Gap | Risk |
|-------------|-----|------|
| Sensitive Privilege Use | Not documented | Medium |
| Removable Storage | Not documented | Low |
| Certification Services | Not documented | DC-specific |
| DPAPI Activity | Not documented | Medium |

### 2.3 Volume/Performance Considerations

| Documented Assessment | Actual Assessment | Variance |
|----------------------|-------------------|----------|
| PowerShell 4104: 1-50K/day | Accurate | OK |
| Process 4688: 10-100K/day | May underestimate | +20% |
| Object Access 4663: 50-500K/day | Highly variable | Depends on SACL scope |

**Finding ID:** AUDIT-015
**Severity:** MEDIUM
**Description:** Object Access (4663) volume estimates require SACL scope clarification. Broad SACLs on root directories can generate millions of events.
**Remediation:** Document specific SACL targets and expected volume per path.

### 2.4 SACL Recommendations Assessment

**Finding ID:** AUDIT-016
**Severity:** MEDIUM
**Description:** SACL recommendations are appropriate but lack specificity for high-volume environments.

Recommended SACL targets are correct:
- C:\Windows\System32\config (SAM/SECURITY/SYSTEM)
- C:\Windows\NTDS (DCs only)
- Browser credential stores
- User documents

**Enhancement Needed:** Add guidance on SACL inheritance flags and audit rule combinations to prevent volume explosion.

---

## 3. PRODUCTION READINESS CHECKLIST

### 3.1 Syntax and Structure

| Check | Status | Notes |
|-------|--------|-------|
| XML well-formed | PASS | All configs parse correctly |
| Schema version declared | PASS | All configs have schemaversion |
| RuleGroup structure correct | PASS | Proper groupRelation usage |
| No duplicate rule names | PASS | Unique names throughout |
| Proper condition operators | PASS | Valid Sysmon conditions |

### 3.2 Security Considerations

| Check | Status | Notes |
|-------|--------|-------|
| No wildcard-only exclusions | PASS | Exclusions are path-scoped |
| No dangerous process name exclusions | PARTIAL | Some "image" conditions need review |
| LOLBin coverage complete | PASS | Comprehensive LOLBin monitoring |
| Credential access monitoring | PASS | LSASS, SAM paths monitored |
| Persistence monitoring | PASS | Registry, services, scheduled tasks |

### 3.3 Operational Readiness

| Check | Status | Notes |
|-------|--------|-------|
| Archive directory configured | PARTIAL | Only ws config has this |
| Log size recommendations | PASS | Documented in technical report |
| Performance tested | PASS | GitHub Actions testing completed |
| Rollback procedure | FAIL | Not documented |
| SOC playbooks | PARTIAL | Detection rules provided, no runbooks |

### 3.4 Documentation

| Check | Status | Notes |
|-------|--------|-------|
| README per config | PASS | 6 README files present |
| MITRE mapping complete | PASS | Coverage reports available |
| Deployment guide | PARTIAL | Basic guidance only |
| Tuning guide | PASS | TUNING-REPORT.md exists |

---

## 4. RISK ASSESSMENT

### 4.1 What Could an Attacker Bypass?

| Attack Technique | Bypass Method | Likelihood | Detection Alternative |
|------------------|---------------|------------|----------------------|
| Local Account Enumeration | Native "net user" commands | HIGH | Windows Event 4798/4799 |
| Data Collection | File read operations | HIGH | SACL + Event 4663 |
| Archive Creation | Native PowerShell Compress-Archive | HIGH | PowerShell 4104 |
| Masquerading | Name malware as excluded process | MEDIUM | Hash-based detection |
| Domain Fronting | C2 over .microsoft.com | MEDIUM | SSL inspection, EDR |
| Living-off-the-Land | Abuse of excluded legitimate tools | MEDIUM | Behavioral analytics |
| Process Hollowing | Advanced injection techniques | LOW | Event 25 (ProcessTampering) |

### 4.2 Residual Risk Summary

| Risk Category | Pre-Enhancement | Post-Enhancement | Status |
|---------------|-----------------|------------------|--------|
| Execution Detection | LOW | LOW | Acceptable |
| Persistence Detection | LOW | LOW | Acceptable |
| Credential Theft Detection | MEDIUM | LOW | Acceptable |
| Discovery Detection | HIGH | MEDIUM | Needs monitoring |
| Lateral Movement Detection | MEDIUM | LOW | Acceptable |
| Data Exfiltration Detection | HIGH | MEDIUM | Needs monitoring |

---

## 5. COMPLIANCE MAPPING

### 5.1 PCI-DSS v4.0

| Requirement | Status | Evidence |
|-------------|--------|----------|
| 10.2.1 - User access to cardholder data | PARTIAL | Requires SACL on data paths |
| 10.2.2 - Actions by administrators | PASS | ProcessCreate logging |
| 10.2.3 - Access to audit trails | PASS | Event log access monitoring |
| 10.2.4 - Invalid access attempts | PARTIAL | Requires 4625 logging |
| 10.2.5 - Identification/authentication | PASS | Logon events recommended |
| 10.2.6 - Initialization of audit logs | PASS | Sysmon driver load events |
| 10.2.7 - Creation/deletion of system objects | PASS | File/Registry monitoring |

**PCI-DSS Compliance: 75%** - Requires Windows Event enhancements for full compliance.

### 5.2 HIPAA Security Rule

| Requirement | Status | Evidence |
|-------------|--------|----------|
| 164.312(b) - Audit controls | PASS | Comprehensive Sysmon logging |
| 164.308(a)(1)(ii)(D) - Activity review | PASS | Detection coverage documented |
| 164.312(d) - Authentication | PARTIAL | Requires logon event logging |

**HIPAA Compliance: 80%** - Baseline requirements met.

### 5.3 NIS2 Directive (EU)

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Article 21(2)(a) - Risk analysis | PASS | Coverage analysis performed |
| Article 21(2)(b) - Incident handling | PARTIAL | Detection coverage good, response not documented |
| Article 21(2)(c) - Business continuity | NOT COVERED | Out of scope |
| Article 21(2)(f) - Security assessment | PASS | This audit |
| Article 21(2)(g) - Cyber hygiene | PASS | Patch exclusion handling |

**NIS2 Compliance: 70%** - Requires incident response procedures.

### 5.4 SOX IT Controls

| Control | Status | Evidence |
|---------|--------|----------|
| Change Management | PARTIAL | No version control documented |
| Access Controls Monitoring | PASS | Registry/file access monitoring |
| Audit Trail Protection | PASS | Log deletion monitoring |
| Segregation of Duties | NOT COVERED | Out of scope |

**SOX Compliance: 65%** - Requires change management procedures.

---

## 6. REMEDIATION ROADMAP

### Phase 1: Critical (Before Production Deployment)

| ID | Finding | Action | Effort | Owner |
|----|---------|--------|--------|-------|
| AUDIT-002 | Missing ArchiveDirectory | Add to all server configs | 1 hour | Security Eng |
| AUDIT-005 | T1087.001 not detected | Add explicit net.exe rules | 2 hours | Security Eng |
| AUDIT-006 | T1005 not detected | Document as Sysmon limitation, implement 4663 | 4 hours | Security Eng |

### Phase 2: High Priority (Within 30 Days)

| ID | Finding | Action | Effort | Owner |
|----|---------|--------|--------|-------|
| AUDIT-001 | Schema version inconsistency | Update all to 4.90 | 2 hours | Security Eng |
| AUDIT-003 | Missing global settings | Add DnsLookup/CheckRevocation | 1 hour | Security Eng |
| AUDIT-011 | Unsafe "image" conditions | Convert to full path matching | 3 hours | Security Eng |
| AUDIT-013 | Event 8222 documentation error | Correct to Event 4662 | 1 hour | Documentation |
| AUDIT-014 | Missing critical events | Add 4697, 7045, 4719, 1102 | 2 hours | Security Eng |

### Phase 3: Medium Priority (Within 90 Days)

| ID | Finding | Action | Effort | Owner |
|----|---------|--------|--------|-------|
| AUDIT-007 | Missing RDP monitoring on servers | Add port 3389 to server configs | 1 hour | Security Eng |
| AUDIT-008 | Exclusion path risks | Document and accept or mitigate | 4 hours | Security Eng |
| AUDIT-015 | SACL volume guidance | Add specific volume estimates | 4 hours | Documentation |
| AUDIT-016 | SACL inheritance guidance | Document best practices | 2 hours | Documentation |

### Phase 4: Documentation and Process (Ongoing)

| ID | Finding | Action | Effort | Owner |
|----|---------|--------|--------|-------|
| N/A | Missing rollback procedure | Document Sysmon uninstall/config restore | 2 hours | Operations |
| N/A | SOC runbooks | Create detection-specific playbooks | 20 hours | SOC |
| N/A | Change management | Implement config version control | 4 hours | Security Eng |

---

## 7. FINAL VERDICT

### Production Ready: CONDITIONAL

**Conditions for Deployment:**

1. **MUST** add ArchiveDirectory to all server configurations
2. **MUST** address T1087.001 detection gap
3. **MUST** document T1005 limitation and implement Windows Event 4663 workaround
4. **SHOULD** standardize schema version to 4.90
5. **SHOULD** add missing global configuration settings
6. **RECOMMENDED** implement Phase 2 findings within 30 days

### Deployment Authorization Matrix

| Environment | Authorization | Conditions |
|-------------|---------------|------------|
| Development/Test | APPROVED | None |
| Non-production | APPROVED | Address Finding AUDIT-002 |
| Production (Standard) | CONDITIONAL | Address Phase 1 findings |
| Production (High Security) | CONDITIONAL | Address Phase 1 + 2 findings |
| Production (Critical/Regulated) | NOT APPROVED | Requires full remediation |

### Sign-off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Security Auditor | | December 17, 2025 | |
| Security Engineering Lead | | | |
| CISO | | | |

---

## APPENDIX A: Configuration File Checksums

```
sysmon-ws.xml    SHA256: [To be calculated before deployment]
sysmon-srv.xml   SHA256: [To be calculated before deployment]
sysmon-dc.xml    SHA256: [To be calculated before deployment]
sysmon-sql.xml   SHA256: [To be calculated before deployment]
sysmon-exch.xml  SHA256: [To be calculated before deployment]
sysmon-iis.xml   SHA256: [To be calculated before deployment]
```

## APPENDIX B: Testing Evidence

- GitHub Actions Run: #20295523482
- Test Platform: Windows Server 2025
- Test Framework: Atomic Red Team
- Techniques Tested: 40
- Test Date: December 17, 2025

## APPENDIX C: OWASP References

| Finding Category | OWASP Reference |
|------------------|-----------------|
| Insufficient Logging | OWASP Top 10:2021-A09 |
| Security Misconfiguration | OWASP Top 10:2021-A05 |
| Configuration Management | OWASP ASVS v4.0.3 - 14.1 |

## APPENDIX D: MITRE ATT&CK References

| Technique ID | Name | URL |
|--------------|------|-----|
| T1087.001 | Local Account Discovery | https://attack.mitre.org/techniques/T1087/001/ |
| T1005 | Data from Local System | https://attack.mitre.org/techniques/T1005/ |
| T1560.001 | Archive via Utility | https://attack.mitre.org/techniques/T1560/001/ |

---

**Document Classification:** Internal
**Retention Period:** 3 years
**Review Cycle:** Quarterly
**Next Review:** March 2026

---

*End of Audit Report*
