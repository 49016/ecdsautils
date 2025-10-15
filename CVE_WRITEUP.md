# Security Advisory: Multiple Critical Vulnerabilities in ecdsautils

## Overview

Multiple critical security vulnerabilities have been discovered and fixed in ecdsautils, an ECDSA signature verification utility. These vulnerabilities could allow attackers to:

1. Completely bypass signature verification
2. Cause denial of service through stack overflow
3. Corrupt internal data structures
4. Cause system hangs during key generation

**All vulnerabilities have been fixed in commit 3ac8df5.**

---

## CVE-2024-XXXXX-1: Signature Verification Bypass

### Summary
Complete bypass of ECDSA signature verification due to missing input validation.

### Affected Versions
- All versions prior to the fix

### Vulnerability Details

**CWE**: CWE-20 (Improper Input Validation), CWE-190 (Integer Overflow)

**CVSS v3.1 Score**: 10.0 (CRITICAL)
- Attack Vector: Network
- Attack Complexity: Low
- Privileges Required: None
- User Interaction: None
- Scope: Changed
- Confidentiality: High
- Integrity: High
- Availability: High

**Description**:

The `verify` command in ecdsautils accepts a `-n` parameter to specify the minimum number of required valid signatures. However, the parameter was parsed using `atoi()` without validation:

```c
case 'n':
    min_good_signatures = atoi(optarg);  // No validation!
```

This allowed attackers to:
1. Pass `-n 0` to set `min_good_signatures = 0`
2. The verification check `if (good_signatures >= min_good_signatures)` becomes `if (0 >= 0)` which is always true
3. Signature verification is completely bypassed

**Exploitation**:
```bash
# Attacker can verify ANY file with ANY fake signature/key
ecdsautil verify -n 0 -s "fake" -p "fake" malicious.bin
# Returns: 0 (SUCCESS) - verification passed!
```

**Impact**:
- Complete security bypass in any system using ecdsautil for verification
- Malicious code execution if used in software update systems
- Compromise of systems relying on signature verification
- Supply chain attacks

**Fix**:
Proper validation using `strtol()` with bounds checking (min_good_signatures >= 1)

---

## CVE-2024-XXXXX-2: Stack-Based Buffer Overflow

### Summary
Stack overflow through variable-length array with unbounded user input.

### Affected Versions
- All versions prior to the fix

### Vulnerability Details

**CWE**: CWE-121 (Stack-based Buffer Overflow), CWE-770 (Allocation of Resources Without Limits)

**CVSS v3.1 Score**: 9.8 (CRITICAL)
- Attack Vector: Network  
- Attack Complexity: Low
- Privileges Required: None
- User Interaction: None
- Scope: Unchanged
- Confidentiality: High
- Integrity: High
- Availability: High

**Description**:

The verify function allocated a variable-length array on the stack with user-controlled size:

```c
ecdsa_verify_context_t ctxs[signatures.size];  // VLA on stack
```

Each context structure is approximately 100+ bytes. An attacker could provide thousands of signatures via repeated `-s` parameters, causing:
- Stack overflow (typical limit: 8 MB)
- Process crash (denial of service)
- Potential code execution via stack smashing

**Exploitation**:
```bash
# Generate 100,000 signatures to overflow stack
for i in {1..100000}; do 
    echo -n "-s $(xxd -p -l 64 /dev/urandom) "
done | xargs ecdsautil verify -p key file
# Result: Segmentation fault
```

**Impact**:
- Denial of service by crashing verification services
- Potential remote code execution via stack overflow
- System resource exhaustion

**Fix**:
- Replaced VLA with heap allocation (`malloc`)
- Added limit of 1024 signatures maximum
- Added memory allocation failure checking

---

## CVE-2024-XXXXX-3: Binary Search Logic Error

### Summary  
Inverted comparison logic in binary search causing data structure corruption.

### Affected Versions
- All versions prior to the fix

### Vulnerability Details

**CWE**: CWE-697 (Incorrect Comparison)

**CVSS v3.1 Score**: 7.5 (HIGH)
- Attack Vector: Network
- Attack Complexity: Low
- Privileges Required: None
- User Interaction: None
- Scope: Unchanged
- Confidentiality: None
- Integrity: High
- Availability: Low

**Description**:

The binary search in `set_add()` had inverted comparison logic:

```c
int cmp = memcmp(set_index(set, cur), el, set->el_size);
if (cmp == 0)
    return true;
else if (cmp < 0)  // BUG: Should be > 0
    max = cur;
```

This caused:
- Failed lookups of existing elements
- Duplicate insertions breaking set uniqueness
- Corrupted sorted order
- Unpredictable verification results

**Impact**:
- May accept invalid signatures
- May reject valid signatures  
- Data structure corruption
- Undefined verification behavior

**Fix**:
Corrected comparison from `cmp < 0` to `cmp > 0`

---

## CVE-2024-XXXXX-4: Denial of Service via Blocking I/O

### Summary
Use of blocking random device causes indefinite hangs.

### Affected Versions
- All versions prior to the fix

### Vulnerability Details

**CWE**: CWE-400 (Uncontrolled Resource Consumption)

**CVSS v3.1 Score**: 6.5 (MEDIUM)
- Attack Vector: Network
- Attack Complexity: Low  
- Privileges Required: None
- User Interaction: None
- Scope: Unchanged
- Confidentiality: None
- Integrity: None
- Availability: High

**Description**:

Key generation used `/dev/random` which blocks when entropy is depleted:

```c
fd = open("/dev/random", O_RDONLY);
```

On systems with low entropy (VMs, containers, headless servers), this causes indefinite blocking.

**Impact**:
- Key generation hangs indefinitely
- Denial of service for automated systems
- Resource exhaustion
- Service unavailability

**Fix**:
Changed to `/dev/urandom` which never blocks and is cryptographically suitable

---

## Other Security Issues Fixed

### File Descriptor Leak (MEDIUM)
- Calling `close()` on invalid file descriptor (-1)
- Improper resource management
- Fixed with validity checks

### Off-by-One Boundary Check (MEDIUM)
- Wrong boundary check (`optind > argc` should be `>=`)
- Potential out-of-bounds array access
- Fixed with correct comparison

---

## Timeline

- **2024-XX-XX**: Vulnerabilities discovered during security audit
- **2024-XX-XX**: Fixes developed and tested
- **2024-XX-XX**: Fixes committed (commit 3ac8df5)
- **2024-XX-XX**: Security advisory published

---

## Recommendations

### For Users
1. **Update immediately** to the fixed version
2. Audit any systems that used ecdsautil for verification
3. Consider re-verifying any previously checked files
4. Review logs for suspicious verification patterns

### For Developers
1. Never use `atoi()` for security-critical parameters
2. Avoid variable-length arrays with user-controlled sizes
3. Always validate input ranges and bounds
4. Use `/dev/urandom` not `/dev/random` for crypto
5. Implement proper error checking for all system calls

---

## Credits

Vulnerabilities discovered and fixed by: [Security Researcher]

---

## References

- [SECURITY_AUDIT.md](SECURITY_AUDIT.md) - Detailed technical analysis
- [EXPLOIT_DEMOS.md](EXPLOIT_DEMOS.md) - Proof of concept exploits
- [FIXES_SUMMARY.md](FIXES_SUMMARY.md) - Code changes
- Commit: 3ac8df5

---

## Contact

For security issues, please contact: [security@example.com]
