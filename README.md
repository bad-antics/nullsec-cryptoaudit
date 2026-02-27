# NullSec CryptoAudit

**Cryptographic Implementation Analyzer**

A static analysis tool for detecting weak cryptographic implementations written in Scala, demonstrating functional-OOP hybrid patterns for security code analysis.

![Scala](https://img.shields.io/badge/Scala-DC322F?style=for-the-badge&logo=scala&logoColor=white)
![Security](https://img.shields.io/badge/Security-Tool-red?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-1.0.0-blue?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

## 🎯 Overview

NullSec CryptoAudit scans source code to identify weak or deprecated cryptographic algorithms. It detects broken hashes, weak ciphers, insufficient key sizes, and insecure random number generators.

## ✨ Features

- **Hash Analysis** - Detect MD5, SHA-1, MD4 usage
- **Cipher Detection** - Find DES, 3DES, RC4, Blowfish
- **Key Size Check** - Flag RSA < 2048 bits
- **PRNG Analysis** - Identify Math.random(), rand()
- **CWE Mapping** - Common Weakness Enumeration
- **MITRE ATT&CK** - Technique references

## 🔍 Detection Capabilities

| Algorithm | Type | Status | CWE |
|-----------|------|--------|-----|
| MD5 | Hash | Broken | CWE-328 |
| SHA-1 | Hash | Deprecated | CWE-328 |
| DES | Cipher | Broken | CWE-327 |
| 3DES | Cipher | Deprecated | CWE-327 |
| RC4 | Cipher | Broken | CWE-327 |
| RSA-1024 | Asymmetric | Weak | CWE-326 |
| Math.random | PRNG | Weak | CWE-338 |
| PBKDF1 | KDF | Deprecated | CWE-916 |

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/bad-antics/nullsec-cryptoaudit
cd nullsec-cryptoaudit

# Compile with scalac
scalac CryptoAudit.scala

# Run
scala nullsec.cryptoaudit.CryptoAudit

# Or use Ammonite
amm CryptoAudit.scala
```

## 🚀 Usage

```bash
# Analyze directory
scala CryptoAudit.scala /path/to/code

# Recursive scan
scala CryptoAudit.scala -r project/

# JSON output
scala CryptoAudit.scala -j src/

# Verbose mode
scala CryptoAudit.scala -v app/

# Run demo
scala CryptoAudit.scala
```

## 💻 Example Output

```
╔══════════════════════════════════════════════════════════════════╗
║         NullSec CryptoAudit - Cryptographic Analyzer             ║
╚══════════════════════════════════════════════════════════════════╝

[Demo Mode]

Analyzing sample code for weak cryptography...

  [CRITICAL] MD5
    File:     auth.java:45
    Code:     MessageDigest md = MessageDigest.getInstance("MD5");
    Status:   Broken
    CWE:      CWE-328
    MITRE:    T1110
    Fix:      Use SHA-256 or SHA-3

  [CRITICAL] DES
    File:     encrypt.js:30
    Code:     const key = crypto.createCipheriv('des', secret, iv);
    Status:   Broken
    CWE:      CWE-327
    MITRE:    T1573
    Fix:      Use AES-256

  [HIGH] Math.random()
    File:     random.js:55
    Code:     const id = Math.random().toString(36);
    Status:   Weak
    CWE:      CWE-338
    MITRE:    T1558
    Fix:      Use crypto.getRandomValues() or SecureRandom

  [MEDIUM] SHA-1
    File:     crypto.py:120
    Code:     hash = hashlib.sha1(password.encode())
    Status:   Deprecated
    CWE:      CWE-328
    MITRE:    T1110
    Fix:      Use SHA-256 or SHA-3

═══════════════════════════════════════════

  Summary:
    Files Analyzed: 10
    Total Findings: 8
    Critical:       4
    High:           1
    Medium:         3
    Low:            0
```

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Source Code Input                         │
│              Java | Python | JavaScript | Go | Ruby          │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                  Pattern Matching Engine                     │
│            Regex patterns for crypto functions              │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                 Algorithm Database Lookup                    │
│           Status | CWE | MITRE | Recommendation             │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    Finding Generation                        │
│           Severity based on algorithm status                │
└─────────────────────────────────────────────────────────────┘
```

## 🎯 Scala Features Demonstrated

- **Sealed Traits** - `Severity`, `AlgorithmType`, `AlgorithmStatus`
- **Case Classes** - Immutable `Algorithm`, `Finding`, `AnalysisResult`
- **Case Objects** - Singleton severity levels
- **Pattern Matching** - Exhaustive match expressions
- **For Comprehensions** - Monadic composition with Option
- **Immutable Collections** - `List`, `Map` operations
- **Higher-Order Functions** - `flatMap`, `groupBy`, `sortBy`
- **String Interpolation** - `s"..."` for output formatting

## 🔧 Data Structures

```scala
case class Algorithm(
  name: String,
  algType: AlgorithmType,
  status: AlgorithmStatus,
  keySize: Option[Int],
  cwe: String,
  recommendation: String
)

case class Finding(
  file: String,
  line: Int,
  code: String,
  algorithm: Algorithm,
  severity: Severity,
  description: String,
  mitre: Option[String]
)
```

## 📊 Severity Mapping

| Status | Severity | Description |
|--------|----------|-------------|
| Broken | Critical | Cryptographically broken |
| Weak | High | Known vulnerabilities |
| Deprecated | Medium | Should not be used |
| Secure | Info | Acceptable algorithms |

## 🛡️ Security Use Cases

- **Code Review** - Automated crypto weakness detection
- **SAST Integration** - CI/CD security scanning
- **Compliance** - Crypto policy enforcement
- **Migration Planning** - Identify legacy crypto
- **Security Auditing** - Comprehensive crypto inventory

## ⚠️ Legal Disclaimer

This tool is intended for:
- ✅ Authorized code review
- ✅ Security assessments
- ✅ Compliance verification
- ✅ Educational purposes

**Only analyze code you're authorized to review.**

## 🔗 Links

- **Portal**: [bad-antics.github.io](https://bad-antics.github.io)
- **Discord**: [x.com/AnonAntics](https://x.com/AnonAntics)
- **GitHub**: [github.com/bad-antics](https://github.com/bad-antics)

## 📄 License

MIT License - See LICENSE file for details.

## 🏷️ Version History

- **v1.0.0** - Initial release with crypto weakness detection and CWE mapping

---

*Part of the NullSec Security Toolkit*
