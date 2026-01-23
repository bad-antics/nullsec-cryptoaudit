// NullSec CryptoAudit - Cryptographic Implementation Analyzer
// Scala security tool demonstrating:
//   - Functional and object-oriented hybrid
//   - Case classes and pattern matching
//   - Immutable collections
//   - For comprehensions
//   - Traits and mixins
//   - Option/Either monads
//
// Author: bad-antics
// License: MIT

package nullsec.cryptoaudit

object CryptoAudit {
  val VERSION = "1.0.0"
  
  // ANSI Colors
  object Color {
    val Red    = "\u001b[31m"
    val Green  = "\u001b[32m"
    val Yellow = "\u001b[33m"
    val Cyan   = "\u001b[36m"
    val Gray   = "\u001b[90m"
    val Reset  = "\u001b[0m"
  }
  
  // Severity sealed trait
  sealed trait Severity {
    def color: String
    def name: String
  }
  
  case object Critical extends Severity {
    val color = Color.Red
    val name = "CRITICAL"
  }
  
  case object High extends Severity {
    val color = Color.Red
    val name = "HIGH"
  }
  
  case object Medium extends Severity {
    val color = Color.Yellow
    val name = "MEDIUM"
  }
  
  case object Low extends Severity {
    val color = Color.Cyan
    val name = "LOW"
  }
  
  case object Info extends Severity {
    val color = Color.Gray
    val name = "INFO"
  }
  
  // Crypto algorithm types
  sealed trait AlgorithmType
  case object SymmetricCipher extends AlgorithmType
  case object AsymmetricCipher extends AlgorithmType
  case object HashFunction extends AlgorithmType
  case object MAC extends AlgorithmType
  case object PRNG extends AlgorithmType
  case object KeyDerivation extends AlgorithmType
  
  // Algorithm status
  sealed trait AlgorithmStatus
  case object Secure extends AlgorithmStatus
  case object Deprecated extends AlgorithmStatus
  case object Broken extends AlgorithmStatus
  case object Weak extends AlgorithmStatus
  
  // Crypto algorithm
  case class Algorithm(
    name: String,
    algType: AlgorithmType,
    status: AlgorithmStatus,
    keySize: Option[Int],
    cwe: String,
    recommendation: String
  )
  
  // Code finding
  case class Finding(
    file: String,
    line: Int,
    code: String,
    algorithm: Algorithm,
    severity: Severity,
    description: String,
    mitre: Option[String]
  )
  
  // Analysis result
  case class AnalysisResult(
    filesAnalyzed: Int,
    findings: List[Finding],
    summary: Map[Severity, Int]
  )
  
  // Known algorithms database
  val algorithms: Map[String, Algorithm] = Map(
    // Broken/Weak Hash Functions
    "MD5" -> Algorithm("MD5", HashFunction, Broken, None, "CWE-328",
      "Use SHA-256 or SHA-3"),
    "SHA1" -> Algorithm("SHA-1", HashFunction, Deprecated, None, "CWE-328",
      "Use SHA-256 or SHA-3"),
    "MD4" -> Algorithm("MD4", HashFunction, Broken, None, "CWE-328",
      "Use SHA-256 or SHA-3"),
      
    // Weak Ciphers
    "DES" -> Algorithm("DES", SymmetricCipher, Broken, Some(56), "CWE-327",
      "Use AES-256"),
    "3DES" -> Algorithm("3DES", SymmetricCipher, Deprecated, Some(168), "CWE-327",
      "Use AES-256"),
    "RC4" -> Algorithm("RC4", SymmetricCipher, Broken, None, "CWE-327",
      "Use AES-GCM or ChaCha20"),
    "Blowfish" -> Algorithm("Blowfish", SymmetricCipher, Deprecated, Some(448), "CWE-327",
      "Use AES-256"),
      
    // Weak RSA
    "RSA-1024" -> Algorithm("RSA-1024", AsymmetricCipher, Weak, Some(1024), "CWE-326",
      "Use RSA-2048 or higher"),
    "RSA-512" -> Algorithm("RSA-512", AsymmetricCipher, Broken, Some(512), "CWE-326",
      "Use RSA-2048 or higher"),
      
    // Weak Key Derivation
    "PBKDF1" -> Algorithm("PBKDF1", KeyDerivation, Deprecated, None, "CWE-916",
      "Use PBKDF2 with high iterations or Argon2"),
      
    // Weak PRNG
    "Math.random" -> Algorithm("Math.random()", PRNG, Weak, None, "CWE-338",
      "Use crypto.getRandomValues() or SecureRandom"),
    "rand" -> Algorithm("rand()", PRNG, Weak, None, "CWE-338",
      "Use a cryptographically secure PRNG"),
      
    // Secure (for reference)
    "AES-256" -> Algorithm("AES-256", SymmetricCipher, Secure, Some(256), "",
      "Secure when used correctly"),
    "SHA-256" -> Algorithm("SHA-256", HashFunction, Secure, None, "",
      "Secure for most applications"),
    "Argon2" -> Algorithm("Argon2", KeyDerivation, Secure, None, "",
      "Recommended for password hashing")
  )
  
  // Patterns to search for (simplified regex patterns)
  val cryptoPatterns: List[(String, String)] = List(
    ("MD5", """(?i)(md5|MessageDigest\.getInstance\("MD5"\))"""),
    ("SHA1", """(?i)(sha-?1|MessageDigest\.getInstance\("SHA-?1"\))"""),
    ("DES", """(?i)(DES/|Cipher\.getInstance\("DES)"""),
    ("3DES", """(?i)(DESede|TripleDES|3DES)"""),
    ("RC4", """(?i)(RC4|ARCFOUR)"""),
    ("Blowfish", """(?i)(Blowfish)"""),
    ("RSA-1024", """(?i)(RSA.*1024|keysize.*1024.*RSA)"""),
    ("Math.random", """Math\.random\(\)"""),
    ("rand", """(?<!Secure)\brand\s*\("""),
    ("PBKDF1", """(?i)PBKDF1""")
  )
  
  // Determine severity based on algorithm status
  def severityFromStatus(status: AlgorithmStatus): Severity = status match {
    case Broken     => Critical
    case Weak       => High
    case Deprecated => Medium
    case Secure     => Info
  }
  
  // MITRE mapping
  def getMitre(algType: AlgorithmType): Option[String] = algType match {
    case SymmetricCipher | AsymmetricCipher => Some("T1573")
    case HashFunction => Some("T1110")
    case PRNG => Some("T1558")
    case _ => None
  }
  
  // Demo code samples
  val demoCode: List[(String, Int, String)] = List(
    ("auth.java", 45, """MessageDigest md = MessageDigest.getInstance("MD5");"""),
    ("crypto.py", 120, """hash = hashlib.sha1(password.encode())"""),
    ("encrypt.js", 30, """const key = crypto.createCipheriv('des', secret, iv);"""),
    ("utils.go", 88, """cipher, _ := des.NewCipher(key)"""),
    ("token.rb", 15, """token = Digest::MD5.hexdigest(user_id.to_s)"""),
    ("random.js", 55, """const id = Math.random().toString(36);"""),
    ("legacy.java", 200, """Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");"""),
    ("stream.c", 42, """RC4_set_key(&key, keylen, data);"""),
    ("good.java", 100, """MessageDigest md = MessageDigest.getInstance("SHA-256");"""),
    ("secure.py", 50, """cipher = AES.new(key, AES.MODE_GCM)""")
  )
  
  // Analyze code sample
  def analyzeCodeSample(file: String, line: Int, code: String): Option[Finding] = {
    for {
      (algName, _) <- cryptoPatterns.find { case (_, pattern) =>
        code.matches(s".*$pattern.*")
      }
      algorithm <- algorithms.get(algName)
      if algorithm.status != Secure
    } yield Finding(
      file = file,
      line = line,
      code = code.trim,
      algorithm = algorithm,
      severity = severityFromStatus(algorithm.status),
      description = s"Use of ${algorithm.status} cryptographic algorithm: ${algorithm.name}",
      mitre = getMitre(algorithm.algType)
    )
  }
  
  // Analyze all samples
  def analyzeAll(samples: List[(String, Int, String)]): AnalysisResult = {
    val findings = samples.flatMap { case (file, line, code) =>
      analyzeCodeSample(file, line, code)
    }
    
    val summary = findings.groupBy(_.severity).map { case (sev, fs) =>
      sev -> fs.length
    }
    
    AnalysisResult(
      filesAnalyzed = samples.map(_._1).distinct.length,
      findings = findings,
      summary = summary
    )
  }
  
  // Print functions
  def printBanner(): Unit = {
    println()
    println("╔══════════════════════════════════════════════════════════════════╗")
    println("║         NullSec CryptoAudit - Cryptographic Analyzer             ║")
    println("╚══════════════════════════════════════════════════════════════════╝")
    println()
  }
  
  def printUsage(): Unit = {
    println("USAGE:")
    println("    cryptoaudit [OPTIONS] <path>")
    println()
    println("OPTIONS:")
    println("    -h, --help       Show this help")
    println("    -j, --json       JSON output")
    println("    -r, --recursive  Recursive directory scan")
    println("    -v, --verbose    Verbose output")
    println()
    println("DETECTED WEAKNESSES:")
    println("    • Broken hash functions (MD5, SHA-1, MD4)")
    println("    • Weak ciphers (DES, 3DES, RC4, Blowfish)")
    println("    • Insufficient key sizes (RSA < 2048)")
    println("    • Weak PRNGs (Math.random, rand)")
    println("    • Deprecated key derivation (PBKDF1)")
  }
  
  def printFinding(f: Finding): Unit = {
    val col = f.severity.color
    val sev = f.severity.name
    
    println()
    println(s"  $col[$sev]${Color.Reset} ${f.algorithm.name}")
    println(s"    File:     ${f.file}:${f.line}")
    println(s"    Code:     ${f.code}")
    println(s"    Status:   ${f.algorithm.status}")
    println(s"    CWE:      ${f.algorithm.cwe}")
    f.mitre.foreach(m => println(s"    MITRE:    $m"))
    println(s"    Fix:      ${f.algorithm.recommendation}")
  }
  
  def printSummary(result: AnalysisResult): Unit = {
    println()
    println(s"${Color.Gray}═══════════════════════════════════════════${Color.Reset}")
    println()
    println("  Summary:")
    println(s"    Files Analyzed: ${result.filesAnalyzed}")
    println(s"    Total Findings: ${result.findings.length}")
    
    val critCount = result.summary.getOrElse(Critical, 0)
    val highCount = result.summary.getOrElse(High, 0)
    val medCount = result.summary.getOrElse(Medium, 0)
    val lowCount = result.summary.getOrElse(Low, 0)
    
    println(s"    Critical:       ${Color.Red}$critCount${Color.Reset}")
    println(s"    High:           ${Color.Red}$highCount${Color.Reset}")
    println(s"    Medium:         ${Color.Yellow}$medCount${Color.Reset}")
    println(s"    Low:            ${Color.Cyan}$lowCount${Color.Reset}")
  }
  
  def demoMode(): Unit = {
    println(s"${Color.Yellow}[Demo Mode]${Color.Reset}")
    println()
    println(s"${Color.Cyan}Analyzing sample code for weak cryptography...${Color.Reset}")
    
    val result = analyzeAll(demoCode)
    
    // Sort by severity
    val sortedFindings = result.findings.sortBy { f =>
      f.severity match {
        case Critical => 0
        case High     => 1
        case Medium   => 2
        case Low      => 3
        case Info     => 4
      }
    }
    
    sortedFindings.foreach(printFinding)
    printSummary(result)
  }
  
  def main(args: Array[String]): Unit = {
    printBanner()
    
    args.toList match {
      case Nil =>
        printUsage()
        println()
        demoMode()
      case "-h" :: _ | "--help" :: _ =>
        printUsage()
      case _ =>
        printUsage()
        println()
        demoMode()
    }
  }
}

// Entry point
CryptoAudit.main(args)
