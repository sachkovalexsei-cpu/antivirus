// analyzer.hpp - PE/ELF static inspection + unified threat scoring (Phase 2).
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace av {

// ---------------------------------------------------------------------------
// Static binary analysis
// ---------------------------------------------------------------------------
struct ImportInfo {
    std::string dll;  // PE: DLL name (empty for ELF)
    std::string api;  // imported function / symbol name
};

struct SectionInfo {
    std::string name;
    uint64_t raw_size = 0;
    double entropy = 0.0; // Shannon entropy of section bytes
};

struct BinaryReport {
    bool is_pe = false;              // MZ/PE32(+) header parsed
    bool is_elf = false;             // \x7fELF parsed
    std::string arch;                // e.g. "x86-64", "aarch64", "i386"
    std::vector<SectionInfo> sections;
    std::vector<std::string> suspicious_imports; // matched API names
    std::vector<ImportInfo> imports;   // full import table (capped)
    std::vector<std::string> yara_hits; // backdoor/virus rule names (filled by scorer)
    double max_section_entropy = 0.0;
    bool packed_heuristic = false;   // high-entropy .text/.upx or unnamed sect
    bool has_tls_callbacks = false;  // PE: TLS directory present (anti-debug vector)
    bool suspicious_dll = false;     // imports from known-abused DLLs
    std::string error;               // parse failure note (non-fatal)
};

/// Inspects a file without executing it. Detects PE and ELF by magic bytes,
/// computes per-section entropy, flags suspicious imports/executable sections.
BinaryReport inspect_binary(const std::string &path, uint64_t max_bytes);

inline constexpr const char *kSuspiciousImports[] = {
    // Process injection / creation
    "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "NtCreateThreadEx", "QueueUserAPC", "SetWindowsHookEx", "OpenProcess",
    "TerminateProcess", "SuspendThread", "ResumeThread", "DebugActiveProcess",
    // Persistence / registry
    "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "schtasks",
    // Network staging
    "URLDownloadToFile", "WinHttpOpen", "InternetConnect", "socket",
    "WSAStartup", "connect",
    // Crypto / anti-analysis
    "CryptDecrypt", "CryptEncrypt", "IsDebuggerPresent", "GetTickCount",
    "QueryPerformanceCounter", "NtQueryInformationProcess",
    // Linux / libc equivalents
    "ptrace", "dlopen", "mmap", "execve", "/bin/sh", "/dev/tcp",
    "LD_PRELOAD", "PTRACE_TRACEME",
    // Backdoor / RAT / cracker tool indicators
    "bind", "listen", "accept", "recv", "send", "shutdown",
    "CreateNamedPipeA", "CreateNamedPipeW", "ConnectNamedPipe",
    "cmd.exe", "powershell", "nc -e", "/dev/null 2>&1",
    "crackstation", "hashcat", "mimikatz", "sekurlsa::logonpasswords",
    "LSASS", "secretsdump", "psexec", "wmic",
};

// ---------------------------------------------------------------------------
// Unified scoring engine
// ---------------------------------------------------------------------------
enum class Verdict; // fwd (core.hpp)

struct ScoreComponents {
    bool hash_match = false;
    std::string hash_threat_name;
    int hash_severity = 0;          // 0..100 from DB
    std::vector<std::string> yara_rules; // matched rule identifiers
    int yara_tags_score = 0;        // derived from tags: trojan/backdoor...
    double entropy = 0.0;           // whole-file shannon entropy
    bool high_entropy = false;      // entropy > 7.5
    bool binary_packed = false;     // packed/exec-section heuristic
    int suspicious_imports = 0;     // count
    bool has_tls_callbacks = false; // PE TLS callback (anti-analysis)
    bool access_error = false;      // could not read fully
};

struct ThreatAssessment {
    std::string file_path;
    std::string sha256;             // may be empty on access error
    uint64_t size_bytes = 0;
    double score = 0.0;             // 0..100
    Verdict verdict;                // CLEAN / SUSPICIOUS / MALICIOUS
    std::string threat_name;        // best-guess family name
    ScoreComponents components;
    double scan_seconds = 0.0;
};

/// Core scoring math (shared with tests).
double compute_threat_score(const ScoreComponents &c);
Verdict verdict_from_score(const ScoreComponents &c, double score);

/// Engine-injection variant used by DetectionService and unit tests.
ThreatAssessment assess_with_engines(const std::string &file_path,
                                     uint64_t max_file_bytes,
                                     HashDb *db, YaraEngine *yara);

/// calculate_threat_score(file_path): combines hash lookup, YARA matches and
/// entropy/binary heuristics into one verdict.
/// Thresholds: score >= 80 => MALICIOUS, 40..79 => SUSPICIOUS, else CLEAN.
ThreatAssessment calculate_threat_score(const std::string &file_path,
                                        uint64_t max_file_bytes);

/// Serialize an assessment to compact JSON (used in IPC + reports).
std::string assessment_to_json(const ThreatAssessment &a, bool pretty = false);

} // namespace av
