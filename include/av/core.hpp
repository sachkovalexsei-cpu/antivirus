// core.hpp - Shared types, utilities and public API for the AV detection engine.
// C++20. Linux-first; Windows hooks are stubbed behind #ifdef _WIN32.
#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace av {

// ---------------------------------------------------------------------------
// Verdicts & threat names
// ---------------------------------------------------------------------------
enum class Verdict { Clean, Suspicious, Malicious };

const char *verdict_str(Verdict v);
bool verdict_from_str(std::string_view s, Verdict &out);

// Well-known synthetic threat names (used by the seed database / hash DB).
inline constexpr const char *kGenericThreat = "Generic.Malware.HashMatch";
inline constexpr const char *kTrojanName    = "Trojan.Win32.Generic";
inline constexpr const char *kWormName      = "Worm.Linux.Downloader";

// ---------------------------------------------------------------------------
// SHA-256 helpers (OpenSSL libcrypto)
// ---------------------------------------------------------------------------
std::string sha256_hex(std::span<const std::byte> data);
/// Streams the file through OpenSSL EVP in 64 KiB chunks.
/// Returns nullopt on access/IO error (permission denied, missing, too large).
std::optional<std::string> sha256_file(const std::string &path,
                                       uint64_t max_bytes,
                                       std::string *err = nullptr);

// ---------------------------------------------------------------------------
// Shannon entropy over a sampled window of the file
// ---------------------------------------------------------------------------
struct EntropyResult {
    double entropy_bits_per_byte = 0.0; // 0..8
    uint64_t bytes_sampled       = 0;
};
std::optional<EntropyResult> file_entropy(const std::string &path,
                                          uint64_t max_bytes,
                                          std::string *err = nullptr);

/// Shannon entropy of an in-memory buffer (used for PE/ELF section analysis).
double span_entropy(std::span<const std::byte> data);

// ---------------------------------------------------------------------------
// JSON output (minimal writer + escaper; no external dependency)
// ---------------------------------------------------------------------------
class JsonWriter {
public:
    explicit JsonWriter(bool pretty = false) : pretty_(pretty) {}
    std::string str() const { return buf_; }
    void begin_obj();
    void end_obj(bool comma = false);
    void begin_arr();
    void end_arr(bool comma = false);
    void key(std::string_view k);
    void value(std::string_view v);            // string
    void value_raw(std::string_view raw_json); // numbers, bools, nested json
    template <typename T>
        requires std::is_arithmetic_v<T> || std::is_same_v<T, bool>
    void value(T n) {
        val_sep();
        if constexpr (std::is_same_v<T, bool>)
            buf_ += n ? "true" : "false";
        else
            buf_ += std::to_string(n);
        pending_elem_ = true;
    }

private:
    void val_sep();
    void write_indent();
    std::string buf_;
    bool pretty_ = false;
    int depth_ = 0;
    bool pending_elem_ = false; // an element was written at current level
    bool just_opened_ = false;
    bool after_key_ = false;
};

std::string json_escape(std::string_view s);

// ---------------------------------------------------------------------------
// Path security: traversal / symlink sanitisation shared by IPC + scanner
// ---------------------------------------------------------------------------
/// True if `p` is free of '..' components, NUL/control bytes. Rejects
/// absolute paths when `allow_absolute` is false (IPC-relative targets).
bool path_is_safe(std::string_view p, bool allow_absolute,
                  std::string *reason = nullptr);

/// Resolve `p` and verify the real path stays inside `root` (no symlink
/// escape). Returns canonical path or nullopt with reason.
std::optional<std::string> sanitize_under_root(const std::string &root,
                                               const std::string &p,
                                               std::string *reason = nullptr);

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------
double now_seconds();          // monotonic wall clock (seconds)
std::string iso8601_utc_now(); // e.g. 2026-10-02T12:34:56Z
uint64_t file_size_or_zero(const std::string &path);
std::string hex_encode(std::span<const std::byte> data);
std::vector<std::byte> hex_decode(std::string_view hex);

} // namespace av
