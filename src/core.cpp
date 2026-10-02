// core.cpp - utilities: hashing, entropy, JSON writer, path sanitisation.
#include "av/core.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdio>
#include <chrono>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <stdexcept>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

namespace fs = std::filesystem;

namespace av {

const char *verdict_str(Verdict v) {
    switch (v) {
    case Verdict::Clean:      return "CLEAN";
    case Verdict::Suspicious: return "SUSPICIOUS";
    case Verdict::Malicious:  return "MALICIOUS";
    }
    return "UNKNOWN";
}

bool verdict_from_str(std::string_view s, Verdict &out) {
    if (s == "CLEAN")      { out = Verdict::Clean;      return true; }
    if (s == "SUSPICIOUS") { out = Verdict::Suspicious; return true; }
    if (s == "MALICIOUS")  { out = Verdict::Malicious;  return true; }
    return false;
}

// ---------------------------------------------------------------------------
// SHA-256
// ---------------------------------------------------------------------------
std::string sha256_hex(std::span<const std::byte> data) {
    std::array<unsigned char, SHA256_DIGEST_LENGTH> md{};
    EVP_Digest(data.data(), data.size(), md.data(), nullptr, EVP_sha256(),
               nullptr);
    static const char *hexd = "0123456789abcdef";
    std::string out;
    out.resize(md.size() * 2);
    for (size_t i = 0; i < md.size(); ++i) {
        out[2 * i]     = hexd[md[i] >> 4];
        out[2 * i + 1] = hexd[md[i] & 0xF];
    }
    return out;
}

std::optional<std::string> sha256_file(const std::string &path,
                                       uint64_t max_bytes, std::string *err) {
    struct stat st {};
    if (::stat(path.c_str(), &st) != 0) {
        if (err) *err = std::strerror(errno);
        return std::nullopt;
    }
    if (!S_ISREG(st.st_mode)) {
        if (err) *err = "not a regular file";
        return std::nullopt;
    }
    if (static_cast<uint64_t>(st.st_size) > max_bytes) {
        if (err) *err = "file exceeds size cap";
        return std::nullopt;
    }

    int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (err) *err = std::strerror(errno);
        return std::nullopt;
    }

    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(
        EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx || EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1) {
        ::close(fd);
        if (err) *err = "openssl digest init failed";
        return std::nullopt;
    }

    std::vector<char> buf(64 * 1024);
    ssize_t n;
    while ((n = ::read(fd, buf.data(), buf.size())) > 0) {
        if (EVP_DigestUpdate(ctx.get(), buf.data(), static_cast<size_t>(n)) != 1) {
            ::close(fd);
            if (err) *err = "openssl digest update failed";
            return std::nullopt;
        }
    }
    ::close(fd);
    if (n < 0) {
        if (err) *err = std::strerror(errno);
        return std::nullopt;
    }

    std::array<unsigned char, SHA256_DIGEST_LENGTH> md{};
    unsigned int mdlen = 0;
    if (EVP_DigestFinal_ex(ctx.get(), md.data(), &mdlen) != 1) {
        if (err) *err = "openssl digest final failed";
        return std::nullopt;
    }
    static const char *hexd = "0123456789abcdef";
    std::string out;
    out.resize(mdlen * 2);
    for (unsigned i = 0; i < mdlen; ++i) {
        out[2 * i]     = hexd[md[i] >> 4];
        out[2 * i + 1] = hexd[md[i] & 0xF];
    }
    return out;
}

// ---------------------------------------------------------------------------
// Shannon entropy over the first `max_bytes` window
// ---------------------------------------------------------------------------
static double shannon_entropy(std::span<const std::byte> data) {
    if (data.empty()) return 0.0;
    std::array<uint64_t, 256> freq{};
    for (auto b : data) ++freq[static_cast<unsigned char>(b)];
    double e = 0.0;
    double total = static_cast<double>(data.size());
    for (uint64_t f : freq) {
        if (!f) continue;
        double p = static_cast<double>(f) / total;
        e -= p * std::log2(p);
    }
    return e;
}

std::optional<EntropyResult> file_entropy(const std::string &path,
                                          uint64_t max_bytes,
                                          std::string *err) {
    // Read head and tail windows (malware packers often pad the middle).
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        if (err) *err = std::strerror(errno);
        return std::nullopt;
    }
    in.seekg(0, std::ios::end);
    auto sz = static_cast<uint64_t>(in.tellg());
    in.seekg(0, std::ios::beg);

    constexpr uint64_t kWindow = 1 << 20; // 1 MiB sample per window
    std::vector<std::byte> samples;
    auto read_window = [&](uint64_t off, uint64_t len) {
        in.seekg(static_cast<std::streamoff>(off));
        size_t old = samples.size();
        samples.resize(old + len);
        in.read(reinterpret_cast<char *>(samples.data() + old),
                static_cast<std::streamsize>(len));
        samples.resize(old + static_cast<size_t>(in.gcount()));
        in.clear();
    };

    uint64_t budget = std::min<uint64_t>(sz, max_bytes);
    if (budget <= 2 * kWindow) {
        read_window(0, budget);
    } else {
        read_window(0, kWindow);
        read_window(budget - kWindow, kWindow);
    }

    EntropyResult r;
    r.bytes_sampled = samples.size();
    r.entropy_bits_per_byte = shannon_entropy(samples);
    return r;
}

double span_entropy(std::span<const std::byte> d) { return shannon_entropy(d); }

// ---------------------------------------------------------------------------
// JsonWriter
// ---------------------------------------------------------------------------
std::string json_escape(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b";  break;
        case '\f': out += "\\f";  break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:
            if (c < 0x20) {
                char b[8];
                std::snprintf(b, sizeof b, "\\u%04x", c);
                out += b;
            } else {
                out += static_cast<char>(c);
            }
        }
    }
    return out;
}

void JsonWriter::write_indent() {
    if (pretty_) buf_.append(static_cast<size_t>(depth_) * 2, ' ');
}

void JsonWriter::val_sep() {
    if (after_key_) { buf_ += ':'; after_key_ = false; if (pretty_) buf_ += ' '; return; }
    if (pending_elem_) buf_ += ',';
    if (pretty_ && !just_opened_) { buf_ += '\n'; write_indent(); }
    just_opened_ = false;
}

void JsonWriter::begin_obj() {
    val_sep();
    buf_ += '{';
    ++depth_;
    just_opened_ = true;
    pending_elem_ = false;
}

void JsonWriter::end_obj(bool comma) {
    --depth_;
    if (pretty_ && !just_opened_) { buf_ += '\n'; write_indent(); }
    buf_ += '}';
    just_opened_ = false;
    pending_elem_ = true;
    if (comma) buf_ += ',';
}

void JsonWriter::begin_arr() {
    val_sep();
    buf_ += '[';
    ++depth_;
    just_opened_ = true;
    pending_elem_ = false;
}

void JsonWriter::end_arr(bool comma) {
    --depth_;
    if (pretty_ && !just_opened_) { buf_ += '\n'; write_indent(); }
    buf_ += ']';
    just_opened_ = false;
    pending_elem_ = true;
    if (comma) buf_ += ',';
}

void JsonWriter::key(std::string_view k) {
    val_sep();
    buf_ += '"';
    buf_ += json_escape(k);
    buf_ += '"';
    after_key_ = true;
    pending_elem_ = false; // next value must not add a comma
}

void JsonWriter::value(std::string_view v) {
    val_sep();
    buf_ += '"';
    buf_ += json_escape(v);
    buf_ += '"';
    pending_elem_ = true;
}

void JsonWriter::value(bool b) {
    val_sep();
    buf_ += b ? "true" : "false";
    pending_elem_ = true;
}

void JsonWriter::value_raw(std::string_view raw_json) {
    val_sep();
    buf_ += raw_json;
    pending_elem_ = true;
}

// ---------------------------------------------------------------------------
// Path security
// ---------------------------------------------------------------------------
bool path_is_safe(std::string_view p, bool allow_absolute, std::string *reason) {
    if (p.empty()) { if (reason) *reason = "empty path"; return false; }
    if (p.find('\0') != std::string_view::npos) {
        if (reason) *reason = "NUL byte in path";
        return false;
    }
    for (char c : p) {
        if (static_cast<unsigned char>(c) < 0x20) {
            if (reason) *reason = "control character in path";
            return false;
        }
    }
    if (!allow_absolute && (p.front() == '/' || p.front() == '\\')) {
        if (reason) *reason = "absolute path not permitted";
        return false;
    }
    // Reject any '.' or '..' traversal component.
    size_t i = 0;
    while (i < p.size()) {
        size_t j = p.find('/', i);
        if (j == std::string_view::npos) j = p.size();
        std::string_view comp = p.substr(i, j - i);
        if (comp == "..") {
            if (reason) *reason = "'..' traversal component";
            return false;
        }
        i = j + 1;
    }
    return true;
}

std::optional<std::string> sanitize_under_root(const std::string &root,
                                               const std::string &p,
                                               std::string *reason) {
    std::error_code ec;
    fs::path root_real = fs::canonical(root, ec);
    if (ec) { if (reason) *reason = "root not resolvable"; return std::nullopt; }

    fs::path target = fs::path(p).is_absolute()
                          ? fs::weakly_canonical(p, ec)
                          : fs::weakly_canonical(root_real / p, ec);
    if (ec) { if (reason) *reason = "target not resolvable"; return std::nullopt; }

    // Lexical containment first (cheap), then symlink-aware canonical check
    // for existing paths.
    auto starts_with = [](const fs::path &child, const fs::path &parent) {
        auto cit = child.begin(), pit = parent.begin();
        for (; cit != child.end() && pit != parent.end(); ++cit, ++pit)
            if (*cit != *pit) return false;
        return pit == parent.end();
    };
    if (!starts_with(target, root_real)) {
        if (reason) *reason = "path escapes allowed root";
        return std::nullopt;
    }
    if (fs::exists(target, ec)) {
        fs::path real = fs::canonical(target, ec);
        if (ec || !starts_with(real, root_real)) {
            if (reason) *reason = "symlink escapes allowed root";
            return std::nullopt;
        }
        return real.string();
    }
    return target.string();
}

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------
double now_seconds() {
    using namespace std::chrono;
    return duration_cast<duration<double>>(steady_clock::now().time_since_epoch()).count();
}

std::string iso8601_utc_now() {
    auto t = std::time(nullptr);
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

uint64_t file_size_or_zero(const std::string &path) {
    struct stat st {};
    if (::stat(path.c_str(), &st) != 0) return 0;
    return static_cast<uint64_t>(st.st_size);
}

std::string hex_encode(std::span<const std::byte> data) {
    static const char *hexd = "0123456789abcdef";
    std::string out;
    out.resize(data.size() * 2);
    for (size_t i = 0; i < data.size(); ++i) {
        auto b = static_cast<unsigned char>(data[i]);
        out[2 * i]     = hexd[b >> 4];
        out[2 * i + 1] = hexd[b & 0xF];
    }
    return out;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::vector<std::byte> hex_decode(std::string_view hex) {
    std::vector<std::byte> out;
    if (hex.size() % 2) return out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = hexval(hex[i]), lo = hexval(hex[i + 1]);
        if (hi < 0 || lo < 0) return {};
        out.push_back(static_cast<std::byte>((hi << 4) | lo));
    }
    return out;
}

} // namespace av
