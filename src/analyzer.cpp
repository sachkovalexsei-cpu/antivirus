// analyzer.cpp - PE/ELF static inspection + unified threat scoring (Phase 2).
#include "av/analyzer.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <format>
#include <fstream>
#include <span>
#include <vector>

#include <fcntl.h>
#include <unistd.h>

#include "av/core.hpp"
#include "av/hash_db.hpp"
#include "av/service.hpp"
#include "av/yara_engine.hpp"

namespace av {

// ---------------------------------------------------------------------------
// Bounds-checked little-endian readers
// ---------------------------------------------------------------------------
namespace {

struct Reader {
    const std::byte *p;
    size_t n;
    bool ok = true;

    uint16_t le16(size_t off) {
        if (off + 2 > n) { ok = false; return 0; }
        return static_cast<uint16_t>(std::to_integer<uint8_t>(p[off])) |
               (static_cast<uint16_t>(std::to_integer<uint8_t>(p[off + 1])) << 8);
    }
    uint32_t le32(size_t off) {
        if (off + 4 > n) { ok = false; return 0; }
        uint32_t v = 0;
        for (int i = 0; i < 4; ++i)
            v |= static_cast<uint32_t>(std::to_integer<uint8_t>(p[off + i]))
                 << (8 * i);
        return v;
    }
    uint64_t le64(size_t off) {
        if (off + 8 > n) { ok = false; return 0; }
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i)
            v |= static_cast<uint64_t>(std::to_integer<uint8_t>(p[off + i]))
                 << (8 * i);
        return v;
    }
    bool inbounds(size_t off, size_t len) const {
        return off <= n && off + len <= n;
    }
};

bool load_file(const std::string &path, uint64_t max_bytes,
               std::vector<std::byte> &out) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in) return false;
    auto sz = static_cast<uint64_t>(in.tellg());
    if (sz > max_bytes) sz = max_bytes; // parse window only (memory cap)
    in.seekg(0);
    out.resize(static_cast<size_t>(sz));
    in.read(reinterpret_cast<char *>(out.data()),
            static_cast<std::streamsize>(sz));
    out.resize(static_cast<size_t>(in.gcount()));
    return !out.empty();
}

/// Substring hunt for known-bad API names inside the raw image. Import lookup
/// tables (PE .rdata) and .dynstr (ELF) store them as ASCIIZ strings, so a
/// bounded byte scan is simple and effective as a first-pass heuristic.
static void hunt_suspicious_strings(const std::vector<std::byte> &buf,
                                    BinaryReport &rep) {
    size_t hay_len = std::min<size_t>(buf.size(), 2u << 20); // 2 MiB window
    std::string_view hay(reinterpret_cast<const char *>(buf.data()), hay_len);
    for (const char *api : kSuspiciousImports) {
        if (hay.find(api) != std::string_view::npos)
            rep.suspicious_imports.emplace_back(api);
    }
}

// ---------------------------------------------------------------------------
// PE parsing: MZ -> e_lfanew -> COFF header -> optional header -> sections
// ---------------------------------------------------------------------------
void parse_pe(const std::vector<std::byte> &buf, BinaryReport &rep) {
    Reader r{buf.data(), buf.size()};
    if (r.le16(0) != 0x5A4D) return; // "MZ"
    uint32_t pe_off = r.le32(0x3C);
    if (!r.ok || !r.inbounds(pe_off, 24)) { rep.error = "bad e_lfanew"; return; }
    if (r.le32(pe_off) != 0x00004550) return; // "PE\0\0"

    rep.is_pe = true;
    uint16_t machine = r.le16(pe_off + 4);
    uint16_t nsec = r.le16(pe_off + 6);
    uint16_t optsz = r.le16(pe_off + 20);
    switch (machine) {
    case 0x014c: rep.arch = "i386";    break;
    case 0x8664: rep.arch = "x86-64";  break;
    case 0xAA64: rep.arch = "arm64ec"; break;
    default:     rep.arch = std::format("0x{:04x}", machine);
    }

    uint32_t sec_off = pe_off + 24 + optsz;
    for (uint16_t i = 0; i < nsec && i < 96; ++i) {
        size_t so = sec_off + static_cast<size_t>(i) * 40;
        if (!r.inbounds(so, 40)) break;
        SectionInfo s;
        char name[9] = {};
        std::memcpy(name, buf.data() + so, 8);
        s.name = name;
        uint32_t rawsz = r.le32(so + 16);
        uint32_t rawoff = r.le32(so + 20);
        s.raw_size = rawsz;
        if (rawsz > 0 && r.inbounds(rawoff, rawsz)) {
            std::span<const std::byte> data(buf.data() + rawoff, rawsz);
            s.entropy = span_entropy(data);
        }
        rep.max_section_entropy = std::max(rep.max_section_entropy, s.entropy);
        rep.sections.push_back(std::move(s));
    }

    hunt_suspicious_strings(buf, rep);

    // Packer heuristic: executable-looking section with very high entropy.
    for (auto &s : rep.sections) {
        if (s.entropy > 7.6 && s.raw_size > 4096) rep.packed_heuristic = true;
        if (s.entropy > 7.2 &&
            (s.name.rfind(".text", 0) == 0 || s.name == ".upx0" ||
             s.name == ".aspack"))
            rep.packed_heuristic = true;
    }
}

// ---------------------------------------------------------------------------
// ELF parsing (ELF64 + ELF32, endianness taken from e_ident)
// ---------------------------------------------------------------------------
void parse_elf(const std::vector<std::byte> &buf, BinaryReport &rep) {
    if (buf.size() < 64) return;
    if (!(std::to_integer<uint8_t>(buf[0]) == 0x7F &&
          std::to_integer<uint8_t>(buf[1]) == 'E' &&
          std::to_integer<uint8_t>(buf[2]) == 'L' &&
          std::to_integer<uint8_t>(buf[3]) == 'F'))
        return;

    rep.is_elf = true;
    uint8_t ei_class = std::to_integer<uint8_t>(buf[4]); // 1=32, 2=64
    uint8_t ei_data  = std::to_integer<uint8_t>(buf[5]); // 1=LE, 2=BE
    bool be = ei_data == 2;
    auto b = [&](size_t o) -> uint64_t {
        return o < buf.size() ? std::to_integer<uint64_t>(buf[o]) : 0;
    };
    auto rd16 = [&](size_t o) -> uint32_t {
        if (o + 2 > buf.size()) return 0;
        return be ? (b(o) << 8) | b(o + 1) : (b(o + 1) << 8) | b(o);
    };
    auto rd32 = [&](size_t o) -> uint32_t {
        if (o + 4 > buf.size()) return 0;
        uint32_t v = 0;
        for (int i = 0; i < 4; ++i) {
            uint32_t byte = static_cast<uint32_t>(b(o + i));
            v |= be ? byte << (8 * (3 - i)) : byte << (8 * i);
        }
        return v;
    };
    auto rd64 = [&](size_t o) -> uint64_t {
        if (o + 8 > buf.size()) return 0;
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) {
            uint64_t byte = b(o + i);
            v |= be ? byte << (8 * (7 - i)) : byte << (8 * i);
        }
        return v;
    };

    uint16_t mach = static_cast<uint16_t>(rd16(18));
    switch (mach) {
    case 0x3E: rep.arch = "x86-64";  break;
    case 0x03: rep.arch = "i386";    break;
    case 0xB7: rep.arch = "aarch64"; break;
    case 0x28: rep.arch = "arm";     break;
    default:   rep.arch = std::format("0x{:02x}", mach);
    }

    if (ei_class == 2) { // ---- ELF64 ----
        uint64_t shoff = rd64(0x28);
        uint16_t shentsize = static_cast<uint16_t>(rd16(0x3A));
        uint16_t shnum = static_cast<uint16_t>(rd16(0x3C));
        uint16_t shstrndx = static_cast<uint16_t>(rd16(0x3E));
        if (shentsize < 64 || shnum == 0 || shnum > 4096 ||
            shoff + static_cast<uint64_t>(shnum) * shentsize > buf.size()) {
            rep.error = "suspicious ELF section header table";
            return;
        }
        size_t str_hdr = shoff + static_cast<size_t>(shstrndx) * shentsize;
        uint64_t stroff = rd64(str_hdr + 24);
        uint64_t strsz  = rd64(str_hdr + 32);
        auto secname = [&](uint32_t nameoff) -> std::string {
            if (stroff >= buf.size() || nameoff >= strsz ||
                stroff + nameoff >= buf.size())
                return "";
            const char *s = reinterpret_cast<const char *>(buf.data()) +
                            stroff + nameoff;
            size_t left = buf.size() - (stroff + nameoff);
            return std::string(s, strnlen(s, std::min<size_t>(left, 32)));
        };
        for (uint16_t i = 0; i < shnum; ++i) {
            size_t ho = shoff + static_cast<size_t>(i) * shentsize;
            uint32_t nameoff = rd32(ho);
            uint64_t size = rd64(ho + 32);
            uint64_t off = rd64(ho + 24);
            uint64_t flags = rd64(ho + 40); // SHF_EXECINSTR = 0x4
            if (size == 0 || size > (1ull << 31)) continue;
            if (off + size > buf.size()) continue;
            SectionInfo s;
            s.name = secname(nameoff);
            s.raw_size = size;
            std::span<const std::byte> data(buf.data() + off,
                                            static_cast<size_t>(size));
            s.entropy = span_entropy(data);
            rep.max_section_entropy = std::max(rep.max_section_entropy,
                                               s.entropy);
            if ((flags & 0x4) && s.entropy > 7.2) rep.packed_heuristic = true;
            rep.sections.push_back(std::move(s));
        }
    } else if (ei_class == 1) { // ---- ELF32 ----
        uint32_t shoff = rd32(0x10);
        uint16_t shentsize = static_cast<uint16_t>(rd16(0x2E));
        uint16_t shnum = static_cast<uint16_t>(rd16(0x30));
        if (shentsize < 40 || shnum == 0 || shnum > 4096 ||
            static_cast<uint64_t>(shoff) +
                    static_cast<uint64_t>(shnum) * shentsize > buf.size()) {
            rep.error = "suspicious ELF32 section header table";
            return;
        }
        for (uint16_t i = 0; i < shnum; ++i) {
            size_t ho = shoff + static_cast<size_t>(i) * shentsize;
            uint32_t size = rd32(ho + 16);
            uint32_t off = rd32(ho + 10);
            if (size == 0 || size > (1u << 31) ||
                static_cast<uint64_t>(off) + size > buf.size())
                continue;
            SectionInfo s;
            s.raw_size = size;
            std::span<const std::byte> data(buf.data() + off,
                                            static_cast<size_t>(size));
            s.entropy = span_entropy(data);
            rep.max_section_entropy = std::max(rep.max_section_entropy,
                                               s.entropy);
            rep.sections.push_back(std::move(s));
        }
    }

    hunt_suspicious_strings(buf, rep);
}

} // namespace

BinaryReport inspect_binary(const std::string &path, uint64_t max_bytes) {
    BinaryReport rep;
    std::vector<std::byte> buf;
    if (!load_file(path, max_bytes, buf)) {
        rep.error = "cannot read file";
        return rep;
    }
    parse_pe(buf, rep);
    if (!rep.is_pe) parse_elf(buf, rep);
    return rep;
}

// ---------------------------------------------------------------------------
// Unified scoring engine
// ---------------------------------------------------------------------------
static int yara_tag_score(std::string_view tag) {
    // Tag semantics defined by rules/*.yar: severe families score highest.
    if (tag == "trojan" || tag == "backdoor" || tag == "ransomware")
        return 70;
    if (tag == "worm" || tag == "exploit" || tag == "spyware")
        return 60;
    if (tag == "miner" || tag == "downloader" || tag == "dropper")
        return 50;
    if (tag == "hacktool" || tag == "pua")
        return 30;
    return 20; // untagged match is still meaningful
}

double compute_threat_score(const ScoreComponents &c) {
    double score = 0.0;
    if (c.hash_match) score += c.hash_severity; // exact DB hit dominates
    if (!c.yara_rules.empty()) {
        score += c.yara_tags_score;
        if (c.yara_rules.size() > 1)
            score += std::min(10.0, 2.0 * (c.yara_rules.size() - 1));
    }
    if (c.high_entropy) score += 25;
    if (c.binary_packed) score += 10;
    score += std::min(15.0, 3.0 * c.suspicious_imports);
    if (c.access_error) score += 5; // blind spot deserves attention
    return std::min(100.0, score);
}

Verdict verdict_from_score(const ScoreComponents &c, double score) {
    if (c.hash_match && c.hash_severity >= 80) return Verdict::Malicious;
    if (score >= 80.0) return Verdict::Malicious;
    if (score >= 40.0) return Verdict::Suspicious;
    return Verdict::Clean;
}

ThreatAssessment assess_with_engines(const std::string &file_path,
                                     uint64_t max_file_bytes,
                                     HashDb *db, YaraEngine *yara) {
    double t0 = now_seconds();
    ThreatAssessment a;
    a.file_path = file_path;
    a.size_bytes = file_size_or_zero(file_path);

    // --- 1. SHA-256 + SQLite hash DB lookup -----------------------------------
    std::string herr;
    auto sha = sha256_file(file_path, max_file_bytes, &herr);
    if (sha) {
        a.sha256 = *sha;
        if (db) {
            if (auto sig = db->lookup(*sha)) {
                a.components.hash_match = true;
                a.components.hash_threat_name = sig->name;
                a.components.hash_severity = sig->severity;
            }
        }
    } else {
        a.components.access_error = herr != "file exceeds size cap";
    }

    // --- 2. YARA rule matches ---------------------------------------------------
    if (yara && yara->has_rules()) {
        std::vector<YaraMatch> matches;
        if (yara->scan_file(file_path, matches) == 0) {
            int best = 0;
            for (auto &m : matches) {
                a.components.yara_rules.push_back(m.rule);
                best = std::max(best, yara_tag_score(m.tag));
            }
            a.components.yara_tags_score = best;
        }
    }

    // --- 3. Shannon entropy (>7.5 flagged) --------------------------------------
    std::string eerr;
    if (auto e = file_entropy(file_path, max_file_bytes, &eerr)) {
        a.components.entropy = e->entropy_bits_per_byte;
        a.components.high_entropy = e->entropy_bits_per_byte > 7.5;
    }

    // --- 4. Static PE/ELF inspection ---------------------------------------------
    if (sha) {
        BinaryReport br = inspect_binary(file_path, max_file_bytes);
        if (br.is_pe || br.is_elf) {
            a.components.binary_packed = br.packed_heuristic;
            a.components.suspicious_imports =
                static_cast<int>(br.suspicious_imports.size());
        }
    }

    // --- 5. Unified verdict --------------------------------------------------------
    a.score = compute_threat_score(a.components);
    a.verdict = verdict_from_score(a.components, a.score);

    if (a.components.hash_match)
        a.threat_name = a.components.hash_threat_name;
    else if (!a.components.yara_rules.empty())
        a.threat_name = "YARA:" + a.components.yara_rules.front();
    else if (a.verdict != Verdict::Clean)
        a.threat_name = kGenericThreat;

    a.scan_seconds = now_seconds() - t0;
    return a;
}

ThreatAssessment calculate_threat_score(const std::string &file_path,
                                        uint64_t max_file_bytes) {
    // Convenience entry point: uses the process-wide service when one is
    // running (so it inherits its DB/YARA engines); standalone callers get
    // hash+entropy-only analysis.
    DetectionService *svc = active_service();
    if (svc) return svc->assess_file(file_path);
    return assess_with_engines(file_path, max_file_bytes, nullptr, nullptr);
}

std::string assessment_to_json(const ThreatAssessment &a, bool pretty) {
    JsonWriter j(pretty);
    j.begin_obj();
    j.key("file");           j.value(a.file_path);
    j.key("sha256");         j.value(a.sha256);
    j.key("size_bytes");     j.value(a.size_bytes);
    j.key("verdict");        j.value(verdict_str(a.verdict));
    j.key("threat_name");    j.value(a.threat_name);
    j.key("score");          j.value_raw(std::format("{:.2f}", a.score));
    j.key("time_seconds");   j.value_raw(std::format("{:.6f}", a.scan_seconds));
    j.key("components");
    j.begin_obj();
    j.key("hash_match");       j.value(a.components.hash_match);
    j.key("hash_severity");    j.value(a.components.hash_severity);
    j.key("yara_matches");
    j.begin_arr();
    for (auto &r : a.components.yara_rules) j.value(r);
    j.end_arr();
    j.key("entropy");          j.value_raw(std::format("{:.4f}", a.components.entropy));
    j.key("high_entropy");     j.value(a.components.high_entropy);
    j.key("packed_heuristic"); j.value(a.components.binary_packed);
    j.key("suspicious_imports"); j.value(a.components.suspicious_imports);
    j.key("access_error");     j.value(a.components.access_error);
    j.end_obj(true);
    j.end_obj();
    return j.str();
}

} // namespace av
