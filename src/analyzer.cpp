// analyzer.cpp - PE/ELF static inspection + unified threat scoring (Phase 2).
#include "av/analyzer.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstring>
#include <format>
#include <fstream>
#include <set>
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

/// Same as load_file but tolerates empty files (a 0-byte file is "loaded"
/// successfully with an empty buffer rather than reported as unreadable).
static bool load_file_for_assess(const std::string &path, uint64_t max_bytes,
                                 std::vector<std::byte> &out) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in) return false;
    auto sz = static_cast<uint64_t>(in.tellg());
    if (sz > max_bytes) sz = max_bytes;
    in.seekg(0);
    out.resize(static_cast<size_t>(sz));
    if (sz > 0) {
        in.read(reinterpret_cast<char *>(out.data()),
                static_cast<std::streamsize>(sz));
        out.resize(static_cast<size_t>(in.gcount()));
    }
    return true;
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

/// Case-insensitive ASCII lowercase helper for DLL-name matching.
static std::string lower_ascii(std::string s) {
    for (auto &c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

/// Known-abused DLLs (credential theft / injection tooling).
static bool abused_dll(std::string_view dll_lower) {
    static constexpr const char *kAbused[] = {
        "scansuite.dll", "dbghelp.dll", "winnsi.dll", "winsta.dll",
        "netapi32.dll", "samlib.dll", "ntdll.dll",
    };
    for (auto d : kAbused)
        if (dll_lower == d) return true;
    return false;
}

// ---------------------------------------------------------------------------
// PE import table walk: data dir [1] -> IMAGE_IMPORT_DESCRIPTOR array ->
// INT/ILT thunks -> IMAGE_IMPORT_BY_NAME hints. All offsets bounds-checked.
// ---------------------------------------------------------------------------
static void parse_pe_imports(const std::vector<std::byte> &buf, Reader &r,
                             uint32_t pe_off, uint16_t optsz, bool pe32plus,
                             BinaryReport &rep) {
    uint32_t dd_off = pe_off + 24 + (pe32plus ? 112u : 96u);
    if (!r.inbounds(dd_off + 8 * 1, 8)) return; // no data directories
    uint32_t imp_rva = r.le32(dd_off + 8 * 1);
    uint32_t imp_sz  = r.le32(dd_off + 8 * 1 + 4);
    if (imp_rva == 0 || imp_sz == 0 || imp_sz > 0x10000) return;

    // RVA -> raw offset conversion using the section table.
    uint32_t sec_off = pe_off + 24 + optsz;
    uint16_t nsec = r.le16(pe_off + 6);
    auto rva_to_off = [&](uint32_t rva) -> uint32_t {
        for (uint16_t i = 0; i < nsec && i < 96; ++i) {
            size_t so = sec_off + static_cast<size_t>(i) * 40;
            if (!r.inbounds(so, 40)) break;
            uint32_t va   = r.le32(so + 12);
            uint32_t vsz  = r.le32(so + 8);
            uint32_t raw  = r.le32(so + 20);
            if (rva >= va && rva < va + vsz + 0x200u) // tolerate alignment slack
                return raw + (rva - va);
        }
        return 0;
    };

    uint32_t imp_off = rva_to_off(imp_rva);
    if (imp_off == 0 || !r.inbounds(imp_off, 20)) return;

    const size_t thunk_sz = pe32plus ? 8 : 4;
    const uint64_t ordinal_flag = pe32plus ? (1ull << 63) : (1u << 31);

    for (int desc = 0; desc < 64; ++desc) { // cap descriptor count
        size_t dobj = imp_off + static_cast<size_t>(desc) * 20;
        if (!r.inbounds(dobj, 20)) break;
        uint32_t name_rva  = r.le32(dobj + 12);
        uint32_t orig_thunk = r.le32(dobj + 16);
        uint32_t first_thunk = r.le32(dobj);
        uint32_t thunk_rva = orig_thunk ? orig_thunk : first_thunk;
        if (name_rva == 0 || thunk_rva == 0) break; // terminator

        uint32_t name_off = rva_to_off(name_rva);
        std::string dll;
        if (name_off && r.inbounds(name_off, 2)) {
            const char *s = reinterpret_cast<const char *>(buf.data()) + name_off;
            size_t left = buf.size() - name_off;
            dll = std::string(s, strnlen(s, std::min<size_t>(left, 64)));
        }
        if (abused_dll(lower_ascii(dll))) rep.suspicious_dll = true;

        uint32_t thunk_off = rva_to_off(thunk_rva);
        if (thunk_off == 0) continue;
        for (int t = 0; t < 512; ++t) { // cap thunks per DLL
            size_t to = thunk_off + static_cast<size_t>(t) * thunk_sz;
            if (!r.inbounds(to, thunk_sz)) break;
            uint64_t thunk = thunk_sz == 8 ? r.le64(to) : r.le32(to);
            if (thunk == 0) break;                       // end of INT
            if (thunk & ordinal_flag) {                  // import by ordinal
                uint16_t ord = static_cast<uint16_t>(thunk & 0xFFFF);
                std::string api = "#" + std::to_string(ord);
                rep.imports.push_back({dll, api});
                if (rep.imports.size() >= 2048) return;
                continue;
            }
            uint32_t ibn_off = rva_to_off(static_cast<uint32_t>(thunk & 0x7FFFFFFF));
            if (ibn_off == 0 || !r.inbounds(ibn_off, 4)) break;
            const char *fn = reinterpret_cast<const char *>(buf.data()) + ibn_off + 2;
            size_t left = buf.size() - (ibn_off + 2);
            std::string api(fn, strnlen(fn, std::min<size_t>(left, 128)));
            rep.imports.push_back({dll, api});
            if (rep.imports.size() >= 2048) return;
        }
    }
}

// ---------------------------------------------------------------------------
// ELF dynamic symbol table (.dynsym/.dynstr): collect imported function names.
// ---------------------------------------------------------------------------
static void parse_elf_symbols(const std::vector<std::byte> &buf,
                              uint64_t dynstr_off, uint64_t dynstr_sz,
                              uint16_t shentsize, uint64_t shoff,
                              uint16_t shnum, bool sym64,
                              BinaryReport &rep) {
    for (uint16_t i = 0; i < shnum; ++i) {
        size_t ho = shoff + static_cast<size_t>(i) * shentsize;
        if (ho + shentsize > buf.size()) break;
        auto rd32h = [&](size_t o) -> uint32_t {
            uint32_t v = 0;
            for (int k = 0; k < 4; ++k)
                v |= static_cast<uint32_t>(std::to_integer<uint8_t>(buf[o + k]))
                     << (8 * k);
            return v;
        };
        auto rd64h = [&](size_t o) -> uint64_t {
            uint64_t v = 0;
            for (int k = 0; k < 8; ++k)
                v |= static_cast<uint64_t>(std::to_integer<uint8_t>(buf[o + k]))
                     << (8 * k);
            return v;
        };
        uint32_t type = rd32h(ho + 4); // SHT_DYNSYM == 11
        if (type != 11) continue;
        uint64_t off = sym64 ? rd64h(ho + 24) : rd32h(ho + 16);
        uint64_t size = sym64 ? rd64h(ho + 32) : rd32h(ho + 20);
        uint64_t entsz = sym64 ? 24 : 16;
        if (entsz == 0 || size > (1ull << 31) || off + size > buf.size())
            continue;
        for (uint64_t s = 0; s + entsz <= size && rep.imports.size() < 2048; ++s) {
            size_t so = off + static_cast<size_t>(s) * entsz;
            uint32_t nameoff = rd32h(so);
            uint8_t info = std::to_integer<uint8_t>(buf[so + (sym64 ? 4 : 12)]);
            uint8_t stype = info & 0xF;
            if (stype != 2) continue; // STT_FUNC only
            if (nameoff == 0 || nameoff >= dynstr_sz) continue;
            if (dynstr_off + nameoff >= buf.size()) continue;
            const char *nm = reinterpret_cast<const char *>(buf.data()) +
                             dynstr_off + nameoff;
            size_t left = buf.size() - (dynstr_off + nameoff);
            rep.imports.push_back({"", std::string(nm, strnlen(nm, std::min<size_t>(left, 128)))});
        }
        break; // first .dynsym is enough
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
    uint16_t magic = r.le16(pe_off + 24); // optional header magic
    bool pe32plus = magic == 0x20b;
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

    // PE image base (for potential future use) + data directories.
    uint32_t dd_off = pe_off + 24 + (pe32plus ? 112u : 96u);
    if (r.inbounds(dd_off, 8 * 10)) {
        // Data directory index 9 = TLS directory. TLS callbacks run before
        // the entry point and are a classic anti-debug / early-payload vector.
        uint32_t tls_rva = r.le32(dd_off + 8 * 9);
        uint32_t tls_sz  = r.le32(dd_off + 8 * 9 + 4);
        rep.has_tls_callbacks = tls_rva != 0 && tls_sz >= 20;
    }

    parse_pe_imports(buf, r, pe_off, optsz, pe32plus, rep);

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
        uint64_t dynstr_off = 0, dynstr_sz = 0;
        for (uint16_t i = 0; i < shnum; ++i) {
            size_t ho = shoff + static_cast<size_t>(i) * shentsize;
            uint32_t nameoff = rd32(ho);
            uint64_t size = rd64(ho + 32);
            uint64_t off = rd64(ho + 24);
            uint32_t type = rd32(ho + 4); // SHT_STRTAB == 3
            uint64_t flags = rd64(ho + 40); // SHF_EXECINSTR = 0x4
            std::string nm = secname(nameoff);
            if (type == 3 && nm == ".dynstr") {
                dynstr_off = off;
                dynstr_sz = size;
            }
            if (size == 0 || size > (1ull << 31)) continue;
            if (off + size > buf.size()) continue;
            SectionInfo s;
            s.name = nm;
            s.raw_size = size;
            std::span<const std::byte> data(buf.data() + off,
                                            static_cast<size_t>(size));
            s.entropy = span_entropy(data);
            rep.max_section_entropy = std::max(rep.max_section_entropy,
                                               s.entropy);
            if ((flags & 0x4) && s.entropy > 7.2) rep.packed_heuristic = true;
            rep.sections.push_back(std::move(s));
        }
        if (dynstr_sz > 0 && dynstr_off + dynstr_sz <= buf.size())
            parse_elf_symbols(buf, dynstr_off, dynstr_sz, shentsize, shoff,
                              shnum, /*sym64=*/true, rep);
    } else if (ei_class == 1) { // ---- ELF32 ----
        uint32_t shoff = rd32(0x10);
        uint16_t shentsize = static_cast<uint16_t>(rd16(0x2E));
        uint16_t shnum = static_cast<uint16_t>(rd16(0x30));
        uint16_t shstrndx = static_cast<uint16_t>(rd16(0x32));
        if (shentsize < 40 || shnum == 0 || shnum > 4096 ||
            static_cast<uint64_t>(shoff) +
                    static_cast<uint64_t>(shnum) * shentsize > buf.size()) {
            rep.error = "suspicious ELF32 section header table";
            return;
        }
        uint32_t str_hdr = shoff + static_cast<uint32_t>(shstrndx) * shentsize;
        uint32_t stroff = rd32(str_hdr + 16);
        uint32_t strsz  = rd32(str_hdr + 20);
        auto secname = [&](uint32_t nameoff) -> std::string {
            if (stroff >= buf.size() || nameoff >= strsz ||
                static_cast<uint64_t>(stroff) + nameoff >= buf.size())
                return "";
            const char *s = reinterpret_cast<const char *>(buf.data()) +
                            stroff + nameoff;
            size_t left = buf.size() - (static_cast<size_t>(stroff) + nameoff);
            return std::string(s, strnlen(s, std::min<size_t>(left, 32)));
        };
        uint64_t dynstr_off = 0, dynstr_sz = 0;
        for (uint16_t i = 0; i < shnum; ++i) {
            size_t ho = shoff + static_cast<size_t>(i) * shentsize;
            uint32_t nameoff = rd32(ho);
            uint32_t type = rd32(ho + 4);
            uint32_t size = rd32(ho + 16);
            uint32_t off = rd32(ho + 10);
            std::string nm = secname(nameoff);
            if (type == 3 && nm == ".dynstr") {
                dynstr_off = off;
                dynstr_sz = size;
            }
            if (size == 0 || size > (1u << 31) ||
                static_cast<uint64_t>(off) + size > buf.size())
                continue;
            SectionInfo s;
            s.name = nm;
            s.raw_size = size;
            std::span<const std::byte> data(buf.data() + off,
                                            static_cast<size_t>(size));
            s.entropy = span_entropy(data);
            rep.max_section_entropy = std::max(rep.max_section_entropy,
                                               s.entropy);
            rep.sections.push_back(std::move(s));
        }
        if (dynstr_sz > 0 && dynstr_off + dynstr_sz <= buf.size())
            parse_elf_symbols(buf, dynstr_off, dynstr_sz, shentsize, shoff,
                              shnum, /*sym64=*/false, rep);
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
    if (tag == "worm" || tag == "exploit" || tag == "spyware" ||
        tag == "virus")
        return 60;
    if (tag == "miner" || tag == "downloader" || tag == "dropper")
        return 50;
    if (tag == "hacktool" || tag == "pua")
        return 30;
    return 20; // untagged match is still meaningful
}

/// True when a YARA rule name/tag clearly indicates a backdoor or RAT.
static bool is_backdoor_rule(const YaraMatch &m) {
    auto has = [](std::string_view s, std::string_view sub) {
        std::string lo(s), q(sub);
        for (auto &c : lo) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        for (auto &c : q)  c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return lo.find(q) != std::string::npos;
    };
    return has(m.tag, "backdoor") || has(m.rule, "backdoor") ||
           has(m.rule, "rat") || has(m.tag, "rat") || has(m.rule, "c2_");
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
    if (c.has_tls_callbacks) score += 8; // PE TLS callback anti-analysis vector
    if (c.access_error) score += 5;      // blind spot deserves attention
    return std::min(100.0, score);
}

Verdict verdict_from_score(const ScoreComponents &c, double score) {
    if (c.hash_match && c.hash_severity >= 80) return Verdict::Malicious;
    // A confirmed backdoor/RAT YARA signature alone is enough to convict.
    for (auto &r : c.yara_rules) {
        std::string lo = r;
        for (auto &ch : lo) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        if (lo.find("backdoor") != std::string::npos || lo.find("_rat") != std::string::npos ||
            lo.find("c2_") != std::string::npos)
            return Verdict::Malicious;
    }
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

    // Load the image once for both YARA memory scanning and static analysis.
    // This also lets us compute an accurate whole-file entropy from the same
    // bytes we already have in memory (fixes duplicate I/O).
    std::vector<std::byte> buf;
    const bool loaded = load_file_for_assess(file_path, max_file_bytes, buf);

    // --- 2. YARA rule matches ---------------------------------------------------
    bool backdoor_hit = false;
    if (yara && yara->has_rules() && loaded) {
        std::vector<YaraMatch> matches;
        if (yara->scan_mem(buf, matches) == 0) {
            int best = 0;
            for (auto &m : matches) {
                a.components.yara_rules.push_back(m.rule);
                best = std::max(best, yara_tag_score(m.tag));
                if (is_backdoor_rule(m)) backdoor_hit = true;
            }
            a.components.yara_tags_score = best;
        }
    }

    // --- 3. Shannon entropy (>7.5 flagged) --------------------------------------
    if (loaded && !buf.empty()) {
        // Sample up to 2 MiB centred on the start for scoring stability.
        std::span<const std::byte> win(buf.data(),
                                       std::min<size_t>(buf.size(), 2u << 20));
        double e = span_entropy(win);
        a.components.entropy = e;
        a.components.high_entropy = e > 7.5;
    } else if (!loaded && !a.components.access_error) {
        std::string eerr;
        if (auto e = file_entropy(file_path, max_file_bytes, &eerr)) {
            a.components.entropy = e->entropy_bits_per_byte;
            a.components.high_entropy = e->entropy_bits_per_byte > 7.5;
        }
    }

    // --- 4. Static PE/ELF inspection ---------------------------------------------
    if (loaded) {
        BinaryReport br;
        parse_pe(buf, br);
        if (!br.is_pe) parse_elf(buf, br);
        if (br.is_pe || br.is_elf) {
            a.components.binary_packed = br.packed_heuristic;
            a.components.has_tls_callbacks = br.has_tls_callbacks;
            // Unique suspicious API names (the substring hunt can hit the same
            // name in several tables).
            std::set<std::string> uniq(br.suspicious_imports.begin(),
                                       br.suspicious_imports.end());
            a.components.suspicious_imports = static_cast<int>(uniq.size());
        }
    }

    // --- 5. Unified verdict --------------------------------------------------------
    a.score = compute_threat_score(a.components);
    a.verdict = verdict_from_score(a.components, a.score);
    if (backdoor_hit) a.verdict = Verdict::Malicious;

    if (a.components.hash_match)
        a.threat_name = a.components.hash_threat_name;
    else if (backdoor_hit)
        a.threat_name = "Backdoor.Generic";
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
