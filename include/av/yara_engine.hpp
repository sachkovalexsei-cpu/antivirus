// yara_engine.hpp - libyara rule compilation + scanning (Phase 2).
#pragma once

#include <memory>
#include <string>
#include <vector>

namespace av {

struct YaraMatch {
    std::string rule;      // rule identifier
    std::string namespace_; // file the rule came from
    std::string tag;       // first tag, if any (e.g. "trojan")
};

/// Compiles every *.yar / *.yara file in a rules directory into a single
/// ruleset and scans files against it. Compiled once, shared across threads
/// (yr_rules_scan_fd is thread-safe).
class YaraEngine {
public:
    YaraEngine();
    ~YaraEngine();
    YaraEngine(const YaraEngine &) = delete;
    YaraEngine &operator=(const YaraEngine &) = delete;

    /// Loads/compiles all rules found in `rules_dir` (non-recursive).
    /// Returns false and sets `err` on compile errors. Empty dir => no rules
    /// but still usable (scans return no matches).
    bool load_rules_from_dir(const std::string &rules_dir, std::string *err);

    /// Compile a single rule string (tests / dynamic updates).
    bool add_rule_string(const std::string &source, const std::string &ns,
                         std::string *err);

    /// Finalize compilation (call after last add_rule_string / file add).
    bool finish_compile(std::string *err);

    bool has_rules() const { return rules_ != nullptr; }
    size_t rule_count() const { return rule_count_; }

    /// Scan an open file descriptor. Appends matches to `out`.
    /// Returns 0 on success, negative YARA error code on failure.
    int scan_fd(int fd, std::vector<YaraMatch> &out, uint64_t timeout_secs = 10);

    /// Convenience: open path, scan, close.
    int scan_file(const std::string &path, std::vector<YaraMatch> &out,
                  uint64_t timeout_secs = 10);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    void *rules_ = nullptr; // YR_RULES* (opaque here)
    size_t rule_count_ = 0;
};

} // namespace av
