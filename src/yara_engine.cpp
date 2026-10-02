// yara_engine.cpp - libyara rule compilation + fd scanning (Phase 2).
#include "av/yara_engine.hpp"

#include <filesystem>
#include <fstream>
#include <sstream>

#include <fcntl.h>
#include <unistd.h>

#include <yara.h>

namespace fs = std::filesystem;

namespace av {

struct YaraEngine::Impl {
    YR_COMPILER *compiler = nullptr;
    YR_RULES *rules = nullptr;
    bool initialized = false;
    std::string last_error;

    ~Impl() {
        if (rules) yr_rules_destroy(rules);
        if (compiler) yr_compiler_destroy(compiler);
        if (initialized) yr_finalize();
    }
};

static bool ensure_yara_init() {
    static std::once_flag once;
    static bool ok = false;
    std::call_once(once, [] { ok = yr_initialize() == ERROR_SUCCESS; });
    return ok;
}

YaraEngine::YaraEngine() : impl_(std::make_unique<Impl>()) {}
YaraEngine::~YaraEngine() {
    if (impl_->rules) yr_rules_destroy(impl_->rules);
    impl_->rules = nullptr;
    rules_ = nullptr;
}

bool YaraEngine::load_rules_from_dir(const std::string &rules_dir,
                                     std::string *err) {
    if (!ensure_yara_init()) {
        if (err) *err = "yr_initialize failed";
        return false;
    }
    if (!impl_->compiler) {
        if (yr_compiler_create(&impl_->compiler) != ERROR_SUCCESS) {
            if (err) *err = "yr_compiler_create failed";
            return false;
        }
    }

    std::error_code ec;
    if (!fs::exists(rules_dir, ec)) {
        // No rules directory: engine stays usable with zero rules.
        return true;
    }

    int loaded = 0;
    for (auto &entry : fs::directory_iterator(rules_dir, ec)) {
        if (!entry.is_regular_file()) continue;
        auto ext = entry.path().extension().string();
        if (ext != ".yar" && ext != ".yara") continue;

        std::ifstream in(entry.path());
        std::ostringstream ss;
        ss << in.rdbuf();
        std::string src = ss.str();

        // Namespace = file stem so rules from different files don't collide.
        std::string ns = entry.path().stem().string();
        // YARA namespaces must be valid identifiers.
        for (auto &c : ns)
            if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_'))
                c = '_';

        int errors = yr_compiler_add_string(impl_->compiler, src.c_str(),
                                             ns.c_str());
        if (errors > 0) {
            if (err) *err = "compile errors in " + entry.path().string();
            return false;
        }
        ++loaded;
    }

    if (loaded == 0) return true;

    if (!finish_compile(err)) return false;
    return true;
}

bool YaraEngine::add_rule_string(const std::string &source,
                                 const std::string &ns, std::string *err) {
    if (!ensure_yara_init()) {
        if (err) *err = "yr_initialize failed";
        return false;
    }
    if (!impl_->compiler &&
        yr_compiler_create(&impl_->compiler) != ERROR_SUCCESS) {
        if (err) *err = "yr_compiler_create failed";
        return false;
    }
    const char *nsz = ns.empty() ? nullptr : ns.c_str();
    if (yr_compiler_add_string(impl_->compiler, source.c_str(), nsz) > 0) {
        if (err) *err = "rule compile error";
        return false;
    }
    return true;
}

bool YaraEngine::finish_compile(std::string *err) {
    if (!impl_->compiler) return true; // nothing to compile
    if (impl_->rules) {
        yr_rules_destroy(impl_->rules);
        impl_->rules = nullptr;
        rules_ = nullptr;
        rule_count_ = 0;
    }
    if (yr_compiler_get_rules(impl_->compiler, &impl_->rules) != ERROR_SUCCESS) {
        if (err) *err = "yr_compiler_get_rules failed";
        return false;
    }
    rules_ = impl_->rules;

    // Count rules for reporting.
    size_t n = 0;
    YR_RULE *r;
    yr_rules_foreach(impl_->rules, r) { ++n; }
    rule_count_ = n;
    return true;
}

namespace {
struct ScanCtx {
    std::vector<YaraMatch> *out;
};

// Legacy YARA 4.x callback signature (Debian libyara-dev 4.2).
int callback(YR_SCAN_CONTEXT *, int message, void *data, void *user_data) {
    if (message != CALLBACK_MSG_RULE_MATCHING) return CALLBACK_CONTINUE;
    auto *ctx = static_cast<ScanCtx *>(user_data);
    auto *rule = static_cast<YR_RULE *>(data);
    YaraMatch m;
    m.rule = rule->identifier ? rule->identifier : "?";
    m.namespace_ = (rule->ns && rule->ns->name) ? rule->ns->name : "";
    // Tags are stored as a packed, null-separated string list.
    const char *t = nullptr;
    yr_rule_tags_foreach(rule, t) {
        if (t && *t) { m.tag = t; break; } // first tag is the classifier tag
    }
    ctx->out->push_back(std::move(m));
    return CALLBACK_CONTINUE;
}
} // namespace

int YaraEngine::scan_fd(int fd, std::vector<YaraMatch> &out,
                        uint64_t timeout_secs) {
    if (!impl_->rules) return 0; // no rules -> no matches
    ScanCtx ctx{&out};
    int rc = yr_rules_scan_fd(impl_->rules, fd, SCAN_FLAGS_FAST_MODE,
                              callback, reinterpret_cast<void *>(&ctx),
                              static_cast<int>(timeout_secs));
    return rc == ERROR_SUCCESS ? 0 : -rc;
}

int YaraEngine::scan_file(const std::string &path, std::vector<YaraMatch> &out,
                          uint64_t timeout_secs) {
    int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    int rc = scan_fd(fd, out, timeout_secs);
    ::close(fd);
    return rc;
}

} // namespace av
