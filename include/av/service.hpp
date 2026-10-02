// service.hpp - DetectionService: the façade that binds Phase 1/2 engine to
// Phase 3 watchdog and Phase 4 quarantine, and exposes IPC-friendly methods.
#pragma once

#include <functional>
#include <memory>
#include <mutex>
#include <string>

#include "av/analyzer.hpp"
#include "av/hash_db.hpp"
#include "av/quarantine.hpp"
#include "av/scanner.hpp"
#include "av/watchdog.hpp"
#include "av/yara_engine.hpp"

namespace av {

struct ServiceConfig {
    std::string data_dir;      // holds signatures.db, .quarantine/, avsd.sock
    std::string rules_dir;     // *.yar files
    unsigned scan_threads = 0; // 0 => hardware_concurrency
    uint64_t max_file_bytes = 128ull << 20;
    double alert_threshold_score = 80.0;
    std::vector<std::string> watch_paths;
};

/// Callback signature for events (alerts / progress) destined for IPC push.
using EventSink = std::function<void(const std::string &json_line)>;

class DetectionService {
public:
    explicit DetectionService(ServiceConfig cfg);
    ~DetectionService();

    bool init(std::string *err); // open DB, compile YARA, init quarantine

    void set_event_sink(EventSink sink);

    // ---- Scanning -----------------------------------------------------------
    /// Synchronous on-demand scan; returns full JSON report.
    std::string scan_path_json(const std::string &path, bool pretty);
    /// Async scan used by IPC "Scan Now"; progress + completion pushed as events.
    void start_async_scan(const std::string &path);
    void cancel_scan();
    bool scan_in_progress() const { return async_scanning_.load(); }

    // ---- Single-file detection (used by watchdog workers) -------------------
    ThreatAssessment assess_file(const std::string &path);

    // ---- Real-time guard ----------------------------------------------------
    bool start_guard(std::string *err);
    void stop_guard();
    bool guard_running() const;
    uint64_t guard_events() const;
    uint64_t guard_checked() const;

    // ---- Quarantine ---------------------------------------------------------
    QuarantineManager &quarantine() { return quar_; }
    /// Auto-quarantine MALICIOUS verdicts from real-time events.
    int64_t auto_quarantine(const ThreatAssessment &a);

    // ---- Status for dashboard ----------------------------------------------
    std::string status_json() const;
    std::string history_json(int limit) const;

    HashDb &db() { return db_; }
    YaraEngine &yara() { return yara_; }
    const ServiceConfig &config() const { return cfg_; }

private:
    void emit_alert(const ThreatAssessment &a, const char *source);

    ServiceConfig cfg_;
    HashDb db_;
    YaraEngine yara_;
    QuarantineManager quar_;
    std::unique_ptr<FileScanner> scanner_;
    std::unique_ptr<RealTimeWatchdog> guard_;
    EventSink sink_;
    std::mutex sink_mu_;
    std::atomic<bool> async_scanning_{false};
    std::thread async_thread_;
    mutable std::mutex stats_mu_;
    uint64_t total_assessed_ = 0;
    uint64_t total_malicious_ = 0;
    uint64_t total_suspicious_ = 0;
    uint64_t total_quarantined_ = 0;
};

} // namespace av
