// scanner.hpp - Thread-pool recursive file scanner (Phase 1).
#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "av/analyzer.hpp"
#include "av/hash_db.hpp"
#include "av/yara_engine.hpp"

namespace av {

struct ScanConfig {
    std::string root_path;          // file or directory
    unsigned threads = std::thread::hardware_concurrency();
    uint64_t max_file_bytes = 128ull << 20; // 128 MiB size cap per file
    bool follow_symlinks = false;   // off by default (loop/escape risk)
    std::vector<std::string> exclude_dirs = {".git", "node_modules", ".quarantine"};
};

struct AccessError {
    std::string path;
    std::string error; // strerror text, e.g. "Permission denied"
};

struct ScanReport {
    std::string root_path;
    double started_at = 0.0;        // epoch seconds
    double duration_seconds = 0.0;
    uint64_t files_scanned = 0;
    uint64_t files_skipped_large = 0;
    uint64_t dirs_visited = 0;
    std::vector<ThreatAssessment> assessments; // sorted by path
    std::vector<AccessError> access_errors;
    uint64_t detections_malicious = 0;
    uint64_t detections_suspicious = 0;

    /// Full structured JSON: summary + per-file entries + errors + timing.
    std::string to_json(bool pretty = true) const;
};

/// Bounded work queue with graceful shutdown (no lost items).
template <typename T>
class WorkQueue {
public:
    void push(T item);
    /// Blocks until an item is available or shutdown+drained. False => stop.
    bool pop(T &out);
    void shutdown();
    size_t approx_size() const;

private:
    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::deque<T> q_;
    bool stopped_ = false;
};

/// The pool owns the walk; each worker analyses files via the injected engine
/// callback (bound to calculate_threat_score by DetectionService).
class FileScanner {
public:
    using AssessFn = std::function<ThreatAssessment(const std::string &)>;

    explicit FileScanner(AssessFn assess) : assess_(std::move(assess)) {}

    /// Runs a full scan synchronously (blocks until complete).
    ScanReport scan(const ScanConfig &cfg);

    /// Cancel an in-flight scan (workers drain remaining queue quickly).
    void cancel() { cancel_.store(true); }

    using ProgressFn = std::function<void(uint64_t done, uint64_t detected)>;
    void set_progress_callback(ProgressFn fn) { on_progress_ = std::move(fn); }

private:
    void walk_and_enqueue(const std::string &dir, const ScanConfig &cfg,
                          WorkQueue<std::string> &queue, ScanReport &report);
    void worker_loop(const ScanConfig &cfg, WorkQueue<std::string> &queue,
                     ScanReport &report, std::atomic<uint64_t> &scanned);

    AssessFn assess_;
    std::mutex report_mu_; // guards ScanReport mutation from workers
    std::atomic<bool> cancel_{false};
    ProgressFn on_progress_;
};

} // namespace av
