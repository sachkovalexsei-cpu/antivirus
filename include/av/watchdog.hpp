// watchdog.hpp - fanotify real-time monitoring service (Phase 3).
#pragma once

#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace av {

class DetectionService; // analyzer pipeline (engine + queue)

struct WatchConfig {
    std::vector<std::string> watch_paths; // e.g. ~/Downloads, /home/user
    unsigned workers = 4;                 // concurrent detection workers
    double alert_threshold_score = 80.0;  // emit IPC alert above this score
    uint64_t max_file_bytes = 128ull << 20;
    bool on_exit_events = true;           // also scan close_write/execve files
};

/// Linux: fanotify FAN_OPEN_EXEC_PERM | FAN_CLOSE_WRITE via a dedicated
/// listener thread; events are forwarded to a bounded worker queue bound to
/// the Phase-2 detection engine. Windows: ReadDirectoryChangesW would plug in
/// behind the same interface (stubbed here).
class RealTimeWatchdog {
public:
    explicit RealTimeWatchdog(DetectionService &svc);
    ~RealTimeWatchdog();

    bool start(const WatchConfig &cfg, std::string *err);
    void stop();

    bool running() const { return running_.load(); }
    uint64_t events_seen() const { return events_seen_.load(); }
    uint64_t files_checked() const { return files_checked_.load(); }

private:
    void listener_loop();     // fanotify read loop
    void worker_loop(int id); // pops pending paths, runs detection
    void enqueue_event(std::string path);

    DetectionService &svc_;
    WatchConfig cfg_;
    int fan_fd_ = -1;
    std::vector<int> mount_fds_;
    std::thread listener_;
    std::vector<std::thread> workers_;
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> events_seen_{0};
    std::atomic<uint64_t> files_checked_{0};

    struct PendingQueueImpl;
    std::unique_ptr<PendingQueueImpl> pending_;
};

} // namespace av
