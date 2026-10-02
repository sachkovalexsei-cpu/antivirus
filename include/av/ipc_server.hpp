// ipc_server.hpp - Unix-domain-socket JSON-RPC server for the GUI (Phase 3/5).
// Wire protocol: newline-delimited JSON. One request -> one response.
//   -> {"id":1,"method":"scan","params":{"path":"/home/u/tmp"}}
//   <- {"id":1,"ok":true,"result":{...report json...}}
// The server also PUSHES unsolicited events (threat alerts, progress) as
// JSON lines: {"event":"alert", "severity":"MALICIOUS", ...}.
//
// Security model:
//  * Socket is created under <data_dir>/avsd.sock with mode 0600.
//  * SO_PEERCRED check: only same-UID clients are accepted (privilege
//    isolation boundary between UI and service).
//  * Every path arriving over IPC is sanitized (no '..', no symlink escape
//    outside allowed roots) before touching the filesystem.
#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace av {

class DetectionService;

struct IpcServerConfig {
    std::string socket_path;                 // absolute path of unix socket
    std::vector<std::string> allowed_roots;  // scan/quarantine targets must live here
    bool allow_quarantine_ops = true;
};

class IpcServer {
public:
    IpcServer(DetectionService &svc, IpcServerConfig cfg);
    ~IpcServer();

    bool start(std::string *err);
    void stop();

    /// Broadcast a JSON line to every connected client (alerts/progress).
    void broadcast(const std::string &json_line);

    size_t client_count() const;

private:
    void accept_loop();
    void client_loop(int fd, uid_t peer_uid);
    std::string handle_request(const std::string &line, int &client_fd);
    bool path_allowed(const std::string &p, std::string *reason);

    DetectionService &svc_;
    IpcServerConfig cfg_;
    int listen_fd_ = -1;
    std::atomic<bool> running_{false};
    std::thread acceptor_;
    std::vector<std::thread> clients_;

    struct ClientConn { int fd; };
    mutable std::mutex clients_mu_;
    std::vector<int> client_fds_;
};

} // namespace av
