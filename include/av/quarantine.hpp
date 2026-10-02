// quarantine.hpp - Secure quarantine manager (Phase 4).
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <sys/types.h>
#include <vector>

#include <sqlite3.h>

namespace av {

struct QuarantineRecord {
    int64_t id = -1;
    std::string original_path;
    std::string quarantine_file; // file name inside .quarantine/
    std::string sha256;
    std::string threat_name;
    double threat_score = 0.0;
    std::string quarantined_at;  // ISO-8601 UTC
    int64_t original_mtime = 0;  // unix epoch ns
    int64_t original_size = 0;
    int mode_before = 0;         // st_mode before revoke
    std::string cipher = "AES-256-GCM";
};

/// Moves, encrypts and records malicious files. The quarantine directory is
/// created 0700; manifest lives in its own SQLite DB with WAL disabled for
/// single-writer simplicity.
class QuarantineManager {
public:
    /// `qdir` = e.g. <data_dir>/.quarantine ; `manifest_db` inside it.
    bool init(const std::string &qdir, std::string *err);
    void close();

    /// Full pipeline:
    ///  1. suspend/terminate processes whose exe resolves to `threat_path`,
    ///  2. revoke execute permissions (chmod a-x),
    ///  3. AES-256-GCM encrypt the file,
    ///  4. move ciphertext into .quarantine/<id>.bin,
    ///  5. insert quarantine_manifest row.
    /// Returns the record id, or nullopt + reason on failure.
    std::optional<int64_t> quarantine_file(const std::string &threat_path,
                                           const std::string &sha256,
                                           const std::string &threat_name,
                                           double threat_score,
                                           std::string *err);

    /// Decrypt and restore to the original location. Refuses to overwrite an
    /// existing file at the destination unless `overwrite` is set.
    bool restore_file(int64_t quarantine_id, bool overwrite, std::string *err);

    /// Permanently delete quarantined blob + mark record deleted.
    bool delete_file(int64_t quarantine_id, std::string *err);

    std::vector<QuarantineRecord> list_records();
    std::optional<QuarantineRecord> get_record(int64_t id);

    /// Process control helpers (Linux /proc scan; Windows stubbed).
    static std::vector<pid_t> find_processes_using(const std::string &exe_path);
    static bool suspend_process(pid_t pid);   // SIGSTOP
    static bool terminate_process(pid_t pid); // SIGTERM then SIGKILL

private:
    bool exec_sql(const char *sql, std::string *err);

    std::string qdir_;
    sqlite3 *db_ = nullptr;
    std::vector<std::byte> key_; // 32-byte device key (key.dat, 0600)
};

} // namespace av
