// hash_db.hpp - SQLite signature database: known-bad SHA-256 hashes + scan history.
#pragma once

#include <optional>
#include <string>
#include <vector>

#include <sqlite3.h>

namespace av {

struct Signature {
    std::string sha256; // lowercase hex, 64 chars
    std::string name;   // threat name, e.g. EICar.Test.File
    int severity = 50;  // 0..100 contribution to the score
};

/// RAII wrapper over a sqlite3 connection with WAL + prepared-statement cache.
class HashDb {
public:
    HashDb() = default;
    ~HashDb();
    HashDb(const HashDb &) = delete;
    HashDb &operator=(const HashDb &) = delete;
    HashDb(HashDb &&o) noexcept : db_(o.db_) { o.db_ = nullptr; }

    /// Opens (creating if needed) the DB and ensures the schema exists.
    bool open(const std::string &path, std::string *err = nullptr);
    void close();
    bool is_open() const { return db_ != nullptr; }
    sqlite3 *handle() const { return db_; }

    /// Look up a hash. Returns nullopt when clean. Thread-safe (serialized).
    std::optional<Signature> lookup(const std::string &sha256_hex);

    bool add_signature(const std::string &sha256_hex, const std::string &name,
                       int severity, std::string *err = nullptr);

    /// Persist one scan result row (used for the dashboard history view).
    bool record_scan(const std::string &file_path, const std::string &sha256,
                     const std::string &verdict, double score,
                     std::string *err = nullptr);

private:
    bool exec(const char *sql, std::string *err);
    sqlite3 *db_ = nullptr;
};

} // namespace av
