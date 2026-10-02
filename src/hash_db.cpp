// hash_db.cpp - SQLite known-bad SHA-256 signature store.
#include "av/hash_db.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <mutex>

namespace av {

static std::mutex g_db_mu; // serializes access to any single connection

HashDb::~HashDb() { close(); }

bool HashDb::exec(const char *sql, std::string *err) {
    char *msg = nullptr;
    int rc = sqlite3_exec(db_, sql, nullptr, nullptr, &msg);
    if (rc != SQLITE_OK) {
        if (err) *err = msg ? msg : "sqlite error";
        sqlite3_free(msg);
        return false;
    }
    return true;
}

bool HashDb::open(const std::string &path, std::string *err) {
    std::lock_guard lk(g_db_mu);
    int rc = sqlite3_open_v2(path.c_str(), &db_,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                             nullptr);
    if (rc != SQLITE_OK) {
        if (err) *err = db_ ? sqlite3_errmsg(db_) : "cannot open db";
        close();
        return false;
    }
    sqlite3_busy_timeout(db_, 5000);
    exec("PRAGMA journal_mode=WAL;", nullptr);
    exec("PRAGMA synchronous=NORMAL;", nullptr);

    const char *schema =
        "CREATE TABLE IF NOT EXISTS signatures ("
        "  sha256   TEXT PRIMARY KEY CHECK(length(sha256)=64),"
        "  name     TEXT NOT NULL,"
        "  severity INTEGER NOT NULL DEFAULT 80,"
        "  added_at TEXT NOT NULL DEFAULT (datetime('now')));"
        "CREATE INDEX IF NOT EXISTS idx_sig_sha ON signatures(sha256);"
        "CREATE TABLE IF NOT EXISTS scan_history ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  file_path TEXT NOT NULL,"
        "  sha256 TEXT,"
        "  verdict TEXT NOT NULL,"
        "  score REAL NOT NULL,"
        "  scanned_at TEXT NOT NULL DEFAULT (datetime('now')));";
    if (!exec(schema, err)) {
        close();
        return false;
    }
    return true;
}

void HashDb::close() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

static std::string lower_hex(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return s;
}

std::optional<Signature> HashDb::lookup(const std::string &sha256_hex) {
    if (!db_ || sha256_hex.size() != 64) return std::nullopt;
    std::lock_guard lk(g_db_mu);
    static const char *sql =
        "SELECT sha256, name, severity FROM signatures WHERE sha256 = ?1;";
    sqlite3_stmt *st = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &st, nullptr) != SQLITE_OK)
        return std::nullopt;
    std::string key = lower_hex(sha256_hex);
    sqlite3_bind_text(st, 1, key.c_str(), -1, SQLITE_TRANSIENT);
    std::optional<Signature> out;
    if (sqlite3_step(st) == SQLITE_ROW) {
        Signature s;
        s.sha256    = reinterpret_cast<const char *>(sqlite3_column_text(st, 0));
        s.name      = reinterpret_cast<const char *>(sqlite3_column_text(st, 1));
        s.severity  = sqlite3_column_int(st, 2);
        out = std::move(s);
    }
    sqlite3_finalize(st);
    return out;
}

bool HashDb::add_signature(const std::string &sha256_hex,
                           const std::string &name, int severity,
                           std::string *err) {
    if (!db_) { if (err) *err = "db not open"; return false; }
    std::string key = lower_hex(sha256_hex);
    if (key.size() != 64) { if (err) *err = "bad hash length"; return false; }
    std::lock_guard lk(g_db_mu);
    sqlite3_stmt *st = nullptr;
    const char *sql =
        "INSERT INTO signatures(sha256,name,severity) VALUES(?1,?2,?3) "
        "ON CONFLICT(sha256) DO UPDATE SET name=excluded.name, "
        "severity=excluded.severity;";
    if (sqlite3_prepare_v2(db_, sql, -1, &st, nullptr) != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return false;
    }
    sqlite3_bind_text(st, 1, key.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 3, severity);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    if (!ok && err) *err = sqlite3_errmsg(db_);
    sqlite3_finalize(st);
    return ok;
}

bool HashDb::record_scan(const std::string &file_path, const std::string &sha256,
                         const std::string &verdict, double score,
                         std::string *err) {
    if (!db_) return false;
    std::lock_guard lk(g_db_mu);
    sqlite3_stmt *st = nullptr;
    const char *sql =
        "INSERT INTO scan_history(file_path,sha256,verdict,score) "
        "VALUES(?1,?2,?3,?4);";
    if (sqlite3_prepare_v2(db_, sql, -1, &st, nullptr) != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return false;
    }
    sqlite3_bind_text(st, 1, file_path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, sha256.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, verdict.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_double(st, 4, score);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    if (!ok && err) *err = sqlite3_errmsg(db_);
    sqlite3_finalize(st);
    return ok;
}

} // namespace av
