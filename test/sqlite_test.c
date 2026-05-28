#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;
typedef int (*sqlite3_callback)(void *, int, char **, char **);

extern sqlite3 *sqlite3_open_ptr;
extern int sqlite3_open(const char *, sqlite3 **);
extern int sqlite3_exec(sqlite3 *, const char *, sqlite3_callback, void *, char **);
extern int sqlite3_close(sqlite3 *);
extern const char *sqlite3_errmsg(sqlite3 *);
extern int sqlite3_prepare_v2(sqlite3 *, const char *, int, sqlite3_stmt **, const char **);
extern int sqlite3_bind_text(sqlite3_stmt *, int, const char *, int, void *);
extern int sqlite3_bind_int(sqlite3_stmt *, int, int);
extern int sqlite3_step(sqlite3_stmt *);
extern int sqlite3_column_int(sqlite3_stmt *, int);
extern const unsigned char *sqlite3_column_text(sqlite3_stmt *, int);
extern int sqlite3_finalize(sqlite3_stmt *);
extern int sqlite3_reset(sqlite3_stmt *);
extern int sqlite3_changes(sqlite3 *);

static int g_ok = 0;
static int g_fail = 0;

__attribute__((constructor))
static void sqlite_ctor(void) { g_ok = 0; g_fail = 0; }

static int callback_count;

static int select_callback(void *data, int argc, char **argv, char **col) {
    callback_count++;
    (void)data;
    for (int i = 0; i < argc; i++)
        printf("[sqlite]   %s = %s\n", col[i], argv[i] ? argv[i] : "NULL");
    return 0;
}

static int test_basic(void) {
    sqlite3 *db;
    char *err = NULL;
    int rc;

    rc = sqlite3_open(":memory:", &db);
    if (rc != 0) {
        printf("[sqlite] open failed: %s\n", sqlite3_errmsg(db));
        return 0;
    }
    printf("[sqlite] opened :memory: database\n");

    rc = sqlite3_exec(db,
        "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, age INTEGER);"
        "INSERT INTO users VALUES (1, 'Alice', 30);"
        "INSERT INTO users VALUES (2, 'Bob', 25);"
        "INSERT INTO users VALUES (3, 'Charlie', 35);",
        NULL, NULL, &err);
    if (rc != 0) {
        printf("[sqlite] create/insert failed: %s\n", err);
        sqlite3_close(db);
        return 0;
    }
    printf("[sqlite] created table + inserted 3 rows (changes=%d)\n",
           sqlite3_changes(db));

    callback_count = 0;
    rc = sqlite3_exec(db, "SELECT * FROM users WHERE age > 26;",
                      select_callback, NULL, &err);
    if (rc != 0) {
        printf("[sqlite] select failed: %s\n", err);
        sqlite3_close(db);
        return 0;
    }
    if (callback_count != 2) {
        printf("[sqlite] expected 2 rows, got %d\n", callback_count);
        sqlite3_close(db);
        return 0;
    }

    sqlite3_close(db);
    return 1;
}

static int test_prepared(void) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc;

    sqlite3_open(":memory:", &db);

    sqlite3_exec(db,
        "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, qty INTEGER);",
        NULL, NULL, NULL);

    rc = sqlite3_prepare_v2(db,
        "INSERT INTO items (name, qty) VALUES (?, ?);", -1, &stmt, NULL);
    if (rc != 0) {
        printf("[sqlite] prepare failed\n");
        sqlite3_close(db);
        return 0;
    }

    const char *names[] = {"apple", "banana", "cherry"};
    int qtys[] = {10, 20, 15};
    for (int i = 0; i < 3; i++) {
        sqlite3_bind_text(stmt, 1, names[i], -1, NULL);
        sqlite3_bind_int(stmt, 2, qtys[i]);
        rc = sqlite3_step(stmt);
        if (rc != 101) {
            printf("[sqlite] insert step %d failed (rc=%d)\n", i, rc);
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return 0;
        }
        sqlite3_reset(stmt);
    }
    sqlite3_finalize(stmt);
    printf("[sqlite] prepared statement: inserted 3 items\n");

    rc = sqlite3_prepare_v2(db, "SELECT SUM(qty) FROM items;", -1, &stmt, NULL);
    if (rc != 0) {
        sqlite3_close(db);
        return 0;
    }
    sqlite3_step(stmt);
    int total = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    if (total != 45) {
        printf("[sqlite] SUM(qty) = %d, expected 45\n", total);
        sqlite3_close(db);
        return 0;
    }
    printf("[sqlite] SUM(qty) = %d OK\n", total);

    sqlite3_close(db);
    return 1;
}

void sqlite_run(const void *user_data, unsigned int user_data_len) {
    printf("[sqlite] === libsqlite3 real-world test ===\n");
    if (user_data && user_data_len > 0)
        printf("[sqlite] user_data: %.*s\n", user_data_len, (const char *)user_data);

    if (test_basic())    g_ok++; else g_fail++;
    if (test_prepared()) g_ok++; else g_fail++;

    printf("[sqlite] results: %d passed, %d failed\n", g_ok, g_fail);
}
