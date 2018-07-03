/* implementation of a basic service provider for use with the trusted
 * module */

#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <sqlite3.h>

#include "crypto.h"
#include "helper.h"
#include "test.h"

/* get type definitions only */
#define CLIENT

#include "trusted_module.h"
#include "service_provider.h"

/* arbitrary */
#define ACL_LOGLEAVES 4

#define MAX_PATH 260

/* should be free'd with free_record */
struct file_record {
    uint64_t idx;
    uint64_t version;
};

struct service_provider {
    const char *data_dir;

    void *db; /* sqlite3 handle */
};

/* write to file data_dir/file_idx/version */
void write_contents(const struct service_provider *sp,
                    int file_idx, int version,
                    const void *data, size_t len)
{
    mkdir(sp->data_dir, 0755);

    char dirname[MAX_PATH];
    snprintf(dirname, sizeof(dirname), "%s/%d", sp->data_dir, file_idx);

    mkdir(dirname, 0755);

    char filename[MAX_PATH];
    snprintf(filename, sizeof(filename), "%s/%d/%d", sp->data_dir, file_idx, version);

    FILE *f = fopen(filename, "w");

    fwrite(data, 1, len, f);

    fclose(f);
}

size_t file_len(FILE *f)
{
    off_t orig = ftell(f);
    fseek(f, 0, SEEK_END);
    off_t len = ftell(f);
    fseek(f, orig, SEEK_SET);

    return (size_t)len;
}

void *read_contents(const struct service_provider *sp,
                    int file_idx, int version,
                    size_t *len)
{
    char filename[MAX_PATH];
    snprintf(filename, sizeof(filename), "%s/%d/%d", sp->data_dir, file_idx, version);

    FILE *f = fopen(filename, "r");

    *len = file_len(f);

    void *buf = malloc(*len);
    fread(buf, 1, *len, f);

    fclose(f);
    return buf;
}

void *db_init(const char *filename)
{
    sqlite3 *db;
    if(sqlite3_open(filename, &db) != SQLITE_OK)
        return NULL;

    sqlite3_exec(db, "PRAGMA synchronous = 0;", 0, 0, 0);
    sqlite3_exec(db, "PRAGMA journal_mode = memory;", 0, 0, 0);

    return db;
}

void begin_transaction(void *db)
{
    sqlite3 *handle = db;
    sqlite3_exec(handle, "BEGIN;", 0, 0, 0);
}

void commit_transaction(void *db)
{
    sqlite3 *handle = db;
    sqlite3_exec(handle, "COMMIT;", 0, 0, 0);
}

/* leaf count will be 2^logleaves */
struct service_provider *sp_new(const void *key, size_t keylen, int logleaves, const char *data_dir, const char *dbpath)
{
    assert(logleaves > 0);
    struct service_provider *sp = calloc(1, sizeof(*sp));

    sp->db = db_init(dbpath);

    sp->data_dir = data_dir;

    return sp;
}

static void free_record(struct file_record *rec)
{
    if(rec)
    {
        free(rec);
    }
}

void sp_free(struct service_provider *sp)
{
    if(sp)
    {
        free(sp);
    }
}

/* linear search for record given idx */
static struct file_record *lookup_record(struct service_provider *sp, uint64_t idx)
{
    sqlite3 *handle = sp->db;

    const char *sql = "SELECT * FROM FileRecords WHERE Idx = ?1;";

    sqlite3_stmt *st;

    sqlite3_prepare_v2(handle, sql, -1, &st, 0);
    sqlite3_bind_int(st, 1, idx);

    int rc = sqlite3_step(st);
    if(rc == SQLITE_ROW)
    {
        struct file_record *rec = calloc(1, sizeof(struct file_record));

        rec->idx = sqlite3_column_int(st, 0);
        rec->version = sqlite3_column_int(st, 1);

        return rec;
    }
    //printf("Failed to find file record with index %lu (%s), ret %d\n", idx, sqlite3_errmsg(handle), rc);
    return NULL;
}

/* Should we insert sorted (for O(logn) lookup), or just at the end to
 * avoid copying (O(n) lookup, O(1) insertion)? Eventually this will
 * be replaced with a SQL backend.  We do not check to ensure that
 * there are no duplicate file indices; that is up to the caller. */
static void insert_record(struct service_provider *sp, const struct file_record *rec)
{
    //printf("Inserting record %lu\n", rec->idx);

    sqlite3 *handle = sp->db;

    const char *sql = "INSERT INTO FileRecords (Idx, Ver) VALUES ( ?1, ?2 );";
    sqlite3_stmt *st;
    sqlite3_prepare_v2(handle, sql, -1, &st, 0);
    sqlite3_bind_int(st, 1, rec->idx);
    sqlite3_bind_int(st, 2, rec->version);

    assert(sqlite3_step(st) == SQLITE_DONE);

    sqlite3_finalize(st);
}

/* Should we insert sorted (for O(logn) lookup), or just at the end to
 * avoid copying (O(n) lookup, O(1) insertion)? Eventually this will
 * be replaced with a SQL backend.  We do not check to ensure that
 * there are no duplicate file indices; that is up to the caller. */
static void update_record(struct service_provider *sp,
                          const struct file_record *rec)
{
    sqlite3 *handle = sp->db;

    const char *sql = "UPDATE FileRecords SET Idx = ?1, Ver = ?2 WHERE Idx = ?7;";

    sqlite3_stmt *st;
    sqlite3_prepare_v2(handle, sql, -1, &st, 0);
    sqlite3_bind_int(st, 1, rec->idx);
    sqlite3_bind_int(st, 2, rec->version);
    sqlite3_bind_int(st, 7, rec->idx);

    assert(sqlite3_step(st) == SQLITE_DONE);

    sqlite3_finalize(st);
}

/* This does the majority of the work that actually modifies or
 * creates a file. It expects a filled and signed tm_request
 * structure, req, and will return the resulting FR certificate and
 * its signature in *hmac_out. Additionally, the module's
 * authenticated acknowledgement (equal to HMAC(req | 0), where |
 * indicates concatenation) is output in *ack_hmac_out.
 *
 * If the request is to modify the file, the parameters
 * encrypted_secret, kf, buildcode, composefile, encrypted_contents,
 * and contents_len are used (otherwise they are
 * ignored). `encrypted_secret' should be the file encryption key
 * XOR'd with HMAC(file index | file counter, user_key). kf should be
 * HMAC(encryption secret, file index).
 *
 * If the request is to either modify the ACL or create a file (which
 * is essentially an ACL update), the ACL will be set to new_acl. This
 * function will make a copy of new_acl, so it can safely be freed
 * after calling this function. */
void sp_request(struct service_provider *sp,
                const struct tm_request *req,
                const void *encrypted_contents, size_t contents_len)
{
    /* update the corresponding file record */
    struct file_record *rec = lookup_record(sp, req->idx);

    bool need_insert = false;
    if(!rec)
    {
        rec = calloc(1, sizeof(struct file_record));
        need_insert = true;
    }

    rec->idx = req->idx;

    if(req->type == FILE_UPDATE)
    {
        rec->version++;

        /* write to disk */
        write_contents(sp, req->idx, rec->version,
                       encrypted_contents, contents_len);
    }

    if(need_insert)
        insert_record(sp, rec);
    else
        update_record(sp, rec);

    free_record(rec);
}

int next_slot(struct service_provider *sp)
{
    const char *sql = "SELECT MAX(Idx) from FileRecords;";

    static sqlite3_stmt *st = NULL;

    sqlite3 *handle = sp->db;

    if(!st)
        sqlite3_prepare_v2(handle, sql, -1, &st, 0);

    sqlite3_reset(st);

    int rc = sqlite3_step(st);

    if(rc == SQLITE_ROW)
    {
        return sqlite3_column_int(st, 0) + 1;
    }

    return 1;
}

int sp_createfile(struct service_provider *sp,
                  uint64_t user_id)
{
    int i = next_slot(sp);

    struct tm_request req;
    req.idx = i;
    req.user_id = user_id;
    req.type = ACL_UPDATE;
    req.counter = 0;

    sp_request(sp,
               &req,
               NULL, 0);

    return i;
}

struct tm_request sp_modifyfile(struct service_provider *sp,
                                uint64_t user_id,
                                uint64_t file_idx,
                                const void *encrypted_file, size_t filelen)
{
    /* modification */
    struct file_record *rec = lookup_record(sp, file_idx);
    if(!rec)
    {
        printf("Could not find file with index %lu\n", file_idx);
        return req_null;
    }

    struct tm_request req;
    req.idx = file_idx;
    req.user_id = user_id;
    req.type = FILE_UPDATE;

    sp_request(sp,
               &req,
               encrypted_file, filelen);

    return req;
}

/* Retrieve authenticated information (using the user's secret as the
 * key) on a version of a file; if version is zero, default to the
 * latest version. If the file does not exist, the function will still
 * succeed, returning an authenticated structure indicating
 * failure. */
struct version_info sp_fileinfo(struct service_provider *sp,
                                uint64_t user_id,
                                uint64_t file_idx,
                                uint64_t version)
{
    struct file_record *rec = lookup_record(sp, file_idx);

    if(!rec)
    {
        return (struct version_info) { file_idx, 0, 0, 0, hash_null, hash_null };
    }

    if(!version)
        version = rec->version;

    struct version_info ret = (struct version_info) { rec->idx, 0, version, rec->version, hash_null, hash_null };

    return ret;
}

/* This file retrieves the file given by file_idx for a given
 * user. *encrypted_secret will be set to the encryption key XOR'd
 * with HMAC(kf, K). kf will be returned via the *kf pointer. The
 * returned value is dynamically allocated and must be freed by the
 * caller. This function returns NULL upon failure. An authenticated
 * proof that the request cannot be satisfied can be obtained by
 * calling sp_fileinfo. */
void *sp_retrieve_file(struct service_provider *sp,
                       uint64_t user_id,
                       uint64_t file_idx,
                       uint64_t version,
                       size_t *len)
{
    struct file_record *rec = lookup_record(sp, file_idx);

    if(!rec || rec->version == 0)
    {
        /* Newly created file, no contents. We don't bother to set
         * *encrypted_secret or *len. Or, file does not exist. */
        *len = 0;
        return NULL;
    }

    if(!version)
        version = rec->version;

    void *ret = read_contents(sp, file_idx, version, len);

    return ret;
}

static void sp_handle_client(struct service_provider *sp, int cl)
{
    /* We should probably fork() here to avoid blocking */
    struct user_request user_req;
    if(recv(cl, &user_req, sizeof(user_req), MSG_WAITALL) != sizeof(user_req))
        return;

    switch(user_req.type)
    {
    case CREATE_FILE:
    {
        printf("Client: create file\n");
        uint64_t slot = sp_createfile(sp, user_req.user_id);
        write(cl, &slot, sizeof(slot));
        break;
    }
    case MODIFY_FILE:
    {
        printf("Client: modify file\n");
        size_t filelen;
        recv(cl, &filelen, sizeof(filelen), MSG_WAITALL);

        printf("File is %lu bytes.\n", filelen);
        void *filebuf = malloc(filelen);
        recv(cl, filebuf, filelen, MSG_WAITALL);

        sp_modifyfile(sp,
                      user_req.user_id,
                      user_req.modify_file.file_idx,
                      filebuf, filelen);
        break;
    }
    case RETRIEVE_INFO:
    {
        printf("Client: retrieve info\n");
        struct version_info verinfo = sp_fileinfo(sp,
                                                  user_req.user_id,
                                                  user_req.retrieve.file_idx,
                                                  user_req.retrieve.version);
        write(cl, &verinfo, sizeof(verinfo));

        break;
    }
    case RETRIEVE_FILE:
    {
        printf("Client: retrieve file\n");
        size_t len = 0;
        void *contents = sp_retrieve_file(sp,
                                          user_req.user_id,
                                          user_req.retrieve.file_idx,
                                          user_req.retrieve.version,
                                          &len);

        write(cl, &len, sizeof(len));
        if(contents)
            write(cl, contents, len);

        break;
    }
    default:
    {
        printf("bad request\n");
        exit(1);
    }
    }
}

int sp_main(int sockfd, int logleaves, const char *dbpath, bool overwrite)
{
    (void) overwrite;
#define BACKLOG 10

    if(listen(sockfd, BACKLOG) < 0)
    {
        perror("listen");
        return 1;
    }

    signal(SIGPIPE, SIG_IGN);

    struct service_provider *sp = sp_new("a", 1, logleaves, "files", dbpath);

    while(1)
    {
        int cl;

        if((cl = accept(sockfd, NULL, NULL)) < 0)
        {
            perror("accept");
            return 1;
        }

        sp_handle_client(sp, cl);
        close(cl);
    }
}
