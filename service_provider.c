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
#include "service_provider.h"
#include "test.h"
#include "trusted_module.h"

/* arbitrary */
#define ACL_LOGLEAVES 4

#define MAX_PATH 260

/* free with free_version */
struct file_version {
    uint64_t version;

    hash_t kf; /* HMAC(key, file_idx) */
    hash_t encrypted_secret; /* XOR'd with HMAC(kf, module secret) */

    struct tm_cert vr_cert; /* VR certificate */
    hash_t vr_hmac;
};

/* should be free'd with free_record */
struct file_record {
    uint64_t idx;
    uint64_t version;
    uint64_t counter;

    struct iomt *acl; /* backed by database */

    struct tm_cert fr_cert; /* issued by module */
    hash_t fr_hmac;
};

struct service_provider {
    struct trusted_module *tm;

    const char *data_dir;

    /* count of number of placeholders (should never be more than
     * 1) */
    int n_placeholders;
    uint64_t next_fileidx;

    void *db; /* sqlite3 handle */
    struct iomt *iomt; /* backed by database */

    sqlite3_stmt *lookup_record, *insert_record, *update_record,
        *insert_version, *count_versions, *lookup_version, *find_empty;
};

/* Generate an EQ certificate for inserting a placeholder with index
 * placeholder_idx, given an encloser (which must actually enclose
 * a). Note: this function will modify the *mt_nodes array to reflect
 * the modification of the encloser node. However, it will restore the
 * original values before returning. This function belongs in here
 * service_provider.c and not helper.c since it directly accesses
 * service-provider specific functionality. */

/* NOTE: encloser_leafidx is *NOT* the index in the merkle tree leaf
 * node. It is the 0-based index of the POSITION of the leaf node,
 * counting from the leftmost leaf. */
struct tm_cert cert_eq(struct service_provider *sp,
                       struct iomt_node encloser,
                       uint64_t encloser_leafidx,
                       uint64_t placeholder_leafidx, uint64_t placeholder_nodeidx,
                       hash_t *hmac_out)
{
    assert(encloses(encloser.idx, encloser.next_idx, placeholder_nodeidx));

    struct iomt_node encloser_mod = encloser;
    encloser_mod.next_idx = placeholder_nodeidx;

    struct iomt_node insert;
    insert.idx = placeholder_nodeidx;
    insert.next_idx = encloser.next_idx;
    insert.val = hash_null;

    hash_t h_enc    = hash_node(encloser);
    hash_t h_encmod = hash_node(encloser_mod);

    hash_t h_ins = hash_node(insert);

    int *enc_orders;
    hash_t *enc_comp = merkle_complement(sp->iomt, encloser_leafidx, &enc_orders);

    /* we need two NU certificates */
    hash_t nu1_hmac, nu2_hmac;

    struct tm_cert nu1 = tm_cert_node_update(sp->tm,
                                             h_enc, h_encmod,
                                             enc_comp, enc_orders, sp->iomt->mt_logleaves,
                                             &nu1_hmac);

    /* We now update the ancestors of the encloser node. */
    hash_t *old_depvalues = malloc(sizeof(hash_t) * sp->iomt->mt_logleaves);
    merkle_update(sp->iomt, encloser_leafidx, h_encmod, old_depvalues);

    int *ins_orders;
    hash_t *ins_comp = merkle_complement(sp->iomt, placeholder_leafidx, &ins_orders);

    struct tm_cert nu2 = tm_cert_node_update(sp->tm,
                                             hash_null, h_ins,
                                             ins_comp, ins_orders, sp->iomt->mt_logleaves,
                                             &nu2_hmac);

    /* restore the tree */
    uint64_t *dep_indices = bintree_ancestors(encloser_leafidx, sp->iomt->mt_logleaves);
    restore_nodes(sp->iomt, dep_indices, old_depvalues, sp->iomt->mt_logleaves);

    free(dep_indices);
    free(old_depvalues);

    free(enc_comp);
    free(ins_comp);
    free(enc_orders);
    free(ins_orders);

    return tm_cert_equiv(sp->tm, &nu1, nu1_hmac, &nu2, nu2_hmac, encloser, placeholder_nodeidx, hmac_out);
}

/* write to file data_dir/file_idx/version */
void write_contents(const struct service_provider *sp,
                    uint64_t file_idx, uint64_t version, const char *suffix,
                    const void *data, size_t len)
{
    mkdir(sp->data_dir, 0755);

    char dirname[MAX_PATH];
    snprintf(dirname, sizeof(dirname), "%s/%lu", sp->data_dir, file_idx);

    mkdir(dirname, 0755);

    char filename[MAX_PATH];
    snprintf(filename, sizeof(filename), "%s/%lu/%lu%s", sp->data_dir, file_idx, version, suffix);

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
                    uint64_t file_idx, uint64_t version, const char *suffix,
                    size_t *len)
{
    assert(len);
    char filename[MAX_PATH];
    snprintf(filename, sizeof(filename), "%s/%lu/%lu%s", sp->data_dir, file_idx, version, suffix);

    FILE *f = fopen(filename, "r");

    if(!f)
    {
        *len = 0;
        return NULL;
    }

    *len = file_len(f);

    void *buf = malloc(*len);
    fread(buf, 1, *len, f);

    fclose(f);
    return buf;
}

int count_rows(void *db, const char *table)
{
    char buf[1000];
    snprintf(buf, sizeof(buf), "SELECT COUNT(*) FROM %s;", table);

    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, buf, -1, &st, 0);

    /* no table */
    if(sqlite3_step(st) != SQLITE_ROW)
        return 0;

    int rows = sqlite3_column_int(st, 0);

    sqlite3_finalize(st);

    return rows;
}

void db_free(void *handle)
{
    sqlite3_close(handle);
}

void *db_init(const char *filename, bool overwrite, bool *need_init)
{
    sqlite3 *db;
    if(sqlite3_open(filename, &db) != SQLITE_OK)
        return NULL;

    sqlite3_exec(db, "PRAGMA synchronous = 0;", 0, 0, 0);
    sqlite3_exec(db, "PRAGMA journal_mode = memory;", 0, 0, 0);

    if(overwrite || count_rows(db, "FileLeaves") == 0)
    {
        extern unsigned char sqlinit_txt[];

        /* create tables */
        if(sqlite3_exec(db, (const char*)sqlinit_txt, NULL, NULL, NULL) != SQLITE_OK)
            warn("failed to initialize database (%s)", sqlite3_errmsg(db));

        *need_init = true;
    }
    else
        *need_init = false;

    return db;
}

int count_placeholders(void *db)
{
    sqlite3 *handle = db;
    const char *sql = "SELECT COUNT(*) FROM FileLeaves WHERE Val = ?1;";

    sqlite3_stmt *st;
    sqlite3_prepare_v2(handle, sql, -1, &st, 0);

    sqlite3_bind_blob(st, 1, &hash_null, sizeof(hash_null), SQLITE_STATIC);

    assert(sqlite3_step(st) == SQLITE_ROW);

    int count = sqlite3_column_int(st, 0);

    sqlite3_finalize(st);

    printf("Counted %d placeholders\n", count);

    return count;
}

uint64_t max_fileindex(void *db)
{
    sqlite3 *handle = db;
    const char *sql = "SELECT MAX(Idx) FROM FileRecords;";

    sqlite3_stmt *st;
    sqlite3_prepare_v2(handle, sql, -1, &st, 0);

    uint64_t max = 0;
    if(sqlite3_step(st) == SQLITE_ROW)
        max = sqlite3_column_int64(st, 0);

    sqlite3_finalize(st);

    printf("maximum index is %lu\n", max);

    return max;
}

/* leaf count will be 2^logleaves */
/* will use old DB contents unless overwrite_db is true */
struct service_provider *sp_new(const void *key, size_t keylen,
                                int logleaves,
                                const char *data_dir,
                                const char *dbpath,
                                bool overwrite_db)
{
    assert(logleaves > 0);
    if(logleaves >= 63)
        warn("logleaves value too large, will likely fail");

    struct service_provider *sp = calloc(1, sizeof(*sp));

    bool iomt_init = true;
    sp->db = db_init(dbpath, overwrite_db, &iomt_init);

    sp->data_dir = data_dir;

    if(iomt_init)
    {
        sp->tm = tm_new(key, keylen);

        /* create IOMT in memory first, then commit to DB */
        sp->iomt = iomt_new_from_db(sp->db,
                                    "FileNodes", "FileLeaves",
                                    NULL, 0,
                                    NULL, 0,
                                    logleaves);

        printf("Initializing IOMT with %llu nodes.\n", 1ULL << logleaves);

        /* The trusted module initializes itself with a single placeholder
         * node (1,0,1). We first update our list of IOMT leaves. Then we
         * insert our desired number of nodes by using EQ certificates to
         * update the internal IOMT root. Note that leaf indices are
         * 1-indexed. */
        iomt_update_leaf_full(sp->iomt,
                              0,
                              1, 1, hash_null);

        sp->n_placeholders = 1;
        sp->next_fileidx = 1;
    }
    else
    {
        sp->iomt = iomt_new_from_db(sp->db,
                                    "FileNodes", "FileLeaves",
                                    NULL, 0,
                                    NULL, 0,
                                    logleaves);

        sp->tm = tm_new_from_savedstate("module_state");
        if(!sp->tm)
        {
            warn("failed to load module state; creating fresh state (will probably fail)");
            sp->tm = tm_new(key, keylen);
        }

        sp->n_placeholders = count_placeholders(sp->db);
        sp->next_fileidx = max_fileindex(sp->db) + 1;

        printf("Resuming from previous state...\n");

#if 0
        int leaves = count_rows(sp->db, "FileLeaves");
        if(leaves != (1ULL << logleaves))
            warn("logleaves value is inconsistent with leaf count in IOMT! (have %d, expect %d)",
                 leaves, 1 << logleaves);
#endif
    }

    /* prepare SQL statements */
    sqlite3_prepare_v2(sp->db, "SELECT * FROM FileRecords WHERE Idx = ?1;", -1, &sp->lookup_record, 0);
    sqlite3_prepare_v2(sp->db, "INSERT INTO FileRecords VALUES ( ?1, ?2, ?3, ?4, ?5, ?6 );", -1, &sp->insert_record, 0);
    sqlite3_prepare_v2(sp->db, "UPDATE FileRecords SET Idx = ?1, Ver = ?2, Ctr = ?3, Cert = ?4, HMAC = ?5, ACL_logleaves = ?6 WHERE Idx = ?7;", -1, &sp->update_record, 0);
    sqlite3_prepare_v2(sp->db, "INSERT INTO Versions VALUES ( ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8 );", -1, &sp->insert_version, 0);

    sqlite3_prepare_v2(sp->db, "SELECT * FROM Versions WHERE FileIdx = ?1 AND Version = ?2;", -1, &sp->lookup_version, 0);

    return sp;
}

static void free_version(struct file_version *ver)
{
    if(ver)
    {
        free(ver);
    }
}

static void free_record(struct file_record *rec)
{
    if(rec)
    {
        iomt_free(rec->acl);
        free(rec);
    }
}

void sp_free(struct service_provider *sp)
{
    if(sp)
    {
        tm_free(sp->tm);
        iomt_free(sp->iomt);

        sqlite3_finalize(sp->lookup_record);
        sqlite3_finalize(sp->insert_record);
        sqlite3_finalize(sp->update_record);
        sqlite3_finalize(sp->insert_version);
        sqlite3_finalize(sp->lookup_version);

        db_free(sp->db);
        free(sp);
    }
}

/* TODO: pre-compile these statements */

/* linear search for record given idx */
static struct file_record *lookup_record(struct service_provider *sp, uint64_t idx)
{
    sqlite3_stmt *st = sp->lookup_record;

    sqlite3_reset(st);
    sqlite3_bind_int64(st, 1, idx);

    int rc = sqlite3_step(st);
    if(rc == SQLITE_ROW)
    {
        struct file_record *rec = calloc(1, sizeof(struct file_record));

        rec->idx = sqlite3_column_int64(st, 0);
        rec->version = sqlite3_column_int64(st, 1);
        rec->counter = sqlite3_column_int64(st, 2);
        memcpy(&rec->fr_cert, sqlite3_column_blob(st, 3), sizeof(rec->fr_cert));
        memcpy(&rec->fr_hmac, sqlite3_column_blob(st, 4), sizeof(rec->fr_hmac));

        int acl_logleaves = sqlite3_column_int(st, 5);
        rec->acl = iomt_new_from_db(sp->db,
                                    "ACLNodes", "ACLLeaves",
                                    "FileIdx", idx,
                                    NULL, 0,
                                    acl_logleaves);

        return rec;
    }
    //printf("Failed to find file record with index %lu (%s), ret %d\n", idx, sqlite3_errmsg(handle), rc);
    return NULL;
}

static void insert_record(struct service_provider *sp, const struct file_record *rec)
{
    //printf("Inserting record %lu\n", rec->idx);

    sqlite3_stmt *st = sp->insert_record;

    sqlite3_reset(st);

    sqlite3_bind_int64(st, 1, rec->idx);
    sqlite3_bind_int64(st, 2, rec->version);
    sqlite3_bind_int64(st, 3, rec->counter);
    sqlite3_bind_blob(st, 4, &rec->fr_cert, sizeof(rec->fr_cert), SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 5, &rec->fr_hmac, sizeof(rec->fr_hmac), SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 6, rec->acl->mt_logleaves);

    assert(sqlite3_step(st) == SQLITE_DONE);
}

/* Should we insert sorted (for O(logn) lookup), or just at the end to
 * avoid copying (O(n) lookup, O(1) insertion)? Eventually this will
 * be replaced with a SQL backend.  We do not check to ensure that
 * there are no duplicate file indices; that is up to the caller. */
static void update_record(struct service_provider *sp,
                          const struct file_record *rec)
{
    sqlite3_stmt *st = sp->update_record;

    sqlite3_reset(st);

    sqlite3_bind_int64(st, 1, rec->idx);
    sqlite3_bind_int64(st, 2, rec->version);
    sqlite3_bind_int64(st, 3, rec->counter);
    sqlite3_bind_blob(st, 4, &rec->fr_cert, sizeof(rec->fr_cert), SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 5, &rec->fr_hmac, sizeof(rec->fr_hmac), SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 6, rec->acl->mt_logleaves);
    sqlite3_bind_int64(st, 7, rec->idx);

    assert(sqlite3_step(st) == SQLITE_DONE);
}

static void insert_version(struct service_provider *sp,
                           const struct file_record *rec,
                           const struct file_version *ver)
{
    sqlite3_stmt *st = sp->insert_version;

    sqlite3_reset(st);

    sqlite3_bind_int64(st, 1, rec->idx);
    sqlite3_bind_int64(st, 2, ver->version);
    sqlite3_bind_blob(st, 3, &ver->kf, sizeof(ver->kf), SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 4, &ver->encrypted_secret, sizeof(ver->encrypted_secret), SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 5, &ver->vr_cert, sizeof(ver->vr_cert), SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 6, &ver->vr_hmac, sizeof(ver->vr_hmac), SQLITE_TRANSIENT);

    int rc = sqlite3_step(st);
    if(rc != SQLITE_DONE)
    {
        printf("Failed\n");
    }
}

static uint64_t count_versions(struct service_provider *sp,
                               uint64_t file_idx)
{
    sqlite3 *handle = sp->db;

    const char *sql = "SELECT COUNT(*) FROM Versions WHERE FileIdx = ?1;";

    sqlite3_stmt *st;

    sqlite3_prepare_v2(handle, sql, -1, &st, 0);
    sqlite3_bind_int64(st, 1, file_idx);

    assert(sqlite3_step(st) == SQLITE_ROW);

    /* praying it works */
    return sqlite3_column_int64(st, 0);
}

static struct file_version *lookup_version(struct service_provider *sp,
                                           uint64_t file_idx,
                                           uint64_t version)
{
    if(!version)
    {
        return NULL;
    }

    sqlite3_stmt *st = sp->lookup_version;

    sqlite3_reset(st);

    sqlite3_bind_int64(st, 1, file_idx);
    sqlite3_bind_int64(st, 2, version);

    int rc = sqlite3_step(st);
    if(rc == SQLITE_ROW)
    {
        struct file_version *ver = calloc(1, sizeof(struct file_version));

        ver->version = sqlite3_column_int64(st, 1);
        memcpy(&ver->kf, sqlite3_column_blob(st, 2), sizeof(ver->kf));
        memcpy(&ver->encrypted_secret, sqlite3_column_blob(st, 3), sizeof(ver->encrypted_secret));
        memcpy(&ver->vr_cert, sqlite3_column_blob(st, 4), sizeof(ver->vr_cert));
        memcpy(&ver->vr_hmac, sqlite3_column_blob(st, 5), sizeof(ver->vr_hmac));
        return ver;
    }
    return NULL;
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
struct tm_cert sp_request(struct service_provider *sp,
                          const struct tm_request *req, hash_t req_hmac,
                          hash_t *hmac_out,
                          struct tm_cert *vr_out, hash_t *vr_hmac_out,
                          hash_t *ack_hmac_out,
                          hash_t encrypted_secret, hash_t kf,
                          const void *encrypted_contents, size_t contents_len,
                          const void *buildcode, size_t buildcode_len,
                          const void *composefile, size_t composefile_len,
                          const struct iomt *new_acl)
{
    struct tm_cert vr = cert_null;
    hash_t vr_hmac, ack_hmac, fr_hmac;
    vr_hmac = ack_hmac = fr_hmac = hash_null;

    /* execute the request */
    struct tm_cert fr = tm_request(sp->tm, req, req_hmac, &fr_hmac, &vr, &vr_hmac, &ack_hmac);

    /* now update our databases based on the result */
    if(fr.type == FR)
    {
        /* update the corresponding file record */
        struct file_record *rec = lookup_record(sp, fr.fr.idx);

        bool need_insert = false;
        if(!rec)
        {
            rec = calloc(1, sizeof(struct file_record));
            need_insert = true;
        }

        rec->idx = fr.fr.idx;
        rec->counter = fr.fr.counter;
        rec->fr_cert = fr;
        rec->fr_hmac = fr_hmac;

        if(req->type == ACL_UPDATE)
        {
            /* check that the passed value matches the calculated root */
            assert(hash_equals(req->val, iomt_getroot(new_acl)));

            iomt_free(rec->acl);

            /* copy the ACL into our database tables (extremely slow) */
            rec->acl = iomt_dup_in_db(sp->db,
                                      "ACLNodes", "ACLLeaves",
                                      "FileIdx", fr.fr.idx,
                                      NULL, 0,
                                      new_acl);
        }

        if(rec->version != fr.fr.version)
        {
            rec->version = fr.fr.version;

            struct file_version ver;
            memset(&ver, 0, sizeof(ver));

            if(!is_zero(encrypted_secret) && !is_zero(kf))
            {
                /* File is encrypted */
                ver.encrypted_secret = tm_verify_and_encrypt_secret(sp->tm,
                                                                    rec->idx, rec->version,
                                                                    req->user_id,
                                                                    encrypted_secret, kf);
                assert(!is_zero(ver.encrypted_secret));

                /* We have no way of verifying that kf=HMAC(encryption
                 * secret, file index) ourselves; instead we rely on the
                 * module to do so for us, as done above. */
                ver.kf = kf;
            }
            else
            {
                ver.encrypted_secret = hash_null;
                ver.kf = hash_null;
            }

            ver.version = fr.fr.version;
            ver.vr_cert = vr;
            ver.vr_hmac = vr_hmac;

            /* write to disk */
            if(encrypted_contents)
                write_contents(sp, fr.fr.idx, fr.fr.version, "",
                               encrypted_contents, contents_len);

            if(buildcode)
                write_contents(sp, fr.fr.idx, fr.fr.version, "_bc",
                               buildcode, buildcode_len);

            if(composefile)
                write_contents(sp, fr.fr.idx, fr.fr.version, "_cf",
                               composefile, composefile_len);

            insert_version(sp, rec, &ver);
        }

        if(need_insert)
            insert_record(sp, rec);
        else
            update_record(sp, rec);

        free_record(rec);

        /* update our tree */
        iomt_update(sp->iomt, req->idx, u64_to_hash(fr.fr.counter));
    }

    /* return values to caller */
    if(hmac_out)
        *hmac_out = fr_hmac;
    if(vr_out)
        *vr_out = vr;
    if(vr_hmac_out)
        *vr_hmac_out = vr_hmac;
    if(ack_hmac_out)
        *ack_hmac_out = ack_hmac;

    if(is_zero(*ack_hmac_out))
        printf("Failed: %s\n", tm_geterror());

    return fr;
}

/* returns a leaf idx (not a file idx!) */
static uint64_t find_empty_slot(struct service_provider *sp)
{
    sqlite3_stmt *st;

    sqlite3 *handle = sp->db;

    const char *sql = "SELECT LeafIdx FROM FileLeaves WHERE Val = ?1 LIMIT 1;";
    sqlite3_prepare_v2(handle, sql, -1, &st, 0);

    sqlite3_bind_blob(st, 1, &hash_null, sizeof(hash_null), SQLITE_STATIC);

    int rc = sqlite3_step(st);

    if(rc == SQLITE_ROW)
    {
        return sqlite3_column_int64(st, 0);
    }

    return (uint64_t) -1;
}

struct tm_request sp_createfile(struct service_provider *sp,
                                uint64_t user_id,
                                hash_t (*sign_request)(void *userdata, const struct tm_request *req),
                                void *userdata,
                                hash_t *ack_hmac)
{
    /* allocate a node in the IOMT */
    uint64_t i = (uint64_t) - 1;

    if(sp->n_placeholders > 0)
    {
        i = find_empty_slot(sp);
        if(i == (uint64_t) -1)
        {
            assert(false); /* shouldn't happen */
        }
    }
    else
    {
        /* we must insert a placeholder node; first find the index of
         * the leaf that loops around to 1 */
        i = sp->next_fileidx - 1;
        if(i >= sp->iomt->mt_leafcount)
        {
            /* TODO: grow tree */
            printf("Tree full!\n");
            return req_null;
        }

        /* generate EQ certificate */
        hash_t hmac;
        struct tm_cert eq = cert_eq(sp,
                                    iomt_getleaf(sp->iomt, i - 1),
                                    i - 1,
                                    i, i + 1,
                                    &hmac);
        assert(eq.type == EQ);

        /* update previous leaf's index */
        iomt_update_leaf_nextidx(sp->iomt, i - 1, i + 1);

        /* next_idx is set to 1 to keep everything circularly linked;
         * in the next iteration it will be updated to point to the
         * next node, if any */
        iomt_update_leaf_full(sp->iomt, i, i + 1, 1, hash_null);

        assert(tm_set_equiv_root(sp->tm, &eq, hmac));

        sp->n_placeholders++;
    }

    printf("Allocated leaf index %lu\n", i);

    int *file_orders;
    hash_t *file_comp = merkle_complement(sp->iomt, i, &file_orders);

    struct iomt *acl = iomt_new_from_db(sp->db,
                                        "ACLNodes", "ACLLeaves",
                                        "FileIdx", sp->next_fileidx,
                                        NULL, 0,
                                        ACL_LOGLEAVES);

    sp->next_fileidx++;

    iomt_update_leaf_full(acl,
                          0,
                          user_id, user_id, u64_to_hash(3));

    struct tm_request req = req_filecreate(sp->tm,
                                           user_id,
                                           iomt_getleaf(sp->iomt, i),
                                           file_comp, file_orders, sp->iomt->mt_logleaves);

    hash_t req_hmac = sign_request(userdata, &req);
    hash_t fr_hmac;

    struct tm_cert fr_cert = sp_request(sp,
                                        &req, req_hmac,
                                        &fr_hmac,
                                        NULL, NULL,
                                        ack_hmac,
                                        hash_null, hash_null,
                                        NULL, 0,
                                        NULL, 0,
                                        NULL, 0,
                                        acl);
    sp->n_placeholders--;

    iomt_free(acl);
    free(file_comp);
    free(file_orders);

    if(fr_cert.type == FR)
        return req;

    return req_null;
}

/* Expects ACL root to already be calculated */
struct tm_request sp_modifyacl(struct service_provider *sp,
                               uint64_t user_id,
                               hash_t (*sign_request)(void *userdata, const struct tm_request *req),
                               void *userdata,
                               uint64_t file_idx,
                               struct iomt *new_acl,
                               hash_t *ack_hmac)
{
    /* modification */
    struct file_record *rec = lookup_record(sp, file_idx);
    if(!rec)
        return req_null;

    int *file_orders, *acl_orders;
    uint64_t file_leafidx;
    struct iomt_node file_node = iomt_find_leaf(sp->iomt, file_idx, &file_leafidx);

    hash_t *file_comp = merkle_complement(sp->iomt,
                                          file_leafidx,
                                          &file_orders);

    uint64_t acl_leafidx;
    struct iomt_node acl_node = iomt_find_leaf(rec->acl, user_id, &acl_leafidx);
    hash_t *acl_comp = merkle_complement(rec->acl,
                                         acl_leafidx,
                                         &acl_orders);

    struct tm_request req = req_aclmodify(sp->tm,
                                          &rec->fr_cert, rec->fr_hmac,
                                          file_node,
                                          file_comp, file_orders, sp->iomt->mt_logleaves,
                                          acl_node,
                                          acl_comp, acl_orders, rec->acl->mt_logleaves,
                                          iomt_getroot(new_acl));

    free_record(rec);

    free(file_comp);
    free(file_orders);
    free(acl_comp);
    free(acl_orders);

    hash_t req_hmac = sign_request(userdata, &req);

    struct tm_cert new_fr = sp_request(sp,
                                       &req, req_hmac,
                                       NULL,
                                       NULL, NULL,
                                       ack_hmac,
                                       hash_null, hash_null,
                                       NULL, 0,
                                       NULL, 0,
                                       NULL, 0,
                                       new_acl);

    if(new_fr.type == FR)
        return req;
    return req_null;
}

struct tm_request sp_modifyfile(struct service_provider *sp,
                                uint64_t user_id,
                                hash_t (*sign_request)(void *userdata, const struct tm_request *req),
                                void *userdata,
                                uint64_t file_idx,
                                hash_t encrypted_secret, hash_t kf,
                                const void *encrypted_file, size_t filelen,
                                const void *buildcode, size_t buildcode_len,
                                const void *composefile, size_t composefile_len,
                                hash_t *ack_hmac)
{
    /* modification */
    struct file_record *rec = lookup_record(sp, file_idx);
    if(!rec)
    {
        printf("Could not find file with index %lu\n", file_idx);
        return req_null;
    }

    int *file_orders, *acl_orders;
    uint64_t file_leafidx;
    struct iomt_node file_node = iomt_find_leaf(sp->iomt, file_idx, &file_leafidx);

    if(!file_node.idx)
    {
        printf("Couldn't find file node???\n");
        return req_null;
    }

    hash_t *file_comp = merkle_complement(sp->iomt,
                                          file_leafidx,
                                          &file_orders);

    uint64_t acl_leafidx;
    struct iomt_node acl_node = iomt_find_leaf(rec->acl, user_id, &acl_leafidx);
    hash_t *acl_comp = merkle_complement(rec->acl,
                                         acl_leafidx,
                                         &acl_orders);

    hash_t gamma = sha256(encrypted_file, filelen);
    hash_t h_bc = buildcode ? sha256(buildcode, buildcode_len) : hash_null;
    hash_t h_cf = composefile ? sha256(composefile, composefile_len) : hash_null;
    hash_t lambda = calc_lambda(gamma, h_bc, h_cf, kf);

    struct tm_request req = req_filemodify(sp->tm,
                                           &rec->fr_cert, rec->fr_hmac,
                                           file_node,
                                           file_comp, file_orders, sp->iomt->mt_logleaves,
                                           acl_node,
                                           acl_comp, acl_orders, rec->acl->mt_logleaves,
                                           lambda);
    free(file_comp);
    free(acl_comp);
    free(file_orders);
    free(acl_orders);

    free_record(rec);

    hash_t req_hmac = sign_request(userdata, &req);

    struct tm_cert vr;
    hash_t vr_hmac, fr_hmac;

    printf("Modifying file with new kf=%s.\n", hash_format(kf, 4).str);

    struct tm_cert new_fr = sp_request(sp,
                                       &req, req_hmac,
                                       &fr_hmac,
                                       &vr, &vr_hmac,
                                       ack_hmac,
                                       encrypted_secret, kf,
                                       encrypted_file, filelen,
                                       buildcode, buildcode_len,
                                       composefile, composefile_len,
                                       NULL);

    /* We return the request because that is how the module's
     * authentication is done. */
    if(new_fr.type == FR)
        return req;
    return req_null;
}

/* Retrieve authenticated information (using the user's secret as the
 * key) on a version of a file; if version is zero, default to the
 * latest version. If the file does not exist, the function will still
 * succeed, returning an authenticated structure indicating
 * failure. */
struct version_info sp_fileinfo(struct service_provider *sp,
                                uint64_t user_id,
                                uint64_t file_idx,
                                uint64_t version,
                                hash_t nonce,
                                hash_t *hmac,
                                struct iomt **acl_out)
{
    struct file_record *rec = lookup_record(sp, file_idx);

    /* RV1 indicates counter */
    hash_t rv1_hmac;
    struct tm_cert rv1 = cert_rv_by_idx(sp->tm,
                                        sp->iomt,
                                        file_idx,
                                        &rv1_hmac);

    /* Produce an authenticated denial proving that no file exists
     * with the given index. */
    if(!rec)
    {
        return tm_verify_fileinfo(sp->tm,
                                  user_id,
                                  &rv1, rv1_hmac,
                                  NULL, hash_null,
                                  NULL, hash_null,
                                  NULL, hash_null,
                                  nonce,
                                  hmac);
    }

    /* RV2 indicates access rights */
    hash_t rv2_hmac;
    struct tm_cert rv2 = cert_rv_by_idx(sp->tm,
                                        rec->acl,
                                        user_id,
                                        &rv2_hmac);

    if(!version)
        version = rec->version;

    struct file_version *ver = lookup_version(sp, rec->idx, version);

    if(acl_out)
        *acl_out = iomt_dup(rec->acl);

    struct version_info ret = tm_verify_fileinfo(sp->tm,
                                                 user_id,
                                                 &rv1, rv1_hmac,
                                                 &rv2, rv2_hmac,
                                                 &rec->fr_cert, rec->fr_hmac,
                                                 ver ? &ver->vr_cert : NULL, ver ? ver->vr_hmac : hash_null,
                                                 nonce,
                                                 hmac);
    free_record(rec);
    free_version(ver);

    return ret;
}

/* This function retrieves the file given by file_idx for a given
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
                       hash_t *encrypted_secret,
                       hash_t *kf,
                       void **buildcode,
                       size_t *bc_len,
                       void **composefile,
                       size_t *cf_len,
                       size_t *len)
{
    struct file_record *rec = lookup_record(sp, file_idx);

    if(!rec || !rec->version)
    {
        /* Newly created file, no contents. We don't bother to set
         * *encrypted_secret or *len. Or, file does not exist. No
         * authenticated denial; the client can use sp_fileinfo() to
         * verify this for themselves. */
        *len = 0;
        return NULL;
    }

    if(!version)
        version = rec->version;

    struct file_version *ver = lookup_version(sp, file_idx, version);

    if(!ver)
    {
        free_record(rec);
        *len = 0;
        return NULL;
    }

    hash_t rv1_hmac, rv2_hmac;
    struct tm_cert rv1 = cert_rv_by_idx(sp->tm, sp->iomt, file_idx, &rv1_hmac);
    struct tm_cert rv2 = cert_rv_by_idx(sp->tm, rec->acl, user_id, &rv2_hmac);

    if(hash_to_u64(rv2.rv.val) < 1)
    {
        free_version(ver);
        /* no permissions; don't return file contents */
        return NULL;
    }

    if(encrypted_secret)
    {
        *encrypted_secret = is_zero(ver->encrypted_secret) ?
            hash_null                                      :
            tm_retrieve_secret(sp->tm,
                               &rv1, rv1_hmac,
                               &rv2, rv2_hmac,
                               &rec->fr_cert, rec->fr_hmac,
                               ver->encrypted_secret, ver->kf);
    }

    if(kf)
        *kf = ver->kf;

    void *ret = read_contents(sp, file_idx, version, "", len);

    /* read contents of build/compose files */
    if(buildcode)
        *buildcode = read_contents(sp, file_idx, version, "_bc", bc_len);
    if(composefile)
        *composefile = read_contents(sp, file_idx, version, "_cf", cf_len);

    free_record(rec);
    free_version(ver);

    return ret;
}

static hash_t get_client_signature(void *userdata, const struct tm_request *req)
{
    int *fd = userdata;
    if(write(*fd, req, sizeof(*req)) != sizeof(*req))
        return hash_null;

    hash_t hmac;
    if(recv(*fd, &hmac, sizeof(hmac), MSG_WAITALL) != sizeof(hmac))
        return hash_null;

    return hmac;
}

static void sp_handle_client(struct service_provider *sp, int cl)
{
    /* We should probably fork() here to avoid blocking */
    struct user_request user_req;
    if(recv(cl, &user_req, sizeof(user_req), MSG_WAITALL) != sizeof(user_req))
        return;

    hash_t ack_hmac = hash_null;

    switch(user_req.type)
    {
    case CREATE_FILE:
    {
        printf("Client: create file\n");
        sp_createfile(sp, user_req.user_id, get_client_signature, &cl, &ack_hmac);
        if(write(cl, &ack_hmac, sizeof(ack_hmac)) != sizeof(ack_hmac))
            return;
        break;
    }
    case MODIFY_ACL:
    {
        printf("Client: modify ACL\n");
        struct iomt *acl = iomt_deserialize(read_from_fd, &cl);

        if(!acl)
            return;

        sp_modifyacl(sp,
                     user_req.user_id,
                     get_client_signature,
                     &cl,
                     user_req.modify_acl.file_idx,
                     acl,
                     &ack_hmac);

        iomt_free(acl);

        if(write(cl, &ack_hmac, sizeof(ack_hmac)) != sizeof(ack_hmac))
            return;
        break;
    }
    case MODIFY_FILE:
    {
        printf("Client: modify file %lu\n", user_req.modify_file.file_idx);
        size_t filelen;
        void *filebuf = deserialize_file(cl, &filelen);

        size_t bc_len, cf_len;
        void *bc = deserialize_file(cl, &bc_len);
        void *cf = deserialize_file(cl, &cf_len);

        if(sp_modifyfile(sp,
                         user_req.user_id,
                         get_client_signature,
                         &cl,
                         user_req.modify_file.file_idx,
                         user_req.modify_file.encrypted_secret,
                         user_req.modify_file.kf,
                         filebuf, filelen,
                         bc, bc_len,
                         cf, cf_len,
                         &ack_hmac).type == REQ_NONE)
        {
            printf("Failed: %s\n", tm_geterror());
        }

        free(filebuf);

        write(cl, &ack_hmac, sizeof(ack_hmac));
        break;
    }
    case RETRIEVE_INFO:
    {
        printf("Client: retrieve info %lu\n", user_req.retrieve.file_idx);
        struct iomt *acl = NULL;
        struct version_info verinfo = sp_fileinfo(sp,
                                                  user_req.user_id,
                                                  user_req.retrieve.file_idx,
                                                  user_req.retrieve.version,
                                                  user_req.retrieve.nonce,
                                                  &ack_hmac,
                                                  &acl);
        write(cl, &verinfo, sizeof(verinfo));
        write(cl, &ack_hmac, sizeof(ack_hmac));

        if(acl && verinfo.idx != 0)
        {
            iomt_serialize(acl, write_to_fd, &cl);
            iomt_free(acl);
        }

        break;
    }
    case RETRIEVE_FILE:
    {
        printf("Client: retrieve file\n");
        hash_t encrypted_secret = hash_null, kf = hash_null;
        size_t len = 0;
        void *bc = NULL, *cf = NULL;
        size_t bc_len = 0, cf_len = 0;

        void *contents = sp_retrieve_file(sp,
                                          user_req.user_id,
                                          user_req.retrieve.file_idx,
                                          user_req.retrieve.version,
                                          &encrypted_secret,
                                          &kf,
                                          &bc, &bc_len,
                                          &cf, &cf_len,
                                          &len);
        /* write everything (no HMAC; the client should do a
         * RETRIEVE_INFO request separately) */
        write(cl, &encrypted_secret, sizeof(encrypted_secret));
        write(cl, &kf, sizeof(kf));

        serialize_file(cl, contents, len);
        serialize_file(cl, bc, bc_len);
        serialize_file(cl, cf, cf_len);

        free(contents);
        free(bc);
        free(cf);

        break;
    }
    case USERREQ_NONE:
    {
        printf("null request\n");
        exit(1);
    }
    }
}

/* will be called by main.c's signal handler to save the module's
 * state */
static struct service_provider *global_sp = NULL;

void sp_save(void)
{
    if(global_sp)
    {
        tm_savestate(global_sp->tm, "module_state");
    }
}

int sp_main(int sockfd, int logleaves, const char *dbpath, bool overwrite)
{
#define BACKLOG 10

    if(listen(sockfd, BACKLOG) < 0)
    {
        perror("listen");
        return 1;
    }

    signal(SIGPIPE, SIG_IGN);

    struct service_provider *sp = sp_new("a", 1, logleaves, "files", dbpath, overwrite);
    global_sp = sp;

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

static hash_t test_sign_request(void *userdata, const struct tm_request *req)
{
    const char *str = userdata;
    return hmac_sha256(req, sizeof(*req), str, strlen(str));
}

void sp_test(void)
{
    int logleaves = 4;

    clock_t start = clock();
    struct service_provider *sp = sp_new("a", 1, logleaves, "files", "csaatest.db", true);
    clock_t stop = clock();

    check("Tree initialization", sp != NULL);
#if 0
    {
        hash_t ack_hmac;
        struct tm_request req = sp_createfile(sp, 1, test_sign_request, "a", &ack_hmac);

        check("File creation", verify_ack(&req, "a", 1, ack_hmac));

        /* IOMT generation from file */
        struct iomt *buildcode = iomt_from_lines("container1/Dockerfile");
        check("IOMT generation from file 1", buildcode != NULL);

        struct iomt_node node1 = { 1, 2, sha256("line1\n", 6) };
        struct iomt_node node2 = { 2, 1, sha256("line2", 5) };

        hash_t correct_root = merkle_parent(hash_node(node1), hash_node(node2), 0);
        check("IOMT generation from file 2", hash_equals(iomt_getroot(buildcode), correct_root));

#define N_MODIFY 10
        start = clock();
        for(int i = 0; i < N_MODIFY; ++i)
            req = sp_modifyfile(sp, 1, test_sign_request, "a", 1, hash_null, hash_null, buildcode, NULL, "contents", 8, &ack_hmac);

        stop = clock();
        printf("%.1f modifications per second\n", (double)N_MODIFY * CLOCKS_PER_SEC / (stop - start));

        check("File modification", verify_ack(&req, "a", 1, ack_hmac));

        hash_t hmac;
        /* check inside range, but empty slot */
        struct version_info vi = sp_fileinfo(sp, 1, 12, 1, hash_null, &hmac, NULL);
        check("Authenticated denial 1", hash_equals(hmac, hmac_sha256(&vi, sizeof(vi), "a", 1)));

        /* check outside range */
        vi = sp_fileinfo(sp, 1, (1 << sp->iomt->mt_logleaves) + 1, 1, hash_null, &hmac, NULL);
        check("Authenticated denial 2", hash_equals(hmac, hmac_sha256(&vi, sizeof(vi), "a", 1)));

        /* check in range */
        vi = sp_fileinfo(sp,
                         1, /* user */
                         1, /* file */
                         1, /* version */
                         hash_null,
                         &hmac,
                         NULL);
        check("File info retrieval 1", hash_equals(hmac, hmac_sha256(&vi, sizeof(vi), "a", 1)));

        hash_t gamma = sha256("contents", 8);
        hash_t kf = hash_null;
        hash_t lambda = calc_lambda(gamma, buildcode, NULL, kf);

        struct iomt_node acl_node = { 1, 1, u64_to_hash(3) };

        struct version_info correct = { 1, N_MODIFY + 1, 1, N_MODIFY, hash_node(acl_node), lambda };
        check("File info retrieval 2", !memcmp(&correct, &vi, sizeof(vi)));
    }

    /* retrieve contents */
    {
        hash_t key;
        size_t len;
        void *contents = sp_retrieve_file(sp,
                                          1,
                                          1,
                                          1,
                                          &key,
                                          NULL,
                                          NULL,
                                          NULL,
                                          &len);
        check("File retrieval 1", !memcmp(contents, "contents", 8) && len == 8);
        free(contents);
    }

    {
        /* ACL modify */
        struct iomt *newacl = iomt_new(ACL_LOGLEAVES);
        iomt_update_leaf_full(newacl, 0, 1, 2, u64_to_hash(3));
        iomt_update_leaf_full(newacl, 1, 2, 1, u64_to_hash(1));

        hash_t ack;
        bool success = true;

#define N_ACLMODIFY 10
        for(int i = 0; i < N_ACLMODIFY; ++i)
        {
            struct tm_request req = sp_modifyacl(sp,
                                                 1,
                                                 test_sign_request, "a",
                                                 1,
                                                 newacl,
                                                 &ack);

            success &= verify_ack(&req, "a", 1, ack);
        }

        check("ACL modification 1", success);
    }
#endif

    if(logleaves < 5)
    {
        printf("CDI-IOMT contents: ");
        iomt_dump(sp->iomt);
    }

    sp_free(sp);

    /* test IOMT code (requires a service provider for the databases) */
    {
        struct service_provider *sp = sp_new("a", 1, logleaves, "files", "csaatest.db", true);
        iomt_dump(sp->iomt);

        iomt_update_leaf_nextidx(sp->iomt, 0, 2);
        iomt_update_leaf_full(sp->iomt, 3, 2, 1, hash_null);

        iomt_dump(sp->iomt);

        /* should fail */
        struct iomt_node encloser = iomt_find_encloser(sp->iomt, 2, NULL);
        check("Encloser search 1", encloser.idx == 0);

        encloser = iomt_find_encloser(sp->iomt, 4, NULL);
        check("Encloser search 2", encloser.idx == 2 && encloser.next_idx == 1);

        encloser = iomt_find_leaf_or_encloser(sp->iomt, 2, NULL);
        check("Encloser/leaf search 1", encloser.idx == 2);

        encloser = iomt_find_leaf_or_encloser(sp->iomt, 1000, NULL);
        check("Encloser/leaf search 2", encloser.idx == 2);

        iomt_update_leaf_full(sp->iomt, 3, 10, 3, hash_null);

        iomt_update_leaf_full(sp->iomt, 0, 3, 10, hash_null);

        iomt_dump(sp->iomt);

        encloser = iomt_find_leaf_or_encloser(sp->iomt, 5, NULL);
        check("Encloser/leaf search 3", encloser.idx == 3);

        encloser = iomt_find_leaf_or_encloser(sp->iomt, 2, NULL);
        check("Encloser/leaf search 4", encloser.idx == 10);

        sp_free(sp);
    }
}
