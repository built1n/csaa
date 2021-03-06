/* An implementation of the trusted module T as described in Mohanty
 * et al. As this code is to execute on a general-purpose computer, no
 * guarantees can be made as to the tamper-resistance of the module,
 * but instead this serves as a proof-of-concept. */

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "crypto.h"
#include "service_provider.h"
#include "test.h"
#include "trusted_module.h"

struct user_key {
    void *key; /* dynamic */
    size_t len;
};

struct trusted_module {
    hash_t root; /* root of IOMT */

    /* shared secret with user */
    struct user_key *user_keys; /* dynamic */
    size_t n_users;

    /* secret for signing self-certificates */
    unsigned char secret[32];
};

static void tm_setroot(struct trusted_module *tm, hash_t newroot)
{
    //printf("TM: %s -> %s\n", hash_format(tm->root, 4).str, hash_format(newroot, 4).str);
    tm->root = newroot;
}

struct trusted_module *tm_new(const void *key, size_t keylen)
{
    struct trusted_module *tm = calloc(1, sizeof(struct trusted_module));

    if(!RAND_bytes(tm->secret, sizeof(tm->secret)))
    {
        free(tm);
        return NULL;
    }

    /* debugging */
    memset(tm->secret, 0, sizeof(tm->secret));

    tm->user_keys = calloc(1, sizeof(*tm->user_keys));
    tm->n_users = 1;
    tm->user_keys[0].len = keylen;
    tm->user_keys[0].key = malloc(keylen);
    memcpy(tm->user_keys[0].key, key, keylen);

    /* initialize with a node of (1, 0, 1) in the tree */
    struct iomt_node boot = (struct iomt_node) { 1, 1, hash_null };

    tm_setroot(tm, merkle_compute(hash_node(boot), NULL, NULL, 0));

    return tm;
}

void tm_free(struct trusted_module *tm)
{
    for(int i = 0; i < tm->n_users; ++i)
        free(tm->user_keys[i].key);
    free(tm->user_keys);
    free(tm);
}

/* hack: no authentication at all */
void tm_savestate(const struct trusted_module *tm, const char *filename)
{
    FILE *f = fopen(filename, "w");

    fwrite(tm->secret, sizeof(tm->secret), 1, f);
    fwrite(&tm->n_users, sizeof(tm->n_users), 1, f);
    for(int i = 0; i < tm->n_users; ++i)
    {
        fwrite(&tm->user_keys[i].len, sizeof(tm->user_keys[i].len), 1, f);
        fwrite(tm->user_keys[i].key, tm->user_keys[i].len, 1, f);
    }

    fwrite(&tm->root, sizeof(tm->root), 1, f);

    printf("Saving state, root=%s\n", hash_format(tm->root, 4).str);
}

struct trusted_module *tm_new_from_savedstate(const char *filename)
{
    FILE *f = fopen(filename, "r");

    if(!f)
        return NULL;

    struct trusted_module *tm = calloc(1, sizeof(struct trusted_module));

    fread(tm->secret, sizeof(tm->secret), 1, f);

    fread(&tm->n_users, sizeof(tm->n_users), 1, f);
    tm->user_keys = calloc(1, sizeof(*tm->user_keys) * tm->n_users);

    for(int i = 0; i < tm->n_users; ++i)
    {
        fread(&tm->user_keys[i].len, sizeof(tm->user_keys[i].len), 1, f);
        tm->user_keys[i].key = malloc(tm->user_keys[i].len);
        fread(tm->user_keys[i].key, tm->user_keys[i].len, 1, f);
    }

    fread(&tm->root, sizeof(tm->root), 1, f);
    printf("Loading state, root=%s\n", hash_format(tm->root, 4).str);

    return tm;
}

static hash_t cert_sign(const struct trusted_module *tm, const struct tm_cert *cert)
{
    return hmac_sha256(cert, sizeof(*cert), tm->secret, sizeof(tm->secret));
}

static bool cert_verify(const struct trusted_module *tm, const struct tm_cert *cert, hash_t hmac)
{
    hash_t calculated = cert_sign(tm, cert);
    return hash_equals(calculated, hmac);
}

struct tm_cert tm_cert_node_update(const struct trusted_module *tm,
                                   hash_t orig, hash_t new,
                                   const hash_t *comp, const int *orders, size_t n,
                                   hash_t *hmac)
{
    struct tm_cert cert = cert_null;
    cert.type = NU;
    cert.nu.orig_node = orig;
    cert.nu.new_node = new;

    cert.nu.orig_root = cert.nu.new_root = merkle_compute(orig, comp, orders, n);

    if(!hash_equals(orig, new))
        cert.nu.new_root = merkle_compute(new, comp, orders, n);

    *hmac = cert_sign(tm, &cert);

    return cert;
}

static const char *tm_error = NULL;
void tm_seterror(const char *error)
{
    tm_error = error;
}

const char *tm_geterror(void)
{
    if(tm_error)
        return tm_error;
    return "success";
}

/* combine two NU certificates, untested. */
struct tm_cert tm_cert_combine(const struct trusted_module *tm,
                               const struct tm_cert *nu1, hash_t hmac1,
                               const struct tm_cert *nu2, hash_t hmac2,
                               hash_t *hmac_out)
{
    if(!nu1 || !nu2)
    {
        tm_seterror("null certificate");
        return cert_null;
    }
    if(nu1->type != NU || nu2->type != NU)
    {
        tm_seterror("wrong certificate type");
        return cert_null;
    }
    if(!cert_verify(tm, nu1, hmac1) || !cert_verify(tm, nu2, hmac2))
    {
        tm_seterror("improper cert authentication");
        return cert_null;
    }

    if(hash_equals(nu1->nu.new_node, nu2->nu.orig_node) &&
       hash_equals(nu1->nu.new_root, nu2->nu.orig_root))
    {
        struct tm_cert cert = cert_null;
        cert.type = NU;
        cert.nu.orig_node = nu1->nu.orig_node;
        cert.nu.orig_root = nu1->nu.orig_root;
        cert.nu.new_node = nu2->nu.new_node;
        cert.nu.new_root = nu2->nu.new_root;

        *hmac_out = cert_sign(tm, &cert);
        return cert;
    }
    else
    {
        tm_seterror("hashes are not of the form a->b, b->c");
        return cert_null;
    }
}

/* Let ve = h(b, b', wb). */
/* Let ve' = h(b, a, wb). */
/* Let vi' = h(a, b', 0). */
/* nu_encl should certify that given [ve is child of y], then [ve' is child of y'] */
/* nu_ins should certify that given [0 is child of y'], then [vi' is child of y''] */
/* this function will then issue a certificate verifying that y and
 * y'' are equivalent roots, indicating that they differ only in y''
 * having an additional placeholder node with index a */
struct tm_cert tm_cert_equiv(const struct trusted_module *tm,
                             const struct tm_cert *nu_encl, hash_t hmac_encl,
                             const struct tm_cert *nu_ins,  hash_t hmac_ins,
                             struct iomt_node encloser,
                             uint64_t a, hash_t *hmac_out)
{
    if(!nu_encl || !nu_ins)
    {
        tm_seterror("null certificate");
        return cert_null;
    }
    if(nu_encl->type != NU || nu_ins->type != NU)
    {
        tm_seterror("one or both certificates are not NU certificates");
        return cert_null;
    }
    if(!cert_verify(tm, nu_encl, hmac_encl) || !cert_verify(tm, nu_ins, hmac_ins))
    {
        tm_seterror("invalid authentication");
        return cert_null;
    }
    if(!encloses(encloser.idx, encloser.next_idx, a))
    {
        tm_seterror("encloser does not actually enclose placeholder index");
        return cert_null;
    }
    if(!hash_equals(nu_encl->nu.new_root, nu_ins->nu.orig_root))
    {
        tm_seterror("NU certificates do not form a chain");
        return cert_null;
    }

    hash_t ve = hash_node(encloser);
    struct iomt_node encloser_mod = encloser;
    encloser_mod.next_idx = a;
    hash_t veprime = hash_node(encloser_mod);

    struct iomt_node ins;
    ins.idx = a;
    ins.next_idx = encloser.next_idx;
    memset(ins.val.hash, 0, sizeof(ins.val.hash));

    hash_t viprime = hash_node(ins);

    if(!hash_equals(nu_encl->nu.orig_node, ve))
    {
        tm_seterror("NU certificate does not contain hash of encloser node as original node value");
        return cert_null;
    }
    if(!hash_equals(nu_encl->nu.new_node, veprime))
    {
        tm_seterror("NU certificate does not contain hash of modified encloser as new node");
        return cert_null;
    }
    if(!is_zero(nu_ins->nu.orig_node))
    {
        tm_seterror("NU certificate does not have zero for original node");
        return cert_null;
    }
    if(!hash_equals(nu_ins->nu.new_node, viprime))
    {
        tm_seterror("NU certificate does not have placeholder as new node");
        return cert_null;
    }

    /* we can now certify that y and y'' are equivalent roots */
    struct tm_cert cert = cert_null;
    memset(&cert, 0, sizeof(cert));
    cert.type = EQ;
    cert.eq.orig_root = nu_encl->nu.orig_root;
    cert.eq.new_root = nu_ins->nu.new_root;

    *hmac_out = cert_sign(tm, &cert);
    return cert;
}

/* nu must be of the form [x,y,x,y] to indicate that x is a child of y */
/* also, if b > 0 and nonexist != NULL, this function will generate a
 * certificate indicating that no node with index b exists with root
 * y */
struct tm_cert tm_cert_record_verify(const struct trusted_module *tm,
                                     const struct tm_cert *nu, hash_t hmac,
                                     struct iomt_node node,
                                     hash_t *hmac_out,
                                     uint64_t b,
                                     struct tm_cert *nonexist,
                                     hash_t *hmac_nonexist)
{
    if(!nu)
        return cert_null;
    if(!cert_verify(tm, nu, hmac))
    {
        tm_seterror("improper certificate authentication");
        return cert_null;
    }

    if(nu->type != NU)
    {
        tm_seterror("wrong certificate type");
        return cert_null;
    }

    if(!hash_equals(nu->nu.orig_node, nu->nu.new_node) || !hash_equals(nu->nu.orig_root, nu->nu.new_root))
        return cert_null;

    hash_t node_h = hash_node(node);
    if(!hash_equals(nu->nu.orig_node, node_h))
        return cert_null;

    /* issue a certificate verifying that no node with index b exists as a child of y */
    if(b > 0 && nonexist && hmac_nonexist)
    {
        if(encloses(node.idx, node.next_idx, b))
        {
            *nonexist = cert_null;
            nonexist->type = RV;
            nonexist->rv.idx = b;

            /* not needed, already zeroed */
            //memset(nonexist->rv.val, 0, sizeof(nonexist->rv.val));

            nonexist->rv.root = nu->nu.orig_root;

            *hmac_nonexist = cert_sign(tm, nonexist);
        }
        else
            *nonexist = cert_null;
    }

    /* verify that this node is a child of y */
    struct tm_cert cert = cert_null;

    cert.type = RV;
    cert.rv.root = nu->nu.orig_root;
    cert.rv.idx = node.idx;
    cert.rv.val = node.val;

    /* can be NULL */
    if(hmac_out)
        *hmac_out = cert_sign(tm, &cert);
    return cert;
}

struct tm_cert tm_cert_record_update(const struct trusted_module *tm,
                                     const struct tm_cert *nu, hash_t nu_hmac,
                                     struct iomt_node node,
                                     hash_t new_val,
                                     hash_t *hmac_out)
{
    if(!nu)
    {
        tm_seterror("null certificate");
        return cert_null;
    }
    if(nu->type != NU)
    {
        tm_seterror("not NU certificate");
        return cert_null;
    }
    if(!cert_verify(tm, nu, nu_hmac))
    {
        tm_seterror("improper certificate authentication");
        return cert_null;
    }

    hash_t orig_h = hash_node(node);

    struct iomt_node new_node = node;
    new_node.val = new_val;

    hash_t new_h = hash_node(new_node);

    if(!hash_equals(nu->nu.orig_node, orig_h) || !hash_equals(nu->nu.new_node, new_h))
    {
        tm_seterror("NU hashes do not match node hashes");
        return cert_null;
    }

    struct tm_cert cert = cert_null;

    cert.type = RU;
    cert.ru.idx = node.idx;
    cert.ru.orig_val = node.val;
    cert.ru.new_val = new_val;
    cert.ru.orig_root = nu->nu.orig_root;
    cert.ru.new_root = nu->nu.new_root;

    *hmac_out = cert_sign(tm, &cert);
    return cert;
}

/* toggle the IOMT root to an equivalent root (which differs only in
 * having an extra zero placeholder) */
bool tm_set_equiv_root(struct trusted_module *tm,
                       const struct tm_cert *cert_eq, hash_t hmac)
{
    if(!cert_eq)
        return false;
    if(cert_eq->type != EQ)
        return false;
    if(!cert_verify(tm, cert_eq, hmac))
        return false;

    if(hash_equals(tm->root, cert_eq->eq.orig_root))
    {
        tm_setroot(tm, cert_eq->eq.new_root);
        return true;
    }

    if(hash_equals(tm->root, cert_eq->eq.new_root))
    {
        tm_setroot(tm, cert_eq->eq.orig_root);
        return true;
    }

    return false;
}

/* user id is 1-indexed */
static hash_t req_sign(const struct trusted_module *tm, const struct tm_request *req, int id)
{
    return hmac_sha256(req, sizeof(*req), tm->user_keys[id - 1].key, tm->user_keys[id - 1].len);
}

/* verify HMAC of user request */
static bool req_verify(const struct trusted_module *tm, const struct tm_request *req, uint64_t id, hash_t hmac)
{
    if(id < 1 || id >= tm->n_users + 1)
        return false;
    hash_t calculated = req_sign(tm, req, id);
    return hash_equals(calculated, hmac);
}

static hash_t req_ack(const struct trusted_module *tm, const struct tm_request *req)
{
    return sign_ack(req,
                    1,
                    tm->user_keys[req->user_id - 1].key,
                    tm->user_keys[req->user_id - 1].len);
}

/* execute a user request, if possible */
/*
 * This function handles all transformations on the IOMT except
 * inserting a placeholder (handled above). The function takes its
 * parameter in the form of a tm_request struct, which must be
 * authenticated or else the function will fail. When a request is
 * successfully completed, *ack_hmac will be updated to the value
 * HMAC(<request> + 1, K), where + denotes concatenation, and K is the
 * shared secret between the user and module. Based on the request
 * contents, one of three actions are performed:
 *
 * 1) req->type == ACL_UPDATE and req->counter == 0:
 *
 * Create a new file entry. A properly authenticated RU certificate
 * must be passed in the `create' struct of the request. The RU
 * certificate must be of the form [ f, 0, current root, 1, new root
 * ]. Additionally, the `val' field of the request struct should be
 * set to the root of the ACL IOMT (a).
 *
 * Given these parameters, this function will then update the internal
 * IOMT root to the new root and will issue an FR certificate of the
 * form [ idx = f, c_f = 1, acl = a, ver = 0 ].
 *
 * 2) req->type == ACL_UPDATE (and req->counter > 0 and access = 3):
 *
 * Three properly authenticated certificates are needed for an update
 * to the ACL: one FR certificate to indicate the ACL root, one RV
 * certificate of the form [ user_id, access, acl_root ] to indicate
 * user access level (which must be 3 in order to change the ACL), and
 * one RU certificate of the form [ f, c_f, current IOMT root, c_f +
 * 1, new IOMT root ] to indicate that the counter c_f is consistent
 * with the internally stored root and the updated IOMT root.
 *
 * Given these three certificates, this function will return an FR
 * certificate (signed in *hmac_out) with the updated ACL root, and
 * will update the internal IOMT root to increment the file counter,
 * c_f.
 *
 * 3) req->type == FILE_UPDATE (and req->counter > 0 and access >= 2):
 *
 * Three properly authenticated certificates are needed for the
 * creation of a new file version (which are also the same as the ones
 * needed for an ACL update, see above). The user access level must be
 * >= 2, otherwise this function will fail.
 *
 * This function returns two certificates: one FR certificate
 * indicating the updated file counter and version number (and an
 * unchanged ACL root), and a new VR certificate, returned in *vr_out
 * and signed in *vr_hmac. Additionally, the internal IOMT root will
 * be updated to reflect the incremented file counter.
 */
struct tm_cert tm_request(struct trusted_module *tm,
                          const struct tm_request *req, hash_t req_hmac,
                          hash_t *hmac_out,
                          struct tm_cert *vr_out, hash_t *vr_hmac,
                          hash_t *hmac_ack)
{
    if(!req)
    {
        tm_seterror("null request");
        return cert_null;
    }
    if(!req_verify(tm, req, req->user_id, req_hmac))
    {
        tm_seterror("improper authentication");
        return cert_null;
    }

    /* invalid request type */
    if(req->type != ACL_UPDATE && req->type != FILE_UPDATE)
    {
        tm_seterror("invalid request type");
        return cert_null;
    }

    /* file creation */
    if(req->type == ACL_UPDATE && req->counter == 0)
    {
        /* We must verify that no file exists with the requested
         * index by checking that we have a valid RU certificate
         * showing that updating the record with index `f' from 0
         * to 1 changes the IOMT root from the stored root (in the
         * TM) to a different root */

        /* we treat the hash like a 256-bit little-endian counter */
        hash_t one = u64_to_hash(1);

        if(req->create.ru_cert.type != RU)
        {
            tm_seterror("wrong certificate type (should be RU)");
            return cert_null;
        }

        /* first check the validity of the certificate */
        if(!cert_verify(tm, &req->create.ru_cert, req->create.ru_hmac))
        {
            tm_seterror("RU cert invalid");
            return cert_null;
        }

        /* verify that:
           - the certificate has the same file index as the request
           - the original value for the record is zero (a placeholder)
           - the original root matches the current IOMT root stored in the module
           - the new value is the value 1
        */
        if(req->create.ru_cert.ru.idx != req->idx ||
           !is_zero(req->create.ru_cert.ru.orig_val)   ||
           !hash_equals(req->create.ru_cert.ru.orig_root, tm->root) ||
           !hash_equals(req->create.ru_cert.ru.new_val, one))
        {
            tm_seterror("RU cert does not show needed information");
            return cert_null;
        }

        /* update the IOMT root */
        tm_setroot(tm, req->create.ru_cert.ru.new_root);

        /* issue an FR certificate */
        struct tm_cert cert = cert_null;
        cert.type = FR;
        cert.fr.idx = req->idx;
        cert.fr.counter = req->counter + 1;
        cert.fr.version = 0;
        cert.fr.acl = req->val;

        *hmac_out = cert_sign(tm, &cert);
        *hmac_ack = req_ack(tm, req);
        return cert;
    }

    /* Otherwise the request is to either modify the ACL or create a
     * new file version. In either case, check the three certificates
     * (to verify ACL and access privilege). */
    if(req->counter <= 0)
    {
        tm_seterror("invalid counter");
        return cert_null;
    }
    if(!cert_verify(tm, &req->modify.fr_cert, req->modify.fr_hmac))
    {
        tm_seterror("FR certificate improperly authenticated");
        return cert_null;
    }
    if(!cert_verify(tm, &req->modify.rv_cert, req->modify.rv_hmac))
    {
        tm_seterror("RV certificate improperly authenticated");
        return cert_null;
    }
    if(!cert_verify(tm, &req->modify.ru_cert, req->modify.ru_hmac))
    {
        tm_seterror("RU certificate improperly authenticated");
        return cert_null;
    }

    if(req->modify.fr_cert.type != FR ||
       req->modify.rv_cert.type != RV ||
       req->modify.ru_cert.type != RU)
    {
        tm_seterror("wrong certificate type");
        return cert_null;
    }

    /* check that FR and RU certificate indices match request index */
    if(req->modify.fr_cert.fr.idx != req->idx ||
       req->modify.ru_cert.ru.idx != req->idx)
    {
        tm_seterror("either FR or RU certificate indices do not match request index");
        return cert_null;
    }

    /* Check that the file counter is consistent with the stored root
     * and the counter in the request. Also check that the FR
     * certificate's counter matches that of the request. */
    if(!hash_equals(req->modify.ru_cert.ru.orig_root, tm->root) ||
       hash_to_u64(req->modify.ru_cert.ru.orig_val) != req->counter ||
       req->modify.fr_cert.fr.counter != req->counter)
    {
        tm_seterror("RU certificate does not correspond to stored root; or FR counter does not match request counter");
        return cert_null;
    }

    /* check that the RU certificate corresponds to an increment of
     * the counter value. */
    if(hash_to_u64(req->modify.ru_cert.ru.orig_val) + 1 != hash_to_u64(req->modify.ru_cert.ru.new_val))
    {
        tm_seterror("RU does not reflect incrementing counter value");
        return cert_null;
    }

    /* check access level using RV cert, which verifies a record in
     * the ACL tree. */
    if(!hash_equals(req->modify.fr_cert.fr.acl, req->modify.rv_cert.rv.root))
    {
        tm_seterror("RV certificate does not match ACL given in file record");
        return cert_null;
    }
    if(req->modify.rv_cert.rv.idx != req->user_id)
    {
        tm_seterror("RV certificate has wrong user id");
        return cert_null;
    }

    /* we treat the first 8 bytes of the counter as a little-endian
     * integer counter */
    uint64_t access = hash_to_u64(req->modify.rv_cert.rv.val);

    /* no write access to file or ACL */
    if(access < 2)
    {
        tm_seterror("user has insufficient permissions");
        return cert_null;
    }

    /* file update */
    if(req->type == FILE_UPDATE)
    {
        /* We need to issue a VR certificate indicating the new
         * version's contents, and an FR certificate with the new
         * version number. */
        struct tm_cert fr_cert = cert_null, vr_cert = cert_null;
        fr_cert.type = FR;
        fr_cert.fr.idx = req->idx;
        fr_cert.fr.counter = req->counter + 1;
        fr_cert.fr.version = req->modify.fr_cert.fr.version + 1;
        fr_cert.fr.acl     = req->modify.fr_cert.fr.acl;

        *hmac_out = cert_sign(tm, &fr_cert);

        vr_cert.type = VR;
        vr_cert.vr.idx = req->idx;
        vr_cert.vr.version = req->modify.fr_cert.fr.version + 1;
        vr_cert.vr.hash = req->val;

        *vr_hmac = cert_sign(tm, &vr_cert);
        *vr_out = vr_cert;

        tm_setroot(tm, req->modify.ru_cert.ru.new_root);

        *hmac_ack = req_ack(tm, req);

        return fr_cert;
    }
    else if(req->type == ACL_UPDATE)
    {
        if(access < 3)
        {
            tm_seterror("user has insufficient permissions");
            return cert_null;
        }

        /* We just need a new FR certificate with the new ACL. */
        struct tm_cert cert = cert_null;
        cert.type = FR;
        cert.fr.idx = req->idx;
        cert.fr.counter = req->counter + 1;
        cert.fr.version = req->modify.fr_cert.fr.version;
        cert.fr.acl = req->val;

        *hmac_out = cert_sign(tm, &cert);

        tm_setroot(tm, req->modify.ru_cert.ru.new_root);
        *hmac_ack = req_ack(tm, req);
        return cert;
    }

    /* should not get here */
    assert(false);
}

/* enc_secret is encrypted by the user by XOR'ing the file encryption
 * key with HMAC(f | c_f, K), where | denotes concatenation. The
 * purpose of this function is to decrypt the secret passed by the
 * user, verify its integrity against kf=HMAC(secret, key=f_idx), and
 * then re-encrypt the secret with the module's secret key. This is
 * the F_rs() function described by Mohanty et al. */

/* Untested. */
hash_t tm_verify_and_encrypt_secret(const struct trusted_module *tm,
                                    uint64_t file_idx,
                                    uint64_t file_version,
                                    uint64_t user_id,
                                    hash_t encrypted_secret, hash_t kf)
{
    hash_t key = crypt_secret(encrypted_secret,
                              file_idx, file_version,
                              tm->user_keys[user_id - 1].key,
                              tm->user_keys[user_id - 1].len);

    if(hash_equals(kf, hmac_sha256(key.hash, sizeof(key.hash),
                                   &file_idx, sizeof(file_idx))))
    {
        /* re-encrypt using key known only to module */
        hash_t pad = hmac_sha256(kf.hash, sizeof(kf.hash),
                                 tm->secret, sizeof(tm->secret));

        return hash_xor(key, pad);
    }

    /* failure */
    return hash_null;
}

/* Decrypt a previously encrypted secret, and then encrypt for receipt
 * by a user. rv1 should bind the file index and counter to the
 * current root. rv2 should verify the user's access level in the
 * ACL. The index (which is a user id) given in rv2 will select the
 * key used to encrypt the secret. As with
 * tm_verify_and_encrypt_secret(), kf=HMAC(secret, key=f_idx). */

/* Untested. */
hash_t tm_retrieve_secret(const struct trusted_module *tm,
                          const struct tm_cert *rv1, hash_t rv1_hmac,
                          const struct tm_cert *rv2, hash_t rv2_hmac,
                          const struct tm_cert *fr, hash_t fr_hmac,
                          hash_t secret, hash_t kf)
{
    if(!rv1 || !rv2 || !fr)
    {
        tm_seterror("null certificate");
        return hash_null;
    }

    if(!cert_verify(tm, rv1, rv1_hmac) ||
       !cert_verify(tm, rv2, rv2_hmac) ||
       !cert_verify(tm, fr, fr_hmac))
    {
        tm_seterror("certificate not authenticated");
        return hash_null;
    }

    if(rv1->type != RV ||
       rv2->type != RV ||
       fr->type != FR)
    {
        tm_seterror("wrong certificate type");
        return hash_null;
    }

    if(rv1->rv.idx != fr->fr.idx)
    {
        tm_seterror("RV1 index does not match file index");
        return hash_null;
    }
    if(hash_to_u64(rv1->rv.val) != fr->fr.counter)
    {
        tm_seterror("counter given by RV1 does not match counter in FR");
        return hash_null;
    }
    if(!hash_equals(rv1->rv.root, tm->root))
    {
        tm_seterror("RV1 root does not match internal root");
        return hash_null;
    }
    if(!hash_equals(rv2->rv.root, fr->fr.acl))
    {
        tm_seterror("RV2 root does not match ACL root");
        return hash_null;
    }

    uint64_t access = hash_to_u64(rv2->rv.val);
    if(access < 1)
    {
        tm_seterror("insufficient permissions");
        return hash_null;
    }

    hash_t pad = hmac_sha256(kf.hash, sizeof(kf.hash),
                             tm->secret, sizeof(tm->secret));

    /* decrypt */
    secret = hash_xor(secret, pad);

    /* verify that kf=HMAC(secret, file_idx) */
    if(!hash_equals(kf, hmac_sha256(secret.hash, sizeof(secret.hash),
                                    &rv1->rv.idx, sizeof(rv1->rv.idx))))
    {
        tm_seterror("secret integrity not confirmed");
        return hash_null;
    }

    /* now re-encrypt for conveyance to user by XOR'ing with HMAC(kf, user_key) */
    pad = hmac_sha256(kf.hash, sizeof(kf.hash),
                      tm->user_keys[rv2->rv.idx - 1].key,
                      tm->user_keys[rv2->rv.idx - 1].len);
    return hash_xor(secret, pad);
}

static hash_t tm_sign_verinfo(const struct trusted_module *tm,
                              const struct version_info *ver,
                              uint64_t user_id)
{
    return sign_verinfo(ver,
                        tm->user_keys[user_id - 1].key,
                        tm->user_keys[user_id - 1].len);
}

/* Verify the integrity of file information passed in the four
 * certificates by checking it against the current root; response is
 * authenticated with HMAC(response, user_key). RV1 should verify the
 * current file counter value against the current root. If the value
 * field for RV1 is zero, then the file does not exist, and the
 * remaining certificates are not needed and can be null. RV2 should
 * prove that the user has the proper access level in the ACL. VR
 * should be signed and can be any version (not just the latest
 * one). Finally, FR should be the latest file record certificate
 * issued by the module, reflecting the latest counter value and
 * ACL. */
struct version_info tm_verify_fileinfo(const struct trusted_module *tm,
                                       uint64_t user_id,
                                       const struct tm_cert *rv1, hash_t rv1_hmac,
                                       const struct tm_cert *rv2, hash_t rv2_hmac,
                                       const struct tm_cert *fr, hash_t fr_hmac,
                                       const struct tm_cert *vr, hash_t vr_hmac,
                                       hash_t nonce,
                                       hash_t *response_hmac)
{
    /* No authenticated response if the parameters are incorrect or
     * improperly signed; it is the service provider's responsibility
     * to make sure these are correct, because if they are not, the
     * user will not receive the expected authentication. */
    if(!rv1)
    {
        tm_seterror("null parameter");
        return verinfo_null;
    }

    if(rv1->type != RV)
    {
        tm_seterror("RV1 is not RV certificate");
        return verinfo_null;
    }

    if(!cert_verify(tm, rv1, rv1_hmac))
    {
        tm_seterror("RV1 certificate signature invalid");
        return verinfo_null;
    }

    /* Check RV1 against root */
    if(!hash_equals(rv1->rv.root, tm->root))
    {
        tm_seterror("RV1 does not reflect current root");
        return verinfo_null;
    }

    /* File does not exist; issue authenticated denial. */
    if(is_zero(rv1->rv.val))
    {
        struct version_info verinfo = verinfo_null;
        verinfo.nonce = nonce;

        verinfo.idx = rv1->rv.idx;
        *response_hmac = tm_sign_verinfo(tm, &verinfo, user_id);
        return verinfo;
    }

    /* We must have these 2 certificates to continue (VR can be null
     * for the next part). */
    if(!rv2 || !fr)
    {
        tm_seterror("null parameter");
        return verinfo_null;
    }

    /* It's possible to have a null VR certificate and a perfectly
     * valid RV2 and FR certificate when the file has just been
     * created, but not modifed yet, so we do not check VR just
     * yet. */
    if(!cert_verify(tm, rv2, rv2_hmac) ||
       !cert_verify(tm, fr, fr_hmac))
    {
        tm_seterror("certificate signature invalid");
        return verinfo_null;
    }

    if(rv2->type != RV ||
       fr->type  != FR)
    {
        tm_seterror("wrong certificate type");
        return verinfo_null;
    }

    /* Ensure that all file indices match */
    if(rv1->rv.idx != fr->fr.idx)
    {
        tm_seterror("certificate indices do not match");
        return verinfo_null;
    }

    /* Ensure that the FR certificate is fresh by checking the counter
     * against the value of RV1 (which is guaranteed to be fresh) */
    if(hash_to_u64(rv1->rv.val) != fr->fr.counter)
    {
        tm_seterror("FR counter is not fresh");
        return verinfo_null;
    }

    if(rv2->rv.idx != user_id)
    {
        tm_seterror("RV2 index does not match user id");
        return verinfo_null;
    }

    /* Make sure that RV2's root is the file ACL */
    if(!hash_equals(rv2->rv.root, fr->fr.acl))
    {
        tm_seterror("RV2 does not have file ACL as root");
        return verinfo_null;
    }

    if(hash_to_u64(rv2->rv.val) < 1)
    {
        /* insufficient access level; produce an authenticated denial
         * (which is indistinguishable from the response when a file
         * does not exist) */

        struct version_info verinfo = verinfo_null;
        verinfo.nonce = nonce;

        verinfo.idx = fr->fr.idx;
        *response_hmac = tm_sign_verinfo(tm, &verinfo, user_id);

        return verinfo;
    }

    if(!vr)
    {
        if(!fr->fr.version)
        {
            /* File has been created, but has no contents (and hence
             * no versions). We issue a response to this effect. */
            struct version_info verinfo;
            verinfo.nonce = nonce;

            verinfo.idx = fr->fr.idx;
            verinfo.counter = fr->fr.counter;
            verinfo.max_version = fr->fr.version;
            verinfo.version = 0;
            verinfo.current_acl = fr->fr.acl;
            verinfo.lambda = hash_null;

            *response_hmac = tm_sign_verinfo(tm, &verinfo, user_id);
            return verinfo;
        }
        tm_seterror("null VR even though maxversion > 0");
        return verinfo_null;
    }

    if(!cert_verify(tm, vr, vr_hmac))
    {
        tm_seterror("certificate signature invalid");
        return verinfo_null;
    }

    if(vr->type != VR)
    {
        tm_seterror("wrong certificate type");
        return verinfo_null;
    }

    if(rv1->rv.idx != vr->vr.idx)
    {
        tm_seterror("certificate indices do not match");
        return verinfo_null;
    }

    /* We have verified that this file version exists and can
     * authenticate its record. */
    struct version_info verinfo;
    verinfo.nonce = nonce;

    verinfo.idx = fr->fr.idx;
    verinfo.counter = fr->fr.counter;
    verinfo.max_version = fr->fr.version;
    verinfo.version = vr->vr.version;
    verinfo.current_acl = fr->fr.acl;
    verinfo.lambda = vr->vr.hash;

    *response_hmac = tm_sign_verinfo(tm, &verinfo, user_id);
    return verinfo;
}

/* self-test */
void tm_test(void)
{
    {
        /* check NU certificate generation */
        struct trusted_module *tm = tm_new("a", 1);

        hash_t node = sha256("a", 1);
        hash_t node_new = sha256("b", 1);
        hash_t comp[] = { sha256("b", 1) };
        int orders[] = { 1 }; /* complementary node is right child */
        hash_t root_1, root_3;
        root_1 = merkle_compute(node, comp, orders, 1);

        hash_t hmac;
        struct tm_cert nu = tm_cert_node_update(tm, node, node_new, comp, orders, 1, &hmac);
        check("NU generation", nu.type == NU &&
              hash_equals(nu.nu.orig_node, node) &&
              hash_equals(nu.nu.orig_root, merkle_compute(node, comp, orders, 1)) &&
              hash_equals(nu.nu.new_node, node_new) &&
              hash_equals(nu.nu.new_root, merkle_compute(node_new, comp, orders, 1)));
        check("Certificate verification 1", cert_verify(tm, &nu, hmac));
        hash_t bogus = { { 0 } };
        check("Certificate verification 2", !cert_verify(tm, &nu, bogus));

        /* test combining NU certificates */
        hash_t node_3 = sha256("c", 1);
        root_3 = merkle_compute(node_3, comp, orders, 1);
        hash_t hmac2, hmac_cat;
        struct tm_cert nu2 = tm_cert_node_update(tm, node_new, node_3, comp, orders, 1, &hmac2);
        struct tm_cert cat = tm_cert_combine(tm, &nu, hmac, &nu2, hmac2, &hmac_cat);
        check("Combine NU certificates",
              nu2.type == NU &&
              cat.type == NU &&
              hash_equals(cat.nu.orig_root, root_1) &&
              hash_equals(cat.nu.orig_node, node) &&
              hash_equals(cat.nu.new_root, root_3) &&
              hash_equals(cat.nu.new_node, node_3) &&
              cert_verify(tm, &cat, hmac_cat));

        tm_free(tm);
    }
}
