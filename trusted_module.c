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
#include "trusted_module.h"

struct user_key {
    const void *key;
    size_t len;
};

struct trusted_module {
    hash_t root; /* root of IOMT */

    /* shared secret with user */
    struct user_key *user_keys;
    size_t n_users;

    /* secret for signing self-certificates */
    unsigned char secret[32];
};

static hash_t hmac_sha256(const void *data, size_t datalen, const void *key, size_t keylen)
{
    hash_t h;
    HMAC(EVP_sha256(), key, keylen, data, datalen, h.hash, NULL);
    return h;
}

static hash_t sha256(const void *data, size_t datalen)
{
    hash_t h;
    SHA256(data, datalen, h.hash);
    return h;
}

bool is_zero(hash_t u)
{
    /* constant-time comparison */
    volatile char c = 0;
    for(int i = 0; i < 32; ++i)
        c |= u.hash[i];

    return c == 0;
}

void dump_hash(hash_t u)
{
    for(int i = 0; i < 32; ++i)
        printf("%02x", u.hash[i]);
    printf("\n");
}

bool hash_equals(hash_t a, hash_t b)
{
    return !memcmp(a.hash, b.hash, 32);
}

struct trusted_module *tm_new(const void *key, size_t keylen)
{
    struct trusted_module *tm = calloc(1, sizeof(struct trusted_module));

    if(!RAND_bytes(tm->secret, 32))
    {
        free(tm);
        return NULL;
    }

    tm->user_keys = calloc(1, sizeof(*tm->user_keys));
    tm->n_users = 1;
    tm->user_keys[0].key = key;
    tm->user_keys[0].len = keylen;

    /* debugging */
    memset(tm->secret, 0, sizeof(tm->secret));
    memset(tm->root.hash, 0, sizeof(tm->root.hash));

    return tm;
}

/* NOTE: we fail to distinguish between intermediate and leaf
 * nodes, making a second-preimage attack possible */
/* order: 0: u is left, v is right, 1: u is right, v is left */
static hash_t merkle_parent(hash_t u, hash_t v, int order)
{
    if(is_zero(u))
        return v;
    if(is_zero(v))
        return u;

    /* append and hash */
    SHA256_CTX ctx;
    hash_t h;

    SHA256_Init(&ctx);

    if(order != 0)
        SHA256_Update(&ctx, v.hash, 32);

    SHA256_Update(&ctx, u.hash, 32);

    if(order == 0)
        SHA256_Update(&ctx, v.hash, 32);

    SHA256_Final(h.hash, &ctx);

    return h;
}

/* Calculate the root of a Merkle tree given the leaf node v, and n
 * complementary nodes, ordered from the closest node (the sibling
 * leaf node at the bottom of the tree) to most distant (the opposite
 * half of the tree). orders[i] represents whether each complementarty
 * node is a left or right child, which is necessary to compute the
 * proper hash value at each stage. This is the f_bt() algorithm
 * described in Mohanty et al. */

/* orders: 0 indiciates that the complementary node is LEFT child, 1:
 * node is RIGHT child */
static hash_t merkle_compute(hash_t node, const hash_t *comp, const int *orders, size_t n)
{
    hash_t parent = node;
    for(size_t i = 0; i < n; ++i)
        parent = merkle_parent(comp[i], parent, orders[i]);

    return parent;
}

static hash_t cert_sign(struct trusted_module *tm, const struct tm_cert *cert)
{
    return hmac_sha256(cert, sizeof(*cert), tm->secret, sizeof(tm->secret));
}

static bool cert_verify(struct trusted_module *tm, const struct tm_cert *cert, hash_t hmac)
{
    hash_t calculated = cert_sign(tm, cert);
    return hash_equals(calculated, hmac);
}

struct tm_cert tm_cert_node_update(struct trusted_module *tm, hash_t orig, hash_t new, const hash_t *comp, const int *orders, size_t n, hash_t *hmac)
{
    struct tm_cert cert;
    cert.type = NU;
    cert.nu.orig_node = orig;
    cert.nu.new_node = new;

    cert.nu.orig_root = cert.nu.new_root = merkle_compute(orig, comp, orders, n);

    if(!hash_equals(orig, new))
        cert.nu.new_root = merkle_compute(new, comp, orders, n);

    *hmac = cert_sign(tm, &cert);

    return cert;
}

static struct tm_cert cert_null = { NONE };

static const char *tm_error = NULL;
static void tm_seterror(const char *error)
{
    tm_error = error;
}

static const char *tm_geterror(void)
{
    if(tm_error)
        return tm_error;
    return "success";
}

/* combine two NU certificates */
struct tm_cert tm_cert_combine(struct trusted_module *tm,
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
        struct tm_cert cert;
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

/* return true iff [b, bprime] encloses a */
static bool encloses(int b, int bprime, int a)
{
    return (b < a < bprime) || (bprime <= b && b < a) || (a < bprime && bprime <= b);
}

static hash_t hash_node(const struct iomt_node *node)
{
    return sha256(node, sizeof(*node));
}

/* Let ve = h(b, b', wb). */
/* Let ve' = h(b, a, wb). */
/* Let vi' = h(a, b', 0). */
/* nu_encl should certify that given [ve is child of y], then [ve' is child of y'] */
/* nu_ins should certify that given [0 is child of y'], then [vi' is child of y''] */
/* this function will then issue a certificate verifying that y and
 * y'' are equivalent roots, indicating that they differ only in y''
 * having an additional placeholder node with index a */
struct tm_cert tm_cert_equiv(struct trusted_module *tm,
                             const struct tm_cert *nu_encl, hash_t hmac_encl,
                             const struct tm_cert *nu_ins,  hash_t hmac_ins,
                             const struct iomt_node *encloser,
                             int a, hash_t *hmac_out)
{
    if(!nu_encl || !nu_ins)
        return cert_null;
    if(nu_encl->type != NU || nu_ins->type != NU)
        return cert_null;
    if(!cert_verify(tm, nu_encl, hmac_encl) || !cert_verify(tm, nu_ins, hmac_ins))
        return cert_null;
    if(!encloses(encloser->idx, encloser->next_idx, a))
        return cert_null;
    if(!hash_equals(nu_encl->nu.new_root, nu_ins->nu.orig_root))
        return cert_null;

    hash_t ve = hash_node(encloser);
    struct iomt_node encloser_mod = *encloser;
    encloser_mod.next_idx = a;
    hash_t veprime = hash_node(&encloser_mod);

    struct iomt_node ins;
    ins.idx = a;
    ins.next_idx = encloser->next_idx;
    memset(ins.val.hash, 0, sizeof(ins.val.hash));

    hash_t viprime = hash_node(&ins);

    if(!hash_equals(nu_encl->nu.orig_node, ve))
        return cert_null;
    if(!hash_equals(nu_encl->nu.new_node, veprime))
        return cert_null;
    if(!is_zero(nu_ins->nu.orig_node))
        return cert_null;
    if(!hash_equals(nu_ins->nu.new_node, viprime))
        return cert_null;

    /* we can now certify that y and y'' are equivalent roots */
    struct tm_cert cert;
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
 * y*/
struct tm_cert tm_cert_record_verify(struct trusted_module *tm,
                                     const struct tm_cert *nu, hash_t hmac,
                                     const struct iomt_node *node,
                                     hash_t *hmac_out,
                                     int b,
                                     struct tm_cert *nonexist,
                                     hash_t *hmac_nonexist)
{
    if(!nu)
        return cert_null;
    if(!hash_equals(nu->nu.orig_node, nu->nu.new_node) || !hash_equals(nu->nu.orig_root, nu->nu.new_root))
        return cert_null;

    hash_t node_h = hash_node(node);
    if(!hash_equals(nu->nu.orig_node, node_h))
        return cert_null;

    /* issue a certificate verifying that no node with index b exists as a child of y */
    if(b > 0 && nonexist && hmac_nonexist)
    {
        if(encloses(node->idx, node->next_idx, b))
        {
            memset(nonexist, 0, sizeof(*nonexist));
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
    struct tm_cert cert;

    memset(&cert, 0, sizeof(cert));

    cert.type = RV;
    cert.rv.root = nu->nu.orig_root;
    cert.rv.idx = node->idx;
    cert.rv.val = node->val;

    *hmac_out = cert_sign(tm, &cert);
    return cert;
}

struct tm_cert tm_cert_record_update(struct trusted_module *tm,
                                     const struct tm_cert *nu, hash_t nu_hmac,
                                     const struct iomt_node *node,
                                     hash_t new_val,
                                     hash_t *hmac_out)
{
    if(!nu)
        return cert_null;
    if(nu->type != NU)
        return cert_null;
    if(!cert_verify(tm, nu, nu_hmac))
        return cert_null;

    hash_t orig_h = hash_node(node);

    struct iomt_node new_node = *node;
    new_node.val = new_val;

    hash_t new_h = hash_node(&new_node);

    if(!hash_equals(nu->nu.orig_node, orig_h) || !hash_equals(nu->nu.new_node, new_h))
        return cert_null;

    struct tm_cert cert;
    memset(&cert, 0, sizeof(cert));

    cert.type = RU;
    cert.ru.idx = node->idx;
    cert.ru.orig_val = node->val;
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
        tm->root = cert_eq->eq.new_root;
        return true;
    }

    if(hash_equals(tm->root, cert_eq->eq.new_root))
    {
        tm->root = cert_eq->eq.orig_root;
        return true;
    }

    return false;
}

/* user id is 1-indexed */
static hash_t req_sign(struct trusted_module *tm, const struct user_request *req, int id)
{
    return hmac_sha256(req, sizeof(*req), tm->user_keys[id - 1].key, tm->user_keys[id - 1].len);
}

/* verify HMAC of user request */
static bool req_verify(struct trusted_module *tm, const struct user_request *req, int id, hash_t hmac)
{
    if(id < 1 || id >= tm->n_users + 1)
        return false;
    hash_t calculated = req_sign(tm, req, id);
    return hash_equals(calculated, hmac);
}

/* convert the first 8 bytes (little endian) to a 64-bit int */
static uint64_t hash_to_u64(hash_t h)
{
    uint64_t ret = 0;
    for(int i = 0; i < 8; ++i)
        ret |= h.hash[i] << (i * 8);
    return ret;
}

/* Generate a signed acknowledgement for successful completion of a
 * request. We append a zero byte to the user request and take the
 * HMAC. */
static hash_t req_ack(const struct trusted_module *tm, const struct user_request *req)
{
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx,
                 tm->user_keys[req->user_id - 1].key,
                 tm->user_keys[req->user_id - 1].len,
                 EVP_sha256(), NULL);

    HMAC_Update(ctx, (const unsigned char*)req, sizeof(*req));

    char zero = 0;
    HMAC_Update(ctx, &zero, 1);

    hash_t hmac;
    HMAC_Final(ctx, hmac.hash, NULL);
    HMAC_CTX_free(ctx);
    
    return hmac;
}

/* execute a user request, if possible */
/* 
 * This function handles all transformations on the IOMT except
 * inserting a placeholder (handled above). The function takes its
 * parameter in the form of a user_request struct, which must be
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
                          const struct user_request *req, hash_t req_hmac,
                          hash_t *hmac_out,
                          struct tm_cert *vr_out, hash_t *vr_hmac,
                          hash_t *hmac_ack)
{
    if(!req)
        return cert_null;
    if(!req_verify(tm, req, req->user_id, req_hmac))
        return cert_null;

    /* invalid request type */
    if(req->type != ACL_UPDATE && req->type != FILE_UPDATE)
        return cert_null;

    /* file creation */
    if(req->type == ACL_UPDATE && req->counter == 0)
    {
        /* We must verify that no file exists with the requested
         * index by checking that we have a valid RU certificate
         * showing that updating the record with index `f' from 0
         * to 1 changes the IOMT root from the stored root (in the
         * TM) to a different root */

        /* we treat the hash like a 256-bit little-endian counter */
        hash_t one;
        memset(&one, 0, sizeof(one));
        one.hash[0] = 1;

        /* first check the validity of the certificate */
        if(!cert_verify(tm, &req->create.ru_cert, req->create.ru_hmac))
            return cert_null;

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
            return cert_null;

        /* update the IOMT root */
        tm->root = req->create.ru_cert.ru.new_root;

        /* issue an FR certificate */
        struct tm_cert cert;
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
        return cert_null;
    if(!cert_verify(tm, &req->modify.fr_cert, req->modify.fr_hmac))
        return cert_null;
    if(!cert_verify(tm, &req->modify.rv_cert, req->modify.rv_hmac))
        return cert_null;
    if(!cert_verify(tm, &req->modify.ru_cert, req->modify.ru_hmac))
        return cert_null;
    
    /* check that FR and RU certificate indices match request index */
    if(req->modify.fr_cert.fr.idx != req->idx ||
       req->modify.ru_cert.ru.idx != req->idx)
        return cert_null;

    /* Check that the file counter is consistent with the stored root
     * and the counter in the request. Also check that the FR
     * certificate's counter matches that of the request. */
    if(!hash_equals(req->modify.ru_cert.ru.orig_root, tm->root) ||
       hash_to_u64(req->modify.ru_cert.ru.orig_val) != req->counter ||
       req->modify.fr_cert.fr.counter != req->counter)
        return cert_null;

    /* check that the RU certificate corresponds to an increment of
     * the counter value. */
    if(hash_to_u64(req->modify.ru_cert.ru.orig_val) + 1 != hash_to_u64(req->modify.ru_cert.ru.new_val))
        return cert_null;
    
    /* check access level using RV cert, which verifies a record in
     * the ACL tree. */
    if(!hash_equals(req->modify.fr_cert.fr.acl, req->modify.rv_cert.rv.root))
        return cert_null;
    if(req->modify.rv_cert.rv.idx != req->user_id)
        return cert_null;

    /* we treat the first 8 bytes of the counter as a little-endian
     * integer counter */
    int access = hash_to_u64(req->modify.rv_cert.rv.val);

    /* no write access to file or ACL */
    if(access < 2)
        return cert_null;
    
    /* file update */
    if(req->type == FILE_UPDATE)
    {
        /* We need to issue a VR certificate indicating the new
         * version's contents, and an FR certificate with the new
         * version number. */
        struct tm_cert fr_cert, vr_cert;
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

        tm->root = req->modify.ru_cert.ru.new_root;
        *hmac_ack = req_ack(tm, req);
            
        return fr_cert;
    }
    else if(req->type == ACL_UPDATE)
    {
        /* We just need a new FR certificate with the new ACL. */
        struct tm_cert cert;
        cert.type = FR;
        cert.fr.idx = req->idx;
        cert.fr.counter = req->counter + 1;
        cert.fr.version = req->modify.fr_cert.fr.version;
        cert.fr.acl = req->val;
        
        *hmac_out = cert_sign(tm, &cert);

        tm->root = req->modify.ru_cert.ru.new_root;
        *hmac_ack = req_ack(tm, req);
        return cert;
    }

    /* should not get here */
    assert(false);
}

/* self-test */
void check(int condition)
{
    printf(condition ? "PASS\n" : "FAIL\n");
}

void tm_test(void)
{
    {
        /* test merkle tree with zeros */
        hash_t zero1, zero2;
        memset(zero1.hash, 0, sizeof(zero1.hash));
        memset(zero2.hash, 0, sizeof(zero2.hash));
        int orders[] = { 0 };

        /* this should return zero */
        hash_t res1 = merkle_compute(zero1, &zero2, orders, 1);
        printf("Merkle parent with zeros: ");
        check(is_zero(res1));

        hash_t a = sha256("a", 1);
        hash_t b = sha256("b", 1);
        hash_t c = sha256("c", 1);
        hash_t d = sha256("d", 1);
        hash_t cd = merkle_parent(c, d, 0);
        //dump_hash(cd);
        char buf[64];
        memcpy(buf, c.hash, 32);
        memcpy(buf + 32, d.hash, 32);
        //dump_hash(sha256(buf, 64));
        printf("Merkle parent: ");
        check(hash_equals(sha256(buf, 64), cd));

        hash_t a_comp[] = { b, cd };
        int a_orders[] = { 1, 1 };
        hash_t root1 = merkle_compute(a, a_comp, a_orders, 2);

        hash_t ab = merkle_parent(a, b, 0);
        hash_t root2 = merkle_parent(ab, cd, 0);
        //dump_hash(root1);
        //dump_hash(root2);
        printf("Merkle compute: ");
        check(hash_equals(root1, root2));
    }
    
    {
        /* check NU certificate generation */
        struct trusted_module *tm = tm_new("a", 1);

        hash_t node = sha256("a", 1);
        hash_t node_new = sha256("b", 1);
        hash_t comp[] = { sha256("b", 1) };
        int orders[] = { 1 }; /* complementary node is right child */
        hash_t root_1, root_2, root_3;
        root_1 = merkle_compute(node, comp, orders, 1);
        root_2 = merkle_compute(node_new, comp, orders, 1);
        
        hash_t hmac;
        struct tm_cert nu = tm_cert_node_update(tm, node, node_new, comp, orders, 1, &hmac);
        printf("NU generation: ");
        check(nu.type == NU &&
              hash_equals(nu.nu.orig_node, node) &&
              hash_equals(nu.nu.orig_root, merkle_compute(node, comp, orders, 1)) &&
              hash_equals(nu.nu.new_node, node_new) &&
              hash_equals(nu.nu.new_root, merkle_compute(node_new, comp, orders, 1)));
        printf("Certificate verification 1: ");
        check(cert_verify(tm, &nu, hmac));
        hash_t bogus = { { 0 } };
        printf("Certificate verification 2: ");
        check(!cert_verify(tm, &nu, bogus));

        /* test combining NU certificates */
        hash_t node_3 = sha256("c", 1);
        root_3 = merkle_compute(node_3, comp, orders, 1);
        hash_t hmac2, hmac_cat;
        struct tm_cert nu2 = tm_cert_node_update(tm, node_new, node_3, comp, orders, 1, &hmac2);
        struct tm_cert cat = tm_cert_combine(tm, &nu, hmac, &nu2, hmac2, &hmac_cat);
        printf("Combine NU certificates: ");
        check(nu2.type == NU &&
              cat.type == NU &&
              hash_equals(cat.nu.orig_root, root_1) &&
              hash_equals(cat.nu.orig_node, node) &&
              hash_equals(cat.nu.new_root, root_3) &&
              hash_equals(cat.nu.new_node, node_3) &&
              cert_verify(tm, &cat, hmac_cat));
        
        //tm_free(tm);
    }

    {
        
    }
}
