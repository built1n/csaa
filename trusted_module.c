/* An implementation of the trusted module T as described in Mohanty
 * et al. As this code is to execute on a general-purpose computer, no
 * guarantees can be made as to the tamper-resistance of the module,
 * but instead this serves as a proof-of-concept. */

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

struct trusted_module {
    hash_t root; /* root of IOMT */

    /* shared secret with user */
    const char *key;
    size_t keylen;

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

struct trusted_module *tm_new(const char *key, size_t keylen)
{
    struct trusted_module *tm = calloc(1, sizeof(struct trusted_module));

    if(!RAND_bytes(tm->secret, 32))
    {
        free(tm);
        return NULL;
    }

    tm->key = key;
    tm->keylen = keylen;

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

/* combine two NU certificates */
struct tm_cert tm_cert_combine(struct trusted_module *tm,
                               const struct tm_cert *nu1, hash_t hmac1,
                               const struct tm_cert *nu2, hash_t hmac2,
                               hash_t *hmac_out)
{
    if(!nu1 || !nu2)
        return cert_null;
    if(nu1->type != NU || nu2->type != NU)
        return cert_null;
    if(!cert_verify(tm, nu1, hmac1) || !cert_verify(tm, nu2, hmac2))
        return cert_null;

    if(hash_equals(nu1->nu.new_node, nu2->nu.orig_node) &&
       hash_equals(nu2->nu.new_root, nu2->nu.orig_root))
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
        return cert_null;
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
    memset(ins.value.hash, 0, sizeof(ins.value.hash));

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
struct tm_cert tm_cert_record_verify(struct trusted_module *tm,
                                     const struct tm_cert *nu, hash_t hmac,
                                     const struct iomt_node *node,
                                     hash_t *hmac_out)
{
    if(!nu)
        return cert_null;
    if(!hash_equals(nu->nu.orig_node, nu->nu.new_node) || !hash_equals(nu->nu.orig_root, nu->nu.new_root))
        return cert_null;

    hash_t node_h = hash_node(node);
    if(!hash_equals(nu->nu.orig_node, node_h))
        return cert_null;


}

void check(int condition)
{
    printf(condition ? "PASS\n" : "FAIL\n");
}

/* self-test */
void tm_test(void)
{
    /* test merkle tree with zeros */
    hash_t zero1, zero2;
    memset(zero1.hash, 0, sizeof(zero1.hash));
    memset(zero2.hash, 0, sizeof(zero2.hash));
    int orders[] = { 0 };

    /* this should return zero */
    hash_t res1 = merkle_compute(zero1, &zero2, orders, 1);
    printf("is_zero(res1) = %d\n", is_zero(res1));
    check(is_zero(res1));

    hash_t a = sha256("a", 1);
    hash_t b = sha256("b", 1);
    hash_t c = sha256("c", 1);
    hash_t d = sha256("d", 1);
    hash_t cd = merkle_parent(c, d, 0);
    dump_hash(cd);
    char buf[64];
    memcpy(buf, c.hash, 32);
    memcpy(buf + 32, d.hash, 32);
    dump_hash(sha256(buf, 64));
    check(hash_equals(sha256(buf, 64), cd));

    hash_t a_comp[] = { b, cd };
    int a_orders[] = { 1, 1 };
    hash_t root1 = merkle_compute(a, a_comp, a_orders, 2);

    hash_t ab = merkle_parent(a, b, 0);
    hash_t root2 = merkle_parent(ab, cd, 0);
    dump_hash(root1);
    dump_hash(root2);
    check(hash_equals(root1, root2));
}
