/* crypto and other generally useful stuff, shared by all code */

#include "crypto.h"
#include "iomt.h"
#include "trusted_module.h"
#include "test.h"

#include <assert.h>
#include <unistd.h>
#include <string.h>

#include <sys/socket.h>

#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

/* return true iff [b, bprime] encloses a */
bool encloses(uint64_t b, uint64_t bprime, uint64_t a)
{
    /* zero is not allowed as an index */
    if(a == 0)
        return false;
    return (b < a && a < bprime) || (bprime <= b && b < a) || (a < bprime && bprime <= b);
}

hash_t hmac_sha256(const void *data, size_t datalen, const void *key, size_t keylen)
{
    hash_t h;
    HMAC(EVP_sha256(), key, keylen, data, datalen, h.hash, NULL);
    return h;
}

hash_t sha256(const void *data, size_t datalen)
{
    hash_t h;
    SHA256(data, datalen, h.hash);
    return h;
}

bool is_zero(hash_t u)
{
    return !memcmp(u.hash, hash_null.hash, sizeof(u.hash));
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

hash_t hash_xor(hash_t a, hash_t b)
{
    for(int i = 0; i < 32; ++i)
        a.hash[i] ^= b.hash[i];
    return a;
}

/* NOTE: we fail to distinguish between intermediate and leaf
 * nodes, making a second-preimage attack possible */
/* order: 0: u is left, v is right, 1: u is right, v is left */
hash_t merkle_parent(hash_t u, hash_t v, int order)
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
hash_t merkle_compute(hash_t node, const hash_t *comp, const int *orders, size_t n)
{
    hash_t parent = node;
    for(size_t i = 0; i < n; ++i)
        parent = merkle_parent(comp[i], parent, orders[i]);

    return parent;
}

/* Calculate the indicies of the complementary nodes to a
 * leaf. `leafidx' is 0 for the rightmost leaf node. This function
 * will return an array with a length equal to the number of levels in
 * the tree minus one (the root is not a complentary node). The 0th
 * element of the returned array will be the index of the immediate
 * sibling, while the 1st element will be the index of the
 * complementary node one level above the leaf node, and so on. Note
 * that logleaves = log2(nleaves). If `orders' is not NULL, the
 * function will additionally allocate an array of `logleaves' *
 * sizeof(int) with each element representing whether each
 * complementary node is a left or right child. */
uint64_t *bintree_complement(uint64_t leafidx, int logleaves, int **orders)
{
    uint64_t *comp = calloc(logleaves, sizeof(uint64_t));
    if(orders)
        *orders = calloc(logleaves, sizeof(int));

    /* true index of leaf */
    uint64_t idx = ((uint64_t)1 << logleaves) - 1 + leafidx;

    /* progress up the tree */
    for(int i = 0; i < logleaves; ++i)
    {
        /* output index of sibling node */
        comp[i] = bintree_sibling(idx);

        /* we really don't need the orders array */
        if(orders)
            (*orders)[i] = idx & 1;

        /* find parent index and loop */
        idx = bintree_parent(idx);
    }

    return comp;
}

uint64_t *bintree_ancestors(uint64_t leafidx, int logleaves)
{
    uint64_t *dep = calloc(logleaves, sizeof(uint64_t));

    uint64_t idx = ((uint64_t)1 << logleaves) - 1 + leafidx;
    for(int i = 0; i < logleaves; ++i)
    {
        idx = bintree_parent(idx);
        dep[i] = idx;
    }

    return dep;
}

/* Shim to get only the orders */
int *bintree_complement_ordersonly(uint64_t leafidx, int logleaves)
{
    int *orders;
    free(bintree_complement(leafidx, logleaves, &orders));
    return orders;
}

struct hashstring hash_format(hash_t h, int n)
{
    struct hashstring ret;
    for(int i = 0; i < n; ++i)
    {
        sprintf(ret.str + 2 * i, "%02x", h.hash[i]);
    }
    return ret;
}

/* convert the first 8 bytes (little endian) to a 64-bit int */
uint64_t hash_to_u64(hash_t h)
{
    uint64_t ret = 0;
    for(int i = 0; i < 8; ++i)
        ret |= h.hash[i] << (i * 8);
    return ret;
}

hash_t u64_to_hash(uint64_t n)
{
    hash_t ret = hash_null;
    for(int i = 0; i < 8; ++i)
    {
        ret.hash[i] = n & 0xff;
        n >>= 8;
    }
    return ret;
}

hash_t hash_increment(hash_t h)
{
    /* incredibly inefficient... FIXME! */
    return u64_to_hash(hash_to_u64(h) + 1);
}

/* workaround for old openssl */
#if OPENSSL_VERSION_NUMBER < 0x10100000L

#include <string.h>
#include <openssl/engine.h>

static void *OPENSSL_zalloc(size_t num)
{
    void *ret = OPENSSL_malloc(num);

    if (ret != NULL)
        memset(ret, 0, num);
    return ret;
}

const unsigned char *EVP_CIPHER_CTX_iv(const EVP_CIPHER_CTX *ctx)
{
    return ctx->iv;
}

unsigned char *EVP_CIPHER_CTX_iv_noconst(EVP_CIPHER_CTX *ctx)
{
    return ctx->iv;
}

EVP_MD_CTX *EVP_MD_CTX_new(void)
{
    return OPENSSL_zalloc(sizeof(EVP_MD_CTX));
}

void EVP_MD_CTX_free(EVP_MD_CTX *ctx)
{
    EVP_MD_CTX_cleanup(ctx);
    OPENSSL_free(ctx);
}
HMAC_CTX *HMAC_CTX_new(void)
{
    HMAC_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    return ctx;
}

void HMAC_CTX_free(HMAC_CTX *ctx)
{
    if (ctx != NULL) {
        OPENSSL_free(ctx);
    }

}

#endif

/* simple XOR cipher, so encryption and decryption are symmetric */
hash_t crypt_secret(hash_t encrypted_secret,
                    uint64_t file_idx, uint64_t file_version,
                    const void *key, size_t keylen)
{
    hash_t pad; /* key = encrypted_secret ^ pad */
    HMAC_CTX *ctx = HMAC_CTX_new();
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_Init(ctx,
              key, keylen,
              EVP_sha256());
#else
    HMAC_Init_ex(ctx,
                 key, keylen,
                 EVP_sha256(), NULL);
#endif
    
    /* potential endianness issue */
    HMAC_Update(ctx, (const unsigned char*)&file_idx, sizeof(file_idx));
    HMAC_Update(ctx, (const unsigned char*)&file_version, sizeof(file_version));

    HMAC_Final(ctx, pad.hash, NULL);
    HMAC_CTX_free(ctx);

    return hash_xor(encrypted_secret, pad);
}

/* These are all fixed-length fields, so we can safely append them and
 * forgo any HMAC. */
hash_t calc_lambda(hash_t gamma, hash_t buildcode_root, hash_t composefile_root, hash_t kf)
{
    SHA256_CTX ctx;
    hash_t h;

    SHA256_Init(&ctx);

    SHA256_Update(&ctx, gamma.hash, sizeof(gamma.hash));
    SHA256_Update(&ctx, buildcode_root.hash, sizeof(buildcode_root.hash));
    SHA256_Update(&ctx, composefile_root.hash, sizeof(composefile_root.hash));
    SHA256_Update(&ctx, kf.hash, sizeof(kf.hash));

    SHA256_Final(h.hash, &ctx);

    printf("calc_lambda: gamma = %s, kf = %s, lambda = %s\n",
           hash_format(gamma, 4).str, hash_format(kf, 4).str,
           hash_format(h, 4).str);
    return h;
}

hash_t generate_nonce(void)
{
    hash_t ret;
    if(!RAND_bytes(ret.hash, sizeof(ret.hash)))
    {
        assert(!"Failed to generate nonce");
    }
    return ret;
}

/* Derive a fixed-length key from an arbitrary-length
 * passphrase. TODO: replace with a real KDF (PBKDF2?) */
hash_t derive_key(const char *passphrase, hash_t nonce)
{
    if(!passphrase || strlen(passphrase) == 0)
        return hash_null;
    return hmac_sha256(passphrase, strlen(passphrase),
                       &nonce, sizeof(nonce));
}

hash_t calc_kf(hash_t encryption_key, uint64_t file_idx)
{
    hash_t kf = hash_null;
    if(!is_zero(encryption_key))
        kf = hmac_sha256(&encryption_key, sizeof(encryption_key),
                         &file_idx, sizeof(file_idx));
    printf("calc_kf: encryption key = %s, file_idx = %lu, kf = %s\n",
           hash_format(encryption_key, 4).str, file_idx,
           hash_format(kf, 4).str);
    return kf;
}

void memxor(unsigned char *dest, const unsigned char *b, size_t len)
{
    while(len--)
        *dest++ ^= *b++;
}

/* symmetric: decryption and encryption are the same operation */
void crypt_bytes(unsigned char *data, size_t len, hash_t key)
{
    /* We use AES256 in CTR mode with a hard-coded IV. We never reuse
     * keys, as they are generated with a combination of the passphrase
     * and a nonce. Therefore, it should be reasonably safe to
     * hard-code the IV: */
    AES_KEY aes;

    AES_set_encrypt_key((void*)&key, 256, &aes);
    unsigned char block[16];

    /* We only use the first 16 bytes of the counter. */
    hash_t counter = u64_to_hash(0);

    size_t i;
    for(i = 0; i < len; i += 16, data += 16)
    {
        AES_ecb_encrypt((void*)&counter, block, &aes, AES_ENCRYPT);
        memxor(data, block, 16);
        counter = hash_increment(counter);
    }

    /* finish up */
    AES_ecb_encrypt((void*)&counter, block, &aes, AES_ENCRYPT);
    memxor(data, block, len - i);
}

/* Generate a signed acknowledgement for successful completion of a
 * request. We append a zero byte to the user request and take the
 * HMAC. */
hash_t sign_ack(const struct tm_request *req, int nzeros, const void *key, size_t keylen)
{
    HMAC_CTX *ctx = HMAC_CTX_new();
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_Init(ctx,
              key, keylen,
              EVP_sha256());
#else
    HMAC_Init_ex(ctx,
                 key, keylen,
                 EVP_sha256(), NULL);
#endif

    HMAC_Update(ctx, (const unsigned char*)req, sizeof(*req));

    unsigned char zero = 0;
    for(int i = 0; i < nzeros; ++i)
        HMAC_Update(ctx, &zero, 1);

    hash_t hmac;
    HMAC_Final(ctx, hmac.hash, NULL);
    HMAC_CTX_free(ctx);

    return hmac;
}

bool verify_ack(const struct tm_request *req,
                const void *secret, size_t secret_len,
                hash_t hmac)
{
    hash_t correct = sign_ack(req, 1, secret, secret_len);
    return hash_equals(hmac, correct);
}

hash_t sign_verinfo(const struct version_info *verinfo, const void *key, size_t len)
{
    return hmac_sha256(verinfo, sizeof(*verinfo), key, len);
}

bool verify_verinfo(const struct version_info *verinfo, const void *key, size_t len, hash_t nonce, hash_t hmac)
{
    if(!hash_equals(nonce, verinfo->nonce))
        return false;

    hash_t correct = sign_verinfo(verinfo, key, len);
    return hash_equals(hmac, correct);
}

void write_to_fd(void *userdata, const void *data, size_t len)
{
    int *fdptr = userdata;
    write(*fdptr, data, len);
}


int read_from_fd(void *userdata, void *buf, size_t len)
{
    int *fdptr = userdata;
    int rc = recv(*fdptr, buf, len, MSG_WAITALL);
    if(rc != len)
    {
        printf("short read");
    }
    return rc;
}

void dump_versioninfo(const struct version_info *verinfo)
{
    printf("idx = %lu, ctr = %lu, ver = %lu, max_ver = %lu, acl = %s, lambda = %s\n",
           verinfo->idx, verinfo->counter, verinfo->version, verinfo->max_version,
           hash_format(verinfo->current_acl, 4).str,
           hash_format(verinfo->lambda, 4).str);
}

void warn(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);

    char buf[256];
    vsnprintf(buf, sizeof(buf), fmt, ap);

    fprintf(stderr, "\033[31;1mWARNING\033[0m: %s\n", buf);
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

void *deserialize_file(int cl, size_t *len)
{
    recv(cl, len, sizeof(*len), MSG_WAITALL);
    
    printf("File is %lu bytes.\n", *len);

    if(!*len)
        return NULL;
    
    void *buf = malloc(*len);
    recv(cl, buf, *len, MSG_WAITALL);

    return buf;
}

void serialize_file(int cl, const void *buf, size_t len)
{
    if(!buf)
	len = 0;
    write(cl, &len, sizeof(len));

    if(!buf || !len)
	return;

    write(cl, buf, len);
}

void *load_file(const char *path, size_t *len)
{
    if(!path)
        return NULL;

    FILE *f = fopen(path, "r");
    fseek(f, 0, SEEK_END);
    *len = ftell(f);
    fseek(f, 0, SEEK_SET);
    void *buf = malloc(*len);
    fread(buf, 1, *len, f);
    return buf;
}

void write_file(const char *path, const void *contents, size_t len)
{
    if(contents)
    {
        FILE *f = fopen(path, "w");
        fwrite(contents, 1, len, f);
        fclose(f);
    }
}

void crypto_test(void)
{
#if 1
    int *orders;
    uint64_t *comp = bintree_complement(6, 4, &orders);
    uint64_t correct[] = { 22, 9, 3, 2 };
    int correct_orders[] = { 1, 0, 0, 1 };
    check("Complement calculation", !memcmp(comp, correct, 4 * sizeof(uint64_t)) && !memcmp(orders, correct_orders, 4 * sizeof(int)));
    free(orders);
    free(comp);

    uint64_t *dep = bintree_ancestors(6, 4);
    uint64_t correct_dep[] = { 10, 4, 1, 0 };
    check("Dependency calculation", !memcmp(dep, correct_dep, 4 * sizeof(uint64_t)));
    free(dep);

    {
        /* test merkle tree with zeros */
        hash_t zero1, zero2;
        memset(zero1.hash, 0, sizeof(zero1.hash));
        memset(zero2.hash, 0, sizeof(zero2.hash));
        int orders[] = { 0 };

        /* this should return zero */
        hash_t res1 = merkle_compute(zero1, &zero2, orders, 1);
        check("Merkle parent with zeros", is_zero(res1));

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
        check("Merkle parent", hash_equals(sha256(buf, 64), cd));

        hash_t a_comp[] = { b, cd };
        int a_orders[] = { 1, 1 };
        hash_t root1 = merkle_compute(a, a_comp, a_orders, 2);

        hash_t ab = merkle_parent(a, b, 0);
        hash_t root2 = merkle_parent(ab, cd, 0);
        //dump_hash(root1);
        //dump_hash(root2);
        check("Merkle compute", hash_equals(root1, root2));
    }

    {
    }
#endif
}
