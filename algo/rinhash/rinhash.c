#include "rinhash-gate.h"
#include "miner.h"
#include "algo-gate-api.h"
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <malloc.h>  // _aligned_malloc, _aligned_free
#include "blake3/blake3.h"
#include "blake3/blake3_impl.h"
#include "sha3/SimpleFIPS202.h"
#include "../argon2d/argon2d/argon2.h"  // Update path to argon2d header

typedef struct {
    blake3_hasher blake;
    argon2_context argon;
} rin_context_holder;


#ifdef _WIN32
    #include <malloc.h>
    #define aligned_malloc _aligned_malloc
    #define aligned_free   _aligned_free
#else
void* aligned_malloc(size_t size, size_t alignment) {
    void* ptr = NULL;
    if (posix_memalign(&ptr, alignment, size) != 0) return NULL;
    return ptr;
}

void aligned_free(void* ptr) {
    free(ptr);
}
#endif

__thread rin_context_holder* rin_ctx;

// RinHash implementation
void rinhash(void* state, const void* input)
{
    if (rin_ctx == NULL) {
        rin_ctx = (rin_context_holder*) aligned_malloc(sizeof(rin_context_holder), 64);
        if (!rin_ctx) {
            fprintf(stderr, "Failed to allocate rin_ctx\n");
            memset(state, 0, 32);
            return;
        }
    }
    uint8_t blake3_out[32];
    blake3_hasher_init(&rin_ctx->blake);
    blake3_hasher_update(&rin_ctx->blake, input, 80); // Block header size
    blake3_hasher_finalize(&rin_ctx->blake, blake3_out, 32);

    // Argon2d parameters
    const char* salt_str = "RinCoinSalt";
    uint8_t argon2_out[32];
    argon2_context context = {0};
    context.out = argon2_out;
    context.outlen = 32;
    context.pwd = blake3_out;
    context.pwdlen = 32;
    context.salt = (uint8_t*)salt_str;
    context.saltlen = strlen(salt_str);
    context.t_cost = 2;
    context.m_cost = 64;
    context.lanes = 1;
    context.threads = 1;
    context.version = ARGON2_VERSION_13;
    context.allocate_cbk = NULL;
    context.free_cbk = NULL;
    context.flags = ARGON2_DEFAULT_FLAGS;

    if (argon2d_ctx(&context) != ARGON2_OK) {
        fprintf(stderr, "Argon2d failed!\n");
        memset(state, 0, 32);
        return;
    }
    
    // SHA3-256
    uint8_t sha3_out[32];
    SHA3_256(sha3_out, (const uint8_t *)argon2_out, 32);
    
    memcpy(state, sha3_out, 32);
}

// 32バイトをワード単位で逆順に並び替える関数
void reverse_words(uint8_t* out, const uint8_t* in) {
    for (int i = 0; i < 8; i++) {
        memcpy(out + (i * 4), in + ((7 - i) * 4), 4);
    }
}

int scanhash_rinhash(struct work *work, uint32_t max_nonce,
    uint64_t *hashes_done, struct thr_info *mythr)
{
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;
    uint32_t n = pdata[19] - 1;
    const uint32_t first_nonce = pdata[19];
    int thr_id = mythr->id;
    uint8_t hash[32];
    uint8_t hash_reversed[32];  // 逆順にするためのバッファを追加

    do {
        n++;
        pdata[19] = n;

        rinhash(hash, pdata);

        reverse_words(hash_reversed, hash);  // ←ここで逆順にする必要がある

        if (fulltest(hash_reversed, ptarget)) {  // hash_reversed を使って比較する
            pdata[19] = n;
            submit_solution(work, hash_reversed, mythr);
        }
    } while (n < max_nonce && !work_restart[thr_id].restart);

    pdata[19] = n;
    *hashes_done = n - first_nonce + 1;
    return 0;
}


// Register algorithm
bool register_rin_algo( algo_gate_t* gate )
{
    gate->scanhash = (void*)&scanhash_rinhash;
    gate->hash = (void*)&rinhash;
    gate->optimizations = SSE2_OPT | AVX2_OPT | AVX512_OPT;
    return true;
}