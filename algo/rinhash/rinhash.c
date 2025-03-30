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


__thread rin_context_holder* rin_ctx;

// RinHash implementation
void rinhash(void* state, const void* input)
{
    if (rin_ctx == NULL) {
        rin_ctx = (rin_context_holder*) _aligned_malloc(sizeof(rin_context_holder), 64);
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

// Scanhash implementation 
int scanhash_rin( struct work *work, uint32_t max_nonce,
                  uint64_t *hashes_done, struct thr_info *mythr )
{
    uint32_t _ALIGN(128) hash[8];
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;
    const uint32_t first_nonce = pdata[19];
    const uint32_t Htarg = ptarget[7];
    uint32_t nonce = first_nonce;

    do {
        pdata[19] = nonce;
        rinhash(hash, pdata);
        if (fulltest((uint8_t*)hash, (uint8_t*)ptarget)) {
            *hashes_done = nonce - first_nonce + 1;
            pdata[19] = nonce;
            return 1;
        }
        nonce++;
    } while (nonce < max_nonce && !work_restart[mythr->id].restart);

    *hashes_done = nonce - first_nonce + 1;
    pdata[19] = nonce;
    return 0;
}

// Register algorithm
bool register_rin_algo( algo_gate_t* gate )
{
    gate->scanhash = (void*)&scanhash_rin;
    gate->hash = (void*)&rinhash;
    gate->optimizations = SSE2_OPT | AVX2_OPT | AVX512_OPT;
    return true;
}