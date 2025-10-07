// blockchain_sim.c
// Simple blockchain transaction simulator in C
// Compile: gcc -std=c11 -O2 -o blockchain_sim blockchain_sim.c
// Run: ./blockchain_sim

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#define MAX_TX_PER_BLOCK 10
#define MAX_PENDING_TX 100
#define HASH_STR_LEN 65   // 64 hex chars + null
#define MAX_NAME_LEN 32

typedef struct {
    char from[MAX_NAME_LEN];
    char to[MAX_NAME_LEN];
    double amount;
} Transaction;

typedef struct Block {
    int index;
    time_t timestamp;
    Transaction txs[MAX_TX_PER_BLOCK];
    int tx_count;
    char prev_hash[HASH_STR_LEN];
    char hash[HASH_STR_LEN];
    unsigned long nonce;
    struct Block *next;
} Block;

typedef struct {
    Block *head;
    Block *tail;
    int length;
} Blockchain;

/* ------------------ Simple deterministic hash (djb2 -> hex) ------------------
   This is NOT cryptographic SHA-256. It's a simple, deterministic hash to
   visualize the blockchain educationally.
----------------------------------------------------------------------------- */
void djb2_hash_hex(const char *str, unsigned long nonce, char out[HASH_STR_LEN]) {
    unsigned long hash = 5381;
    for (const unsigned char *p = (const unsigned char*)str; *p; ++p) {
        hash = ((hash << 5) + hash) + *p; /* hash * 33 + c */
    }
    // mix nonce into hash
    hash = ((hash << 5) + hash) + (nonce & 0xFF);
    // create hex string from hash (repeat to fill 64 hex chars)
    char buffer[HASH_STR_LEN];
    char temp[17];
    // produce repeating pattern from hash to fill 64 hex chars
    for (int i = 0; i < 4; ++i) {
        unsigned long v = hash ^ (hash << (i*7));
        snprintf(temp, sizeof(temp), "%08lx", v);
        strcat(buffer, temp);
    }
    // ensure buffer constructed properly (first usage)
    if (strlen(buffer) == 0) {
        snprintf(buffer, sizeof(buffer), "%08lx%08lx%08lx%08lx",
                 hash, hash ^ 0xabcdef, hash << 3, hash >> 2);
    }
    // copy first 64 chars
    buffer[64] = '\0';
    strncpy(out, buffer, HASH_STR_LEN);
    out[HASH_STR_LEN-1] = '\0';
}

/* ------------------ Utility ------------------ */
void timestamp_to_str(time_t t, char *buf, size_t n) {
    struct tm *tm_info = localtime(&t);
    strftime(buf, n, "%Y-%m-%d %H:%M:%S", tm_info);
}

/* ------------------ Blockchain operations ------------------ */

Blockchain *create_blockchain() {
    Blockchain *bc = malloc(sizeof(Blockchain));
    if (!bc) exit(1);
    bc->head = bc->tail = NULL;
    bc->length = 0;
    return bc;
}

Block *create_block(int index, const char prev_hash[HASH_STR_LEN]) {
    Block *b = malloc(sizeof(Block));
    if (!b) exit(1);
    b->index = index;
    b->timestamp = time(NULL);
    b->tx_count = 0;
    b->nonce = 0;
    b->next = NULL;
    strncpy(b->prev_hash, prev_hash ? prev_hash : "0", HASH_STR_LEN);
    b->hash[0] = '\0';
    return b;
}

void append_block(Blockchain *bc, Block *block) {
    if (!bc->head) {
        bc->head = bc->tail = block;
    } else {
        bc->tail->next = block;
        bc->tail = block;
    }
    bc->length++;
}

/* Build a block content string to hash */
void block_content_string(Block *b, char *out, size_t n) {
    char buf[1024];
    char timebuf[64];
    timestamp_to_str(b->timestamp, timebuf, sizeof(timebuf));
    snprintf(out, n, "%d|%s|%s|", b->index, timebuf, b->prev_hash);
    for (int i = 0; i < b->tx_count; ++i) {
        snprintf(buf, sizeof(buf), "%s->%s:%.2f|",
                 b->txs[i].from, b->txs[i].to, b->txs[i].amount);
        strncat(out, buf, n - strlen(out) - 1);
    }
}

/* Compute hash for block using content and nonce */
void compute_block_hash(Block *b, char out[HASH_STR_LEN]) {
    char content[2048] = {0};
    block_content_string(b, content, sizeof(content));
    // include nonce in the hash by appending it
    char content_with_nonce[2200];
    snprintf(content_with_nonce, sizeof(content_with_nonce), "%s|%lu", content, b->nonce);
    // compute simple djb2-based hex hash
    // clear buffer used by djb2_hash_hex
    char tempbuf[HASH_STR_LEN] = {0};
    djb2_hash_hex(content_with_nonce, b->nonce, tempbuf);
    // copy (ensure null-terminated)
    strncpy(out, tempbuf, HASH_STR_LEN);
    out[HASH_STR_LEN-1] = '\0';
}

/* Mine block for difficulty: number of leading '0' hex characters */
int mine_block(Block *b, int difficulty, int max_iterations) {
    if (difficulty <= 0) {
        compute_block_hash(b, b->hash);
        return 1;
    }
    char target_prefix[65];
    for (int i = 0; i < difficulty; ++i) target_prefix[i] = '0';
    target_prefix[difficulty] = '\0';

    // try nonces until hash starts with target_prefix
    for (int iter = 0; iter < max_iterations; ++iter) {
        compute_block_hash(b, b->hash);
        if (strncmp(b->hash, target_prefix, difficulty) == 0) {
            return 1; // found
        }
        b->nonce++;
    }
    // not found within iteration limit
    return 0;
}

/* Create genesis block */
void create_genesis(Blockchain *bc) {
    Block *g = create_block(0, "0");
    // put a dummy tx
    Transaction t = {"network", "genesis", 0.0};
    g->txs[g->tx_count++] = t;
    compute_block_hash(g, g->hash);
    append_block(bc, g);
}

/* Validate chain: recompute hashes and verify prev_hash links */
int validate_chain(Blockchain *bc) {
    Block *cur = bc->head;
    if (!cur) return 0;
    while (cur) {
        // recompute hash from content and stored nonce and compare
        char recomputed[HASH_STR_LEN];
        compute_block_hash(cur, recomputed);
        if (strcmp(recomputed, cur->hash) != 0) {
            printf("Invalid hash at block %d\n", cur->index);
            return 0;
        }
        if (cur->next) {
            if (strcmp(cur->next->prev_hash, cur->hash) != 0) {
                printf("Invalid prev_hash linkage between %d and %d\n", cur->index, cur->next->index);
                return 0;
            }
        }
        cur = cur->next;
    }
    return 1;
}

/* ------------------ Pending transactions pool ------------------ */
Transaction pending_pool[MAX_PENDING_TX];
int pending_count = 0;

int add_transaction_to_pool(const char *from, const char *to, double amount) {
    if (pending_count >= MAX_PENDING_TX) return 0;
    Transaction t;
    strncpy(t.from, from, MAX_NAME_LEN-1); t.from[MAX_NAME_LEN-1] = '\0';
    strncpy(t.to, to, MAX_NAME_LEN-1); t.to[MAX_NAME_LEN-1] = '\0';
    t.amount = amount;
    pending_pool[pending_count++] = t;
    return 1;
}

/* Create block from pending transactions (up to MAX_TX_PER_BLOCK) */
Block *create_block_from_pending(Blockchain *bc) {
    if (pending_count == 0) return NULL;
    char prev_hash[HASH_STR_LEN] = "0";
    int index = 0;
    if (bc->tail) {
        strncpy(prev_hash, bc->tail->hash, HASH_STR_LEN);
        index = bc->tail->index + 1;
    }
    Block *b = create_block(index, prev_hash);
    int to_take = pending_count < MAX_TX_PER_BLOCK ? pending_count : MAX_TX_PER_BLOCK;
    for (int i = 0; i < to_take; ++i) {
        b->txs[b->tx_count++] = pending_pool[i];
    }
    // shift remaining pending transactions
    for (int i = to_take; i < pending_count; ++i) {
        pending_pool[i - to_take] = pending_pool[i];
    }
    pending_count -= to_take;
    return b;
}

/* Print chain */
void print_chain(Blockchain *bc) {
    printf("\n===== Blockchain (len=%d) =====\n", bc->length);
    Block *cur = bc->head;
    while (cur) {
        char timebuf[64];
        timestamp_to_str(cur->timestamp, timebuf, sizeof(timebuf));
        printf("Block %d | time: %s | nonce: %lu\n", cur->index, timebuf, cur->nonce);
        printf("  prev: %.12s... | hash: %.12s...\n", cur->prev_hash, cur->hash);
        printf("  txs (%d):\n", cur->tx_count);
        for (int i = 0; i < cur->tx_count; ++i) {
            printf("    - %s -> %s : %.2f\n", cur->txs[i].from, cur->txs[i].to, cur->txs[i].amount);
        }
        printf("\n");
        cur = cur->next;
    }
}

/* ------------------ Simple interactive UI ------------------ */

void print_menu() {
    printf("\nCommands:\n");
    printf(" 1) addtx  - add a transaction\n");
    printf(" 2) mine   - create & mine a block from pending txs\n");
    printf(" 3) show   - display blockchain\n");
    printf(" 4) pending- show pending txs\n");
    printf(" 5) validate - validate the chain\n");
    printf(" 6) quit\n");
}

void show_pending() {
    printf("\nPending transactions (%d):\n", pending_count);
    for (int i = 0; i < pending_count; ++i) {
        printf("  %d) %s -> %s : %.2f\n", i+1,
               pending_pool[i].from, pending_pool[i].to, pending_pool[i].amount);
    }
}

/* small helper to eat newline */
void eatline() { int c; while ((c = getchar()) != '\n' && c != EOF); }

int main() {
    srand((unsigned int)time(NULL));
    Blockchain *bc = create_blockchain();
    create_genesis(bc);

    printf("Simple Blockchain Simulator (console)\n");
    printf("Genesis block created.\n");

    int difficulty = 2; // number of leading hex zeros required (tweak)
    int max_mine_iters = 2000000; // safety

    while (1) {
        print_menu();
        printf("\nEnter command: \n");
        char cmd[32];
        if (!fgets(cmd, sizeof(cmd), stdin)) break;
        // trim newline and spaces
        for (char *p = cmd; *p; ++p) if (*p == '\n') *p = '\0';
        if (strlen(cmd) == 0) continue;

        if (strcasecmp(cmd, "addtx") == 0 || strcmp(cmd, "1") == 0) {
            char from[MAX_NAME_LEN], to[MAX_NAME_LEN];
            double amount;
            printf("From: ");
            if (!fgets(from, sizeof(from), stdin)) break;
            from[strcspn(from, "\n")] = '\0';
            printf("To: ");
            if (!fgets(to, sizeof(to), stdin)) break;
            to[strcspn(to, "\n")] = '\0';
            printf("Amount: ");
            if (scanf("%lf", &amount) != 1) { eatline(); printf("Invalid amount.\n"); continue; }
            eatline();
            if (add_transaction_to_pool(from, to, amount)) {
                printf("Transaction added to pending pool.\n");
            } else {
                printf("Pending pool full!\n");
            }
        } else if (strcasecmp(cmd, "mine") == 0 || strcmp(cmd, "2") == 0) {
            Block *b = create_block_from_pending(bc);
            if (!b) {
                printf("No pending transactions to mine.\n");
                continue;
            }
            printf("Mining block with %d tx(s) ... difficulty=%d\n", b->tx_count, difficulty);
            clock_t t0 = clock();
            int ok = mine_block(b, difficulty, max_mine_iters);
            clock_t t1 = clock();
            double secs = (double)(t1 - t0) / CLOCKS_PER_SEC;
            if (!ok) {
                printf("Mining failed (iteration limit reached). Block not appended.\n");
                free(b);
            } else {
                // set prev_hash to tail hash to be safe (tail may have changed)
                if (bc->tail) strncpy(b->prev_hash, bc->tail->hash, HASH_STR_LEN);
                // recompute hash fully with correct prev_hash (nonce already found)
                compute_block_hash(b, b->hash);
                append_block(bc, b);
                printf("Block mined & appended! nonce=%lu hash=%.12s... time=%.3fs\n", b->nonce, b->hash, secs);
            }
        } else if (strcasecmp(cmd, "show") == 0 || strcmp(cmd, "3") == 0) {
            print_chain(bc);
        } else if (strcasecmp(cmd, "pending") == 0 || strcmp(cmd, "4") == 0) {
            show_pending();
        } else if (strcasecmp(cmd, "validate") == 0 || strcmp(cmd, "5") == 0) {
            printf("Validating chain...\n");
            int v = validate_chain(bc);
            if (v) printf("Chain valid ✅\n");
            else printf("Chain INVALID ❌\n");
        } else if (strcasecmp(cmd, "quit") == 0 || strcmp(cmd, "6") == 0) {
            printf("Exiting.\n");
            break;
        } else {
            printf("Unknown command: '%s'\n", cmd);
        }
    }

    // free blocks
    Block *cur = bc->head;
    while (cur) {
        Block *n = cur->next;
        free(cur);
        cur = n;
    }
    free(bc);
    return 0;
}
