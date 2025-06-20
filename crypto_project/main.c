#define _CRT_SECURE_NO_WARNINGS
// ----- main.c -----
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>

#include "lea.h"
#include "mceliece.h"
#include "ecdsa.h"

#define MAX_RECORDS    10
#define MAX_ENTRY_LEN 1024

/* ----------------------------------------
   Simple in-memory Database definition
   ---------------------------------------- */
typedef struct {
    char data[MAX_RECORDS][MAX_ENTRY_LEN];
    int  num_entries;
} Database;

static bool simulate_mitm = false;  // toggle bit-flip before verify
static bool verbose = false;  // toggle verbose output

void print_hex(const unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}

void init_database(Database* db) {
    db->num_entries = 3;
    strcpy(db->data[0], "This is confidential record #1");
    strcpy(db->data[1], "This is confidential record #2");
    strcpy(db->data[2], "This is confidential record #3");
}

int verify_user(const char* u, const char* p) {
    (void)u; (void)p;
    return 0;  // stub: always succeed
}

void print_records(const Database* db) {
    printf("\nRecords (total %d):\n", db->num_entries);
    for (int i = 0; i < db->num_entries; i++) {
        printf("%2d: %s\n", i + 1, db->data[i]);
    }
}

void remove_record(Database* db) {
    if (db->num_entries == 0) {
        printf("No records to remove.\n");
        return;
    }
    int idx;
    print_records(db);
    printf("Enter record number to remove: ");
    if (scanf("%d", &idx) != 1 || idx < 1 || idx > db->num_entries) {
        printf("Invalid selection.\n");
        return;
    }
    for (int i = idx - 1; i < db->num_entries - 1; i++) {
        strcpy(db->data[i], db->data[i + 1]);
    }
    db->num_entries--;
    printf("Record removed.\n");
}

void add_record(Database* db, const ecdsa_keypair* ek) {
    if (db->num_entries >= MAX_RECORDS) {
        printf("Database full, cannot add more.\n");
        return;
    }

    char buf[MAX_ENTRY_LEN];
    printf("Enter new record: ");
    getchar();                  // consume leftover newline
    fgets(buf, sizeof(buf), stdin);
    if (strlen(buf) > 0 && buf[strlen(buf) - 1] == '\n')
        buf[strlen(buf) - 1] = '\0';
    size_t L = strlen(buf);

    // 1) Sign the record
    ecdsa_signature sig;
    ecdsa_sign(ek, (unsigned char*)buf, L, &sig);
    if (verbose) {
        printf("[VERBOSE] ECDSA Signature: r=%d, s=%d\n", sig.r, sig.s);
    }

    // 2) Simulate MITM: copy & maybe tamper
    char witness[MAX_ENTRY_LEN];
    memcpy(witness, buf, L + 1);
    if (simulate_mitm) {
        printf("[MITM] flipping first byte of the record...\n");
        witness[0] ^= 0xFF;
    }

    // 3) Verify using the original signed length
    bool ok = ecdsa_verify(&ek->public_key,
        (unsigned char*)witness,
        L,
        &sig);
    if (verbose) {
        printf("[VERBOSE] Verification result: %s\n", ok ? "PASS" : "FAIL");
    }
    if (!ok) {
        printf("Signature verification failed! Tamper detected, record rejected.\n");
        return;
    }

    // 4) Append original record
    strcpy(db->data[db->num_entries++], buf);
    printf("Record added and verified.\n");
}

void print_verbose_info(const unsigned char symm[16],
    const unsigned char iv[LEA_BLOCK_SIZE],
    const ecdsa_keypair* ek) {
    printf("[VERBOSE] Algorithms: McEliece (n=%d,k=%d,t=%d), LEA-OFB, ECDSA\n",
        MC_N, MC_K, MC_T);
    printf("[VERBOSE] Symmetric key (hex): "); print_hex(symm, 16);
    printf("[VERBOSE] IV (hex): ");              print_hex(iv, LEA_BLOCK_SIZE);
    printf("[VERBOSE] ECDSA public key: (x=%d, y=%d)\n",
        ek->public_key.x, ek->public_key.y);
}

int main(void) {
    srand((unsigned)time(NULL));

    Database db;
    init_database(&db);

    char user[32], pass[32];
    printf("Username: "); scanf("%31s", user);
    printf("Password: "); scanf("%31s", pass);
    if (verify_user(user, pass) < 0) {
        printf("Authentication failed!\n");
        return 1;
    }
    printf("Authentication successful!\n");

    // McEliece key-exchange handshake (stub)
    mceliece_keypair mc;
    mceliece_keygen(&mc);

    // Derive a stub symmetric key
    unsigned char symm[16];
    for (int i = 0; i < 16; i++) symm[i] = rand() & 0xFF;

    // LEA/OFB setup
    LEA_KEY lk;
    lea_set_key(&lk, symm, 16);
    unsigned char iv[LEA_BLOCK_SIZE];
    for (int i = 0; i < LEA_BLOCK_SIZE; i++) iv[i] = rand() & 0xFF;

    // ECDSA keypair for signing/verifying
    ecdsa_keypair ek;
    ecdsa_keygen(&ek);

    if (verbose) print_verbose_info(symm, iv, &ek);

    int choice;
    do {
        printf("\nMenu:\n");
        printf(" 1. View records\n");
        printf(" 2. Add record\n");
        printf(" 3. Remove record\n");
        printf(" 4. Toggle MITM (currently %s)\n", simulate_mitm ? "ON" : "OFF");
        printf(" 5. Toggle Verbose (currently %s)\n", verbose ? "ON" : "OFF");
        printf(" 6. Exit\n");
        printf("Choice: ");
        if (scanf("%d", &choice) != 1) break;
        switch (choice) {
        case 1: print_records(&db); break;
        case 2: add_record(&db, &ek); break;
        case 3: remove_record(&db); break;
        case 4:
            simulate_mitm = !simulate_mitm;
            printf("MITM simulation is now %s\n",
                simulate_mitm ? "ON" : "OFF");
            break;
        case 5:
            verbose = !verbose;
            printf("Verbose mode is now %s\n", verbose ? "ON" : "OFF");
            if (verbose) print_verbose_info(symm, iv, &ek);
            break;
        case 6:
            printf("Goodbye!\n");
            break;
        default:
            printf("Invalid option.\n");
        }
    } while (choice != 6);

    return 0;
}
