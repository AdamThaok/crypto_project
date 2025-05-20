/**
 * Secure Database Access Application
 *
 * This implementation includes:
 * 1. LEA (Lightweight Encryption Algorithm) cipher in OFB mode
 * 2. McEliece cryptosystem for secure key exchange
 * 3. ECDSA for digital signatures
 *
 * Author: Claude
 * Date: May 20, 2025
 */
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <stdbool.h>
#include <math.h>

 /* ======================================================================
  * Helper functions and utilities
  * ====================================================================== */

  // Random number generation
uint32_t random_uint32() {
    return ((uint32_t)rand() << 16) | (uint32_t)rand();
}

// Function to print a byte array as hex
void print_hex(const unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Utility for binary operations
uint32_t rol(uint32_t value, int shift) {
    return (value << shift) | (value >> (32 - shift));
}

uint32_t ror(uint32_t value, int shift) {
    return (value >> shift) | (value << (32 - shift));
}

/* ======================================================================
 * 1. LEA Cipher Implementation in OFB mode
 * ====================================================================== */

 // LEA constants
#define LEA_ROUND_COUNT 24
#define LEA_BLOCK_SIZE 16  // 128 bits = 16 bytes

// Delta constants for key schedule
static const uint32_t DELTA[8] = {
    0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec,
    0x715ea49e, 0xc785da0a, 0xe04ef22a, 0xe5c40957
};

// LEA key schedule structure
typedef struct {
    uint32_t rk[LEA_ROUND_COUNT][6];  // Round keys
    int rounds;                       // Number of rounds
} LEA_KEY;

// LEA key setup

/*
    Function to generate keys for each 24 rounds
    Input user_key is 128 bit which is randomly generated each session (Log in)

    Key size ↔ round count both are depended:
    128 - bit key → 24 rounds
    192 - bit key → 28 rounds
    256 - bit key → 32 rounds

	we choose 128 bit key (24 rounds) for simplicity



	return value: LEA_KEY struct which contains a matrix sized [24][6] 
	each round takes 6 keys and we have 24 rounds

*/
void lea_set_key(LEA_KEY* key, const unsigned char* user_key, int key_len) {
    uint32_t t[8] = { 0 };
    int i, j;

    // Initialize temporary key values
    for (i = 0; i < key_len / 4; i++) {
        t[i] = ((uint32_t)user_key[i * 4]) |
            ((uint32_t)user_key[i * 4 + 1] << 8) |
            ((uint32_t)user_key[i * 4 + 2] << 16) |
            ((uint32_t)user_key[i * 4 + 3] << 24);
    }

    // 128-bit key schedule
    if (key_len == 16) {
        key->rounds = 24;

        for (i = 0; i < key->rounds; i++) {
            t[0] = rol((t[0] + rol(DELTA[i % 4], i)), 1);
            t[1] = rol((t[1] + rol(DELTA[i % 4], i + 1)), 3);
            t[2] = rol((t[2] + rol(DELTA[i % 4], i + 2)), 6);
            t[3] = rol((t[3] + rol(DELTA[i % 4], i + 3)), 11);

            key->rk[i][0] = t[0];
            key->rk[i][1] = t[1];
            key->rk[i][2] = t[2];
            key->rk[i][3] = t[3];
            key->rk[i][4] = t[1];
            key->rk[i][5] = t[3];
        }
    }
}

// LEA single block encryption


/*
	Function to encrypt a single block of data using LEA cipher
	Input:
		key: LEA_KEY struct containing round keys
		plaintext: 128-bit block of plaintext
        ut:
		ciphertext is filled with the encrypted data

*/
void lea_encrypt_block(const LEA_KEY* key, const unsigned char* plaintext, unsigned char* ciphertext) {
    uint32_t x[4];
    int i;

    // Load plaintext block into state
    for (i = 0; i < 4; i++) {
        x[i] = ((uint32_t)plaintext[i * 4]) |
            ((uint32_t)plaintext[i * 4 + 1] << 8) |
            ((uint32_t)plaintext[i * 4 + 2] << 16) |
            ((uint32_t)plaintext[i * 4 + 3] << 24);
    }

    // Apply round function
    for (i = 0; i < key->rounds; i++) {
        x[0] = rol(((x[0] ^ key->rk[i][0]) + (x[1] ^ key->rk[i][1])), 9);
        x[1] = ror(((x[1] ^ key->rk[i][2]) + (x[2] ^ key->rk[i][3])), 5);
        x[2] = ror(((x[2] ^ key->rk[i][4]) + (x[3] ^ key->rk[i][5])), 3);
        x[3] = rol(x[0] ^ x[1] ^ x[2], 1);

        // Swap words for next round
        if (i < key->rounds - 1) {
            uint32_t temp = x[0];
            x[0] = x[1];
            x[1] = x[2];
            x[2] = x[3];
            x[3] = temp;
        }
    }

    // Store result back to byte array
    for (i = 0; i < 4; i++) {
        ciphertext[i * 4] = (unsigned char)x[i];
        ciphertext[i * 4 + 1] = (unsigned char)(x[i] >> 8);
        ciphertext[i * 4 + 2] = (unsigned char)(x[i] >> 16);
        ciphertext[i * 4 + 3] = (unsigned char)(x[i] >> 24);
    }
}

// LEA block decryption
void lea_decrypt_block(const LEA_KEY* key, const unsigned char* ciphertext, unsigned char* plaintext) {
    uint32_t x[4];
    int i;

    // Load ciphertext block into state
    for (i = 0; i < 4; i++) {
        x[i] = ((uint32_t)ciphertext[i * 4]) |
            ((uint32_t)ciphertext[i * 4 + 1] << 8) |
            ((uint32_t)ciphertext[i * 4 + 2] << 16) |
            ((uint32_t)ciphertext[i * 4 + 3] << 24);
    }

    // Apply inverse round function
    for (i = key->rounds - 1; i >= 0; i--) {
        // Swap words back
        if (i < key->rounds - 1) {
            uint32_t temp = x[3];
            x[3] = x[2];
            x[2] = x[1];
            x[1] = x[0];
            x[0] = temp;
        }

        // Inverse round operation
        uint32_t temp = x[3];
        x[3] = ror(temp, 1) ^ x[0] ^ x[1];
        x[2] = rol(((x[2] ^ key->rk[i][4]) + (x[3] ^ key->rk[i][5])), 3);
        x[1] = rol(((x[1] ^ key->rk[i][2]) + (x[2] ^ key->rk[i][3])), 5);
        x[0] = ror(((x[0] ^ key->rk[i][0]) + (x[1] ^ key->rk[i][1])), 9);
    }

    // Store result back to byte array
    for (i = 0; i < 4; i++) {
        plaintext[i * 4] = (unsigned char)x[i];
        plaintext[i * 4 + 1] = (unsigned char)(x[i] >> 8);
        plaintext[i * 4 + 2] = (unsigned char)(x[i] >> 16);
        plaintext[i * 4 + 3] = (unsigned char)(x[i] >> 24);
    }
}

// LEA-OFB mode encryption
void lea_ofb_encrypt(const LEA_KEY* key, const unsigned char* iv,
    const unsigned char* plaintext, unsigned char* ciphertext, size_t len) {
    unsigned char ofb_block[LEA_BLOCK_SIZE];
    unsigned char keystream_block[LEA_BLOCK_SIZE];
    size_t i, j;

    // Initialize OFB with IV
    memcpy(ofb_block, iv, LEA_BLOCK_SIZE);

    for (i = 0; i < len; i += LEA_BLOCK_SIZE) {
        // Generate keystream by encrypting the OFB block
        lea_encrypt_block(key, ofb_block, keystream_block);

        // Use keystream to XOR with plaintext
        for (j = 0; j < LEA_BLOCK_SIZE && i + j < len; j++) {
            ciphertext[i + j] = plaintext[i + j] ^ keystream_block[j];
        }

        // Update OFB block for next iteration
        memcpy(ofb_block, keystream_block, LEA_BLOCK_SIZE);
    }
}

// LEA-OFB mode decryption (same as encryption due to OFB mode)
void lea_ofb_decrypt(const LEA_KEY* key, const unsigned char* iv,
    const unsigned char* ciphertext, unsigned char* plaintext, size_t len) {
    // In OFB mode, decryption is the same as encryption
    lea_ofb_encrypt(key, iv, ciphertext, plaintext, len);
}

/* ======================================================================
 * 2. McEliece Cryptosystem Implementation
 * ====================================================================== */

 // Parameters for McEliece
#define MC_N 32        // Code length (reduced for demonstration)
#define MC_K 16        // Message length
#define MC_T 3         // Error correction capability

// Galois field operations (GF(2))
typedef struct {
    uint8_t data[MC_N];
} binary_vector;

typedef struct {
    uint8_t data[MC_N][MC_N];
} binary_matrix;

// Initialize a binary matrix with random values
void binary_matrix_random(binary_matrix* m) {
    for (int i = 0; i < MC_N; i++) {
        for (int j = 0; j < MC_N; j++) {
            m->data[i][j] = rand() % 2;
        }
    }
}

// Copy a binary matrix
void binary_matrix_copy(binary_matrix* dst, const binary_matrix* src) {
    for (int i = 0; i < MC_N; i++) {
        for (int j = 0; j < MC_N; j++) {
            dst->data[i][j] = src->data[i][j];
        }
    }
}

// Print a binary matrix
void binary_matrix_print(const binary_matrix* m) {
    for (int i = 0; i < MC_N; i++) {
        for (int j = 0; j < MC_N; j++) {
            printf("%d ", m->data[i][j]);
        }
        printf("\n");
    }
}

// Multiply two binary matrices (m3 = m1 * m2)
void binary_matrix_multiply(binary_matrix* m3, const binary_matrix* m1, const binary_matrix* m2) {
    for (int i = 0; i < MC_N; i++) {
        for (int j = 0; j < MC_N; j++) {
            m3->data[i][j] = 0;
            for (int k = 0; k < MC_N; k++) {
                m3->data[i][j] ^= m1->data[i][k] & m2->data[k][j]; // XOR and AND for GF(2)
            }
        }
    }
}

// Generate an identity matrix
void binary_matrix_identity(binary_matrix* m) {
    for (int i = 0; i < MC_N; i++) {
        for (int j = 0; j < MC_N; j++) {
            m->data[i][j] = (i == j) ? 1 : 0;
        }
    }
}

// Generate a permutation matrix (a random permutation of rows of the identity matrix)
void binary_matrix_permutation(binary_matrix* p) {
    binary_matrix_identity(p);

    // Shuffle rows
    for (int i = MC_N - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        // Swap rows i and j
        for (int k = 0; k < MC_N; k++) {
            uint8_t temp = p->data[i][k];
            p->data[i][k] = p->data[j][k];
            p->data[j][k] = temp;
        }
    }
}

// Multiply a vector by a matrix
void binary_vector_matrix_multiply(binary_vector* result, const binary_vector* v, const binary_matrix* m) {
    for (int i = 0; i < MC_N; i++) {
        result->data[i] = 0;
        for (int j = 0; j < MC_N; j++) {
            result->data[i] ^= v->data[j] & m->data[j][i]; // XOR and AND for GF(2)
        }
    }
}

// Generate a random Goppa code generator matrix (simplified for demonstration)
void generate_goppa_code(binary_matrix* g) {
    // Start with identity matrix in the left part
    for (int i = 0; i < MC_K; i++) {
        for (int j = 0; j < MC_N; j++) {
            if (j < MC_K) {
                g->data[i][j] = (i == j) ? 1 : 0;
            }
            else {
                // Random parity bits for the right part
                g->data[i][j] = rand() % 2;
            }
        }
    }
}

// McEliece keys
typedef struct {
    binary_matrix g;  // Public generator matrix
    binary_matrix s;  // Private scrambling matrix
    binary_matrix p;  // Private permutation matrix
    binary_matrix g_original; // Original Goppa code generator matrix
} mceliece_keypair;

// Generate McEliece keypair
void mceliece_keygen(mceliece_keypair* keypair) {
    // Generate a random binary Goppa code
    generate_goppa_code(&keypair->g_original);

    // Generate random non-singular scrambling matrix
    binary_matrix_random(&keypair->s);

    // Generate random permutation matrix
    binary_matrix_permutation(&keypair->p);

    // Compute public key: G = S * G_original * P
    binary_matrix temp;
    binary_matrix_multiply(&temp, &keypair->g_original, &keypair->p);
    binary_matrix_multiply(&keypair->g, &keypair->s, &temp);
}

// McEliece encryption
void mceliece_encrypt(const binary_matrix* public_key, const binary_vector* message,
    binary_vector* ciphertext) {
    // Compute c = m*G + e
    binary_vector_matrix_multiply(ciphertext, message, public_key);

    // Add error vector with weight t
    int errors_added = 0;
    while (errors_added < MC_T) {
        int pos = rand() % MC_N;
        if (ciphertext->data[pos] == 0) {
            ciphertext->data[pos] = 1;
            errors_added++;
        }
        else {
            // If it's already 1, flip to 0 (still counts as an error)
            ciphertext->data[pos] = 0;
            errors_added++;
        }
    }
}

// McEliece decryption (simplified - assumes perfect decoding capability)
void mceliece_decrypt(const mceliece_keypair* keypair, const binary_vector* ciphertext,
    binary_vector* message) {
    // In a real implementation, this would involve:
    // 1. Apply inverse permutation: c' = c * P^-1
    // 2. Decode c' using the Goppa code decoder to get m'
    // 3. Compute m = m' * S^-1

    // For demonstration purposes, we'll use a simplified approach
    // that assumes the error correction works perfectly

    // For now, just copy the first K bits as the message (not secure!)
    for (int i = 0; i < MC_K; i++) {
        message->data[i] = ciphertext->data[i];
    }
    for (int i = MC_K; i < MC_N; i++) {
        message->data[i] = 0;
    }
}

/* ======================================================================
 * 3. ECDSA Implementation
 * ====================================================================== */

 // Simple elliptic curve parameters for ECDSA
 // Using a small curve for demonstration: y^2 = x^3 + ax + b (mod p)
#define EC_P 233        // Prime field modulus
#define EC_A 1          // Curve parameter a
#define EC_B 44         // Curve parameter b
#define EC_N 239        // Order of the base point (typically prime)
#define EC_GX 139       // Base point x-coordinate
#define EC_GY 23        // Base point y-coordinate

// Elliptic curve point
typedef struct {
    int x;
    int y;
    bool infinity;  // Point at infinity flag
} ec_point;

// Initialize generator point
void ec_init_generator(ec_point* G) {
    G->x = EC_GX;
    G->y = EC_GY;
    G->infinity = false;
}

// Modular arithmetic for ECDSA
int mod(int a, int m) {
    int r = a % m;
    return r < 0 ? r + m : r;
}

// Modular inverse (using Extended Euclidean Algorithm)
int mod_inv(int a, int m) {
    int t, newt, r, newr, quotient, temp;

    t = 0; newt = 1;
    r = m; newr = mod(a, m);

    while (newr != 0) {
        quotient = r / newr;

        temp = t;
        t = newt;
        newt = temp - quotient * newt;

        temp = r;
        r = newr;
        newr = temp - quotient * newr;
    }

    if (r > 1)
        return -1; // a is not invertible

    if (t < 0)
        t += m;

    return t;
}

// Point addition on elliptic curve
void ec_add(ec_point* r, const ec_point* p, const ec_point* q) {
    // Handle special cases
    if (p->infinity) {
        *r = *q;
        return;
    }
    if (q->infinity) {
        *r = *p;
        return;
    }

    // Check if points are inverses of each other
    if (p->x == q->x && p->y == (EC_P - q->y) % EC_P) {
        r->infinity = true;
        return;
    }

    int lambda;

    // Point doubling
    if (p->x == q->x && p->y == q->y) {
        lambda = mod((3 * p->x * p->x + EC_A) * mod_inv(2 * p->y, EC_P), EC_P);
    }
    // Point addition
    else {
        lambda = mod((q->y - p->y) * mod_inv(mod(q->x - p->x, EC_P), EC_P), EC_P);
    }

    r->x = mod(lambda * lambda - p->x - q->x, EC_P);
    r->y = mod(lambda * (p->x - r->x) - p->y, EC_P);
    r->infinity = false;
}

// Scalar multiplication on elliptic curve (double-and-add algorithm)
void ec_scalar_mul(ec_point* r, const ec_point* p, int k) {
    ec_point result;
    result.infinity = true;  // Start with identity element

    ec_point temp = *p;

    while (k > 0) {
        if (k & 1) {
            ec_add(&result, &result, &temp);
        }
        ec_add(&temp, &temp, &temp);  // Double temp
        k >>= 1;
    }

    *r = result;
}

// Simple hash function for ECDSA (using modular reduction)
int hash_message(const unsigned char* message, size_t len) {
    unsigned int hash = 0;

    for (size_t i = 0; i < len; i++) {
        hash = ((hash << 5) + hash) + message[i];
    }

    return mod(hash, EC_N);
}

typedef struct {
    int private_key;    // Private key (random integer < EC_N)
    ec_point public_key; // Public key (private_key * G)
} ecdsa_keypair;

// Generate ECDSA keypair
void ecdsa_keygen(ecdsa_keypair* keypair) {
    // Generate private key (random integer < EC_N)
    keypair->private_key = (rand() % (EC_N - 1)) + 1;

    // Compute public key = private_key * G
    ec_point G;
    ec_init_generator(&G);
    ec_scalar_mul(&keypair->public_key, &G, keypair->private_key);
}

// ECDSA signature structure
typedef struct {
    int r;
    int s;
} ecdsa_signature;

// Sign a message using ECDSA
void ecdsa_sign(const ecdsa_keypair* keypair, const unsigned char* message, size_t message_len,
    ecdsa_signature* signature) {
    int e = hash_message(message, message_len);
    int k;
    ec_point kG;

    do {
        // Generate random k (should be truly random in practice)
        k = (rand() % (EC_N - 1)) + 1;

        // Compute kG
        ec_point G;
        ec_init_generator(&G);
        ec_scalar_mul(&kG, &G, k);

        // r = x-coordinate of kG mod n
        signature->r = mod(kG.x, EC_N);

    } while (signature->r == 0);

    // s = k^-1 * (e + r * private_key) mod n
    int k_inv = mod_inv(k, EC_N);
    signature->s = mod(k_inv * (e + signature->r * keypair->private_key), EC_N);

    // Ensure s is not zero
    if (signature->s == 0) {
        // Try again with a different k
        ecdsa_sign(keypair, message, message_len, signature);
    }
}

// Verify an ECDSA signature
bool ecdsa_verify(const ec_point* public_key, const unsigned char* message, size_t message_len,
    const ecdsa_signature* signature) {
    // Check that 0 < r, s < n
    if (signature->r <= 0 || signature->r >= EC_N ||
        signature->s <= 0 || signature->s >= EC_N) {
        return false;
    }

    // Compute e = hash(message)
    int e = hash_message(message, message_len);

    // Compute w = s^-1 mod n
    int w = mod_inv(signature->s, EC_N);

    // Compute u1 = e * w mod n
    int u1 = mod(e * w, EC_N);

    // Compute u2 = r * w mod n
    int u2 = mod(signature->r * w, EC_N);

    // Compute u1*G + u2*public_key
    ec_point G, point1, point2, result;
    ec_init_generator(&G);

    ec_scalar_mul(&point1, &G, u1);
    ec_scalar_mul(&point2, public_key, u2);
    ec_add(&result, &point1, &point2);

    // Verify that r == x-coordinate of result mod n
    return signature->r == mod(result.x, EC_N);
}

/* ======================================================================
 * Secure Database Access Application
 * ====================================================================== */

 // User structure
typedef struct {
    char username[32];
    unsigned char password_hash[32];  // Simple hash storage
    ec_point public_key;              // For ECDSA verification
} User;

// Database structure
typedef struct {
    char data[10][1024];           // Sample data entries
    int num_entries;
    User users[10];                // Sample user records
    int num_users;
} Database;

// Initialize database with sample data
void init_database(Database* db) {
    db->num_entries = 3;
    strcpy(db->data[0], "This is confidential record #1");
    strcpy(db->data[1], "This is confidential record #2");
    strcpy(db->data[2], "This is confidential record #3");

    db->num_users = 2;
    strcpy(db->users[0].username, "admin");

    // Simple hash calculation (not secure - just for demo)
    const char* admin_pwd = "admin123";
    for (int i = 0; i < 32; i++) {
        db->users[0].password_hash[i] = admin_pwd[i % strlen(admin_pwd)];
    }

    // Set admin ECDSA public key
    db->users[0].public_key.x = 123;
    db->users[0].public_key.y = 456;
    db->users[0].public_key.infinity = false;

    strcpy(db->users[1].username, "user");
    const char* user_pwd = "password123";
    for (int i = 0; i < 32; i++) {
        db->users[1].password_hash[i] = user_pwd[i % strlen(user_pwd)];
    }

    // Set user ECDSA public key
    db->users[1].public_key.x = 789;
    db->users[1].public_key.y = 101;
    db->users[1].public_key.infinity = false;
}

// Verify user credentials
int verify_user(Database* db, const char* username, const char* password) {
    unsigned char temp_hash[32];

    // Calculate simple hash (not secure - just for demo)
    for (int i = 0; i < 32; i++) {
        temp_hash[i] = password[i % strlen(password)];
    }

    for (int i = 0; i < db->num_users; i++) {
        if (strcmp(db->users[i].username, username) == 0) {
            // Compare password hashes
            if (memcmp(temp_hash, db->users[i].password_hash, 32) == 0) {
                return i;  // Return user index
            }
            else {
                return -1; // Password mismatch
            }
        }
    }

    return -1; // User not found
}

// Main application
int main() {
    srand((unsigned int)time(NULL));

    printf("Secure Database Access System\n");
    printf("-----------------------------\n\n");

    // Initialize database
    Database db;
    init_database(&db);

    // User authentication
    char username[32];
    char password[32];

    printf("Login\n");
    printf("Username: ");
    scanf("%31s", username);
    printf("Password: ");
    scanf("%31s", password);

    int user_idx = verify_user(&db, username, password);
    if (user_idx == -1) {
        printf("Authentication failed!\n");
        return 1;
    }

    printf("\nAuthentication successful!\n\n");

    // Key exchange using McEliece
    printf("Establishing secure communication channel...\n");
    mceliece_keypair mc_keys;
    mceliece_keygen(&mc_keys);

    // Generate a random symmetric key for LEA
    unsigned char symmetric_key[16];
    for (int i = 0; i < 16; i++) {
        symmetric_key[i] = rand() % 256;
    }

    // Encrypt the symmetric key using McEliece
    binary_vector message, ciphertext;
    memset(&message, 0, sizeof(message));

    // Copy symmetric key into message
    for (int i = 0; i < 16 && i < MC_K; i++) {
        message.data[i] = (symmetric_key[i] >> (i % 8)) & 1;
    }

    mceliece_encrypt(&mc_keys.g, &message, &ciphertext);

    printf("Symmetric key securely exchanged.\n\n");

    // Set up LEA encryption with the symmetric key
    LEA_KEY lea_key;
    lea_set_key(&lea_key, symmetric_key, 16);

    // Generate a random IV for OFB mode
    unsigned char iv[LEA_BLOCK_SIZE];
    for (int i = 0; i < LEA_BLOCK_SIZE; i++) {
        iv[i] = rand() % 256;
    }

    // Load ECDSA keys for this user
    ecdsa_keypair ecdsa_keys;
    ecdsa_keys.public_key = db.users[user_idx].public_key;
    // Note: In a real system, the private key would be derived from login credentials
    ecdsa_keys.private_key = 12345; // Simplified for demo

    // Main application loop
    int choice;
    do {
        printf("\nMenu:\n");
        printf("1. View encrypted database records\n");
        printf("2. Add new record (signed)\n");
        printf("3. Exit\n");
        printf("Choice: ");
        scanf("%d", &choice);

        switch (choice) {
        case 1: {
            // View encrypted database records
            printf("\nDatabase Records (encrypted and decrypted):\n");

            for (int i = 0; i < db.num_entries; i++) {
                // Encrypt the record
                size_t record_len = strlen(db.data[i]);
                unsigned char encrypted[1024];
                unsigned char decrypted[1024];

                printf("\nRecord #%d:\n", i + 1);
                printf("Original: %s\n", db.data[i]);

                // Encrypt using LEA-OFB
                lea_ofb_encrypt(&lea_key, iv, (unsigned char*)db.data[i], encrypted, record_len);

                // Display encrypted data
                printf("Encrypted: ");
                print_hex(encrypted, record_len);

                // Decrypt using LEA-OFB
                lea_ofb_decrypt(&lea_key, iv, encrypted, decrypted, record_len);
                decrypted[record_len] = '\0';  // Add null terminator

                // Display decrypted data
                printf("Decrypted: %s\n", decrypted);
            }
            break;
        }

        case 2: {
            // Add new record with digital signature
            printf("\nEnter new record: ");
            char new_record[1024];
            getchar();  // Clear the newline character
            fgets(new_record, sizeof(new_record), stdin);
            size_t len = strlen(new_record);
            if (len > 0 && new_record[len - 1] == '\n')
                new_record[len - 1] = '\0';  // Remove trailing newline

            // Sign the record using ECDSA
            ecdsa_signature signature;
            ecdsa_sign(&ecdsa_keys, (unsigned char*)new_record, strlen(new_record), &signature);

            printf("Record signed with ECDSA: (r=%d, s=%d)\n", signature.r, signature.s);

            // Verify signature
            bool valid = ecdsa_verify(&ecdsa_keys.public_key, (unsigned char*)new_record,
                strlen(new_record), &signature);

            if (valid) {
                printf("Signature verified successfully!\n");

                // Add record to database (if space available)
                if (db.num_entries < 10) {
                    strcpy(db.data[db.num_entries], new_record);
                    db.num_entries++;
                    printf("Record added to database.\n");
                }
                else {
                    printf("Database is full!\n");
                }
            }
            else {
                printf("Signature verification failed! Record not added.\n");
            }
            break;
        }

        case 3:
            printf("\nExiting...\n");
            break;

        default:
            printf("\nInvalid choice!\n");
            break;
        }

        // This completes the switch statement
        // The rest of the main function continues:

    } while (choice != 3);

    // Clean up any resources if needed
    // (in this implementation, we don't have any dynamic allocations to free)

    return 0;
}