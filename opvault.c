// https://support.1password.com/opvault-design

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/conf.h>

#include "cJSON.h"

#define JSONVAR(typ, var, jstyp, json, name) typ var; { \
    cJSON *item = cJSON_GetObjectItem(json, name); \
    if (!item) { \
        fprintf(stderr, "No " name " field in profile.\n"); \
        return 0; \
    } \
    var = (typ) item->value##jstyp; \
}

static cJSON *load_json(const char *fname)
{
    cJSON *retval = NULL;
    FILE *io = fopen(fname, "rb");

    if (io != NULL) {
        if (fseek(io, 0, SEEK_END) == 0) {
            long len = ftell(io);
            if ((len != -1) && (fseek(io, 0, SEEK_SET) == 0)) {
                char *buf = (char *) malloc(len + 1);
                if ((buf != NULL) && (fread(buf, len, 1, io) == 1)) {
                    char *json = buf;
                    json[len] = '\0';

                    // !!! FIXME: hack.
                    if (strncmp(json, "ld(", 3) == 0) {
                        json[len-2] = '\0';  // chop off ");" from end.
                        json += 3;  // skip past "ld(".
                        len -= 5;
                    } else if (strncmp(json, "loadFolders(", 12) == 0) {
                        json[len-2] = '\0';  // chop off ");" from end.
                        json += 12;  // skip past "loadFolders(".
                        len -= 14;
                    } else if (strncmp(json, "var profile=", 12) == 0) {
                        json[len-1] = '\0';  // chop off ";" from end.
                        json += 12;  // skip past "var profile=".
                        len -= 13;
                    }

                    retval = cJSON_Parse(json);
                }
                free(buf);
            }
        }
        fclose(io);
    }

    return retval;
}

static void dump_json_internal(const cJSON *json, const int indent)
{
    const cJSON *i;
    int j;

    if (!json) return;

    for (j = 0; j < (indent*2); j++) {
        printf(" ");
    }

    if (json->string != NULL) {
        printf("%s : ", json->string);
    }

    switch (json->type) {
        default: printf("[!unknown type!]"); break;
        case cJSON_Invalid: printf("[!invalid!]"); break;
        case cJSON_False: printf("false"); break;
        case cJSON_True: printf("true"); break;
        case cJSON_NULL: printf("null"); break;
        case cJSON_Number: printf("%f", json->valuedouble); break;
        case cJSON_Raw: printf("!CDATA[\"%s\"]", json->valuestring); break;
        case cJSON_String: printf("\"%s\"", json->valuestring); break;

        case cJSON_Array:
            printf("[\n");
            for (i = json->child; i != NULL; i = i->next) {
                dump_json_internal(i, indent + 1);
                if (i->next != NULL) {
                    printf(", ");
                }
                printf("\n");
            }
            for (j = 0; j < (indent*2); j++) {
                printf(" ");
            }
            printf("]");
            break;

        case cJSON_Object:
            printf("{\n");
            for (i = json->child; i != NULL; i = i->next) {
                dump_json_internal(i, indent + 1);
                if (i->next != NULL) {
                    printf(", ");
                }
                printf("\n");
            }
            for (j = 0; j < (indent*2); j++) {
                printf(" ");
            }
            printf("}");
            break;
    }
}

static void dump_json(const cJSON *json)
{
    dump_json_internal(json, 0);
    printf("\n");
}


static int base64_decode(const char *in, const int inlen, uint8_t **out)
{
    const int len = (inlen == -1) ? (int) strlen(in) : inlen;

    *out = NULL;

    BIO *b64f = BIO_new(BIO_f_base64());
    BIO *buff = buff = BIO_push(b64f, BIO_new_mem_buf(in, len));

    uint8_t *decoded = (uint8_t *) malloc(len);
    if (!decoded) {
        fprintf(stderr, "Out of memory!\n");
        return -1;
    }

    BIO_set_flags(buff, BIO_FLAGS_BASE64_NO_NL);
    BIO_set_close(buff, BIO_CLOSE);
    const int retval = BIO_read(buff, decoded, len);
    if (retval < 0) {
        free(decoded);
        return -1;
    }
    decoded[retval] = '\0';

    BIO_free_all(buff);

    *out = decoded;
    return retval;
}

static int decrypt_opdata(const char *name, const uint8_t *opdata, const int opdatalen, const uint8_t *encryptionkey, const uint8_t *mackey, uint8_t **out, int *outlen)
{
    *out = NULL;
    if (outlen) {
        *outlen = 0;
    }

    if ((opdatalen < 64) || (memcmp(opdata, "opdata01", 8) != 0)) {
        fprintf(stderr, "opdata(%s) isn't actually in opdata01 format.\n", name);
        return 0;
    }

    // !!! FIXME: byteswap
    const int plaintextlen = (int) (*((uint64_t *) (opdata + 8)));
    const int paddedplaintextlen = plaintextlen + (16 - (plaintextlen % 16));
    if (paddedplaintextlen > (opdatalen - (8 + 8 + 16 + 32))) {  // minus magic, len, iv, hmac
        fprintf(stderr, "opdata(%s) plaintext length is bogus.\n", name);
        return 0;
    }

    uint8_t digest[32];
    unsigned int digestlen = sizeof (digest);
    if (!HMAC(EVP_sha256(), mackey, 32, opdata, opdatalen-32, (unsigned char *) digest, &digestlen)) {
        fprintf(stderr, "opdata(%s) HMAC failed.\n", name);
        return 0;
    } else if (digestlen != sizeof (digest)) {
        fprintf(stderr, "opdata(%s) HMAC is wrong size (got=%u expected=%u).\n", name, digestlen, (unsigned int) sizeof (digest));
        return 0;
    } else if (memcmp(digest, opdata + (opdatalen-sizeof (digest)), sizeof (digest)) != 0) {
        fprintf(stderr, "opdata(%s) HMAC verification failed.\n", name);
        return 0;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "opdata(%s) EVP_CIPHER_CTX_new() failed\n", name);
        return 0;
    }

    const unsigned char *iv = (unsigned char *) (opdata + 16);
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (const unsigned char *) encryptionkey, iv)) {
        fprintf(stderr, "opdata(%s) EVP_DecryptInit_ex() failed\n", name);
        EVP_CIPHER_CTX_cleanup(ctx);
        return 0;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    uint8_t *plaintext = (uint8_t *) malloc(paddedplaintextlen);
    if (!plaintext) {
        fprintf(stderr, "opdata(%s) Out of memory.\n", name);
        EVP_CIPHER_CTX_cleanup(ctx);
        return 0;
    }

    // opdata+32 == first byte past magic, len, and iv.
    int decryptedlen = 0;
    if (!EVP_DecryptUpdate(ctx, plaintext, &decryptedlen, opdata + 32, paddedplaintextlen)) {
        fprintf(stderr, "opdata(%s) EVP_DecryptUpdate() failed\n", name);
        free(plaintext);
        EVP_CIPHER_CTX_cleanup(ctx);
        return 0;
    }

    int totaldecryptedlen = decryptedlen;
    if (!EVP_DecryptFinal_ex(ctx, plaintext + decryptedlen, &decryptedlen)) {
        fprintf(stderr, "opdata(%s) EVP_DecryptFinal_ex() failed\n", name);
        free(plaintext);
        EVP_CIPHER_CTX_cleanup(ctx);
        return 0;
    }
    totaldecryptedlen += decryptedlen;

    EVP_CIPHER_CTX_cleanup(ctx);

    if (totaldecryptedlen != paddedplaintextlen) {
        fprintf(stderr, "opdata(%s) decrypted to wrong size (got=%d expected=%u).\n", name, totaldecryptedlen, (unsigned int) paddedplaintextlen);
        free(plaintext);
        return 0;
    }

    // random padding bytes are prepended. Drop them.
    const int paddinglen = paddedplaintextlen - plaintextlen;
    memmove(plaintext, plaintext + paddinglen, plaintextlen);

    *out = plaintext;
    if (outlen) {
        *outlen = plaintextlen;
    }

    return 1;
}

static int decrypt_opdata_base64(const char *name, const char *base64data, const uint8_t *encryptionkey, const uint8_t *mackey, uint8_t **out, int *outlen)
{
    uint8_t *opdata = NULL;
    const int opdatalen = base64_decode(base64data, -1, &opdata);
    if (opdatalen == -1) {
        fprintf(stderr, "opdata(%s) wasn't a valid base64 string\n", name);
        return 0;
    }

    const int retval = decrypt_opdata(name, opdata, opdatalen, encryptionkey, mackey, out, outlen);
    free(opdata);
    return retval;
}

static int decrypt_key(const char *name, const char *base64data, const uint8_t *encryptionkey, const uint8_t *mackey, uint8_t *finalkey, uint8_t *finalhmac)
{
    uint8_t *decryptedkey = NULL;
    int decryptedkeylen = 0;
    if (!decrypt_opdata_base64(name, base64data, encryptionkey, mackey, &decryptedkey, &decryptedkeylen)) {
        return 0;
    }

    uint8_t digest[64];
    unsigned int digestlen = sizeof (digest);
    const int rc = EVP_Digest(decryptedkey, decryptedkeylen, (unsigned char *) digest, &digestlen, EVP_sha512(), NULL);
    free(decryptedkey);
    if (!rc) {
        fprintf(stderr, "Hashing %s failed.\n", name);
        return 0;
    } else if (digestlen != sizeof (digest)) {
        fprintf(stderr, "Hash for %s is wrong size (got=%u expected=%u).\n", name, digestlen, (unsigned int) sizeof (digest));
        return 0;
    }

    memcpy(finalkey, digest, 32);
    memcpy(finalhmac, digest + 32, 32);
    return 1;
}

static int derive_keys_from_password(const char *password, const char *base64salt, const int iterations, uint8_t *encryptionkey, uint8_t *mackey)
{
    uint8_t salt[16];
    uint8_t *buf = NULL;
    int saltlen = base64_decode(base64salt, -1, &buf);
    if (saltlen == -1) {
        fprintf(stderr, "Salt wasn't a valid base64 string.\n");
        return 0;
    } else if (saltlen != 16) {
        fprintf(stderr, "Expected salt to base64-decode to 16 bytes (it was %lu).\n", (unsigned long) saltlen);
        free(buf);
        return 0;
    }
    memcpy(salt, buf, saltlen);
    free(buf);

    uint8_t derived[64];
    if (!PKCS5_PBKDF2_HMAC(password, -1,
            (const unsigned char *) salt, saltlen, iterations,
            EVP_sha512(), sizeof (derived), (unsigned char *) derived)) {
        fprintf(stderr, "Key derivation failed.\n");
        return 0;
    }

    // first half of the derived key is the encryption key, second half is MAC key.
    memcpy(encryptionkey, derived, 32);
    memcpy(mackey, derived + 32, 32);
    return 1;
}

static int prepare_keys(cJSON *profile, const char *password,
                        uint8_t *masterkey, uint8_t *masterhmac,
                        uint8_t *overviewkey, uint8_t *overviewhmac)
{
    JSONVAR(const char *, base64salt, string, profile, "salt");
    JSONVAR(const char *, base64masterkey, string, profile, "masterKey");
    JSONVAR(const char *, base64overviewkey, string, profile, "overviewKey");
    JSONVAR(int, iterations, double, profile, "iterations");

    uint8_t encryptionkey[32];
    uint8_t mackey[32];
    if (!derive_keys_from_password(password, base64salt, iterations, encryptionkey, mackey)) {
        return 0;
    } else if (!decrypt_key("master key", base64masterkey, encryptionkey, mackey, masterkey, masterhmac)) {
        return 0;
    } else if (!decrypt_key("overview key", base64overviewkey, encryptionkey, mackey, overviewkey, overviewhmac)) {
        return 0;
    }

    return 1;
}

static void dump_folders(const uint8_t *overviewkey, const uint8_t *overviewhmac)
{
    cJSON *folders = load_json("folders.js");
    cJSON *i;

    if (!folders || !folders->child) {
        printf("(no folders.)\n");
        return;
    }

    printf("\nFolders...\n");
    for (i = folders->child; i != NULL; i = i->next) {
        char *encrypted = NULL;
        uint8_t *decrypted = NULL;
        cJSON *overview = cJSON_GetObjectItem(i, "overview");
        if (overview) {
            encrypted = overview->valuestring;
            int decryptedlen = 0;
            if (decrypt_opdata_base64("overview", encrypted, overviewkey, overviewhmac, &decrypted, &decryptedlen)) {
                decrypted[decryptedlen] = 0;
                overview->valuestring = (char *) decrypted;
            }
        }

        dump_json(i);
        printf("\n");

        if (overview) {
            overview->valuestring = encrypted; // put this back for cleanup.
        }
        free(decrypted);
    }

    printf("\n");

    cJSON_Delete(folders);
}

typedef struct CategoryMap
{
    const char *name;
    const char *idstr;
} CategoryMap;

static const CategoryMap category_map[] = {
    { "Login", "001" },
    { "Credit Card", "002" },
    { "Secure Note", "003" },
    { "Identity", "004" },
    { "Password", "005" },
    { "Tombstone", "099" },
    { "Software License", "100" },
    { "Bank Account", "101" },
    { "Database", "102" },
    { "Driver License", "103" },
    { "Outdoor License", "104" },
    { "Membership", "105" },
    { "Passport", "106" },
    { "Rewards", "107" },
    { "SSN", "108" },
    { "Router", "109" },
    { "Server", "110" },
    { "Email", "111" }
};

static int compare_cjson_by_fieldname(const void *a, const void *b)
{
    return strcmp( (*(const cJSON **) a)->string, (*(const cJSON **) b)->string );
}

static int test_item_hmac(cJSON *item, const char *base64hmac, const uint8_t *overviewhmac)
{
    // sort all the fields into alphabetic order.
    int total = 0;
    for (cJSON *i = item->child; i != NULL; i = i->next) {
        total++;
    }

    total--;  // don't include "hmac"

    cJSON **items = (cJSON **) calloc(total, sizeof (cJSON *));
    if (!items) {
        return 0;  // oh well.
    }

    total = 0;
    for (cJSON *i = item->child; i != NULL; i = i->next) {
        if (strcmp(i->string, "hmac") == 0) {
            continue;
        }
        items[total++] = i;
    }

    qsort(items, total, sizeof (cJSON *), compare_cjson_by_fieldname);

    int retval = 0;
    uint8_t digest[32];
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    if (HMAC_Init(&ctx, overviewhmac, 32, EVP_sha256())) {
        int i;
        for (i = 0; i < total; i++) {
            cJSON *it = items[i];
            if (!HMAC_Update(&ctx, (const unsigned char *) it->string, strlen(it->string))) {
                break;
            }

            char strbuf[64];
            const char *str = NULL;
            switch (it->type) {
                case cJSON_False: str = "0"; break;
                case cJSON_True: str = "1"; break;
                case cJSON_Number: str = strbuf; snprintf(strbuf, sizeof (strbuf), "%d", (int) it->valuedouble); break;  // !!! FIXME: might be wrong.
                case cJSON_String: str = it->valuestring; break;
                default: fprintf(stderr, "uhoh, can't HMAC this field ('%s')!\n", it->string); break;
            }

            if (!HMAC_Update(&ctx, (const unsigned char *) str, strlen(str))) {
                break;
            }
        }

        unsigned int digestlen = sizeof (digest);
        if ((i == total) && (HMAC_Final(&ctx, digest, &digestlen)) && (digestlen == sizeof (digest))) {
            uint8_t *expected = NULL;
            if (base64_decode(base64hmac, -1, &expected) == sizeof (digest)) {
                retval = (memcmp(digest, expected, sizeof (digest)) == 0) ? 1 : 0;
            }
            free(expected);
        }
    }

    HMAC_CTX_cleanup(&ctx);
    free(items);

    return retval;
}

static void dump_band(cJSON *band, const uint8_t *masterkey, const uint8_t *masterhmac, const uint8_t *overviewkey, const uint8_t *overviewhmac)
{
    for (cJSON *i = band->child; i != NULL; i = i->next) {
        //dump_json(i);
        cJSON *json;
        uint8_t itemkey[32];
        uint8_t itemhmac[32];
        int itemkeysokay = 0;

        printf("uuid %s:\n", i->string);

        if ((json = cJSON_GetObjectItem(i, "category")) != NULL) {
            const char *category = json->valuestring;
            for (int i = 0; i < sizeof (category_map) / sizeof (category_map[0]); i++) {
                if (strcmp(category_map[i].idstr, category) == 0) {
                    category = category_map[i].name;
                    break;
                }
            }
            printf(" category: %s\n", category);
        }

        if ((json = cJSON_GetObjectItem(i, "created")) != NULL) {
            time_t t = (time_t) json->valuedouble;
            printf(" created: %s", ctime(&t));
        }

        if ((json = cJSON_GetObjectItem(i, "updated")) != NULL) {
            time_t t = (time_t) json->valuedouble;
            printf(" updated: %s", ctime(&t));
        }

        if ((json = cJSON_GetObjectItem(i, "tx")) != NULL) {
            time_t t = (time_t) json->valuedouble;
            printf(" last tx: %s", ctime(&t));
        }

        printf(" trashed: %s\n", cJSON_IsTrue(cJSON_GetObjectItem(i, "trashed")) ? "true" : "false");

        json = cJSON_GetObjectItem(i, "folder");
        printf(" folder uuid: %s\n", json ? json->valuestring : "[none]");

        if ((json = cJSON_GetObjectItem(i, "fave")) != NULL) {
            printf(" fave: %lu\n", (unsigned long) json->valuedouble);
        } else {
            printf(" fave: [no]\n");
        }

        if ((json = cJSON_GetObjectItem(i, "hmac")) != NULL) {
            const char *base64hmac = json->valuestring;
            const int valid = test_item_hmac(i, base64hmac, overviewhmac);
            printf(" hmac: %s [%svalid]\n", base64hmac, valid ? "" : "in");
        } else {
            printf(" hmac: [none]\n");
        }

        // !!! FIXME: lots of code dupe with master key decrypt.
        if ((json = cJSON_GetObjectItem(i, "k")) != NULL) {
            const char *base64key = json->valuestring;
            uint8_t *decoded = NULL;
            const int decodedlen = base64_decode(base64key, -1, &decoded);
            if ((decodedlen != -1) && (decodedlen > 32)) {
                uint8_t digest[32];
                unsigned int digestlen = sizeof (digest);
                if (!HMAC(EVP_sha256(), masterhmac, 32, (const unsigned char *) decoded, decodedlen-digestlen, (unsigned char *) digest, &digestlen)) {
                    fprintf(stderr, " [item key HMAC failed.]\n");
                } else if (digestlen != sizeof (digest)) {
                    fprintf(stderr, "[item key HMAC is wrong size (got=%u expected=%u)].\n", digestlen, (unsigned int) sizeof (digest));
                } else if (memcmp(digest, decoded + (decodedlen-sizeof (digest)), sizeof (digest)) != 0) {
                    fprintf(stderr, "[item key HMAC verification failed.]\n");
                } else {  // HMAC cleared.
                    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
                    const unsigned char *iv = (unsigned char *) (decoded);
                    uint8_t *plaintext = NULL;
                    int decryptedlen = 0;
                    int decryptedlen2 = 0;

                    if (!ctx) {
                        fprintf(stderr, "[item key EVP_CIPHER_CTX_new() failed.]\n");
                    } else if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (const unsigned char *) masterkey, iv)) {
                        fprintf(stderr, "[item key EVP_DecryptInit_ex() failed.]\n");
                    } else if (!EVP_CIPHER_CTX_set_padding(ctx, 0)) {
                        fprintf(stderr, "[item key EVP_CIPHER_CTX_set_padding() failed.]\n");
                    } else if ((plaintext = (uint8_t *) malloc(decodedlen)) == NULL) {
                        fprintf(stderr, "[item key Out of memory.]\n");
                    } else if (!EVP_DecryptUpdate(ctx, plaintext, &decryptedlen, decoded + 16, decodedlen - 48)) {
                        fprintf(stderr, "[item key EVP_DecryptUpdate() failed.]\n");
                    } else if (!EVP_DecryptFinal_ex(ctx, plaintext + decryptedlen, &decryptedlen2)) {
                        fprintf(stderr, "[item key EVP_DecryptFinal_ex() failed.]\n");
                    } else if ((decryptedlen + decryptedlen2) != 64) {
                        fprintf(stderr, "[item key is wrong size.]\n");
                    } else {
                        memcpy(itemkey, plaintext, 32);
                        memcpy(itemhmac, plaintext + 32, 32);
                        itemkeysokay = 1;
                    }

                    free(plaintext);

                    if (ctx) {
                        EVP_CIPHER_CTX_cleanup(ctx);
                    }
                }
            }
            free(decoded);
        }

        if ((json = cJSON_GetObjectItem(i, "o")) != NULL) {
            uint8_t *decrypted = NULL;
            int decryptedlen = 0;
            if (decrypt_opdata_base64("o", json->valuestring, overviewkey, overviewhmac, &decrypted, &decryptedlen)) {
                decrypted[decryptedlen] = 0;
                printf(" o: %s\n", decrypted);
                free(decrypted);
            } else {
                printf(" o: [failed to decrypt]\n");
            }
        }

        if ((json = cJSON_GetObjectItem(i, "d")) != NULL) {
            uint8_t *decrypted = NULL;
            int decryptedlen = 0;
            if (itemkeysokay && decrypt_opdata_base64("d", json->valuestring, itemkey, itemhmac, &decrypted, &decryptedlen)) {
                decrypted[decryptedlen] = 0;
                printf(" d: %s\n", decrypted);
                free(decrypted);
            } else {
                printf(" d: [failed to decrypt]\n");
            }
        }

        printf("\n");
    }

    printf("\n");
}

static void dump_bands(const uint8_t *masterkey, const uint8_t *masterhmac, const uint8_t *overviewkey, const uint8_t *overviewhmac)
{
    for (unsigned int i = 0; i < 16; i++) {
        char fname[16];
        snprintf(fname, sizeof (fname), "band_%X.js", i);
        cJSON *band = load_json(fname);
        if (band) {
            printf("\nBand %s...\n\n", fname);
            dump_band(band, masterkey, masterhmac, overviewkey, overviewhmac);
            cJSON_Delete(band);
        }
    }
}

int main(int argc, char **argv)
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    OPENSSL_config(NULL);

    if (argc != 3) {
        fprintf(stderr, "\n\nUSAGE: %s </path/to/1Password.opvault> <keychain password>\n\n", argv[0]);
        return 2;
    }

    const char *opvaultpath = argv[1];
    const char *password = argv[2];

    if (chdir(opvaultpath) == -1) {
        fprintf(stderr, "chdir(\"%s\") failed: %s\n", opvaultpath, strerror(errno));
        return 1;
    } else if (chdir("default") == -1) {
        fprintf(stderr, "chdir(\"%s/default\") failed: %s\n", opvaultpath, strerror(errno));
        return 1;
    }

    cJSON *profile = load_json("profile.js");
    if (!profile) {
        fprintf(stderr, "load_json(\"profile.js\") failed.\n");
        return 1;
    }

    printf("profile : "); dump_json(profile); printf("\n");

    uint8_t masterkey[32];
    uint8_t masterhmac[32];
    uint8_t overviewkey[32];
    uint8_t overviewhmac[32];
    if (!prepare_keys(profile, password, masterkey, masterhmac, overviewkey, overviewhmac)) {
        return 1;
    }

    cJSON_Delete(profile);

    dump_folders(overviewkey, overviewhmac);
    dump_bands(masterkey, masterhmac, overviewkey, overviewhmac);

    return 0;
}

