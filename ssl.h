#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

void handle_openssl_error() {
    char err_buf[512];
    ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
    fprintf(stderr, "OpenSSL error: %s\n", err_buf);
    exit(1);
}

void init() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

void keygen_init(EVP_PKEY_CTX *pctx) {
    if (EVP_PKEY_keygen_init(pctx) <= 0) handle_openssl_error();
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp256k1) <= 0) handle_openssl_error();
}

void freeSSL() {
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
}

EVP_PKEY_CTX* generate_context() {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx) handle_openssl_error();
    return pctx;
}

EVP_PKEY* generate_privkey(EVP_PKEY_CTX *pctx) {
    if (EVP_PKEY_keygen_init(pctx) <= 0) handle_openssl_error();
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp256k1) <= 0) handle_openssl_error();
    
    EVP_PKEY *priv = NULL;
    if (EVP_PKEY_keygen(pctx, &priv) <= 0) handle_openssl_error();
    return priv;
}

EVP_PKEY* generate_pubkey(EVP_PKEY* privkey) {
    EVP_PKEY *pubkey = EVP_PKEY_get1_EC_KEY(privkey) ? EVP_PKEY_new() : NULL;
    if (!pubkey) handle_openssl_error();
    if (EVP_PKEY_set1_EC_KEY(pubkey, EVP_PKEY_get0_EC_KEY(privkey)) <= 0)
        handle_openssl_error();
    return pubkey;
}

EVP_PKEY_CTX* make_ECDH_context(EVP_PKEY* privkey) {
    EVP_PKEY_CTX *derive_ctx = EVP_PKEY_CTX_new(privkey, NULL);
    if (!derive_ctx) handle_openssl_error();
    return derive_ctx;
}

unsigned char* find_secret(EVP_PKEY_CTX* derive_ctx, EVP_PKEY* pubkey) {
    size_t secret_len;
    if (EVP_PKEY_derive_init(derive_ctx) <= 0) handle_openssl_error();
    if (EVP_PKEY_derive_set_peer(derive_ctx, pubkey) <= 0) handle_openssl_error();
    if (EVP_PKEY_derive(derive_ctx, NULL, &secret_len) <= 0) handle_openssl_error();
    
    unsigned char *secret = OPENSSL_malloc(secret_len);
    if (!secret) handle_openssl_error();
    if (EVP_PKEY_derive(derive_ctx, secret, &secret_len) <= 0) handle_openssl_error();
    return secret;
}

void derive_keys(const unsigned char* secret, size_t secret_len, 
                unsigned char* enc_key, unsigned char* sig_key) {
    // соль
    unsigned char salt[] = "protocol-salt";
    size_t salt_len = sizeof(salt) - 1; // Длина без нулевого байта

    // Информационный контекст для разделения ключей
    const unsigned char info[] = "ECDH_enc_sig_keys";
    size_t info_len = sizeof(info) - 1;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!ctx) {
        handle_openssl_error();
    }
     // Инициализируем контекст
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        handle_openssl_error();
    }

    // Устанавливаем алгоритм хеширования (SHA-256)
    if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        handle_openssl_error();
    }

    // Устанавливаем соль
    if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, salt_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        handle_openssl_error();
    }

    // Устанавливаем общий секрет
    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, secret, secret_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        handle_openssl_error();
    }
    
    unsigned char derived[64];
    size_t derived_len = sizeof(derived);
    
    if (EVP_PKEY_derive(ctx, derived, &derived_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        handle_openssl_error();
    }

    memcpy(enc_key, derived, 32);        // Первые 32 байта - ключ шифрования
    memcpy(sig_key, derived + 32, 32);

    EVP_PKEY_CTX_free(ctx);
}

void generate_iv(unsigned char* iv) {
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        fprintf(stderr, "Ошибка генерации IV\n");
        exit(1);
    }
}

int encrypt_aes_gcm(const unsigned char *key, const unsigned char *iv, const unsigned char *aad,
                    const unsigned char *plaintext, unsigned char *ciphertext, unsigned char *tag) {
    size_t iv_len = sizeof(iv);
    size_t aad_len = strlen((char*)aad);
    size_t plaintext_len = strlen(plaintext);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -2;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -3;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -4;
    }

    int len;
    if (aad && aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return -5;
        }
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -6;
    }
    int ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -7;
    }
    ciphertext_len += len;

    // Получение тега аутентификации
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -8;
    }

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;

}

int decrypt_aes_gcm(const unsigned char *key, const unsigned char *iv, const unsigned char *aad, 
                    const unsigned char *ciphertext, size_t ciphertext_len, const unsigned char *tag, unsigned char *plaintext) {
    size_t iv_len = sizeof(iv);
    size_t aad_len = strlen((char*)aad);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    // Инициализация режима расшифрования
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Установка IV длины
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -2;
    }

    // Установка ключа и IV
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -3;
    }

    int len;
    // Обработка AAD (если есть)
    if (aad && aad_len > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return -4;
        }
    }

    // Расшифрование данных
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -5;
    }
    int plaintext_len = len;

    // Установка тега для проверки аутентичности
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -6;
    }

    int ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    
    if (ret > 0) {
        return plaintext_len; // Успешное расшифрование
    } else {
        return -7; // Ошибка проверки тега
    }
}
