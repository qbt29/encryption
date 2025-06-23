#include "ssl.h"

int main() {
    // Инициализация OpenSSL
    init();

    // Создание контекста для ключей
    EVP_PKEY_CTX *pctx = generate_context();

    // Генерация ключевой пары для Alice
    keygen_init(pctx);
    EVP_PKEY *alice_priv = generate_privkey(pctx);
    EVP_PKEY_CTX_free(pctx);
    // Генерация ключевой пары для Bob
    EVP_PKEY_CTX *pctx = generate_context();
    keygen_init(pctx);
    EVP_PKEY *bob_priv = generate_privkey(pctx);
    EVP_PKEY_CTX_free(pctx);

    // Извлечение публичных ключей
    EVP_PKEY *alice_pub = generate_pubkey(alice_priv);
    EVP_PKEY *bob_pub = generate_pubkey(bob_priv);

    // Создание контекста для ECDH
    EVP_PKEY_CTX *derive_ctx = make_ECDH_context(alice_priv);
    
    // Вычисление общего секрета Alice
    unsigned char* alice_secret = find_secret(derive_ctx, bob_pub);

    EVP_PKEY_CTX_free(derive_ctx);
    // Вычисление общего секрета Bob
    derive_ctx = make_ECDH_context(bob_priv);
    unsigned char *bob_secret = find_secret(derive_ctx, alice_pub);
    size_t secret_len = strlen(bob_secret);

    // Проверка совпадения секретов
    unsigned char enc_key[32];
    unsigned char sig_key[32];
        
    // Генерация ключей из общего секрета
    derive_keys(alice_secret, secret_len, enc_key, sig_key);

    unsigned char message[] = "Hello, Bob!";
    unsigned char aad[] = "ALice -> Bob";
    size_t message_len = strlen((char*)message);
    size_t aad_len = strlen((char*)aad);

    unsigned char iv[12];
    generate_iv(iv);

    unsigned char ciphertext[message_len];
    unsigned char tag[16];

    int ciphertext_len = encrypt_aes_gcm(enc_key, iv, aad, message, ciphertext, tag);
    if (ciphertext_len < 0) {
        fprintf(stderr, "Encrypting error, code: %d\n", ciphertext_len);
        exit(1);
    }
    unsigned char decrypted[4096];
    int decrypted_len = decrypt_aes_gcm(enc_key, iv, aad, ciphertext, ciphertext_len, tag, decrypted);
    if (decrypted_len < 0) {
        fprintf(stderr, "Decrypting error, code: %d\n", decrypted_len);
        exit(1);
    }

    printf("%s\n", decrypted);
    if (memcmp(message, decrypted, message_len) == 0) {
        printf("Сообщение успешно расшифровано!\n");
    }
    else {
        printf("Ошибка: несовпадение исходного текста с расшифрованным!\n");
    }

    // Очистка ресурсов
    OPENSSL_free(alice_secret);
    OPENSSL_free(bob_secret);
    EVP_PKEY_CTX_free(derive_ctx);
    EVP_PKEY_free(alice_priv);
    EVP_PKEY_free(bob_priv);
    EVP_PKEY_free(alice_pub);
    EVP_PKEY_free(bob_pub);
    // Освобождение глобальных ресурсов OpenSSL
    freeSSL();

    return 0;
}

//compile via gcc -lssl -lcrypto