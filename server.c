#include "ssl.h"
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 4096

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};
    // Создание TCP сокета
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    // Настройка адреса сервера
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    // Привязка сокета к порту
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    // Ожидание подключений
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    printf("Server listening on port %d...\n", PORT);
    // Принятие входящего подключения
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
        perror("accept");
        exit(EXIT_FAILURE);
    }
    init();
    // Генерация ключевой пары для Bob
    pctx = generate_context();
    keygen_init(pctx);
    EVP_PKEY *bob_priv = generate_privkey(pctx);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY *bob_pub = generate_pubkey(bob_priv);
    EVP_PKEY_CTX *derive_ctx = make_ECDH_context(bob_priv);

    // Чтение alice_pubkey
    read(new_socket, buffer, BUFFER_SIZE);
    printf("Received message: %s\n", buffer);

    unsigned char *rptr = buffer;
    free(buffer);

    // Извлекаем компоненты
    uint32_t r_net_aad_len;
    memcpy(&r_net_aad_len, rptr, 4); rptr += 4;
    size_t r_aad_len = ntohl(r_net_aad_len);

    unsigned char *r_aad = malloc(r_aad_len + 1);
    memcpy(r_aad, rptr, r_aad_len); rptr += r_aad_len;
    r_aad[r_aad_len] = '\0';

    uint32_t r_net_sig_len;
    memcpy(&r_net_sig_len, rptr, 4); rptr += 4;
    size_t r_sig_len = ntohl(r_net_sig_len);

    unsigned char *r_signature = malloc(r_sig_len);
    memcpy(r_signature, rptr, r_sig_len); rptr += r_sig_len;

    unsigned char r_iv[12];
    memcpy(r_iv, rptr, 12); rptr += 12;

    unsigned char r_tag[16];
    memcpy(r_tag, rptr, 16); rptr += 16;

    uint32_t r_net_ciphertext_len;
    memcpy(&r_net_ciphertext_len, rptr, 4); rptr += 4;
    size_t r_ciphertext_len = ntohl(r_net_ciphertext_len);

    unsigned char *r_ciphertext = malloc(r_ciphertext_len);
    memcpy(r_ciphertext, rptr, r_ciphertext_len);

    // Проверяем подпись
    size_t data_to_verify_len = r_aad_len + 12 + r_ciphertext_len + 16;
    unsigned char *data_to_verify = malloc(data_to_verify_len);
    memcpy(data_to_verify, r_aad, r_aad_len);
    memcpy(data_to_verify + r_aad_len, r_iv, 12);
    memcpy(data_to_verify + r_aad_len + 12, r_ciphertext, r_ciphertext_len);
    memcpy(data_to_verify + r_aad_len + 12 + r_ciphertext_len, r_tag, 16);

    if (verify_signature(alice_pub, data_to_verify, data_to_verify_len, r_signature, r_sig_len) != 0) {
        fprintf(stderr, "Ошибка проверки подписи!\n");
        exit(1);
    }

    // Расшифровываем
    unsigned char decrypted[4096];
    int decrypted_len = decrypt_aes_gcm(
        benc_key,    // Ключ расшифрования получателя
        r_iv,
        r_aad,
        r_ciphertext,
        r_ciphertext_len,
        r_tag,
        decrypted
    );
    char *response = "200";
    if (decrypted_len < 0) {
        *response = "201";
        send(new_socket, response, strlen(response), 0);
        fprintf(stderr, "Ошибка расшифровки: %d\n", decrypted_len);
        exit(1);
    }

    // Проверяем целостность
    decrypted[decrypted_len] = '\0';
    printf("Расшифрованное сообщение: %s\n", decrypted);
    // Отправка ответа
    send(new_socket, response, strlen(response), 0);
    printf("Response sent\n");
    
    // Закрытие сокетов
    close(new_socket);
    close(server_fd);
    return 0;
}