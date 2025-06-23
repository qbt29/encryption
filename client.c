#include "ssl.h"
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 4096

void create_sock(int* sock, struct sockaddr_in* serv_addr) {
    if ((*sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket creation error");
        exit(EXIT_FAILURE);
    }
    serv_addr->sin_family = AF_INET;
    serv_addr->sin_port = htons(PORT);
}

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE] = {0};
    // Создание TCP сокета
    init_sock(&sock);
    // Преобразование IP-адреса
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        perror("invalid address");
        exit(EXIT_FAILURE);
    }
    // Подключение к серверу
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connection failed");
        exit(EXIT_FAILURE);
    }
    
    
    // Отправка сообщения
    char *message = "Hello from client";
    send(sock, message, strlen(message), 0);
    printf("Message sent\n");
    // Чтение ответа сервера
    read(sock, buffer, BUFFER_SIZE);
    printf("Server response: %s\n", buffer);
    
    close(sock);
    return 0;
}