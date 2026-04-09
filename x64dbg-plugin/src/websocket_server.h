#pragma once
#pragma warning(disable: 4005)
// winsock2 must come before windows.h
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include <vector>
#include <mutex>

class CommandHandler;

/**
 * Minimal WebSocket server (RFC 6455) — no external deps.
 * Handles one client at a time (AIrevtool connects once per session).
 * For production, replace with uWebSockets or civetweb.
 */
class WebSocketServer {
public:
    WebSocketServer(int port, CommandHandler* handler);
    ~WebSocketServer();

    void run();
    void stop();
    void broadcast(const std::string& message);
    bool hasClients() const;

private:
    int  m_port;
    CommandHandler* m_handler;
    SOCKET m_listenSock  = INVALID_SOCKET;
    SOCKET m_clientSock  = INVALID_SOCKET;
    std::atomic<bool> m_running{ false };
    std::mutex m_clientMutex;

    void acceptLoop();
    void handleClient(SOCKET clientSock);

    // WebSocket handshake
    bool doHandshake(SOCKET sock);
    std::string makeHandshakeResponse(const std::string& key);
    std::string base64(const unsigned char* data, size_t len);
    std::string sha1(const std::string& input);

    // WebSocket frame codec
    bool recvFrame(SOCKET sock, std::string& payload);
    bool sendFrame(SOCKET sock, const std::string& payload);

    std::string recvAll(SOCKET sock, int maxBytes);
};
