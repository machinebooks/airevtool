#include "websocket_server.h"
#include "command_handler.h"
#include <sstream>
#include <algorithm>
#include <stdexcept>

#pragma comment(lib, "ws2_32.lib")

// ── SHA-1 (for WS handshake) — minimal implementation ────────

static uint32_t rot32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

static std::string sha1_impl(const std::string& msg) {
    uint32_t h[5] = { 0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0 };
    // Padding
    std::string padded = msg;
    padded += '\x80';
    while ((padded.size() % 64) != 56) padded += '\x00';
    uint64_t bits = (uint64_t)msg.size() * 8;
    for (int i = 7; i >= 0; i--) padded += (char)((bits >> (i * 8)) & 0xFF);

    for (size_t i = 0; i < padded.size(); i += 64) {
        uint32_t w[80];
        for (int j = 0; j < 16; j++) {
            w[j] = ((uint8_t)padded[i+j*4] << 24) | ((uint8_t)padded[i+j*4+1] << 16) |
                   ((uint8_t)padded[i+j*4+2] << 8) | (uint8_t)padded[i+j*4+3];
        }
        for (int j = 16; j < 80; j++) w[j] = rot32(w[j-3]^w[j-8]^w[j-14]^w[j-16], 1);

        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4];
        for (int j = 0; j < 80; j++) {
            uint32_t f,k;
            if      (j < 20) { f=(b&c)|((~b)&d); k=0x5A827999; }
            else if (j < 40) { f=b^c^d;          k=0x6ED9EBA1; }
            else if (j < 60) { f=(b&c)|(b&d)|(c&d); k=0x8F1BBCDC; }
            else             { f=b^c^d;          k=0xCA62C1D6; }
            uint32_t temp = rot32(a,5)+f+e+k+w[j];
            e=d; d=c; c=rot32(b,30); b=a; a=temp;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e;
    }
    char out[20];
    for (int i = 0; i < 5; i++) {
        out[i*4]   = (h[i]>>24)&0xFF;
        out[i*4+1] = (h[i]>>16)&0xFF;
        out[i*4+2] = (h[i]>>8)&0xFF;
        out[i*4+3] =  h[i]&0xFF;
    }
    return std::string(out, 20);
}

static const char* B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static std::string base64_impl(const unsigned char* data, size_t len) {
    std::string out;
    for (size_t i = 0; i < len; i += 3) {
        int b = (data[i] << 16) | (i+1<len?(data[i+1]<<8):0) | (i+2<len?data[i+2]:0);
        out += B64[(b>>18)&63]; out += B64[(b>>12)&63];
        out += (i+1<len) ? B64[(b>>6)&63] : '=';
        out += (i+2<len) ? B64[b&63] : '=';
    }
    return out;
}

// ── WebSocketServer ──────────────────────────────────────────

WebSocketServer::WebSocketServer(int port, CommandHandler* handler)
    : m_port(port), m_handler(handler) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);
}

WebSocketServer::~WebSocketServer() {
    stop();
    WSACleanup();
}

void WebSocketServer::run() {
    m_running = true;
    m_listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_listenSock == INVALID_SOCKET) return;

    int opt = 1;
    setsockopt(m_listenSock, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(m_port);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (bind(m_listenSock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) { closesocket(m_listenSock); return; }
    if (listen(m_listenSock, 1) == SOCKET_ERROR) { closesocket(m_listenSock); return; }

    acceptLoop();
}

void WebSocketServer::acceptLoop() {
    // Set timeout on accept so we can check m_running
    while (m_running) {
        fd_set fds; FD_ZERO(&fds); FD_SET(m_listenSock, &fds);
        timeval tv{ 1, 0 };
        if (select((int)m_listenSock + 1, &fds, nullptr, nullptr, &tv) <= 0) continue;

        sockaddr_in clientAddr{}; int addrLen = sizeof(clientAddr);
        SOCKET client = accept(m_listenSock, (sockaddr*)&clientAddr, &addrLen);
        if (client == INVALID_SOCKET) continue;

        {
            std::lock_guard<std::mutex> lock(m_clientMutex);
            if (m_clientSock != INVALID_SOCKET) closesocket(m_clientSock);
            m_clientSock = client;
        }

        handleClient(client);

        {
            std::lock_guard<std::mutex> lock(m_clientMutex);
            if (m_clientSock == client) m_clientSock = INVALID_SOCKET;
        }
    }
}

void WebSocketServer::handleClient(SOCKET sock) {
    if (!doHandshake(sock)) { closesocket(sock); return; }

    while (m_running) {
        std::string payload;
        if (!recvFrame(sock, payload)) break;
        if (payload.empty()) continue;

        std::string response = m_handler->handle(payload);
        if (!sendFrame(sock, response)) break;
    }
    closesocket(sock);
}

void WebSocketServer::stop() {
    m_running = false;
    if (m_listenSock != INVALID_SOCKET) { closesocket(m_listenSock); m_listenSock = INVALID_SOCKET; }
    std::lock_guard<std::mutex> lock(m_clientMutex);
    if (m_clientSock != INVALID_SOCKET) { closesocket(m_clientSock); m_clientSock = INVALID_SOCKET; }
}

void WebSocketServer::broadcast(const std::string& message) {
    std::lock_guard<std::mutex> lock(m_clientMutex);
    if (m_clientSock != INVALID_SOCKET) sendFrame(m_clientSock, message);
}

bool WebSocketServer::hasClients() const {
    return m_clientSock != INVALID_SOCKET;
}

// ── WebSocket handshake ──────────────────────────────────────

bool WebSocketServer::doHandshake(SOCKET sock) {
    std::string request = recvAll(sock, 4096);
    if (request.empty()) return false;

    // Extract Sec-WebSocket-Key
    std::string keyHeader = "Sec-WebSocket-Key: ";
    size_t pos = request.find(keyHeader);
    if (pos == std::string::npos) return false;
    pos += keyHeader.size();
    size_t end = request.find("\r\n", pos);
    std::string key = request.substr(pos, end - pos);

    std::string response = makeHandshakeResponse(key);
    send(sock, response.c_str(), (int)response.size(), 0);
    return true;
}

std::string WebSocketServer::makeHandshakeResponse(const std::string& key) {
    std::string magic = key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    std::string hash = sha1_impl(magic);
    std::string accept = base64_impl((const unsigned char*)hash.data(), hash.size());

    return "HTTP/1.1 101 Switching Protocols\r\n"
           "Upgrade: websocket\r\n"
           "Connection: Upgrade\r\n"
           "Sec-WebSocket-Accept: " + accept + "\r\n\r\n";
}

// ── WebSocket frame codec ────────────────────────────────────

bool WebSocketServer::recvFrame(SOCKET sock, std::string& payload) {
    // Read 2 header bytes
    unsigned char header[2];
    if (recv(sock, (char*)header, 2, MSG_WAITALL) != 2) return false;

    bool fin     = (header[0] & 0x80) != 0;
    int  opcode  = header[0] & 0x0F;
    bool masked  = (header[1] & 0x80) != 0;
    uint64_t len = header[1] & 0x7F;

    if (opcode == 8) return false;  // close frame

    if (len == 126) {
        unsigned char ext[2];
        if (recv(sock, (char*)ext, 2, MSG_WAITALL) != 2) return false;
        len = (uint64_t)ext[0] << 8 | ext[1];
    } else if (len == 127) {
        unsigned char ext[8];
        if (recv(sock, (char*)ext, 8, MSG_WAITALL) != 8) return false;
        len = 0;
        for (int i = 0; i < 8; i++) len = (len << 8) | ext[i];
    }

    unsigned char mask[4] = {};
    if (masked) {
        if (recv(sock, (char*)mask, 4, MSG_WAITALL) != 4) return false;
    }

    if (len > 4 * 1024 * 1024) return false;  // 4MB max
    std::string data((size_t)len, '\0');
    if (len > 0 && recv(sock, &data[0], (int)len, MSG_WAITALL) != (int)len) return false;

    if (masked) {
        for (size_t i = 0; i < data.size(); i++) data[i] ^= mask[i % 4];
    }
    payload = std::move(data);
    return true;
}

bool WebSocketServer::sendFrame(SOCKET sock, const std::string& payload) {
    std::vector<unsigned char> frame;
    frame.push_back(0x81);  // FIN + text frame

    size_t len = payload.size();
    if (len < 126) {
        frame.push_back((unsigned char)len);
    } else if (len < 65536) {
        frame.push_back(126);
        frame.push_back((len >> 8) & 0xFF);
        frame.push_back(len & 0xFF);
    } else {
        frame.push_back(127);
        for (int i = 7; i >= 0; i--) frame.push_back((unsigned char)((len >> (i * 8)) & 0xFF));
    }

    for (char c : payload) frame.push_back((unsigned char)c);

    return send(sock, (const char*)frame.data(), (int)frame.size(), 0) == (int)frame.size();
}

std::string WebSocketServer::recvAll(SOCKET sock, int maxBytes) {
    std::string buf(maxBytes, '\0');
    fd_set fds; FD_ZERO(&fds); FD_SET(sock, &fds);
    timeval tv{ 3, 0 };
    if (select((int)sock + 1, &fds, nullptr, nullptr, &tv) <= 0) return "";
    int n = recv(sock, &buf[0], maxBytes - 1, 0);
    if (n <= 0) return "";
    buf.resize(n);
    return buf;
}
