#ifndef TCP_SERVER_H
#define TCP_SERVER_H

#include <string>
#include <cstdint>
#include <vector>
#include <thread>
#include <map>
#include <functional>
#include <sys/socket.h>      // Linux平台
#include <netinet/in.h>      // Linux平台
#include <unistd.h>          // close() 函数
#include <mutex>             // 添加mutex头文件
#include "file_transfer_protocol.h"

const int SOCKET_ERROR = -1;

struct ClientConnection;

// 客户端连接信息
struct ClientConnection {
    SOCKET sockfd;
    sockaddr_in address;
    std::thread handler_thread;
    bool active;
};

class TCPServer {
private:
    uint16_t port;
    SOCKET listen_sockfd;
    bool running;
    std::vector<ClientConnection> clients;
    std::string upload_dir;  // 上传文件保存目录
    std::string download_dir; // 可供下载的文件目录
    std::mutex client_mutex; // 添加mutex成员

    // 处理客户端连接
    void handle_client(ClientConnection& client);
    
    // 发送和接收数据包的内部函数
    bool send_packet(SOCKET sock, const PacketHeader& header, const std::vector<uint8_t>& payload);
    bool receive_packet(SOCKET sock, PacketHeader& header, std::vector<uint8_t>& payload);
    
    // 处理上传
    void handle_upload(SOCKET sock, const PacketHeader& header, const std::vector<uint8_t>& payload);
    
    // 处理下载
    void handle_download(SOCKET sock, const PacketHeader& header, const std::vector<uint8_t>& payload);

public:
    TCPServer(uint16_t port, const std::string& upload_dir = "./uploads", const std::string& download_dir = "./downloads");
    ~TCPServer();

    // 启动服务器
    bool start();
    
    // 停止服务器
    void stop();
    
    // 设置上传和下载目录
    void set_upload_directory(const std::string& dir);
    void set_download_directory(const std::string& dir);
};

#endif // TCP_SERVER_H