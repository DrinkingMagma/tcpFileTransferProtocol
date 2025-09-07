#ifndef TCP_CLIENT_H
#define TCP_CLIENT_H

#include <string>
#include <cstdint>
#include <vector>
#include <functional>
#include <sys/socket.h> // Linux平台
#include <netinet/in.h> // Linux平台
#include <unistd.h>     // close()函数
#include <arpa/inet.h>  // inet_pton函数
#include "file_transfer_protocol.h"
class TCPClient {
private:
    std::string server_ip;
    uint16_t server_port;
    SOCKET sockfd;
    bool connected;

    // 发送和接收数据包的内部函数
    bool send_packet(const PacketHeader& header, const std::vector<uint8_t>& payload);
    bool receive_packet(PacketHeader& header, std::vector<uint8_t>& payload);

public:
    TCPClient(const std::string& ip, uint16_t port);
    ~TCPClient();

    // 连接到服务器
    bool connect_to_server();
    
    // 断开连接
    void disconnect();
    
    // 上传文件
    bool upload_file(const std::string& local_path, 
                    const std::string& remote_filename,
                    std::function<void(uint32_t, uint32_t)> progress_callback = nullptr);
    
    // 下载文件
    bool download_file(const std::string& remote_filename, 
                      const std::string& local_path,
                      std::function<void(uint32_t, uint32_t)> progress_callback = nullptr);
    
    // 中止当前传输
    bool abort_transfer(uint64_t file_id, const std::string& reason);
};

#endif // TCP_CLIENT_H