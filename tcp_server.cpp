#include "tcp_server.h"
#include "file_transfer_protocol.h"
#include <fstream>
#include <iostream>
#include <filesystem>
#include <sstream>
#include <algorithm>
#include <openssl/md5.h> // 需要OpenSSL库
#include <cstring>       // 添加cstring头文件

namespace fs = std::filesystem;

TCPServer::TCPServer(uint16_t port, const std::string& upload_dir, const std::string& download_dir)
    : port(port), listen_sockfd(INVALID_SOCKET), running(false), 
      upload_dir(upload_dir), download_dir(download_dir) {
    // Linux下不需要初始化Winsock
    // 创建上传和下载目录
    fs::create_directories(upload_dir);
    fs::create_directories(download_dir);
}

TCPServer::~TCPServer() {
    stop();
    // Linux下不需要WSACleanup()
}

bool TCPServer::start() {
    if (running) return true;

    // 创建监听套接字
    listen_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sockfd == INVALID_SOCKET) {
        std::cerr << "Failed to create socket" << std::endl;
        return false;
    }

    // 设置服务器地址
    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    // 绑定套接字
    if (bind(listen_sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        std::cerr << "Bind failed" << std::endl;
        close(listen_sockfd);  // Linux使用close()
        listen_sockfd = INVALID_SOCKET;
        return false;
    }

    // 开始监听
    if (listen(listen_sockfd, 5) == SOCKET_ERROR) {
        std::cerr << "Listen failed" << std::endl;
        close(listen_sockfd);  // Linux使用close()
        listen_sockfd = INVALID_SOCKET;
        return false;
    }

    running = true;
    std::cout << "Server started on port " << port << std::endl;

    // 启动接受接受客户端连接的线程
    std::thread accept_thread([this]() {
        while (running) {
            sockaddr_in client_addr;
            socklen_t client_addr_len = sizeof(client_addr);  // Linux使用socklen_t
            
            // 接受客户端连接
            SOCKET client_sock = accept(listen_sockfd, (struct sockaddr*)&client_addr, &client_addr_len);
            if (client_sock == INVALID_SOCKET) {
                if (running) {
                    std::cerr << "Accept failed" << std::endl;
                }
                continue;
            }

            std::cout << "New client connected" << std::endl;

            // 创建客户端连接并启动处理线程
            ClientConnection client;
            client.sockfd = client_sock;
            client.address = client_addr;
            client.active = true;
            client.handler_thread = std::thread(&TCPServer::handle_client, this, std::ref(client));

            // 将客户端添加到列表
            {
                std::lock_guard<std::mutex> lock(client_mutex);
                clients.push_back(std::move(client));
            }
        }
    });

    // 分离接受线程
    accept_thread.detach();

    return true;
}

void TCPServer::stop() {
    if (!running) return;

    running = false;
    std::cout << "Stopping server..." << std::endl;

    // 关闭监听套接字
    if (listen_sockfd != INVALID_SOCKET) {
        close(listen_sockfd);  // Linux使用close()
        listen_sockfd = INVALID_SOCKET;
    }

    // 关闭所有客户端连接
    {
        std::lock_guard<std::mutex> lock(client_mutex);
        for (auto& client : clients) {
            client.active = false;
            if (client.sockfd != INVALID_SOCKET) {
                close(client.sockfd);  // Linux使用close()
            }
            if (client.handler_thread.joinable()) {
                client.handler_thread.join();
            }
        }
        clients.clear();
    }

    std::cout << "Server stopped" << std::endl;
}

void TCPServer::set_upload_directory(const std::string& dir) {
    upload_dir = dir;
    fs::create_directories(upload_dir);
}

void TCPServer::set_download_directory(const std::string& dir) {
    download_dir = dir;
    fs::create_directories(download_dir);
}

bool TCPServer::send_packet(SOCKET sock, const PacketHeader& header, const std::vector<uint8_t>& payload) {
    // 序列化头部
    std::vector<uint8_t> header_data = serialize_header(header);
    
    // 发送头部（确保完整发送）
    ssize_t bytes_sent = 0;
    ssize_t total_bytes_sent = 0;
    
    while (total_bytes_sent < static_cast<ssize_t>(header_data.size())) {
        bytes_sent = send(sock, reinterpret_cast<const char*>(header_data.data()) + total_bytes_sent, 
                         header_data.size() - total_bytes_sent, 0);
        if (bytes_sent <= 0) {
            std::cerr << "Failed to send header" << std::endl;
            return false;
        }
        total_bytes_sent += bytes_sent;
    }

    // 发送 payload（确保完整发送）
    if (!payload.empty()) {
        total_bytes_sent = 0;
        while (total_bytes_sent < static_cast<ssize_t>(payload.size())) {
            bytes_sent = send(sock, reinterpret_cast<const char*>(payload.data()) + total_bytes_sent, 
                             payload.size() - total_bytes_sent, 0);
            if (bytes_sent <= 0) {
                std::cerr << "Failed to send payload" << std::endl;
                return false;
            }
            total_bytes_sent += bytes_sent;
        }
    }

    return true;
}

bool TCPServer::receive_packet(SOCKET sock, PacketHeader& header, std::vector<uint8_t>& payload) {
    // 接收头部
    std::vector<uint8_t> header_data(sizeof(PacketHeader));
    ssize_t bytes_received = 0;
    ssize_t total_bytes_received = 0;
    
    // 循环接收直到获取完整的头部
    while (total_bytes_received < static_cast<ssize_t>(sizeof(PacketHeader))) {
        bytes_received = recv(sock, reinterpret_cast<char*>(header_data.data()) + total_bytes_received, 
                             sizeof(PacketHeader) - total_bytes_received, 0);
        if (bytes_received <= 0) {
            if (bytes_received == 0) {
                std::cerr << "Connection closed by client while receiving header" << std::endl;
            } else {
                std::cerr << "Failed to receive header. Error code: " << errno << ", Error message: " << strerror(errno) << std::endl;
            }
            return false;
        }
        total_bytes_received += bytes_received;
    }

    // 反序列化头部
    if (!deserialize_header(header_data, header)) {
        std::cerr << "Failed to deserialize header" << std::endl;
        return false;
    }

    // 检查协议版本
    if (header.version != PROTOCOL_VERSION) {
        std::cerr << "Unsupported protocol version. Expected: " << PROTOCOL_VERSION 
                  << ", Received: " << header.version << std::endl;
        return false;
    }

    // 接收 payload
    if (header.payload_size > 0) {
        payload.resize(header.payload_size);
        total_bytes_received = 0;
        
        // 循环接收直到获取完整的payload
        while (total_bytes_received < static_cast<ssize_t>(header.payload_size)) {
            bytes_received = recv(sock, reinterpret_cast<char*>(payload.data()) + total_bytes_received, 
                                 header.payload_size - total_bytes_received, 0);
            if (bytes_received <= 0) {
                if (bytes_received == 0) {
                    std::cerr << "Connection closed while receiving payload" << std::endl;
                } else {
                    std::cerr << "Failed to receive payload. Error code: " << errno << ", Error message: " << strerror(errno) << std::endl;
                }
                return false;
            }
            total_bytes_received += bytes_received;
        }
    }

    return true;
}

void TCPServer::handle_client(ClientConnection& client) {
    std::cout << "Handling new client connection" << std::endl;
    SOCKET client_sock = client.sockfd;

    while (client.active) {
        PacketHeader header;
        std::vector<uint8_t> payload;

        // 接收客户端发送的数据包
        if (!receive_packet(client_sock, header, payload)) {
            std::cerr << "Client connection closed" << std::endl;
            break;
        }

        // 根据命令类型分发处理
        switch (header.command) {
            case CommandType::UPLOAD_REQUEST:
                handle_upload(client_sock, header, payload);
                break;
            case CommandType::DOWNLOAD_REQUEST:
                handle_download(client_sock, header, payload);
                break;
            case CommandType::TRANSFER_ABORT:
                // 传输中止处理
                std::cout << "Transfer aborted by client" << std::endl;
                break;
            default:
                std::cerr << "Unknown command type: " << static_cast<int>(header.command) << std::endl;
                // 发送错误响应
                ErrorResponse error;
                error.error_code = ErrorCode::INVALID_PACKET;
                error.message = "Unknown command";
                send_packet(client_sock, PacketHeader{PROTOCOL_VERSION, CommandType::ERROR_RESPONSE, 
                    static_cast<uint32_t>(serialize_error_response(error).size()), 0, 0, 0}, serialize_error_response(error));
                break;
        }
    }

    // 清理客户端连接
    close(client_sock);
    client.active = false;
    std::cout << "Client connection closed" << std::endl;
}

void TCPServer::handle_upload(SOCKET sock, const PacketHeader& header, const std::vector<uint8_t>& payload) {
    UploadRequest req;
    if (!deserialize_upload_request(payload, req)) {
        std::cerr << "Failed to deserialize upload request" << std::endl;
        
        // 发送错误响应
        ErrorResponse error;
        error.error_code = ErrorCode::INVALID_PACKET;
        error.message = "Invalid upload request";
        
        PacketHeader resp_header;
        resp_header.version = PROTOCOL_VERSION;
        resp_header.command = CommandType::ERROR_RESPONSE;
        resp_header.payload_size = serialize_error_response(error).size();
        resp_header.file_id = 0;
        resp_header.block_index = 0;
        resp_header.total_blocks = 0;
        
        send_packet(sock, resp_header, serialize_error_response(error));
        return;
    }

    std::cout << "Received upload request for file: " << req.filename 
              << ", size: " << req.file_size << std::endl;

    // 生成唯一文件ID
    uint64_t file_id = std::hash<std::string>{}(req.filename + std::to_string(time(nullptr)));
    
    // 构建文件路径
    std::string file_path = upload_dir + "/" + req.filename;
    
    // 检查是否可以断点续传
    uint32_t start_block = 0;
    if (fs::exists(file_path) && fs::is_regular_file(file_path)) {
        uint64_t existing_size = fs::file_size(file_path);
        if (existing_size < req.file_size) {
            // 文件存在但不完整，可以续传
            start_block = static_cast<uint32_t>(existing_size / DATA_BLOCK_SIZE);
            std::cout << "Resuming upload from block: " << start_block << std::endl;
        } else if (existing_size == req.file_size) {
            // 文件已存在且完整
            std::cout << "File already exists and is complete" << std::endl;
            
            UploadResponse resp;
            resp.accepted = false;
            resp.error_code = ErrorCode::SUCCESS; // 特殊情况：文件已存在
            resp.file_id = file_id;
            resp.start_block = 0;
            
            PacketHeader resp_header;
            resp_header.version = PROTOCOL_VERSION;
            resp_header.command = CommandType::UPLOAD_RESPONSE;
            resp_header.payload_size = serialize_upload_response(resp).size();
            resp_header.file_id = file_id;
            resp_header.block_index = 0;
            resp_header.total_blocks = header.total_blocks;
            
            send_packet(sock, resp_header, serialize_upload_response(resp));
            return;
        }
    }

    // 发送上传响应
    UploadResponse resp;
    resp.accepted = true;
    resp.error_code = ErrorCode::SUCCESS;
    resp.file_id = file_id;
    resp.start_block = start_block;
    
    PacketHeader resp_header;
    resp_header.version = PROTOCOL_VERSION;
    resp_header.command = CommandType::UPLOAD_RESPONSE;
    resp_header.payload_size = serialize_upload_response(resp).size();
    resp_header.file_id = file_id;
    resp_header.block_index = 0;
    resp_header.total_blocks = header.total_blocks;
    
    if (!send_packet(sock, resp_header, serialize_upload_response(resp))) {
        std::cerr << "Failed to send upload response" << std::endl;
        return;
    }

    // 打开文件准备写入（追加模式，如果是续传）
    std::ofstream file(file_path, std::ios::binary | (start_block > 0 ? std::ios::app : std::ios::trunc));
    if (!file) {
        std::cerr << "Failed to open file for writing: " << file_path << std::endl;
        
        // 发送错误响应
        ErrorResponse error;
        error.error_code = ErrorCode::PERMISSION_DENIED;
        error.message = "Failed to open file for writing";
        
        PacketHeader error_header;
        error_header.version = PROTOCOL_VERSION;
        error_header.command = CommandType::ERROR_RESPONSE;
        error_header.payload_size = serialize_error_response(error).size();
        error_header.file_id = file_id;
        error_header.block_index = 0;
        error_header.total_blocks = 0;
        
        send_packet(sock, error_header, serialize_error_response(error));
        close(sock);  // 关闭连接
        return;
    }

    // 循环接收数据块
    PacketHeader data_header;
    std::vector<uint8_t> data_payload;
    while (true) {
        // 接收数据块头部和 payload
        if (!receive_packet(sock, data_header, data_payload)) {
            std::cerr << "Failed to receive data block" << std::endl;
            break;
        }

        // 处理数据块
        if (data_header.command == CommandType::DATA_BLOCK) {
            // 写入数据到文件
            file.write(reinterpret_cast<const char*>(data_payload.data()), data_payload.size());
            if (!file) {
                std::cerr << "Failed to write to file" << std::endl;
                // 发送错误响应
                ErrorResponse error;
                error.error_code = ErrorCode::TRANSFER_FAILED;
                error.message = "Failed to write to file";
                PacketHeader error_header;
                error_header.version = PROTOCOL_VERSION;
                error_header.command = CommandType::ERROR_RESPONSE;
                error_header.payload_size = serialize_error_response(error).size();
                error_header.file_id = data_header.file_id;
                error_header.block_index = data_header.block_index;
                error_header.total_blocks = data_header.total_blocks;
                send_packet(sock, error_header, serialize_error_response(error));
                file.close();
                close(sock);
                return;
            }

            // 发送块确认
            BlockAck ack;
            ack.success = true;
            ack.error_code = ErrorCode::SUCCESS;
            ack.block_index = data_header.block_index;
            PacketHeader ack_header;
            ack_header.version = PROTOCOL_VERSION;
            ack_header.command = CommandType::BLOCK_ACK;
            ack_header.payload_size = serialize_block_ack(ack).size();
            ack_header.file_id = data_header.file_id;
            ack_header.block_index = data_header.block_index;
            ack_header.total_blocks = data_header.total_blocks;
            if (!send_packet(sock, ack_header, serialize_block_ack(ack))) {
                std::cerr << "Failed to send block ACK" << std::endl;
                file.close();
                close(sock);
                return;
            }

            // 检查是否所有块都已接收
            if (data_header.block_index + 1 >= data_header.total_blocks) {
                break;
            }
        }
        // 处理传输完成通知
        else if (data_header.command == CommandType::TRANSFER_COMPLETE) {
            TransferComplete complete;
            if (deserialize_transfer_complete(data_payload, complete)) {
                std::cout << "File transfer completed. Success: " << std::boolalpha << complete.success << std::endl;
            }
            break;
        }
        // 处理错误情况
        else {
            std::cerr << "Unexpected command type: " << static_cast<int>(data_header.command) << std::endl;
            break;
        }
    }

    file.close();
    std::cout << "File saved to: " << file_path << std::endl;
}

void TCPServer::handle_download(SOCKET sock, const PacketHeader& header, const std::vector<uint8_t>& payload) {
    // 下载处理逻辑（根据需要实现）
    std::cout << "Handling download request (not fully implemented)" << std::endl;

    // 临时使用参数避免警告
    (void)header;
    (void)payload;
    
    // 发送错误响应表示未实现
    ErrorResponse error;
    error.error_code = ErrorCode::SUCCESS;
    error.message = "Download functionality not implemented";
    
    PacketHeader resp_header;
    resp_header.version = PROTOCOL_VERSION;
    resp_header.command = CommandType::ERROR_RESPONSE;
    resp_header.payload_size = serialize_error_response(error).size();
    resp_header.file_id = 0;
    resp_header.block_index = 0;
    resp_header.total_blocks = 0;
    
    send_packet(sock, resp_header, serialize_error_response(error));
}