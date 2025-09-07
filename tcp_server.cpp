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

    // 启动接受客户端连接的线程
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
    
    // 发送头部
    ssize_t bytes_sent = send(sock, reinterpret_cast<const char*>(header_data.data()), header_data.size(), 0);
    if (bytes_sent != static_cast<ssize_t>(header_data.size())) {
        std::cerr << "Failed to send header" << std::endl;
        return false;
    }

    // 发送 payload
    if (!payload.empty()) {
        bytes_sent = send(sock, reinterpret_cast<const char*>(payload.data()), payload.size(), 0);
        if (bytes_sent != static_cast<ssize_t>(payload.size())) {
            std::cerr << "Failed to send payload" << std::endl;
            return false;
        }
    }

    return true;
}

bool TCPServer::receive_packet(SOCKET sock, PacketHeader& header, std::vector<uint8_t>& payload) {
    // 接收头部
    std::vector<uint8_t> header_data(sizeof(PacketHeader));
    ssize_t bytes_received = recv(sock, reinterpret_cast<char*>(header_data.data()), header_data.size(), 0);
    if (bytes_received <= 0) {
        std::cerr << "Failed to receive header or connection closed" << std::endl;
        return false;
    }

    // 反序列化头部
    if (!deserialize_header(header_data, header)) {
        std::cerr << "Failed to deserialize header" << std::endl;
        return false;
    }

    // 检查协议版本
    if (header.version != PROTOCOL_VERSION) {
        std::cerr << "Unsupported protocol version" << std::endl;
        return false;
    }

    // 接收 payload
    if (header.payload_size > 0) {
        payload.resize(header.payload_size);
        bytes_received = recv(sock, reinterpret_cast<char*>(payload.data()), payload.size(), 0);
        if (bytes_received != static_cast<ssize_t>(payload.size())) {
            std::cerr << "Failed to receive payload" << std::endl;
            return false;
        }
    }

    return true;
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
        return;
    }

    // 接收数据块
    bool transfer_complete = false;
    while (!transfer_complete && running) {
        PacketHeader data_header;
        std::vector<uint8_t> data_payload;
        
        if (!receive_packet(sock, data_header, data_payload)) {
            std::cerr << "Failed to receive data packet" << std::endl;
            break;
        }

        if (data_header.file_id != file_id) {
            std::cerr << "Mismatched file ID" << std::endl;
            continue;
        }

        switch (data_header.command) {
            case CommandType::DATA_BLOCK: {
                // 写入数据块
                file.write(reinterpret_cast<const char*>(data_payload.data()), data_payload.size());
                if (!file) {
                    std::cerr << "Failed to write block " << data_header.block_index << std::endl;
                    
                    // 发送块确认（失败）
                    BlockAck ack;
                    ack.success = false;
                    ack.error_code = ErrorCode::TRANSFER_FAILED;
                    ack.block_index = data_header.block_index;
                    
                    PacketHeader ack_header;
                    ack_header.version = PROTOCOL_VERSION;
                    ack_header.command = CommandType::BLOCK_ACK;
                    ack_header.payload_size = serialize_block_ack(ack).size();
                    ack_header.file_id = file_id;
                    ack_header.block_index = data_header.block_index;
                    ack_header.total_blocks = data_header.total_blocks;
                    
                    send_packet(sock, ack_header, serialize_block_ack(ack));
                    return;
                }

                std::cout << "Received block " << data_header.block_index + 1 
                          << "/" << data_header.total_blocks << std::endl;

                // 发送块确认（成功）
                BlockAck ack;
                ack.success = true;
                ack.error_code = ErrorCode::SUCCESS;
                ack.block_index = data_header.block_index;
                
                PacketHeader ack_header;
                ack_header.version = PROTOCOL_VERSION;
                ack_header.command = CommandType::BLOCK_ACK;
                ack_header.payload_size = serialize_block_ack(ack).size();
                ack_header.file_id = file_id;
                ack_header.block_index = data_header.block_index;
                ack_header.total_blocks = data_header.total_blocks;
                
                send_packet(sock, ack_header, serialize_block_ack(ack));

                // 检查是否完成
                if (data_header.block_index == data_header.total_blocks - 1) {
                    transfer_complete = true;
                }
                break;
            }
            
            case CommandType::TRANSFER_COMPLETE: {
                transfer_complete = true;
                std::cout << "Upload completed for file: " << req.filename << std::endl;
                
                // 验证文件哈希 
                std::string received_hash = calculate_file_hash(file_path);
                if (received_hash == req.hash) {
                    std::cout << "File hash verified successfully" << std::endl;
                } else {
                    std::cerr << "File hash verification failed" << std::endl;
                }
                break;
            }
            
            case CommandType::TRANSFER_ABORT: {
                std::cout << "Upload aborted by client" << std::endl;
                return;
            }
            
            default:
                std::cerr << "Unexpected command type: " << static_cast<int>(data_header.command) << std::endl;
                break;
        }
    }
}

void TCPServer::handle_download(SOCKET sock, const PacketHeader& header, const std::vector<uint8_t>& payload) {
    // ? 显示标记header未使用
    (void)header;
    // 1. 解析下载请求
    DownloadRequest req;
    if (!deserialize_download_request(payload, req)) {
        std::cerr << "Failed to deserialize download request" << std::endl;
        
        // 发送错误响应
        ErrorResponse error;
        error.error_code = ErrorCode::INVALID_PACKET;
        error.message = "Invalid download request";
        
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

    // 2. 检查文件是否存在
    std::string file_path = download_dir + "/" + req.filename;
    if (!fs::exists(file_path) || !fs::is_regular_file(file_path)) {
        std::cerr << "File not found: " << file_path << std::endl;
        
        // 发送文件不存在的响应
        DownloadResponse resp;
        resp.found = false;
        resp.error_code = ErrorCode::FILE_NOT_FOUND;
        resp.file_id = 0;
        resp.file_size = 0;
        resp.total_blocks = 0;
        resp.hash = "";
        
        PacketHeader resp_header;
        resp_header.version = PROTOCOL_VERSION;
        resp_header.command = CommandType::DOWNLOAD_RESPONSE;
        resp_header.payload_size = serialize_download_response(resp).size();
        resp_header.file_id = 0;
        resp_header.block_index = 0;
        resp_header.total_blocks = 0;
        
        send_packet(sock, resp_header, serialize_download_response(resp));
        return;
    }

    // 3. 准备文件信息（计算大小、哈希、总块数等）
    uint64_t file_size = fs::file_size(file_path);
    std::string file_hash = calculate_file_hash(file_path); // 假设已有此函数
    uint32_t total_blocks = static_cast<uint32_t>((file_size + DATA_BLOCK_SIZE - 1) / DATA_BLOCK_SIZE);
    uint64_t file_id = std::hash<std::string>{}(req.filename + std::to_string(file_size));

    // 4. 发送下载响应（告知客户端可以开始下载）
    DownloadResponse resp;
    resp.found = true;
    resp.error_code = ErrorCode::SUCCESS;
    resp.file_id = file_id;
    resp.file_size = file_size;
    resp.total_blocks = total_blocks;
    resp.hash = file_hash;
    
    PacketHeader resp_header;
    resp_header.version = PROTOCOL_VERSION;
    resp_header.command = CommandType::DOWNLOAD_RESPONSE;
    resp_header.payload_size = serialize_download_response(resp).size();
    resp_header.file_id = file_id;
    resp_header.block_index = 0;
    resp_header.total_blocks = total_blocks;
    
    if (!send_packet(sock, resp_header, serialize_download_response(resp))) {
        std::cerr << "Failed to send download response" << std::endl;
        return;
    }

    // 5. 打开文件并发送数据块（从请求的start_block开始）
    std::ifstream file(file_path, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open file for reading: " << file_path << std::endl;
        // 发送错误响应（略）
        return;
    }

    // 6. 定位到起始块位置
    if (req.start_block > 0) {
        file.seekg(req.start_block * DATA_BLOCK_SIZE, std::ios::beg);
    }

    // 7. 循环发送数据块
    for (uint32_t i = req.start_block; i < total_blocks && running; ++i) {
        // 读取数据块
        std::vector<uint8_t> block_data(DATA_BLOCK_SIZE);
        file.read(reinterpret_cast<char*>(block_data.data()), DATA_BLOCK_SIZE);
        size_t bytes_read = file.gcount();
        if (bytes_read == 0) break;

        // 调整实际读取的大小（最后一块可能不满）
        block_data.resize(bytes_read);

        // 发送数据块
        PacketHeader data_header;
        data_header.version = PROTOCOL_VERSION;
        data_header.command = CommandType::DATA_BLOCK;
        data_header.payload_size = block_data.size();
        data_header.file_id = file_id;
        data_header.block_index = i;
        data_header.total_blocks = total_blocks;

        if (!send_packet(sock, data_header, block_data)) {
            std::cerr << "Failed to send block " << i << std::endl;
            return;
        }

        // 等待客户端确认
        PacketHeader ack_header;
        std::vector<uint8_t> ack_payload;
        if (!receive_packet(sock, ack_header, ack_payload) || 
            ack_header.command != CommandType::BLOCK_ACK) {
            std::cerr << "Failed to receive ack for block " << i << std::endl;
            return;
        }

        BlockAck ack;
        if (!deserialize_block_ack(ack_payload, ack) || !ack.success) {
            std::cerr << "Block " << i << " transfer failed" << std::endl;
            return;
        }

        std::cout << "Sent block " << i + 1 << "/" << total_blocks << std::endl;
    }

    // 8. 发送传输完成通知
    TransferComplete complete;
    complete.success = true;
    complete.error_code = ErrorCode::SUCCESS;
    complete.hash = file_hash;

    PacketHeader complete_header;
    complete_header.version = PROTOCOL_VERSION;
    complete_header.command = CommandType::TRANSFER_COMPLETE;
    complete_header.payload_size = serialize_transfer_complete(complete).size();
    complete_header.file_id = file_id;
    complete_header.block_index = total_blocks - 1;
    complete_header.total_blocks = total_blocks;

    send_packet(sock, complete_header, serialize_transfer_complete(complete));
    std::cout << "Download completed for file: " << req.filename << std::endl;
}

void TCPServer::handle_client(ClientConnection& client) {
    std::cout << "Handling new client connection" << std::endl;

    while (client.active && running) {
        PacketHeader header;
        std::vector<uint8_t> payload;
        
        if (!receive_packet(client.sockfd, header, payload)) {
            break;
        }

        // 根据命令类型处理
        switch (header.command) {
            case CommandType::UPLOAD_REQUEST:
                handle_upload(client.sockfd, header, payload);
                break;
                
            case CommandType::DOWNLOAD_REQUEST:
                handle_download(client.sockfd, header, payload);
                break;
                
            case CommandType::TRANSFER_ABORT:
                std::cout << "Client aborted transfer for file ID: " << header.file_id << std::endl;
                break;
                
            default:
                std::cerr << "Received unknown command: " << static_cast<int>(header.command) << std::endl;
                
                // 发送错误响应
                ErrorResponse error;
                error.error_code = ErrorCode::INVALID_PACKET;
                error.message = "Unknown command";
                
                PacketHeader error_header;
                error_header.version = PROTOCOL_VERSION;
                error_header.command = CommandType::ERROR_RESPONSE;
                error_header.payload_size = serialize_error_response(error).size();
                error_header.file_id = header.file_id;
                error_header.block_index = header.block_index;
                error_header.total_blocks = header.total_blocks;
                
                send_packet(client.sockfd, error_header, serialize_error_response(error));
                break;
        }
    }

    std::cout << "Client connection closed" << std::endl;

    // 清理客户端连接
    close(client.sockfd);  // Linux使用close()
    client.sockfd = INVALID_SOCKET;
    client.active = false;

    // 从客户端列表中移除
    {
        std::lock_guard<std::mutex> lock(client_mutex);
        auto it = std::remove_if(clients.begin(), clients.end(), [&](const ClientConnection& c) {
            return !c.active;
        });
        if (it != clients.end()) {
            clients.erase(it, clients.end());
        }
    }
}