#include "tcp_server.h"
#include "file_transfer_protocol.h"
#include <fstream>
#include <iostream>
#include <filesystem>
#include <sstream>
#include <algorithm>
#include <openssl/md5.h> // 需要OpenSSL库用于计算文件哈希
#include <cstring>       // 提供字符串操作函数

// 命名空间别名，简化文件系统操作代码
namespace fs = std::filesystem;

/**
 * @brief 构造函数，初始化服务器端口和目录
 * @param port 服务器监听端口
 * @param upload_dir 上传文件保存目录
 * @param download_dir 可供下载的文件目录
 */
TCPServer::TCPServer(uint16_t port, const std::string& upload_dir, const std::string& download_dir)
    : port(port), listen_sockfd(INVALID_SOCKET), running(false), 
      upload_dir(upload_dir), download_dir(download_dir) {
    // 创建上传和下载目录（如果不存在）
    fs::create_directories(upload_dir);
    fs::create_directories(download_dir);
}

/**
 * @brief 析构函数，停止服务器并释放资源
 */
TCPServer::~TCPServer() {
    stop();
}

/**
 * @brief 启动服务器，创建监听套接字并开始接受 * @return 启动 */
bool TCPServer::start() {
    if (running) return true; // 如果已运行则直接返回

    // 创建TCP套接字（IPv4，流式套接字）
    listen_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sockfd == INVALID_SOCKET) {
        std::cerr << "server: Failed to create socket" << std::endl;
        return false;
    }

    // 设置服务器地址结构
    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;                  // IPv4协议
    server_addr.sin_addr.s_addr = INADDR_ANY;          // 监听所有网络接口
    server_addr.sin_port = htons(port);                // 转换端口到网络字节序

    // 绑定套接字到指定端口
    if (bind(listen_sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        std::cerr << "server: Bind failed" << std::endl;
        close(listen_sockfd);  // 绑定失败时关闭套接字
        listen_sockfd = INVALID_SOCKET;
        return false;
    }

    // 开始监听连接请求，最大等待队列长度为5
    if (listen(listen_sockfd, 5) == SOCKET_ERROR) {
        std::cerr << "server: Listen failed" << std::endl;
        close(listen_sockfd);  // 监听失败时关闭套接字
        listen_sockfd = INVALID_SOCKET;
        return false;
    }

    running = true;
    std::cout << "server: Server started on port " << port << std::endl;

    // 启动接受客户端连接的线程
    std::thread accept_thread([this]() {
        while (running) {
            sockaddr_in client_addr;
            socklen_t client_addr_len = sizeof(client_addr);  // 客户端地址长度
            
            // 接受客户端连接
            SOCKET client_sock = accept(listen_sockfd, (struct sockaddr*)&client_addr, &client_addr_len);
            if (client_sock == INVALID_SOCKET) {
                if (running) {  // 如果服务器仍在运行，则输出错误
                    std::cerr << "server: Accept failed" << std::endl;
                }
                continue;
            }

            std::cout << "server: New client connected" << std::endl;

            // 创建客户端连接对象并启动处理线程
            ClientConnection client;
            client.sockfd = client_sock;
            client.address = client_addr;
            client.active = true;
            // 启动客户端处理线程
            client.handler_thread = std::thread(&TCPServer::handle_client, this, std::ref(client));

            // 将客户端添加到列表（线程安全）
            {
                std::lock_guard<std::mutex> lock(client_mutex);
                clients.push_back(std::move(client));
            }
        }
    });

    // 分离接受线程，使其独立运行
    accept_thread.detach();

    return true;
}

/**
 * @brief 停止服务器，关闭所有套接字和线程
 */
void TCPServer::stop() {
    if (!running) return;  // 如果已停止则直接返回

    running = false;
    std::cout << "server: Stopping server..." << std::endl;

    // 关闭监听套接字
    if (listen_sockfd != INVALID_SOCKET) {
        close(listen_sockfd);  // Linux使用close()关闭套接字
        listen_sockfd = INVALID_SOCKET;
    }

    // 关闭所有客户端连接
    {
        std::lock_guard<std::mutex> lock(client_mutex);
        for (auto& client : clients) {
            client.active = false;
            if (client.sockfd != INVALID_SOCKET) {
                close(client.sockfd);  // 关闭客户端套接字
            }
            if (client.handler_thread.joinable()) {
                client.handler_thread.join();  // 等待客户端线程结束
            }
        }
        clients.clear();  // 清空客户端列表
    }

    std::cout << "server: Server stopped" << std::endl;
}

/**
 * @brief 设置上传目录
 * @param dir 新的上传目录路径
 */
void TCPServer::set_upload_directory(const std::string& dir) {
    upload_dir = dir;
    fs::create_directories(upload_dir);  // 确保目录存在
}

/**
 * @brief 设置下载目录
 * @param dir 新的下载目录路径
 */
void TCPServer::set_download_directory(const std::string& dir) {
    download_dir = dir;
    fs::create_directories(download_dir);  // 确保目录存在
}

/**
 * @brief 向客户端发送数据包
 * @param sock 客户端套接字
 * @param header 数据包头部
 * @param payload 数据载荷
 * @return 发送成功返回true，否则返回false
 */
bool TCPServer::send_packet(SOCKET sock, const PacketHeader& header, const std::vector<uint8_t>& payload) {
    // 序列化头部为字节流
    std::vector<uint8_t> header_data = serialize_header(header);
    
    // 发送头部
    ssize_t bytes_sent = send(sock, reinterpret_cast<const char*>(header_data.data()), header_data.size(), 0);
    if (bytes_sent != static_cast<ssize_t>(header_data.size())) {
        std::cerr << "server: Failed to send header" << std::endl;
        return false;
    }

    // 发送数据载荷（如果有）
    if (!payload.empty()) {
        bytes_sent = send(sock, reinterpret_cast<const char*>(payload.data()), payload.size(), 0);
        if (bytes_sent != static_cast<ssize_t>(payload.size())) {
            std::cerr << "server: Failed to send payload" << std::endl;
            return false;
        }
    }

    return true;
}

/**
 * @brief 从客户端接收数据包
 * @param sock 客户端套接字
 * @param header 用于存储接收的数据包头部
 * @param payload 用于存储接收的数据载荷
 * @return 接收成功返回true，否则返回false
 */
bool TCPServer::receive_packet(SOCKET sock, PacketHeader& header, std::vector<uint8_t>& payload) {
    // 接收头部
    std::vector<uint8_t> header_data(sizeof(PacketHeader));
    ssize_t bytes_received = recv(sock, reinterpret_cast<char*>(header_data.data()), header_data.size(), 0);
    if (bytes_received <= 0) {
        std::cerr << "server: Failed to receive header or connection closed" << std::endl;
        return false;
    }

    // 反序列化头部
    if (!deserialize_header(header_data, header)) {
        std::cerr << "server: Failed to deserialize header" << std::endl;
        return false;
    }

    // 检查协议版本是否匹配
    if (header.version != PROTOCOL_VERSION) {
        std::cerr << "server: Unsupported protocol version" << std::endl;
        return false;
    }

    // 接收数据载荷（如果有）
    if (header.payload_size > 0) {
        ssize_t total_received = 0;
        auto data_ptr = reinterpret_cast<char*>(payload.data());
        size_t remaining = payload.size();

        while (static_cast<size_t>(total_received) < payload.size()) {
            ssize_t bytes_received = recv(sock, data_ptr + total_received, remaining, 0);
            
            if (bytes_received < 0) {
                std::cerr << "server: Receive error: " << strerror(errno) << std::endl;
                return false;
            } else if (bytes_received == 0) {
                std::cerr << "server: Connection closed by peer" << std::endl;
                return false;
            }
            
            total_received += bytes_received;
            remaining -= bytes_received;
        }

        // 全部接收完成
        std::cout << "server: Successfully received all " << total_received << " bytes" << std::endl;
    }

    return true;
}

/**
 * @brief 处理客户端上传请求
 * @param sock 客户端套接字
 * @param header 接收到的数据包头部
 * @param payload 接收到的数据载荷
 */
void TCPServer::handle_upload(SOCKET sock, const PacketHeader& header, const std::vector<uint8_t>& payload) {
    UploadRequest req;
    // 反序列化上传请求
    if (!deserialize_upload_request(payload, req)) {
        std::cerr << "server: Failed to deserialize upload request" << std::endl;
        
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

    std::cout << "server: Received upload request for file: " << req.filename 
              << ", size: " << req.file_size << std::endl;

    // 生成唯一文件ID（基于文件名和当前时间）
    uint64_t file_id = std::hash<std::string>{}(req.filename + std::to_string(time(nullptr)));
    
    // 构建文件保存路径
    std::string file_path = upload_dir + "/" + req.filename;
    
    // 检查是否可以断点续传
    uint32_t start_block = 0;
    if (fs::exists(file_path) && fs::is_regular_file(file_path)) {
        uint64_t existing_size = fs::file_size(file_path);
        if (existing_size < req.file_size) {
            // 文件存在但不完整，可以续传
            start_block = static_cast<uint32_t>(existing_size / DATA_BLOCK_SIZE);
            std::cout << "server: Resuming upload from block: " << start_block << std::endl;
        } else if (existing_size == req.file_size) {
            // 文件已存在且完整
            std::cout << "server: File already exists and is complete" << std::endl;
            
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

    // 发送上传响应（接受上传）
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
        std::cerr << "server: Failed to send upload response" << std::endl;
        return;
    }

    // 打开文件准备写入（追加模式，如果是续传）
    std::ofstream file(file_path, std::ios::binary | (start_block > 0 ? std::ios::app : std::ios::trunc));
    if (!file) {
        std::cerr << "server: Failed to open file for writing: " << file_path << std::endl;
        
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

    // 循环接收数据块
    uint32_t total_blocks = header.total_blocks;
    for (uint32_t i = start_block; i < total_blocks; ++i) {
        PacketHeader data_header;
        std::vector<uint8_t> data_payload;
        
        // 接收数据块
        if (!receive_packet(sock, data_header, data_payload)) {
            std::cerr << "server: Failed to receive data block " << i << std::endl;
            file.close();
            return;
        }
        
        // 验证数据包信息
        if (data_header.command != CommandType::DATA_BLOCK || 
            data_header.file_id != file_id || 
            data_header.block_index != i) {
            std::cerr << "server: Invalid data block " << i << std::endl;
            
            // 发送错误确认
            BlockAck ack;
            ack.success = false;
            ack.error_code = ErrorCode::INVALID_PACKET;
            ack.block_index = i;
            
            PacketHeader ack_header;
            ack_header.version = PROTOCOL_VERSION;
            ack_header.command = CommandType::BLOCK_ACK;
            ack_header.payload_size = serialize_block_ack(ack).size();
            ack_header.file_id = file_id;
            ack_header.block_index = i;
            ack_header.total_blocks = total_blocks;
            
            send_packet(sock, ack_header, serialize_block_ack(ack));
            file.close();
            return;
        }
        
        // 写入数据块到文件
        file.write(reinterpret_cast<const char*>(data_payload.data()), data_payload.size());
        if (!file) {
            std::cerr << "server: Failed to write data block " << i << " to file" << std::endl;
            
            // 发送错误确认
            BlockAck ack;
            ack.success = false;
            ack.error_code = ErrorCode::PERMISSION_DENIED;
            ack.block_index = i;
            
            PacketHeader ack_header;
            ack_header.version = PROTOCOL_VERSION;
            ack_header.command = CommandType::BLOCK_ACK;
            ack_header.payload_size = serialize_block_ack(ack).size();
            ack_header.file_id = file_id;
            ack_header.block_index = i;
            ack_header.total_blocks = total_blocks;
            
            send_packet(sock, ack_header, serialize_block_ack(ack));
            file.close();
            return;
        }
        
        // 发送成功确认
        BlockAck ack;
        ack.success = true;
        ack.error_code = ErrorCode::SUCCESS;
        ack.block_index = i;
        
        PacketHeader ack_header;
        ack_header.version = PROTOCOL_VERSION;
        ack_header.command = CommandType::BLOCK_ACK;
        ack_header.payload_size = serialize_block_ack(ack).size();
        ack_header.file_id = file_id;
        ack_header.block_index = i;
        ack_header.total_blocks = total_blocks;
        
        if (!send_packet(sock, ack_header, serialize_block_ack(ack))) {
            std::cerr << "server: Failed to send ACK for block " << i << std::endl;
            file.close();
            return;
        }
        
        std::cout << "server: Received block " << i + 1 << "/" << total_blocks << std::endl;
    }
    
    file.close(); // 关闭文件
    
    // 接收传输完成通知
    PacketHeader complete_header;
    std::vector<uint8_t> complete_payload;
    if (!receive_packet(sock, complete_header, complete_payload)) {
        std::cerr << "server: Failed to receive transfer complete notification" << std::endl;
        return;
    }
    
    if (complete_header.command != CommandType::TRANSFER_COMPLETE || 
        complete_header.file_id != file_id) {
        std::cerr << "server: Invalid transfer complete notification" << std::endl;
        return;
    }
    
    // 验证文件哈希
    TransferComplete complete;
    if (!deserialize_transfer_complete(complete_payload, complete)) {
        std::cerr << "server: Failed to deserialize transfer complete notification" << std::endl;
        return;
    }
    
    std::string received_hash = complete.hash;
    std::string calculated_hash = calculate_file_hash(file_path);
    
    if (received_hash != calculated_hash) {
        std::cerr << "server: File hash mismatch. Upload corrupted." << std::endl;
        std::cerr << "server: Received hash: " << received_hash << std::endl;
        std::cerr << "server: Calculated hash: " << calculated_hash << std::endl;
        
        // 发送错误响应
        ErrorResponse error;
        error.error_code = ErrorCode::TRANSFER_FAILED;
        error.message = "File hash mismatch. Upload corrupted.";
        
        PacketHeader error_header;
        error_header.version = PROTOCOL_VERSION;
        error_header.command = CommandType::ERROR_RESPONSE;
        error_header.payload_size = serialize_error_response(error).size();
        error_header.file_id = file_id;
        error_header.block_index = 0;
        error_header.total_blocks = total_blocks;
        
        send_packet(sock, error_header, serialize_error_response(error));
        return;
    }
    
    std::cout << "server: File upload completed successfully. Hash verified." << std::endl;
}

/**
 * @brief 处理客户端下载请求
 * @param sock 客户端套接字
 * @param header 接收到的数据包头部
 * @param payload 接收到的数据载荷
 */
void TCPServer::handle_download(SOCKET sock, const PacketHeader& header, const std::vector<uint8_t>& payload) {
    DownloadRequest req;
    
    // 显示说明未使用header
    (void)header;

    // 反序列化下载请求
    if (!deserialize_download_request(payload, req)) {
        std::cerr << "server: Failed to deserialize download request" << std::endl;
        
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

    std::cout << "server: Received download request for file: " << req.filename << std::endl;
    
    // 构建文件路径
    std::string file_path = download_dir + "/" + req.filename;
    
    // 检查文件是否存在
    if (!fs::exists(file_path) || !fs::is_regular_file(file_path)) {
        std::cerr << "server: File not found: " << file_path << std::endl;
        
        // 发送下载响应（文件未找到）
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
    
    // 获取文件信息
    uint64_t file_size = fs::file_size(file_path);
    std::string file_hash = calculate_file_hash(file_path);
    uint32_t total_blocks = static_cast<uint32_t>((file_size + DATA_BLOCK_SIZE - 1) / DATA_BLOCK_SIZE);
    uint64_t file_id = std::hash<std::string>{}(req.filename + std::to_string(file_size));
    
    // 检查请求的起始块是否有效
    uint32_t start_block = req.start_block;
    if (start_block >= total_blocks) {
        std::cerr << "server: Invalid start block: " << start_block << std::endl;
        
        // 发送错误响应
        ErrorResponse error;
        error.error_code = ErrorCode::INVALID_PACKET;
        error.message = "Invalid start block";
        
        PacketHeader error_header;
        error_header.version = PROTOCOL_VERSION;
        error_header.command = CommandType::ERROR_RESPONSE;
        error_header.payload_size = serialize_error_response(error).size();
        error_header.file_id = file_id;
        error_header.block_index = 0;
        error_header.total_blocks = total_blocks;
        
        send_packet(sock, error_header, serialize_error_response(error));
        return;
    }
    
    // 发送下载响应（文件找到）
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
        std::cerr << "server: Failed to send download response" << std::endl;
        return;
    }
    
    // 打开文件准备读取
    std::ifstream file(file_path, std::ios::binary);
    if (!file) {
        std::cerr << "server: Failed to open file for reading: " << file_path << std::endl;
        
        // 发送错误响应
        ErrorResponse error;
        error.error_code = ErrorCode::PERMISSION_DENIED;
        error.message = "Failed to open file for reading";
        
        PacketHeader error_header;
        error_header.version = PROTOCOL_VERSION;
        error_header.command = CommandType::ERROR_RESPONSE;
        error_header.payload_size = serialize_error_response(error).size();
        error_header.file_id = file_id;
        error_header.block_index = 0;
        error_header.total_blocks = total_blocks;
        
        send_packet(sock, error_header, serialize_error_response(error));
        return;
    }
    
    // 定位到起始块位置
    if (start_block > 0) {
        file.seekg(static_cast<std::streamoff>(start_block) * DATA_BLOCK_SIZE);
    }
    
    // 发送数据块
    for (uint32_t i = start_block; i < total_blocks; ++i) {
        // 读取数据块
        DataBlock block;
        block.data.resize(DATA_BLOCK_SIZE);
        file.read(reinterpret_cast<char*>(block.data.data()), DATA_BLOCK_SIZE);
        block.data.resize(file.gcount()); // 调整最后一块的大小
        
        // 发送数据块
        PacketHeader data_header;
        data_header.version = PROTOCOL_VERSION;
        data_header.command = CommandType::DATA_BLOCK;
        data_header.payload_size = block.data.size();
        data_header.file_id = file_id;
        data_header.block_index = i;
        data_header.total_blocks = total_blocks;
        
        if (!send_packet(sock, data_header, block.data)) {
            std::cerr << "server: Failed to send data block " << i << std::endl;
            file.close();
            return;
        }
        
        // 等待确认
        PacketHeader ack_header;
        std::vector<uint8_t> ack_payload;
        if (!receive_packet(sock, ack_header, ack_payload)) {
            std::cerr << "server: Failed to receive ACK for block " << i << std::endl;
            file.close();
            return;
        }
        
        if (ack_header.command != CommandType::BLOCK_ACK || 
            ack_header.file_id != file_id || 
            ack_header.block_index != i) {
            std::cerr << "server: Invalid ACK for block " << i << std::endl;
            file.close();
            return;
        }
        
        // 解析确认包
        BlockAck ack;
        if (!deserialize_block_ack(ack_payload, ack)) {
            std::cerr << "server: Failed to deserialize block ACK" << std::endl;
            file.close();
            return;
        }
        
        if (!ack.success) {
            std::cerr << "server: Block " << i << " rejected. Error code: " << static_cast<int>(ack.error_code) << std::endl;
            file.close();
            return;
        }
        
        std::cout << "server: Sent block " << i + 1 << "/" << total_blocks << std::endl;
    }
    
    file.close(); // 关闭文件
    
    std::cout << "server: File download completed successfully" << std::endl;
}

/**
 * @brief 处理客户端连接的主函数，循环接收并处理请求
 * @param client 客户端连接对象
 */
void TCPServer::handle_client(ClientConnection& client) {
    std::cout << "server: Handling new client connection" << std::endl;
    
    while (client.active) {
        PacketHeader header;
        std::vector<uint8_t> payload;
        
        // 接收数据包
        if (!receive_packet(client.sockfd, header, payload)) {
            break; // 接收失败或连接关闭，退出循环
        }
        
        // 根据命令类型处理不同请求
        switch (header.command) {
            case CommandType::UPLOAD_REQUEST:
                handle_upload(client.sockfd, header, payload);
                break;
                
            case CommandType::DOWNLOAD_REQUEST:
                handle_download(client.sockfd, header, payload);
                break;
                
            case CommandType::TRANSFER_ABORT:
                std::cout << "server: Client aborted transfer" << std::endl;
                // 处理传输中止
                break;
                
            default:
                std::cerr << "server: Received unknown command type: " << static_cast<int>(header.command) << std::endl;
                // 发送错误响应
                ErrorResponse error;
                error.error_code = ErrorCode::INVALID_PACKET;
                error.message = "Unknown command type";
                
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
    
    std::cout << "server: Client disconnected" << std::endl;
    
    // 关闭客户端套接字
    if (client.sockfd != INVALID_SOCKET) {
        close(client.sockfd);
        client.sockfd = INVALID_SOCKET;
    }
    
    // 从客户端列表中移除
    {
        std::lock_guard<std::mutex> lock(client_mutex);
        auto it = std::remove_if(clients.begin(), clients.end(),
            [&](const ClientConnection& c) { return !c.active; });
        if (it != clients.end()) {
            clients.erase(it, clients.end());
        }
    }
}