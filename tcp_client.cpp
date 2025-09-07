#include "tcp_client.h"
#include "file_transfer_protocol.h"
#include <fstream>
#include <iostream>
#include <filesystem>
#include <sstream>
#include <openssl/md5.h> // 需要OpenSSL库
#include <cstring>       // 添加cstring头文件
#include <iomanip>       // 添加iomanip头文件

namespace fs = std::filesystem;

TCPClient::TCPClient(const std::string& ip, uint16_t port) 
    : server_ip(ip), server_port(port), sockfd(INVALID_SOCKET), connected(false) {
    // Linux下不需要初始化Winsock
}

TCPClient::~TCPClient() {
    disconnect();
    // Linux下不需要WSACleanup()
}

bool TCPClient::connect_to_server() {
    if (connected) return true;

    // 创建套接字
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == INVALID_SOCKET) {
        std::cerr << "Failed to create socket" << std::endl;
        return false;
    }

    // 设置服务器地址
    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address/ Address not supported" << std::endl;
        close(sockfd);  // Linux使用close()
        sockfd = INVALID_SOCKET;
        return false;
    }

    // 连接到服务器
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Connection failed" << std::endl;
        close(sockfd);  // Linux使用close()
        sockfd = INVALID_SOCKET;
        return false;
    }

    connected = true;
    return true;
}

void TCPClient::disconnect() {
    if (connected && sockfd != INVALID_SOCKET) {
        close(sockfd);  // Linux使用close()
        sockfd = INVALID_SOCKET;
        connected = false;
    }
}

bool TCPClient::send_packet(const PacketHeader& header, const std::vector<uint8_t>& payload) {
    if (!connected) return false;

    // 序列化头部
    std::vector<uint8_t> header_data = serialize_header(header);
    
    // 发送头部
    ssize_t bytes_sent = send(sockfd, reinterpret_cast<const char*>(header_data.data()), header_data.size(), 0);
    if (bytes_sent != static_cast<ssize_t>(header_data.size())) {
        std::cerr << "Failed to send header" << std::endl;
        return false;
    }

    // 发送 payload
    if (!payload.empty()) {
        bytes_sent = send(sockfd, reinterpret_cast<const char*>(payload.data()), payload.size(), 0);
        if (bytes_sent != static_cast<ssize_t>(payload.size())) {
            std::cerr << "Failed to send payload" << std::endl;
            return false;
        }
    }

    return true;
}

bool TCPClient::receive_packet(PacketHeader& header, std::vector<uint8_t>& payload) {
    if (!connected) return false;

    // 接收头部
    std::vector<uint8_t> header_data(sizeof(PacketHeader));
    ssize_t bytes_received = recv(sockfd, reinterpret_cast<char*>(header_data.data()), header_data.size(), 0);
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
        bytes_received = recv(sockfd, reinterpret_cast<char*>(payload.data()), payload.size(), 0);
        if (bytes_received != static_cast<ssize_t>(payload.size())) {
            std::cerr << "Failed to receive payload" << std::endl;
            return false;
        }
    }

    return true;
}
 
bool TCPClient::upload_file(const std::string& local_path, 
                           const std::string& remote_filename,
                           std::function<void(uint32_t, uint32_t)> progress_callback) {
    if (!connected) {
        if (!connect_to_server()) {
            return false;
        }
    }

    // 检查文件是否存在
    if (!fs::exists(local_path) || !fs::is_regular_file(local_path)) {
        std::cerr << "File not found or is not a regular file: " << local_path << std::endl;
        return false;
    }

    // 获取文件信息
    uint64_t file_size = fs::file_size(local_path);
    std::string file_hash = calculate_file_hash(local_path);
    uint32_t total_blocks = static_cast<uint32_t>((file_size + DATA_BLOCK_SIZE - 1) / DATA_BLOCK_SIZE);

    // 发送上传请求
    UploadRequest req;
    req.filename = remote_filename;
    req.file_size = file_size;
    req.hash = file_hash;

    PacketHeader header;
    header.version = PROTOCOL_VERSION;
    header.command = CommandType::UPLOAD_REQUEST;
    header.payload_size = serialize_upload_request(req).size();
    header.file_id = 0; // 上传请求时文件ID由服务器分配
    header.block_index = 0;
    header.total_blocks = total_blocks;

    if (!send_packet(header, serialize_upload_request(req))) {
        std::cerr << "Failed to send upload request" << std::endl;
        return false;
    }

    // 接收上传响应
    std::vector<uint8_t> response_payload;
    if (!receive_packet(header, response_payload)) {
        std::cerr << "Failed to receive upload response" << std::endl;
        return false;
    }

    if (header.command != CommandType::UPLOAD_RESPONSE) {
        std::cerr << "Unexpected response to upload request" << std::endl;
        return false;
    }

    UploadResponse resp;
    if (!deserialize_upload_response(response_payload, resp)) {
        std::cerr << "Failed to deserialize upload response" << std::endl;
        return false;
    }

    if (!resp.accepted) {
        std::cerr << "Upload rejected. Error code: " << static_cast<int>(resp.error_code) << std::endl;
        return false;
    }

    uint64_t file_id = resp.file_id;
    uint32_t start_block = resp.start_block;

    std::cout << "Upload accepted. File ID: " << file_id 
              << ", Starting from block: " << start_block << std::endl;

    // 打开文件准备读取
    std::ifstream file(local_path, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open file for reading: " << local_path << std::endl;
        return false;
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
        header.version = PROTOCOL_VERSION;
        header.command = CommandType::DATA_BLOCK;
        header.payload_size = block.data.size();
        header.file_id = file_id;
        header.block_index = i;
        header.total_blocks = total_blocks;

        if (!send_packet(header, block.data)) {
            std::cerr << "Failed to send data block " << i << std::endl;
            return false;
        }

        // 等待确认
        std::vector<uint8_t> ack_payload;
        if (!receive_packet(header, ack_payload)) {
            std::cerr << "Failed to receive ACK for block " << i << std::endl;
            return false;
        }

        if (header.command != CommandType::BLOCK_ACK) {
            std::cerr << "Unexpected response to data block " << i << std::endl;
            return false;
        }

        // 初始化ack变量并反序列化
        BlockAck ack{};  // 使用值初始化，确保所有成员都有初始值
        if (!deserialize_block_ack(ack_payload, ack)) {
            std::cerr << "Failed to deserialize block ack" << std::endl;
            return false;
        }

        if (!ack.success) {
            std::cerr << "Block " << i << " rejected. Error code: " << static_cast<int>(ack.error_code) << std::endl;
            return false;
        }

        if (!ack.success) {
            std::cerr << "Block " << i << " rejected. Error code: " << static_cast<int>(ack.error_code) << std::endl;
            return false;
        }

        // 调用进度回调
        if (progress_callback) {
            progress_callback(i + 1, total_blocks);
        }

        std::cout << "Sent block " << i + 1 << "/" << total_blocks << std::endl;
    }

    // 发送传输完成通知
    TransferComplete complete;
    complete.success = true;
    complete.error_code = ErrorCode::SUCCESS;
    complete.hash = file_hash;

    header.version = PROTOCOL_VERSION;
    header.command = CommandType::TRANSFER_COMPLETE;
    header.payload_size = serialize_transfer_complete(complete).size();
    header.file_id = file_id;
    header.block_index = 0;
    header.total_blocks = total_blocks;

    if (!send_packet(header, serialize_transfer_complete(complete))) {
        std::cerr << "Failed to send transfer complete notification" << std::endl;
        return false;
    }

    std::cout << "File upload completed successfully" << std::endl;
    return true;
}

bool TCPClient::download_file(const std::string& remote_filename,
                               const std::string& local_path,
                               std::function<void(uint32_t, uint32_t)> progress_callback) {
    if (!connected) {
        if (!connect_to_server()) {
            return false;
        }
    }

    // 1. 发送下载请求
    DownloadRequest req;
    req.filename = remote_filename;

    PacketHeader header;
    header.version = PROTOCOL_VERSION;
    header.command = CommandType::DOWNLOAD_REQUEST;
    header.payload_size = serialize_download_request(req).size();
    header.file_id = 0;
    header.block_index = 0;
    header.total_blocks = 0;

    if (!send_packet(header, serialize_download_request(req))) {
        std::cerr << "Failed to send download request" << std::endl;
        return false;
    }

    // 2. 接收服务器响应
    std::vector<uint8_t> response_payload;
    if (!receive_packet(header, response_payload)) {
        std::cerr << "Failed to receive download response" << std::endl;
        return false;
    }

    if (header.command != CommandType::DOWNLOAD_RESPONSE) {
        std::cerr << "Unexpected response to download request" << std::endl;
        return false;
    }

    DownloadResponse resp;
    if (!deserialize_download_response(response_payload, resp)) {
        std::cerr << "Failed to deserialize download response" << std::endl;
        return false;
    }

    // 使用 resp.found 字段进行判断
    if (!resp.found) {
        std::cerr << "Download rejected. Error code: " << static_cast<int>(resp.error_code) << std::endl;
        return false;
    }

    uint64_t file_id = resp.file_id;
    uint64_t file_size = resp.file_size;
    std::string file_hash_remote = resp.hash;
    uint32_t total_blocks = static_cast<uint32_t>((file_size + DATA_BLOCK_SIZE - 1) / DATA_BLOCK_SIZE);

    std::cout << "Download accepted. File ID: " << file_id
              << ", Total blocks: " << total_blocks << std::endl;

    // 3. 打开文件准备写入
    std::ofstream file(local_path, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open file for writing: " << local_path << std::endl;
        return false;
    }

    // 4. 接收数据块并写入文件
    for (uint32_t i = 0; i < total_blocks; ++i) {
        std::vector<uint8_t> data_block_payload;
        if (!receive_packet(header, data_block_payload)) {
            std::cerr << "Failed to receive data block " << i << std::endl;
            return false;
        }

        if (header.command != CommandType::DATA_BLOCK || header.block_index != i) {
            std::cerr << "Unexpected response for block " << i << std::endl;
            return false;
        }

        file.write(reinterpret_cast<const char*>(data_block_payload.data()), data_block_payload.size());
        
        // 5. 发送块确认
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

        if (!send_packet(ack_header, serialize_block_ack(ack))) {
            std::cerr << "Failed to send ACK for block " << i << std::endl;
            return false;
        }

        // 调用进度回调
        if (progress_callback) {
            progress_callback(i + 1, total_blocks);
        }
        std::cout << "Received block " << i + 1 << "/" << total_blocks << std::endl;
    }
    
    file.close();

    // 6. 接收传输完成通知并进行校验
    std::vector<uint8_t> complete_payload;
    if (!receive_packet(header, complete_payload)) {
        std::cerr << "Failed to receive transfer complete notification" << std::endl;
        return false;
    }

    if (header.command != CommandType::TRANSFER_COMPLETE) {
        std::cerr << "Unexpected response after all blocks received" << std::endl;
        return false;
    }

    TransferComplete complete_data;
    if (!deserialize_transfer_complete(complete_payload, complete_data)) {
        std::cerr << "Failed to deserialize transfer complete" << std::endl;
        return false;
    }
    
    // 校验哈希值
    std::string file_hash_local = calculate_file_hash(local_path);
    if (file_hash_local != file_hash_remote) {
        std::cerr << "File hash mismatch! Downloaded file may be corrupted." << std::endl;
        return false;
    }

    std::cout << "File downloaded and verified successfully." << std::endl;
    return true; 
}

bool TCPClient::abort_transfer(uint64_t file_id, const std::string& reason) {
    if (!connected) return false;

    TransferAbort abort;
    abort.reason = reason;

    PacketHeader header;
    header.version = PROTOCOL_VERSION;
    header.command = CommandType::TRANSFER_ABORT;
    header.payload_size = serialize_transfer_abort(abort).size();
    header.file_id = file_id;
    header.block_index = 0;
    header.total_blocks = 0;

    return send_packet(header, serialize_transfer_abort(abort));
}