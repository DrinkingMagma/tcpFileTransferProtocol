#ifndef FILE_TRANSFER_PROTOCOL_H
#define FILE_TRANSFER_PROTOCOL_H

#include <cstdint>
#include <string>
#include <vector>
#include <map>

// 类型定义和常量
typedef int SOCKET;
const SOCKET INVALID_SOCKET = -1;
const uint16_t PROTOCOL_VERSION = 1;
const uint32_t MAX_PACKET_SIZE = 1024 * 1024 * 2; // 2MB
const uint32_t DATA_BLOCK_SIZE = 1024 * 512;      // 512KB

// 命令类型
enum class CommandType : uint8_t {
    // 认证与会话管理
    AUTH_REQUEST = 1,
    AUTH_RESPONSE,
    
    // 文件传输命令
    UPLOAD_REQUEST,
    UPLOAD_RESPONSE,
    DOWNLOAD_REQUEST,
    DOWNLOAD_RESPONSE,
    
    // 数据传输与控制
    DATA_BLOCK,
    BLOCK_ACK,
    TRANSFER_COMPLETE,
    TRANSFER_ABORT,
    
    // 错误处理
    ERROR_RESPONSE,
    
    // 会话管理
    PING, // 心跳包，用于维持连接和检测对方状态
    PONG, // 心跳包响应
};

// 错误代码
enum class ErrorCode : uint8_t {
    SUCCESS = 0,
    AUTH_FAILED,
    FILE_NOT_FOUND,
    PERMISSION_DENIED,
    INVALID_PACKET,
    UNSUPPORTED_VERSION,
    TRANSFER_FAILED,
    INTERNAL_SERVER_ERROR,
    BLOCK_CHECKSUM_MISMATCH // 数据块校验和错误
};

// 通用数据包头部
struct PacketHeader {
    uint16_t version;
    CommandType command;
    uint32_t payload_size;
};

// 认证请求
struct AuthRequest {
    std::string username;
    std::string password_hash;
};

// 认证响应
struct AuthResponse {
    bool success;
    ErrorCode error_code;
    uint64_t session_id;
};

// 上传请求
struct UploadRequest {
    uint64_t session_id;
    std::string filename;
    uint64_t file_size;
    std::string file_hash;
};

// 上传响应
struct UploadResponse {
    bool accepted;
    ErrorCode error_code;
    uint64_t file_id;
    uint32_t start_block;
};

// 下载请求
struct DownloadRequest {
    uint64_t session_id;
    std::string filename;
    uint32_t start_block;
};

// 下载响应
struct DownloadResponse {
    bool found;
    ErrorCode error_code;
    uint64_t file_id;
    uint64_t file_size;
    uint32_t total_blocks;
    std::string file_hash;
};

// 数据块
struct DataBlock {
    uint64_t file_id;
    uint32_t block_index;
    uint32_t block_size;
    std::vector<uint8_t> data;
    uint32_t checksum;
};

// 块确认
struct BlockAck {
    uint64_t file_id;
    uint32_t block_index;
    bool success;
    ErrorCode error_code;
};

// 传输完成
struct TransferComplete {
    uint64_t file_id;
    bool success;
    ErrorCode error_code;
    std::string final_hash;
};

// 传输中止
struct TransferAbort {
    uint64_t file_id;
    std::string reason;
};

// 错误响应
struct ErrorResponse {
    ErrorCode error_code;
    std::string message;
};


namespace Protocol {
    // 通用辅助函数
    template<typename T>
    void serialize(std::vector<uint8_t>& buffer, const T& value);
    template<typename T>
    bool deserialize(const std::vector<uint8_t>& buffer, size_t& offset, T& value);
    uint64_t htonll(uint64_t value);
    uint64_t ntohll(uint64_t value);

    // 所有命令的序列化函数
    std::vector<uint8_t> serialize_header(const PacketHeader& header);
    std::vector<uint8_t> serialize_auth_request(const AuthRequest& req);
    std::vector<uint8_t> serialize_auth_response(const AuthResponse& resp);
    std::vector<uint8_t> serialize_upload_request(const UploadRequest& req);
    std::vector<uint8_t> serialize_upload_response(const UploadResponse& resp);
    std::vector<uint8_t> serialize_download_request(const DownloadRequest& req);
    std::vector<uint8_t> serialize_download_response(const DownloadResponse& resp);
    std::vector<uint8_t> serialize_data_block(const DataBlock& block);
    std::vector<uint8_t> serialize_block_ack(const BlockAck& ack);
    std::vector<uint8_t> serialize_transfer_complete(const TransferComplete& complete);
    std::vector<uint8_t> serialize_transfer_abort(const TransferAbort& abort);
    std::vector<uint8_t> serialize_error_response(const ErrorResponse& error);

    // 所有命令的反序列化函数
    bool deserialize_header(const std::vector<uint8_t>& data, PacketHeader& header);
    bool deserialize_auth_request(const std::vector<uint8_t>& data, AuthRequest& req);
    bool deserialize_auth_response(const std::vector<uint8_t>& data, AuthResponse& resp);
    bool deserialize_upload_request(const std::vector<uint8_t>& data, UploadRequest& req);
    bool deserialize_upload_response(const std::vector<uint8_t>& data, UploadResponse& resp);
    bool deserialize_download_request(const std::vector<uint8_t>& data, DownloadRequest& req);
    bool deserialize_download_response(const std::vector<uint8_t>& data, DownloadResponse& resp);
    bool deserialize_data_block(const std::vector<uint8_t>& data, DataBlock& block);
    bool deserialize_block_ack(const std::vector<uint8_t>& data, BlockAck& ack);
    bool deserialize_transfer_complete(const std::vector<uint8_t>& data, TransferComplete& complete);
    bool deserialize_transfer_abort(const std::vector<uint8_t>& data, TransferAbort& abort);
    bool deserialize_error_response(const std::vector<uint8_t>& data, ErrorResponse& error);
}

#endif // FILE_TRANSFER_PROTOCOL_H