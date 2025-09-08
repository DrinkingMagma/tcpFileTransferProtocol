#ifndef FILE_TRANSFER_PROTOCOL_H
#define FILE_TRANSFER_PROTOCOL_H

#include <cstdint>
#include <string>
#include <vector>

// 协议常量定义
// 在 Linux 中，SOCKET 实际上是 int 类型
typedef int SOCKET;
const SOCKET INVALID_SOCKET = -1;
const uint16_t PROTOCOL_VERSION = 1;
const uint32_t MAX_PACKET_SIZE = 1024 * 1024; // 1MB
const uint32_t DATA_BLOCK_SIZE = 1024 * 512;  // 512KB数据块
constexpr size_t HEADER_SERIALIZED_SIZE = 23;


// 命令类型
enum class CommandType : uint8_t {
    UPLOAD_REQUEST = 1,    // 上传请求
    UPLOAD_RESPONSE,       // 上传响应
    DOWNLOAD_REQUEST,      // 下载请求
    DOWNLOAD_RESPONSE,     // 下载响应
    DATA_BLOCK,            // 数据块
    BLOCK_ACK,             // 数据块确认
    TRANSFER_COMPLETE,     // 传输完成
    TRANSFER_ABORT,        // 传输中止
    ERROR_RESPONSE         // 错误响应
};

// 错误代码
enum class ErrorCode : uint8_t {
    SUCCESS = 0,
    FILE_NOT_FOUND,
    PERMISSION_DENIED,
    INVALID_PACKET,
    UNSUPPORTED_VERSION,
    TRANSFER_FAILED,
    UNKNOWN_ERROR
};

// 数据包头部结构
struct PacketHeader {
    uint16_t version;      // 协议版本
    CommandType command;   // 命令类型
    uint32_t payload_size; // 有效载荷大小
    uint64_t file_id;      // 文件唯一标识
    uint32_t block_index;  // 块索引
    uint32_t total_blocks; // 总块数
};

// 上传请求 payload
struct UploadRequest {
    std::string filename;  // 文件名
    uint64_t file_size;    // 文件大小
    std::string hash;      // 文件哈希值，用于校验
};

// 上传响应 payload
struct UploadResponse {
    bool accepted;         // 是否接受上传
    ErrorCode error_code;  // 错误代码
    uint64_t file_id;      // 服务器分配的文件ID
    uint32_t start_block;  // 开始传输的块索引(用于断点续传)
};

// 下载请求 payload
struct DownloadRequest {
    std::string filename;  // 文件名
    uint32_t start_block;  // 开始下载的块索引(用于断点续传)
};

// 下载响应 payload
struct DownloadResponse {
    bool found;            // 是否找到文件
    ErrorCode error_code;  // 错误代码
    uint64_t file_id;      // 文件ID
    uint64_t file_size;    // 文件大小
    uint32_t total_blocks; // 总块数
    std::string hash;      // 文件哈希值
};

// 数据块 payload
struct DataBlock {
    std::vector<uint8_t> data; // 数据内容
};

// 块确认 payload
struct BlockAck {
    bool success;          // 是否成功接收
    ErrorCode error_code;  // 错误代码
    uint32_t block_index;  // 已接收的块索引
};

// 传输完成 payload
struct TransferComplete {
    bool success;          // 是否成功完成
    ErrorCode error_code;  // 错误代码
    std::string hash;      // 接收方计算的哈希值
};

// 传输中止 payload
struct TransferAbort {
    std::string reason;    // 中止原因
};

// 错误响应 payload
struct ErrorResponse {
    ErrorCode error_code;  // 错误代码
    std::string message;   // 错误信息
};

// 序列化和反序列化函数声明
std::vector<uint8_t> serialize_header(const PacketHeader& header);
bool deserialize_header(const std::vector<uint8_t>& data, PacketHeader& header);

std::vector<uint8_t> serialize_upload_request(const UploadRequest& req);
bool deserialize_upload_request(const std::vector<uint8_t>& data, UploadRequest& req);

std::vector<uint8_t> serialize_upload_response(const UploadResponse& resp);
bool deserialize_upload_response(const std::vector<uint8_t>& data, UploadResponse& resp);

std::vector<uint8_t> serialize_error_response(const ErrorResponse& error);
bool deserialize_error_response(const std::vector<uint8_t>& data, ErrorResponse& error);
// 块确认相关的序列化和反序列化函数
std::vector<uint8_t> serialize_block_ack(const BlockAck& ack);
bool deserialize_block_ack(const std::vector<uint8_t>& data, BlockAck& ack);

std::vector<uint8_t> serialize_transfer_complete(const TransferComplete& complete);
bool deserialize_transfer_complete(const std::vector<uint8_t>& data, TransferComplete& complete);

std::vector<uint8_t> serialize_transfer_abort(const TransferAbort& abort);
bool deserialize_transfer_abort(const std::vector<uint8_t>& data, TransferAbort& abort);

// 下载响应的序列化与反序列化
std::vector<uint8_t> serialize_download_response(const DownloadResponse& resp);
bool deserialize_download_response(const std::vector<uint8_t>& data, DownloadResponse& resp);

std::vector<uint8_t> serialize_download_request(const DownloadRequest& req);
bool deserialize_download_request(const std::vector<uint8_t>& data, DownloadRequest& req);

// 其他工具函数
// 计算文件的哈希值
std::string calculate_file_hash(const std::string& file_path);

#endif // FILE_TRANSFER_PROTOCOL_H
