#include "file_transfer_protocol.h"
#include <cstring>
#include <algorithm>
#include <openssl/md5.h>
#include <iostream>
#include <fstream>
#include <iomanip>       // 添加iomanip头文件

// 辅助函数：将整数转换为字节流（小端模式）
template <typename T>
void int_to_bytes(T value, std::vector<uint8_t>& bytes) {
    for (size_t i = 0; i < sizeof(T); ++i) {
        bytes.push_back(static_cast<uint8_t>((value >> (8 * i)) & 0xFF));
    }
}

// 辅助函数：从字节流解析整数（小端模式）
template <typename T>
bool bytes_to_int(const std::vector<uint8_t>& bytes, size_t& offset, T& value) {
    if (offset + sizeof(T) > bytes.size()) {
        return false;
    }
    
    value = 0;
    for (size_t i = 0; i < sizeof(T); ++i) {
        value |= static_cast<T>(bytes[offset + i]) << (8 * i);
    }
    offset += sizeof(T);
    return true;
}

// 序列化PacketHeader
std::vector<uint8_t> serialize_header(const PacketHeader& header) {
    std::vector<uint8_t> data;
    
    // 协议版本（2字节）
    int_to_bytes(header.version, data);
    
    // 命令类型（1字节）
    data.push_back(static_cast<uint8_t>(header.command));
    
    // 有效载荷大小（4字节）
    int_to_bytes(header.payload_size, data);
    
    // 文件ID（8字节）
    int_to_bytes(header.file_id, data);
    
    // 块索引（4字节）
    int_to_bytes(header.block_index, data);
    
    // 总块数（4字节）
    int_to_bytes(header.total_blocks, data);
    
    return data;
}

// 反序列化PacketHeader
bool deserialize_header(const std::vector<uint8_t>& data, PacketHeader& header) {
    size_t offset = 0;
    
    // 协议版本
    if (!bytes_to_int(data, offset, header.version)) return false;
    
    // 命令类型
    if (offset + 1 > data.size()) return false;
    header.command = static_cast<CommandType>(data[offset++]);
    
    // 有效载荷大小
    if (!bytes_to_int(data, offset, header.payload_size)) return false;
    
    // 文件ID
    if (!bytes_to_int(data, offset, header.file_id)) return false;
    
    // 块索引
    if (!bytes_to_int(data, offset, header.block_index)) return false;
    
    // 总块数
    if (!bytes_to_int(data, offset, header.total_blocks)) return false;
    
    return true;
}

// 序列化UploadRequest
std::vector<uint8_t> serialize_upload_request(const UploadRequest& req) {
    std::vector<uint8_t> data;
    
    // 文件名长度（4字节）+ 文件名
    uint32_t filename_len = static_cast<uint32_t>(req.filename.size());
    int_to_bytes(filename_len, data);
    data.insert(data.end(), req.filename.begin(), req.filename.end());
    
    // 文件大小（8字节）
    int_to_bytes(req.file_size, data);
    
    // 哈希值长度（4字节）+ 哈希值
    uint32_t hash_len = static_cast<uint32_t>(req.hash.size());
    int_to_bytes(hash_len, data);
    data.insert(data.end(), req.hash.begin(), req.hash.end());
    
    return data;
}

// 反序列化UploadRequest
bool deserialize_upload_request(const std::vector<uint8_t>& data, UploadRequest& req) {
    size_t offset = 0;
    uint32_t str_len;
    
    // 文件名
    if (!bytes_to_int(data, offset, str_len)) return false;
    if (offset + str_len > data.size()) return false;
    req.filename = std::string(reinterpret_cast<const char*>(&data[offset]), str_len);
    offset += str_len;
    
    // 文件大小
    if (!bytes_to_int(data, offset, req.file_size)) return false;
    
    // 哈希值
    if (!bytes_to_int(data, offset, str_len)) return false;
    if (offset + str_len > data.size()) return false;
    req.hash = std::string(reinterpret_cast<const char*>(&data[offset]), str_len);
    offset += str_len;
    
    return true;
}

// 序列化UploadResponse
std::vector<uint8_t> serialize_upload_response(const UploadResponse& resp) {
    std::vector<uint8_t> data;
    
    // 是否接受（1字节）
    data.push_back(resp.accepted ? 1 : 0);
    
    // 错误代码（1字节）
    data.push_back(static_cast<uint8_t>(resp.error_code));
    
    // 文件ID（8字节）
    int_to_bytes(resp.file_id, data);
    
    // 开始块索引（4字节）
    int_to_bytes(resp.start_block, data);
    
    return data;
}

// 反序列化UploadResponse
bool deserialize_upload_response(const std::vector<uint8_t>& data, UploadResponse& resp) {
    size_t offset = 0;
    
    // 是否接受
    if (offset + 1 > data.size()) return false;
    resp.accepted = (data[offset++] == 1);
    
    // 错误代码
    if (offset + 1 > data.size()) return false;
    resp.error_code = static_cast<ErrorCode>(data[offset++]);
    
    // 文件ID
    if (!bytes_to_int(data, offset, resp.file_id)) return false;
    
    // 开始块索引
    if (!bytes_to_int(data, offset, resp.start_block)) return false;
    
    return true;
}

// 序列化ErrorResponse
std::vector<uint8_t> serialize_error_response(const ErrorResponse& error) {
    std::vector<uint8_t> data;
    
    // 错误代码（1字节）
    data.push_back(static_cast<uint8_t>(error.error_code));
    
    // 错误信息长度（4字节）+ 错误信息
    uint32_t msg_len = static_cast<uint32_t>(error.message.size());
    int_to_bytes(msg_len, data);
    data.insert(data.end(), error.message.begin(), error.message.end());
    
    return data;
}

// 反序列化ErrorResponse
bool deserialize_error_response(const std::vector<uint8_t>& data, ErrorResponse& error) {
    size_t offset = 0;
    uint32_t str_len;
    
    // 错误代码
    if (offset + 1 > data.size()) return false;
    error.error_code = static_cast<ErrorCode>(data[offset++]);
    
    // 错误信息
    if (!bytes_to_int(data, offset, str_len)) return false;
    if (offset + str_len > data.size()) return false;
    error.message = std::string(reinterpret_cast<const char*>(&data[offset]), str_len);
    offset += str_len;
    
    return true;
}

// BlockAck序列化
std::vector<uint8_t> serialize_block_ack(const BlockAck& ack) {
    std::vector<uint8_t> data;
    
    // 成功标志（1字节）：1表示成功，0表示失败
    data.push_back(ack.success ? 1 : 0);
    
    // 错误代码（1字节）
    data.push_back(static_cast<uint8_t>(ack.error_code));
    
    // 块索引（4字节）
    int_to_bytes(ack.block_index, data);
    
    return data;
}

// BlockAck反序列化
bool deserialize_block_ack(const std::vector<uint8_t>& data, BlockAck& ack) {
    size_t offset = 0;
    
    // 检查数据长度是否足够（1+1+4=6字节）
    if (data.size() < 6) {
        return false;
    }
    
    // 解析成功标志
    ack.success = (data[offset++] == 1);
    
    // 解析错误代码
    ack.error_code = static_cast<ErrorCode>(data[offset++]);
    
    // 解析块索引
    if (!bytes_to_int(data, offset, ack.block_index)) {
        return false;
    }
    
    return true;
}

// TransferComplete序列化
std::vector<uint8_t> serialize_transfer_complete(const TransferComplete& complete) {
    std::vector<uint8_t> data;
    
    // 成功标志（1字节）：1表示成功，0表示失败
    data.push_back(complete.success ? 1 : 0);
    
    // 错误代码（1字节）
    data.push_back(static_cast<uint8_t>(complete.error_code));
    
    // 哈希值长度（4字节）+ 哈希值内容
    uint32_t hash_len = static_cast<uint32_t>(complete.hash.size());
    int_to_bytes(hash_len, data);
    data.insert(data.end(), complete.hash.begin(), complete.hash.end());
    
    return data;
}

// TransferComplete反序列化
bool deserialize_transfer_complete(const std::vector<uint8_t>& data, TransferComplete& complete) {
    size_t offset = 0;
    uint32_t str_len;
    
    // 检查最小数据长度（1+1+4=6字节）
    if (data.size() < 6) {
        return false;
    }
    
    // 解析成功标志
    complete.success = (data[offset++] == 1);
    
    // 解析错误代码
    complete.error_code = static_cast<ErrorCode>(data[offset++]);
    
    // 解析哈希值长度
    if (!bytes_to_int(data, offset, str_len)) {
        return false;
    }
    
    // 解析哈希值内容
    if (offset + str_len > data.size()) {
        return false;
    }
    complete.hash = std::string(reinterpret_cast<const char*>(&data[offset]), str_len);
    offset += str_len;
    
    return true;
}

// 序列化TransferAbort
std::vector<uint8_t> serialize_transfer_abort(const TransferAbort& abort) {
    std::vector<uint8_t> data;
    
    // 中止原因长度（4字节）
    uint32_t reason_len = static_cast<uint32_t>(abort.reason.size());
    int_to_bytes(reason_len, data);
    
    // 中止原因内容
    data.insert(data.end(), abort.reason.begin(), abort.reason.end());
    
    return data;
}

// 反序列化TransferAbort
bool deserialize_transfer_abort(const std::vector<uint8_t>& data, TransferAbort& abort) {
    size_t offset = 0;
    uint32_t reason_len;
    
    // 解析原因长度
    if (!bytes_to_int(data, offset, reason_len)) {
        return false;
    }
    
    // 检查数据长度是否足够
    if (offset + reason_len > data.size()) {
        return false;
    }
    
    // 解析原因内容
    abort.reason = std::string(reinterpret_cast<const char*>(&data[offset]), reason_len);
    offset += reason_len;
    
    return true;
}

// 序列化DownloadResponse
std::vector<uint8_t> serialize_download_response(const DownloadResponse& resp) {
    std::vector<uint8_t> data;
    
    // 是否找到文件（1字节）
    data.push_back(resp.found ? 1 : 0);
    
    // 错误代码（1字节）
    data.push_back(static_cast<uint8_t>(resp.error_code));
    
    // 文件ID（8字节）
    int_to_bytes(resp.file_id, data);
    
    // 文件大小（8字节）
    int_to_bytes(resp.file_size, data);
    
    // 总块数（4字节）
    int_to_bytes(resp.total_blocks, data);
    
    // 哈希值长度（4字节）+ 哈希值内容
    uint32_t hash_len = static_cast<uint32_t>(resp.hash.size());
    int_to_bytes(hash_len, data);
    data.insert(data.end(), resp.hash.begin(), resp.hash.end());
    
    return data;
}

// 反序列化_download_response
bool deserialize_download_response(const std::vector<uint8_t>& data, DownloadResponse& resp) {
    size_t offset = 0;
    uint32_t str_len;
    
    // 检查最小数据长度（1+1+8+8+4+4=26字节）
    if (data.size() < 26) {
        return false;
    }
    
    // 解析是否找到文件
    resp.found = (data[offset++] == 1);
    
    // 解析错误代码
    resp.error_code = static_cast<ErrorCode>(data[offset++]);
    
    // 解析文件ID
    if (!bytes_to_int(data, offset, resp.file_id)) {
        return false;
    }
    
    // 解析文件大小
    if (!bytes_to_int(data, offset, resp.file_size)) {
        return false;
    }
    
    // 解析总块数
    if (!bytes_to_int(data, offset, resp.total_blocks)) {
        return false;
    }
    
    // 解析哈希值长度
    if (!bytes_to_int(data, offset, str_len)) {
        return false;
    }
    
    // 解析哈希值内容
    if (offset + str_len > data.size()) {
        return false;
    }
    resp.hash = std::string(reinterpret_cast<const char*>(&data[offset]), str_len);
    offset += str_len;
    
    return true;
}

// 序列化DownloadRequest
std::vector<uint8_t> serialize_download_request(const DownloadRequest& req) {
    std::vector<uint8_t> data;
    
    // 文件名长度（4字节）
    uint32_t filename_len = static_cast<uint32_t>(req.filename.size());
    int_to_bytes(filename_len, data);
    
    // 文件名内容
    data.insert(data.end(), req.filename.begin(), req.filename.end());
    
    // 开始块索引（4字节）
    int_to_bytes(req.start_block, data);
    
    return data;
}

// 反序列化DownloadRequest
bool deserialize_download_request(const std::vector<uint8_t>& data, DownloadRequest& req) {
    size_t offset = 0;
    uint32_t str_len;
    
    // 检查最小数据长度（4字节文件名长度 + 4字节开始块索引）
    if (data.size() < 8) {
        return false;
    }
    
    // 解析文件名长度
    if (!bytes_to_int(data, offset, str_len)) {
        return false;
    }
    
    // 检查文件名数据是否足够
    if (offset + str_len > data.size()) {
        return false;
    }
    
    // 解析文件名
    req.filename = std::string(reinterpret_cast<const char*>(&data[offset]), str_len);
    offset += str_len;
    
    // 解析开始块索引（断点断点续传起点）
    if (!bytes_to_int(data, offset, req.start_block)) {
        return false;
    }
    
    return true;
}

std::string calculate_file_hash(const std::string& file_path) {
    std::ifstream file(file_path, std::ios::binary);
    if (!file) return "";

    MD5_CTX md5_context;
    MD5_Init(&md5_context);

    char buffer[DATA_BLOCK_SIZE];
    // 关键修复：循环不依赖read()的返回值，而是判断实际读取的字节数
    while (true) {
        file.read(buffer, DATA_BLOCK_SIZE);
        size_t bytes_read = file.gcount(); // 记录本次实际读取的字节数
        if (bytes_read == 0) {
            break; // 读取到文件末尾，退出循环
        }
        MD5_Update(&md5_context, buffer, bytes_read); // 处理所有实际读取的数据
    }

    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5_Final(hash, &md5_context);

    std::stringstream ss;
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }

    return ss.str();
}