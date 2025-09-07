#include "tcp_server.h"
#include "tcp_client.h"
#include <iostream>
#include <thread>
#include <chrono>

void run_server() {
    TCPServer server(12345);
    if (server.start()) {
        std::cout << "Server is running. Press Enter to stop..." << std::endl;
        std::cin.get();
        server.stop();
    }
}

void run_client() {
    // 等待服务器启动
    std::this_thread::sleep_for(std::chrono::seconds(1));

    TCPClient client("127.0.0.1", 12345);
    if (client.connect_to_server()) {
        std::cout << "Connected to server" << std::endl;

        // 上传文件示例
        std::string local_file = "STL Resource codes analyze.pdf";  // 替换为实际文件路径
        std::string remote_file = "uploaded_large_file.pdf";
        
        std::cout << "Starting file upload..." << std::endl;
        bool success = client.upload_file(local_file, remote_file, 
            [](uint32_t current, uint32_t total) {
                float progress = static_cast<float>(current) / total * 100;
                std::cout << "Upload progress: " << progress << "%" << std::endl;
            });
        
        if (success) {
            std::cout << "File uploaded successfully" << std::endl;
        } else {
            std::cout << "File upload failed" << std::endl;
        }

        // 下载文件示例
        // std::string download_file = "uploaded_large_file.dat";
        // std::string save_path = "downloaded_large_file.dat";
        // client.download_file(download_file, save_path,
        //     [](uint32_t current, uint32_t total) {
        //         float progress = static_cast<float>(current) / total * 100;
        //         std::cout << "Download progress: " << progress << "%" << std::endl;
        //     });

        client.disconnect();
    } else {
        std::cout << "Failed to connect to server" << std::endl;
    }
}

int main() {
    // 启动服务器线程
    std::thread server_thread(run_server);
    
    // 启动客户端线程
    std::thread client_thread(run_client);
    
    // 等待线程完成
    if (server_thread.joinable()) {
        server_thread.join();
    }
    if (client_thread.joinable()) {
        client_thread.join();
    }

    return 0;
}