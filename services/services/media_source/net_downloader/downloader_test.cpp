/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <iostream>
#include <thread>
#include <chrono>

#include "downloader.h"

using namespace OHOS::Media::MediaDownload;

class TestCallback : public DownloadCallback {
public:
    void OnStateChanged(DownloadState state) override {
        std::cout << "[Callback] OnStateChanged: " << state << std::endl;
    }
    
    void OnCompleted(int64_t downloadedSize) override {
        std::cout << "[Callback] OnCompleted: downloadedSize=" << downloadedSize << std::endl;
    }
    
    void OnFailed(DownloadErrorType errorType, int32_t errorCode, const std::string &errorMsg) override {
        std::cout << "[Callback] OnFailed: type=" << errorType 
                  << ", code=" << errorCode 
                  << ", msg=" << errorMsg << std::endl;
    }
    
    void OnProgress(const DownloadProgress &progress) override {
        std::cout << "[Callback] OnProgress: " << progress.progressPercent << "%"
                  << " (" << progress.downloadedSize << "/" << progress.totalSize << ")"
                  << " speed=" << progress.downloadSpeed << " B/s" << std::endl;
    }
};

int main()
{
    std::cout << "=== NetDownloader Test ===" << std::endl;
    
    auto downloader = DownloaderFactory::CreateDownloader();
    if (downloader == nullptr) {
        std::cout << "Failed to create downloader" << std::endl;
        return -1;
    }
    
    std::cout << "DownloaderId: " << downloader->GetDownloaderId() << std::endl;
    std::cout << "Initial state: " << downloader->GetState() << std::endl;
    std::cout << "TaskId in IDLE: " << downloader->GetCurrentTaskId() << std::endl;
    
    int32_t ret = downloader->SetUrl("https://example.com/test.bin");
    std::cout << "SetUrl result: " << ret << std::endl;
    
    ret = downloader->SetOutputPath("/tmp/test.bin");
    std::cout << "SetOutputPath result: " << ret << std::endl;
    
    std::map<std::string, std::string> headers;
    headers["User-Agent"] = "NetDownloader/1.0";
    ret = downloader->SetHeader(headers);
    std::cout << "SetHeader result: " << ret << std::endl;
    
    DownloadConfig config;
    config.progressCallbackIntervalMs = 500;
    config.timeoutMs = 30000;
    config.retryCount = 3;
    config.allowWifi = true;
    config.allowMobileData = false;
    config.continueOnNetworkChange = true;
    ret = downloader->SetConfig(config);
    std::cout << "SetConfig result: " << ret << std::endl;
    
    auto callback = std::make_shared<TestCallback>();
    ret = downloader->SetDownloadCallback(callback);
    std::cout << "SetDownloadCallback result: " << ret << std::endl;
    
    ret = downloader->Start();
    std::cout << "Start result: " << ret << std::endl;
    std::cout << "State after start: " << downloader->GetState() << std::endl;
    std::cout << "TaskId after start: " << downloader->GetCurrentTaskId() << std::endl;
    
    for (int i = 0; i < 5; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        DownloadState state = downloader->GetState();
        std::cout << "Current state: " << state << std::endl;
        
        if (state == DOWNLOAD_RUNNING) {
            DownloadProgress progress;
            ret = downloader->GetProgress(progress);
            if (ret == DOWNLOAD_ERROR_OK) {
                std::cout << "Progress: " << progress.progressPercent << "%"
                          << " (" << progress.downloadedSize << "/" << progress.totalSize << ")" << std::endl;
            }
        }
    }
    
    ret = downloader->Pause();
    std::cout << "Pause result: " << ret << std::endl;
    std::cout << "State after pause: " << downloader->GetState() << std::endl;
    
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    
    ret = downloader->Resume();
    std::cout << "Resume result: " << ret << std::endl;
    std::cout << "State after resume: " << downloader->GetState() << std::endl;
    
    std::this_thread::sleep_for(std::chrono::milliseconds(3000));
    
    ret = downloader->Cancel();
    std::cout << "Cancel result: " << ret << std::endl;
    std::cout << "State after cancel: " << downloader->GetState() << std::endl;
    
    ret = downloader->Release();
    std::cout << "Release result: " << ret << std::endl;
    std::cout << "State after release: " << downloader->GetState() << std::endl;
    
    downloader = nullptr;
    
    std::cout << "=== Test Completed ===" << std::endl;
    return 0;
}