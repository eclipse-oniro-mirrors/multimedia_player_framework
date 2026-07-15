/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef AVDOWNLOADER_MANAGER_IMPL_H
#define AVDOWNLOADER_MANAGER_IMPL_H

#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <fstream>
#include <mutex>
#include <queue>
#include <memory>
#include <atomic>
#include <tuple>
#include "download_task.h"
#include "downloader.h"
#include "refbase.h"
#include "av_downloader_manager.h"
#include "source_parse_agent.h"
#include "message_queue.h"
#include "media_source.h"
#include "network_utils.h"
#include "../downloaded_cache_loader/cache_mapping_format.h"

namespace OHOS {
namespace Media {

struct DownloadFileInfo {       // 一份源中的所有下载数据结构
    std::string url;
    std::string filePath;
    bool downloaded = false;
    bool needParse = false;
    uint64_t fileSize = 0;
};

struct AVDownloadTaskInfo {     // 对应DonwloaderImpl
    std::string taskId;     // downloader的id
    std::string url;    // 根url
    std::string cacheDir;   // 根路径
    std::string currentFilePath;   // 当前下载的文件路径
    AVDownloadTaskState state = AVDownloadTaskState::INIT;      // 媒体源的state
    double progress = 0.0;      // 指一个媒体源的进度
    int32_t errorCode = 0;
    std::string errorMsg;
    bool protocolSniffed = false;       // 当前downloader是否已嗅探过
    bool parseCompleted = false;        // ParseFiles解析完成标记，用于控制进度上报
    Plugins::HttpPlugin::StreamProtocolType detectedProtocol = Plugins::HttpPlugin::StreamProtocolType::HTTP;   // 协议类型
    std::vector<DownloadFileInfo> fileList;       // 所有下载文件（保持插入/解析顺序）
    Plugins::PlayStrategy strategy;
    Plugins::TrackSelectionFilter filter;
    std::unordered_map<std::string, std::streamoff> urlToFileSizeOffset_;
    bool mappingFileCreated = false;
};

class AVDownloaderManagerImpl;

class DownloadTaskCallback : public MediaDownload::DownloadCallback {
public:
    explicit DownloadTaskCallback(const std::weak_ptr<AVDownloaderManagerImpl> &manager)
        : manager_(manager) {}
    ~DownloadTaskCallback() = default;

    void OnStateChanged(uint64_t downloaderId, MediaDownload::DownloadState state) override;
    void OnCompleted(uint64_t downloaderId, int64_t downloadedSize) override;
    void OnFailed(uint64_t downloaderId, MediaDownload::DownloadErrorType errorType, int32_t errorCode,
                  const std::string &errorMsg) override;
    void OnProgress(uint64_t downloaderId, const MediaDownload::DownloadProgress &progress) override;
    void OnFileCompleted(uint64_t downloaderId, const std::string &url, int64_t fileSize) override;

private:
    void ProcessDownloadFinish(uint64_t downloaderId, std::shared_ptr<AVDownloaderManagerImpl> manager,
        std::map<std::string, std::shared_ptr<MediaDownload::Downloader>>::iterator &downloaderIter);
    void ParseFiles(uint64_t downloaderId, std::shared_ptr<AVDownloadTaskInfo> taskInfo,
        std::vector<DownloadFileInfo> &filesToAdd, std::shared_ptr<AVDownloaderManagerImpl> manager);
    void GenerateMappingFile(std::shared_ptr<AVDownloadTaskInfo> taskInfo);
    void WriteMappingEntries(std::ofstream& f, std::shared_ptr<AVDownloadTaskInfo> taskInfo,
        std::streamoff baseOffset);
    void ParseSingleFile(uint64_t downloaderId, DownloadFileInfo &fileInfo,
        std::shared_ptr<AVDownloadTaskInfo> taskInfo, std::vector<DownloadFileInfo> &filesToAdd,
        std::shared_ptr<AVDownloaderManagerImpl> manager);
    void SniffStreamProtocol(uint64_t downloaderId, const MediaDownload::DownloadProgress &progress,
        std::string currentFilePath, std::shared_ptr<AVDownloadTaskInfo> taskInfo);
    void SubmitRemainingTasks(std::shared_ptr<MediaDownload::Downloader> downloader,
        std::shared_ptr<AVDownloadTaskInfo> taskInfo, std::shared_ptr<AVDownloaderManagerImpl> manager);
    std::weak_ptr<AVDownloaderManagerImpl> manager_;
};

class __attribute__((visibility("default"))) AVDownloaderManagerImpl : public AVDownloaderManager,
    public std::enable_shared_from_this<AVDownloaderManagerImpl> {
public:
    AVDownloaderManagerImpl();
    ~AVDownloaderManagerImpl() = default;

    int32_t SetAllowCellularAccess(bool allow) override;
    int32_t SetRequestTimeout(int32_t timeoutMs) override;
    std::string AddDownloadTask(std::shared_ptr<Plugins::MediaSource> source) override;
    std::string FindExistingTask(const std::string& url);
    std::tuple<std::string, std::shared_ptr<AVDownloadTaskInfo>, std::shared_ptr<MediaDownload::Downloader>,
        std::string> CreateNewDownloaderAndTask(std::shared_ptr<Plugins::MediaSource> source, const std::string& url);
    int32_t RemoveDownloadTask(const std::string &taskId) override;
    int32_t PauseDownloadTask(const std::string &taskId) override;
    int32_t ResumeDownloadTask(const std::string &taskId) override;
    std::vector<std::string> GetDownloadTasks() override;
    std::string GetTaskCacheDirectory(const std::string &taskId) override;
    AVDownloadTaskState GetTaskStatus(const std::string &taskId) override;
    double GetTaskProgress(const std::string &taskId) override;
    int32_t SetManagerCallback(const std::weak_ptr<AVDownloaderManagerCallback> &callback) override;
    int32_t Release() override;

    void NotifyStatusChange(const std::string &taskId, AVDownloadTaskState state);
    void NotifyProgressChange(const std::string &taskId, double progress);
    static AVDownloadTaskState ConvertToAVDownloadTaskState(MediaDownload::DownloadState state);
    std::string GetFilePath(const std::string& rootDir, const std::string& url);
    void ProcessNextPendingTask();

    std::map<std::string, std::shared_ptr<AVDownloadTaskInfo>> taskMap_;
    std::map<std::string, std::shared_ptr<MediaDownload::Downloader>> downloaderMap_;
    std::queue<std::pair<std::string, std::string>> pendingTaskQueue_;      // Downloader队列
    std::unique_ptr<MediaDownload::MessageQueue> messageQueue_;     // 消息队列
    int32_t requestTimeoutMs_ = 30000;
    bool allowCellularAccess_ = false;
    std::atomic<int32_t> activeDownloaderCount_ {0};
protected:
    virtual MediaSourceUtils::NetConnType GetNetworkType();
private:
    std::string GetDefaultCacheDir(const std::string& url);
    void HandleMessage(const MediaDownload::Message &msg);
    void HandleTaskAdded(std::shared_ptr<AVDownloadTaskInfo> taskInfo, std::string taskId, std::string url,
        std::shared_ptr<MediaDownload::Downloader> downloader, std::string filePath);
    void StartNetworkListening();
    void StopNetworkListening();
    void OnNetworkChanged(MediaSourceUtils::NetConnType newType);
    bool IsNetworkAllowDownload(MediaSourceUtils::NetConnType newType);

    std::weak_ptr<AVDownloaderManagerCallback> callback_;
    std::mutex cbMutex_;
    std::mutex mapMutex_;
    std::string defaultCacheDir_;
    std::shared_ptr<DownloadTaskCallback> taskCallback_;
    bool networkListeningStarted_ = false;

    friend class AVDownloaderManagerTest;
};

} // namespace Media
} // namespace OHOS
#endif // AVDOWNLOADER_MANAGER_IMPL_H