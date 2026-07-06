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

#include "av_downloader_manager_impl.h"
#include "source_parse_agent.h"
#include "media_log.h"
#include "media_errors.h"
#include "media_source.h"
#include "download_task.h"
#include "downloader.h"
#include "downloader_impl.h"
#include "../downloaded_cache_loader/sha256_hasher.h"
#include "../downloaded_cache_loader/cache_mapping_format.h"
#include "../downloaded_cache_loader/play_strategy_serializer.h"
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "AVDownloaderManagerImpl"};
constexpr int32_t MAX_DOWNLOADER_COUNT = 3;
}

namespace OHOS {
namespace Media {

// DownloaderImpl回调接口，返回sub task的状态和进度
void DownloadTaskCallback::OnStateChanged(uint64_t downloaderId, MediaDownload::DownloadState state)
{
    MEDIA_LOGI("OnStateChanged downloaderId: %{public}" PRIu64 ", state: %{public}d", downloaderId, state);
    auto manager = manager_.lock();
    if (manager == nullptr) {
        return;
    }
    AVDownloadTaskState downloadState = AVDownloaderManagerImpl::ConvertToAVDownloadTaskState(state);
    manager->NotifyStatusChange(std::to_string(downloaderId), downloadState);
}

void DownloadTaskCallback::OnCompleted(uint64_t downloaderId, int64_t downloadedSize)
{
    MEDIA_LOGI("OnCompleted TaskId: %{public}" PRIu64 " completed, size: %{public}" PRId64,
        downloaderId, downloadedSize);
    auto manager = manager_.lock();
    if (manager == nullptr) {
        return;
    }
    auto taskIter = manager->taskMap_.find(std::to_string(downloaderId));
    if (taskIter == manager->taskMap_.end()) {
        return;
    }
    auto& taskInfo = taskIter->second;
    bool hasFilesToParse = false;
    for (auto& pair : taskInfo->fileList) {
        pair.second.downloaded = true;
        if (pair.second.needParse && !hasFilesToParse) {
            hasFilesToParse = true;
        }
    }
    auto downloaderIter = manager->downloaderMap_.find(std::to_string(downloaderId));
    if (downloaderIter == manager->downloaderMap_.end()) {
        return;
    }
    if (!hasFilesToParse) {
        GenerateMappingFile(taskInfo);
        ProcessDownloadFinish(downloaderId, manager, downloaderIter);
        return;
    }

    std::vector<DownloadFileInfo> filesToAdd;
    ParseFiles(downloaderId, taskInfo, filesToAdd, manager);
    for (const auto& fileInfo : filesToAdd) {
        taskInfo->fileList.emplace(fileInfo.url, fileInfo);
    }

    // 检查是否还有需要解析的文件（如HLS子列表），若无则标记完成
    bool hasMoreToParse = false;
    for (const auto& pair : taskInfo->fileList) {
        if (pair.second.needParse) {
            hasMoreToParse = true;
            break;
        }
    }
    if (!hasMoreToParse) {
        MEDIA_LOGI("TaskId: %{public}" PRIu64 ", has no more files to parse", downloaderId);
        taskInfo->parseCompleted = true;
    }
    SubmitRemainingTasks(downloaderIter->second, taskInfo, manager);
}

void DownloadTaskCallback::ProcessDownloadFinish(uint64_t downloaderId,
    std::shared_ptr<AVDownloaderManagerImpl> manager, std::map<std::string,
    std::shared_ptr<MediaDownload::Downloader>>::iterator &downloaderIter)
{
    MEDIA_LOGI("TaskId: %{public}" PRIu64 ", all files downloaded, task completed", downloaderId);
    manager->NotifyStatusChange(std::to_string(downloaderId), AVDownloadTaskState::COMPLETED);
    manager->NotifyProgressChange(std::to_string(downloaderId), 1.0);
    manager->activeDownloaderCount_.fetch_sub(1);      // 一个任务完成，减少一个
    MEDIA_LOGI("TaskId: %{public}" PRIu64 ", activeDownloaderCount_ decremented to %{public}d",
        downloaderId, manager->activeDownloaderCount_.load());
    MediaDownload::Message releaseMsg;
    releaseMsg.type = MediaDownload::MSG_RELEASE_DOWNLOADER;
    releaseMsg.downloader = downloaderIter->second;
    manager->messageQueue_->PostMessage(releaseMsg);
    MEDIA_LOGI("TaskId: %{public}" PRIu64 ", release message posted", downloaderId);
    MediaDownload::Message nextMsg;
    nextMsg.type = MediaDownload::MSG_PROCESS_NEXT_TASK;
    manager->messageQueue_->PostMessage(nextMsg);
}

void DownloadTaskCallback::ParseFiles(uint64_t downloaderId, std::shared_ptr<AVDownloadTaskInfo> taskInfo,
    std::vector<DownloadFileInfo> &filesToAdd, std::shared_ptr<AVDownloaderManagerImpl> manager)
{
    (void)SourceParseAgent::Create();
    for (auto& pair : taskInfo->fileList) {
        auto& fileInfo = pair.second;
        if (!fileInfo.needParse) {
            continue;
        }
        MEDIA_LOGI("TaskId: %{public}" PRIu64 ", parsing file: %{public}s", downloaderId, fileInfo.filePath.c_str());

        FILE* fp = fopen(fileInfo.filePath.c_str(), "rb");
        if (fp == nullptr) {
            MEDIA_LOGE("failed to open file");
            continue;
        }
        fseek(fp, 0, SEEK_END);
        long fileSize = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        if (fileSize <= 0) {
            fclose(fp);
            MEDIA_LOGE("file size is 0");
            continue;
        }
        std::vector<uint8_t> buffer(fileSize);
        size_t readLen = fread(buffer.data(), 1, fileSize, fp);
        fclose(fp);
        if (readLen != static_cast<size_t>(fileSize)) {
            MEDIA_LOGE("failed to read full file");
            continue;
        }

        auto parser = SourceParseAgent::GetStreamResourceParser(buffer.data(), buffer.size(),
            taskInfo->detectedProtocol, fileInfo.url);
        if (parser == nullptr) {
            MEDIA_LOGE("TaskId: %{public}" PRIu64 ", GetStreamResourceParser failed", downloaderId);
            continue;
        }

        auto resources = parser->GetAll();
        MEDIA_LOGD("TaskId: %{public}" PRIu64 ", parsed %{public}zu sub-resources from %{public}s",
            downloaderId, resources.size(), fileInfo.filePath.c_str());

        for (const auto& resource : resources) {
            std::string subFilePath = manager->GetFilePath(taskInfo->cacheDir, resource.url);
            DownloadFileInfo subFileInfo;
            subFileInfo.url = resource.url;
            subFileInfo.filePath = subFilePath;
            subFileInfo.downloaded = false;
            subFileInfo.needParse = resource.isSubPlaylist;
            filesToAdd.push_back(subFileInfo);
        }
        fileInfo.needParse = false;
    }
    SourceParseAgent::Destroy();
}

// generate mapping file
void DownloadTaskCallback::GenerateMappingFile(std::shared_ptr<AVDownloadTaskInfo> taskInfo)
{
    DownloadedCache::CacheMappingHeader* mappingHeader = new DownloadedCache::CacheMappingHeader;
    memset_s(mappingHeader, sizeof(DownloadedCache::CacheMappingHeader), 0,
        sizeof(DownloadedCache::CacheMappingHeader));
    mappingHeader->magic[0] = 'D';
    mappingHeader->magic[1] = 'C';
    mappingHeader->magic[2] = 'M';
    mappingHeader->magic[3] = 'H';
    mappingHeader->version = 1;

    auto count = taskInfo->fileList.size();
    mappingHeader->entryCount = count;
    DownloadedCache::CacheMappingEntry* mappingEntries = new DownloadedCache::CacheMappingEntry[count];
    memset_s(mappingEntries, sizeof(DownloadedCache::CacheMappingEntry) * count, 0,
        sizeof(DownloadedCache::CacheMappingEntry) * count);

    std::ofstream f(taskInfo->cacheDir + "/cache_mapping.txt", std::ios::out | std::ios::binary);
    DownloadedCache::CacheMappingSerializer::CalculateHeaderChecksum(*mappingHeader);
    DownloadedCache::CacheMappingSerializer::WriteHeader(f, *mappingHeader);

    std::vector<uint8_t> playbackParam;
    DownloadedCache::PlayStrategySerializer::Serialize(taskInfo->url, taskInfo->strategy, taskInfo->filter,
        playbackParam);
    DownloadedCache::CacheMappingSerializer::WritePlaybackParamData(f, playbackParam.data(),
        playbackParam.size());

    int32_t index = 0;
    for (const auto& [k, v] : taskInfo->fileList) {
        auto urlHash = DownloadedCache::SHA256Hasher::GenerateHash(v.url);
        std::copy_n(urlHash.data(), urlHash.size(), mappingEntries[index].header.urlHash);
        std::string tmp = v.filePath.substr(taskInfo->cacheDir.size());
        mappingEntries[index].header.pathLength = tmp.length();
        mappingEntries[index].header.fileSize = 0;
        mappingEntries[index].filePath = tmp;
        DownloadedCache::CacheMappingSerializer::WriteEntry(f, mappingEntries[index], taskInfo->cacheDir);
        std::string hashIndexTmp = DownloadedCache::SHA256Hasher::HashToString(urlHash);
        index++;
        MEDIA_LOGD("Serialize: %{public}s, hash: %{public}s, tmp path: %{public}s, value path: %{public}s",
            v.url.c_str(), hashIndexTmp.c_str(), tmp.c_str(), v.filePath.c_str());
    }
    f.close();
}

void DownloadTaskCallback::SubmitRemainingTasks(std::shared_ptr<MediaDownload::Downloader> downloader,
    std::shared_ptr<AVDownloadTaskInfo> taskInfo, std::shared_ptr<AVDownloaderManagerImpl> manager)
{
    MediaDownload::DownloadConfig config;
    config.timeoutMs = manager->requestTimeoutMs_;
    config.allowMobileData = manager->allowCellularAccess_;
    config.allowWifi = true;
    for (const auto& pair : taskInfo->fileList) {
        const auto& fileInfo = pair.second;
        if (fileInfo.downloaded) {
            continue;
        }
        downloader->SetConfig(config);
        downloader->AddFileTask(fileInfo.url, fileInfo.filePath, config);
    }
    (void)downloader->Start();
}

void DownloadTaskCallback::OnFailed(uint64_t downloaderId, MediaDownload::DownloadErrorType errorType,
    int32_t errorCode, const std::string &errorMsg)
{
    MEDIA_LOGI("OnFailed TaskId: %{public}" PRIu64 " failed, "
           "errorType: %{public}d, errorCode: %{public}d, msg: %{public}s",
           downloaderId, errorType, errorCode, errorMsg.c_str());
    auto manager = manager_.lock();
    if (manager == nullptr) {
        return;
    }
    manager->NotifyStatusChange(std::to_string(downloaderId), AVDownloadTaskState::ERROR);
    manager->activeDownloaderCount_.fetch_sub(1);
    MEDIA_LOGI("TaskId: %{public}" PRIu64 ", activeDownloaderCount_ decremented to %{public}d on failed",
        downloaderId, manager->activeDownloaderCount_.load());

    auto downloaderIter = manager->downloaderMap_.find(std::to_string(downloaderId));
    if (downloaderIter != manager->downloaderMap_.end()) {
        MediaDownload::Message msg;
        msg.type = MediaDownload::MSG_RELEASE_DOWNLOADER;
        msg.downloader = downloaderIter->second;
        manager->messageQueue_->PostMessage(msg);
        MEDIA_LOGI("TaskId: %{public}" PRIu64 ", release message posted on failed", downloaderId);
    }
    MediaDownload::Message nextMsg;
    nextMsg.type = MediaDownload::MSG_PROCESS_NEXT_TASK;
    manager->messageQueue_->PostMessage(nextMsg);
    MEDIA_LOGI("TaskId: %{public}" PRIu64 ", process next task message posted on failed", downloaderId);
}

void DownloadTaskCallback::OnProgress(uint64_t downloaderId, const MediaDownload::DownloadProgress &progress)
{
    double progressValue = static_cast<double>(progress.progressPercent) / 100.0;
    MEDIA_LOGI("OnProgress TaskId: %{public}" PRIu64 " progress: %{public}f", downloaderId, progressValue);
    auto manager = manager_.lock();
    if (manager == nullptr) {
        MEDIA_LOGE("OnProgress failed, manager is null");
        return;
    }

    auto taskIter = manager->taskMap_.find(std::to_string(downloaderId));
    if (taskIter == manager->taskMap_.end()) {
        return;
    }
    auto& taskInfo = taskIter->second;
    bool shouldReportProgress = taskInfo->parseCompleted ||
        (taskInfo->protocolSniffed && taskInfo->detectedProtocol == Plugins::HttpPlugin::StreamProtocolType::HTTP);
    if (shouldReportProgress) {
        manager->NotifyProgressChange(std::to_string(downloaderId), progressValue);
    }
    if (taskInfo->protocolSniffed) {
        return;
    }

    auto downloaderIter = manager->downloaderMap_.find(std::to_string(downloaderId));
    if (downloaderIter == manager->downloaderMap_.end()) {
        return;
    }
    auto downloader = std::static_pointer_cast<MediaDownload::DownloaderImpl>(downloaderIter->second);
    std::string currentFilePath = downloader->GetCurrentFilePath();
    if (currentFilePath.empty()) {
        return;
    }
    MEDIA_LOGI("currentFilePath: %{public}s,", currentFilePath.c_str());

    SniffStreamProtocol(downloaderId, progress, currentFilePath, taskInfo);
}

void DownloadTaskCallback::SniffStreamProtocol(uint64_t downloaderId, const MediaDownload::DownloadProgress &progress,
    std::string currentFilePath, std::shared_ptr<AVDownloadTaskInfo> taskInfo)
{
    SourceParseAgent::Create();
    size_t sniffSize = SourceParseAgent::GetSniffBufferSize();
    do {
        if (progress.downloadedSize < static_cast<int64_t>(sniffSize)) {
            break;
        }
        MEDIA_LOGI("TaskId: %{public}" PRIu64 ", downloadedSize=%{public}" PRId64 " >= sniffSize=%{public}zu, sniff",
            downloaderId, progress.downloadedSize, sniffSize);
        FILE* fp = fopen(currentFilePath.c_str(), "rb");
        if (fp == nullptr) {
            MEDIA_LOGE("TaskId: %{public}" PRIu64 ", failed to open file: %{public}s",
                downloaderId, currentFilePath.c_str());
            break;
        }
        std::vector<uint8_t> buffer(sniffSize);
        size_t readLen = fread(buffer.data(), 1, sniffSize, fp);
        fclose(fp);
        if (readLen < sniffSize) {
            MEDIA_LOGW("TaskId: %{public}" PRIu64 ", readLen=%{public}zu < sniffSize=%{public}zu",
                downloaderId, readLen, sniffSize);
            break;
        }
        MEDIA_LOGI("readLen: %{public}zu", readLen);
        auto protocol = SourceParseAgent::SniffStreamProtocol(buffer.data(), readLen);
        taskInfo->detectedProtocol = protocol;
        taskInfo->protocolSniffed = true;
        taskInfo->currentFilePath = currentFilePath;
        if (protocol == Plugins::HttpPlugin::StreamProtocolType::HLS ||
            protocol == Plugins::HttpPlugin::StreamProtocolType::DASH) {    // HLS or Dash
            if (!taskInfo->fileList.empty()) {
                taskInfo->fileList.begin()->second.needParse = true;
                MEDIA_LOGI("TaskId: %{public}" PRIu64 ", protocol is HLS/DASH, needParse", downloaderId);
            }
        }
        MEDIA_LOGI("TaskId: %{public}" PRIu64 ", detected protocol: %{public}d",
            downloaderId, static_cast<int>(protocol));
    } while (0);
    SourceParseAgent::Destroy();
}

std::shared_ptr<AVDownloaderManager> AVDownloaderManagerFactory::Create()
{
    MEDIA_LOGI("AVDownloaderManager create");
    return std::make_shared<AVDownloaderManagerImpl>();
}

namespace {
bool CreateDirRecursive(const std::string& path)
{
    if (path.empty()) {
        return true;
    }

    std::string subPath = path;
    for (size_t i = 1; i < subPath.size(); ++i) {
        if (subPath[i] != '/') {
            continue;
        }
        subPath[i] = '\0';
        if (access(subPath.c_str(), F_OK) != 0 && mkdir(subPath.c_str(), S_IRWXU | S_IRGRP | S_IXGRP) != 0) {
            MEDIA_LOGE("Create dir failed: %{public}s", subPath.c_str());
            return false;
        }
        subPath[i] = '/';
    }

    if (access(path.c_str(), F_OK) != 0 && mkdir(path.c_str(), S_IRWXU | S_IRGRP | S_IXGRP) != 0) {
        MEDIA_LOGE("Create dir again failed: %{public}s", path.c_str());
        return false;
    }
    return true;
}
}

AVDownloaderManagerImpl::AVDownloaderManagerImpl()
{
    messageQueue_ = std::make_unique<MediaDownload::MessageQueue>();
    messageQueue_->Start([this](const MediaDownload::Message &msg) {
        HandleMessage(msg);
    });
    MEDIA_LOGI("AVDownloaderManagerImpl: messageQueue_ started");
    StartNetworkListening();
}

std::string AVDownloaderManagerImpl::GetDefaultCacheDir(const std::string& url)
{
    std::string baseDir = "/data/storage/el2/base/cache/avplayer_downloaded_cache/";
    auto hash = DownloadedCache::SHA256Hasher::GenerateHash(url);
    std::string hashStr = DownloadedCache::SHA256Hasher::HashToString(hash);
    baseDir += hashStr;
    if (access(baseDir.c_str(), F_OK) != 0) {
        if (!CreateDirRecursive(baseDir)) {
            MEDIA_LOGE("Create base cache dir failed: %{public}s", baseDir.c_str());
        }
    }
    return baseDir;
}

std::string AVDownloaderManagerImpl::GetFilePath(const std::string& rootDir, const std::string& url)
{
    size_t lastSlashPos = url.find_last_of("/\\");
    std::string fileName = (lastSlashPos != std::string::npos) ? url.substr(lastSlashPos + 1) : url;
    if (fileName.empty()) {
        fileName = "download";
    }
    std::string filePath = rootDir + "/1/" + fileName;
    std::string dirPath = rootDir + "/1";
    if (access(dirPath.c_str(), F_OK) != 0) {
        if (!CreateDirRecursive(dirPath)) {
            MEDIA_LOGE("Create file dir failed: %{public}s", dirPath.c_str());
        }
    }
    return filePath;
}

int32_t AVDownloaderManagerImpl::SetAllowCellularAccess(bool allow)
{
    MEDIA_LOGI("SetAllowCellularAccess: %{public}d", allow);
    allowCellularAccess_ = allow;
    return MSERR_OK;
}

int32_t AVDownloaderManagerImpl::SetRequestTimeout(int32_t timeoutMs)
{
    MEDIA_LOGI("SetRequestTimeout: %{public}d", timeoutMs);
    requestTimeoutMs_ = timeoutMs;
    return MSERR_OK;
}

std::string AVDownloaderManagerImpl::AddDownloadTask(std::shared_ptr<Plugins::MediaSource> source)
{
    auto url = source->GetSourceUri();
    MEDIA_LOGI("AddDownloadTask url: %{public}s, activeDownloaderCount_=%{public}d",
        url.c_str(), activeDownloaderCount_.load());

    if (url.empty()) {
        MEDIA_LOGE("AddDownloadTask failed: url is empty");
        return "";
    }

    std::lock_guard<std::mutex> lock(mapMutex_);

    std::string existingTaskId = FindExistingTask(url);
    if (!existingTaskId.empty()) {
        return existingTaskId;
    }

    auto [taskId, taskInfo, downloader, filePath] = CreateNewDownloaderAndTask(source, url);
    if (taskId.empty()) {
        return "";
    }

    taskMap_[taskId] = taskInfo;
    downloaderMap_[taskId] = downloader;
    HandleTaskAdded(taskInfo, taskId, url, downloader, filePath);

    MEDIA_LOGI("AddDownloadTask success: taskId=%{public}s, url=%{public}s, state=%{public}d",
        taskId.c_str(), url.c_str(), static_cast<int>(taskInfo->state));
    return taskId;
}

std::string AVDownloaderManagerImpl::FindExistingTask(const std::string& url)
{
    for (const auto& pair : taskMap_) {
        if (pair.second->url != url) {
            continue;
        }
        MEDIA_LOGI("AddDownloadTask: task with same url already exists, taskId=%{public}s, state=%{public}d",
                pair.first.c_str(), static_cast<int>(pair.second->state));
        if (pair.second->state == AVDownloadTaskState::RUNNING ||
            pair.second->state == AVDownloadTaskState::QUEUED ||
            pair.second->state == AVDownloadTaskState::INIT) {
            return pair.first;
        }
        if (pair.second->state != AVDownloadTaskState::PAUSED) {
            continue;
        }
        MEDIA_LOGI("AddDownloadTask: resuming paused task, taskId=%{public}s", pair.first.c_str());
        auto downloaderIter = downloaderMap_.find(pair.first);
        if (downloaderIter == downloaderMap_.end()) {
            continue;
        }
        if (activeDownloaderCount_.load() >= MAX_DOWNLOADER_COUNT) {
            MEDIA_LOGI("AddDownloadTask: activeDownloaderCount_=%{public}d >= MAX=%{public}d, queuing paused task",
                activeDownloaderCount_.load(), MAX_DOWNLOADER_COUNT);
            pendingTaskQueue_.push({pair.second->url, pair.first});
            pair.second->state = AVDownloadTaskState::QUEUED;
            NotifyStatusChange(pair.first, AVDownloadTaskState::QUEUED);
            return pair.first;
        }
        downloaderIter->second->Resume();
        pair.second->state = AVDownloadTaskState::RUNNING;
        NotifyStatusChange(pair.first, AVDownloadTaskState::RUNNING);
        activeDownloaderCount_.fetch_add(1);
        return pair.first;
    }
    return "";
}

std::tuple<std::string, std::shared_ptr<AVDownloadTaskInfo>, std::shared_ptr<MediaDownload::Downloader>, std::string>
AVDownloaderManagerImpl::CreateNewDownloaderAndTask(std::shared_ptr<Plugins::MediaSource> source,
    const std::string& url)
{
    auto downloader = MediaDownload::DownloaderFactory::CreateDownloader();
    if (downloader == nullptr) {
        MEDIA_LOGE("CreateDownloader failed");
        return {"", nullptr, nullptr, ""};
    }

    std::string taskId = std::to_string(downloader->GetDownloaderId());
    std::string cacheDir = GetDefaultCacheDir(url);
    std::string filePath = GetFilePath(cacheDir, url);

    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = taskId;
    taskInfo->url = url;
    taskInfo->cacheDir = cacheDir;
    taskInfo->currentFilePath = filePath;
    auto strategy = source->GetPlayStrategy();
    if (strategy) {
        taskInfo->strategy = *strategy;
    }
    memset_s(&(taskInfo->filter), sizeof(Plugins::TrackSelectionFilter), 0, sizeof(Plugins::TrackSelectionFilter));
    MEDIA_LOGI("GetDefaultCacheDir: %{public}s, file path: %{public}s", cacheDir.c_str(), filePath.c_str());
    taskInfo->state = AVDownloadTaskState::INIT;

    DownloadFileInfo fileInfo;
    fileInfo.url = url;
    fileInfo.filePath = filePath;
    taskInfo->fileList.emplace(url, fileInfo);

    return {taskId, taskInfo, downloader, filePath};
}
 
void AVDownloaderManagerImpl::HandleTaskAdded(std::shared_ptr<AVDownloadTaskInfo> taskInfo, std::string taskId,
    std::string url, std::shared_ptr<MediaDownload::Downloader> downloader, std::string filePath)
{
    if (activeDownloaderCount_.load() >= MAX_DOWNLOADER_COUNT) {
        MEDIA_LOGI("AddDownloadTask: activeDownloaderCount_=%{public}d >= MAX=%{public}d, pending task",
            activeDownloaderCount_.load(), MAX_DOWNLOADER_COUNT);
        pendingTaskQueue_.push({url, taskId});
        taskInfo->state = AVDownloadTaskState::QUEUED;
        NotifyStatusChange(taskId, taskInfo->state);
    } else {
        MediaDownload::DownloadConfig config;
        config.timeoutMs = requestTimeoutMs_;
        config.allowMobileData = allowCellularAccess_;
        config.allowWifi = true;
        downloader->AddFileTask(url, filePath, config);
        if (taskCallback_ == nullptr) {
            taskCallback_ = std::make_shared<DownloadTaskCallback>(weak_from_this());
        }
        downloader->SetDownloadCallback(taskCallback_);

        downloader->SetConfig(config);
        auto ret = downloader->Start();
        if (ret != MSERR_OK) {
            MEDIA_LOGE("Downloader Start failed, ret: %{public}d", ret);
            taskInfo->state = AVDownloadTaskState::ERROR;
        } else {
            taskInfo->state = AVDownloadTaskState::RUNNING;
            activeDownloaderCount_.fetch_add(1);
        }
        NotifyStatusChange(taskId, taskInfo->state);
    }
}

int32_t AVDownloaderManagerImpl::RemoveDownloadTask(const std::string &taskId)
{
    MEDIA_LOGI("RemoveDownloadTask taskId: %{public}s", taskId.c_str());
    std::lock_guard<std::mutex> lock(mapMutex_);

    bool isRunning = false;
    auto taskIter = taskMap_.find(taskId);
    if (taskIter != taskMap_.end() && taskIter->second->state == AVDownloadTaskState::RUNNING) {
        isRunning = true;
    }

    auto downloaderIter = downloaderMap_.find(taskId);
    if (downloaderIter != downloaderMap_.end()) {
        if (downloaderIter->second != nullptr) {
            downloaderIter->second->Cancel();
            downloaderIter->second->Release();
        }
        downloaderMap_.erase(downloaderIter);
    }

    if (taskIter != taskMap_.end()) {
        taskIter->second->state = AVDownloadTaskState::REMOVING;
        taskMap_.erase(taskIter);
    }

    if (isRunning) {
        activeDownloaderCount_.fetch_sub(1);
        MEDIA_LOGI("RemoveDownloadTask: activeDownloaderCount_ decremented to %{public}d",
            activeDownloaderCount_.load());
        MediaDownload::Message nextMsg;
        nextMsg.type = MediaDownload::MSG_PROCESS_NEXT_TASK;
        messageQueue_->PostMessage(nextMsg);
    }

    NotifyStatusChange(taskId, AVDownloadTaskState::REMOVING);
    return MSERR_OK;
}

int32_t AVDownloaderManagerImpl::PauseDownloadTask(const std::string &taskId)
{
    MEDIA_LOGI("PauseDownloadTask taskId: %{public}s", taskId.c_str());
    std::lock_guard<std::mutex> lock(mapMutex_);

    auto downloaderIter = downloaderMap_.find(taskId);
    if (downloaderIter == downloaderMap_.end()) {
        MEDIA_LOGE("PauseDownloadTask failed: task not found");
        return MSERR_INVALID_VAL;
    }

    bool wasRunning = false;
    auto taskIter = taskMap_.find(taskId);
    if (taskIter != taskMap_.end() && taskIter->second->state == AVDownloadTaskState::RUNNING) {
        wasRunning = true;
    }

    auto ret = downloaderIter->second->Pause();
    if (ret == MSERR_OK) {
        if (taskIter != taskMap_.end()) {
            taskIter->second->state = AVDownloadTaskState::PAUSED;
            NotifyStatusChange(taskId, AVDownloadTaskState::PAUSED);
        }
        if (wasRunning) {
            activeDownloaderCount_.fetch_sub(1);
            MEDIA_LOGI("PauseDownloadTask: activeDownloaderCount_ decremented to %{public}d",
                activeDownloaderCount_.load());
            MediaDownload::Message nextMsg;
            nextMsg.type = MediaDownload::MSG_PROCESS_NEXT_TASK;
            messageQueue_->PostMessage(nextMsg);
        }
    }
    return ret;
}

int32_t AVDownloaderManagerImpl::ResumeDownloadTask(const std::string &taskId)
{
    MEDIA_LOGI("ResumeDownloadTask taskId: %{public}s", taskId.c_str());
    std::lock_guard<std::mutex> lock(mapMutex_);

    if (activeDownloaderCount_.load() >= MAX_DOWNLOADER_COUNT) {
        MEDIA_LOGI("ResumeDownloadTask: activeDownloaderCount_=%{public}d >= MAX=%{public}d, cannot resume",
            activeDownloaderCount_.load(), MAX_DOWNLOADER_COUNT);
        return MSERR_INVALID_VAL;
    }

    auto downloaderIter = downloaderMap_.find(taskId);
    if (downloaderIter == downloaderMap_.end()) {
        MEDIA_LOGE("ResumeDownloadTask failed: task not found");
        return MSERR_INVALID_VAL;
    }

    auto networkType = GetNetworkType();
    if (!IsNetworkAllowDownload(networkType)) {
        MEDIA_LOGE("ResumeDownloadTask failed: network not available");
        return MSERR_IO_NETWORK_UNAVAILABLE;
    }

    auto ret = downloaderIter->second->Resume();
    if (ret == MSERR_OK) {
        auto taskIter = taskMap_.find(taskId);
        if (taskIter != taskMap_.end()) {
            taskIter->second->state = AVDownloadTaskState::RUNNING;
            NotifyStatusChange(taskId, AVDownloadTaskState::RUNNING);
            activeDownloaderCount_.fetch_add(1);
            MEDIA_LOGI("ResumeDownloadTask: activeDownloaderCount_ incremented to %{public}d",
                activeDownloaderCount_.load());
        }
    }
    return ret;
}

std::vector<std::string> AVDownloaderManagerImpl::GetDownloadTasks()
{
    MEDIA_LOGI("GetDownloadTasks");
    std::lock_guard<std::mutex> lock(mapMutex_);

    std::vector<std::string> taskIds;
    for (const auto &pair : taskMap_) {
        taskIds.push_back(pair.first);
    }
    return taskIds;
}

std::string AVDownloaderManagerImpl::GetTaskCacheDirectory(const std::string &taskId)
{
    MEDIA_LOGI("GetTaskCacheDirectory taskId: %{public}s", taskId.c_str());
    std::lock_guard<std::mutex> lock(mapMutex_);

    auto taskIter = taskMap_.find(taskId);
    if (taskIter == taskMap_.end()) {
        MEDIA_LOGE("GetTaskCacheDirectory failed: task not found");
        return "";
    }
    return taskIter->second->cacheDir;
}

AVDownloadTaskState AVDownloaderManagerImpl::GetTaskStatus(const std::string &taskId)
{
    MEDIA_LOGI("GetTaskStatus taskId: %{public}s", taskId.c_str());
    std::lock_guard<std::mutex> lock(mapMutex_);

    auto taskIter = taskMap_.find(taskId);
    if (taskIter == taskMap_.end()) {
        MEDIA_LOGE("GetTaskCacheDirectory failed: task not found");
        return AVDownloadTaskState::ERROR;
    }

    MEDIA_LOGI("GetTaskStatus taskId success: %{public}s, state: %{public}d", taskId.c_str(), taskIter->second->state);
    return taskIter->second->state;
}

// State transfer
AVDownloadTaskState AVDownloaderManagerImpl::ConvertToAVDownloadTaskState(MediaDownload::DownloadState state)
{
    AVDownloadTaskState downloadState = AVDownloadTaskState::INIT;
    switch (state) {
        case MediaDownload::DownloadState::DOWNLOAD_IDLE:
            downloadState = AVDownloadTaskState::INIT;
            break;
        case MediaDownload::DownloadState::DOWNLOAD_PREPARING:
            downloadState = AVDownloadTaskState::QUEUED;
            break;
        case MediaDownload::DownloadState::DOWNLOAD_RUNNING:
            downloadState = AVDownloadTaskState::RUNNING;
            break;
        case MediaDownload::DownloadState::DOWNLOAD_PAUSED:
            downloadState = AVDownloadTaskState::PAUSED;
            break;
        case MediaDownload::DownloadState::DOWNLOAD_COMPLETED:
            downloadState = AVDownloadTaskState::COMPLETED;
            break;
        case MediaDownload::DownloadState::DOWNLOAD_FAILED:
            downloadState = AVDownloadTaskState::ERROR;
            break;
        case MediaDownload::DownloadState::DOWNLOAD_CANCELED:
            downloadState = AVDownloadTaskState::REMOVING;
            break;
        default:
            downloadState = AVDownloadTaskState::ERROR;
            break;
    }
    return downloadState;
}

double AVDownloaderManagerImpl::GetTaskProgress(const std::string &taskId)
{
    MEDIA_LOGI("GetTaskProgress taskId: %{public}s", taskId.c_str());
    std::lock_guard<std::mutex> lock(mapMutex_);

    auto taskIter = taskMap_.find(taskId);
    if (taskIter == taskMap_.end()) {
        MEDIA_LOGE("GetTaskProgress failed: task not found");
        return 0.0;
    }

    MEDIA_LOGI("GetProgress success: %{public}s, state: %{public}f", taskId.c_str(), taskIter->second->progress);
    return taskIter->second->progress;
}

int32_t AVDownloaderManagerImpl::SetManagerCallback(const std::weak_ptr<AVDownloaderManagerCallback> &callback)
{
    MEDIA_LOGI("SetManagerCallback");
    callback_ = callback;
    return MSERR_OK;
}

int32_t AVDownloaderManagerImpl::Release()
{
    MEDIA_LOGI("Release");
    StopNetworkListening();
    std::lock_guard<std::mutex> lock(mapMutex_);

    for (auto &pair : downloaderMap_) {
        if (pair.second != nullptr) {
            pair.second->Cancel();
            pair.second->Release();
        }
    }
    downloaderMap_.clear();
    taskMap_.clear();
    callback_.reset();

    return MSERR_OK;
}

void AVDownloaderManagerImpl::NotifyStatusChange(const std::string &taskId, AVDownloadTaskState state)
{
    MEDIA_LOGI("NotifyStatusChange: %{public}s, Task state: %{public}d", taskId.c_str(), state);
    auto taskIter = taskMap_.find(taskId);
    if (taskIter != taskMap_.end()) {
        taskIter->second->state = state;
    }
    std::lock_guard<std::mutex> lock(cbMutex_);
    auto callback = callback_.lock();
    if (callback != nullptr) {
        MEDIA_LOGI("NotifyStatusChange: %{public}s, callback not null", taskId.c_str());
        callback->OnStatusChange(taskId, state);
    }
}

void AVDownloaderManagerImpl::NotifyProgressChange(const std::string &taskId, double progress)
{
    MEDIA_LOGI("NotifyProgressChange: %{public}s, Task state: %{public}f", taskId.c_str(), progress);
    std::lock_guard<std::mutex> lock(cbMutex_);
    auto taskIter = taskMap_.find(taskId);
    if (taskIter != taskMap_.end()) {
        taskIter->second->progress = progress;
    }
    auto callback = callback_.lock();
    if (callback != nullptr) {
        MEDIA_LOGI("NotifyProgressChange: %{public}s, callback not null", taskId.c_str());
        callback->OnProgressChange(taskId, progress);
    }
}

void AVDownloaderManagerImpl::ProcessNextPendingTask()
{
    std::lock_guard<std::mutex> lock(mapMutex_);
    if (activeDownloaderCount_.load() >= MAX_DOWNLOADER_COUNT) {
        MEDIA_LOGI("ProcessNextPendingTask: activeDownloaderCount_=%{public}d >= MAX=%{public}d, waiting",
            activeDownloaderCount_.load(), MAX_DOWNLOADER_COUNT);
        return;
    }
    if (pendingTaskQueue_.empty()) {
        MEDIA_LOGI("ProcessNextPendingTask: pending queue is empty");
        return;
    }
    auto [url, taskId] = pendingTaskQueue_.front();
    pendingTaskQueue_.pop();

    auto downloaderIter = downloaderMap_.find(taskId);
    if (downloaderIter == downloaderMap_.end()) {
        MEDIA_LOGE("ProcessNextPendingTask: downloader not found for taskId=%{public}s", taskId.c_str());
        return;
    }
    auto downloader = downloaderIter->second;
    
    if (taskCallback_ == nullptr) {
        taskCallback_ = std::make_shared<DownloadTaskCallback>(weak_from_this());
    }
    downloader->SetDownloadCallback(taskCallback_);

    auto taskIter = taskMap_.find(taskId);        // 取taskInfo
    if (taskIter == taskMap_.end()) {
        return;
    }
    auto& taskInfo = taskIter->second;

    MediaDownload::DownloadConfig config;
    config.timeoutMs = requestTimeoutMs_;
    config.allowMobileData = allowCellularAccess_;
    config.allowWifi = true;
    downloader->AddFileTask(taskInfo->url, taskInfo->currentFilePath, config);

    downloader->SetConfig(config);
    auto ret = downloader->Start();
    if (ret == MSERR_OK) {
        activeDownloaderCount_.fetch_add(1);
        MEDIA_LOGI("ProcessNextPendingTask: started taskId=%{public}s, activeDownloaderCount_=%{public}d",
            taskId.c_str(), activeDownloaderCount_.load());
    } else {
        MEDIA_LOGE("ProcessNextPendingTask: Start failed for taskId=%{public}s, ret=%{public}d", taskId.c_str(), ret);
    }
}

void AVDownloaderManagerImpl::HandleMessage(const MediaDownload::Message &msg)
{
    switch (msg.type) {
        case MediaDownload::MSG_RELEASE_DOWNLOADER:
            if (msg.downloader != nullptr) {
                MEDIA_LOGI("HandleMessage: releasing downloader");
                msg.downloader->Release();
            }
            break;
        case MediaDownload::MSG_PROCESS_NEXT_TASK:
            MEDIA_LOGI("HandleMessage: processing next task");
            ProcessNextPendingTask();
            break;
        default:
            MEDIA_LOGW("HandleMessage: unknown message type=%{public}d", msg.type);
            break;
    }
}

void AVDownloaderManagerImpl::StartNetworkListening()
{
    if (networkListeningStarted_) {
        return;
    }
    auto& networkUtils = MediaSourceUtils::NetworkUtils::GetInstance();
    MEDIA_LOGI("StartNetworkListening, current network: %{public}d", networkUtils.GetCurrentNetworkType());

    networkUtils.RegisterNetworkChangeCallback(
        [this](MediaSourceUtils::NetConnType newType) {
            OnNetworkChanged(newType);
        });
    networkListeningStarted_ = true;
}

void AVDownloaderManagerImpl::StopNetworkListening()
{
    if (!networkListeningStarted_) {
        return;
    }
    MEDIA_LOGI("StopNetworkListening, current network: %{public}d",
        MediaSourceUtils::NetworkUtils::GetInstance().GetCurrentNetworkType());
    MediaSourceUtils::NetworkUtils::GetInstance().UnregisterNetworkChangeCallback();
    networkListeningStarted_ = false;
}

void AVDownloaderManagerImpl::OnNetworkChanged(MediaSourceUtils::NetConnType newType)
{
    MEDIA_LOGI("OnNetworkChanged: newType=%{public}d", newType);
    std::lock_guard<std::mutex> lock(mapMutex_);
    for (auto& pair : downloaderMap_) {
        auto downloader = pair.second;
        if (downloader == nullptr) {
            continue;
        }
        if (IsNetworkAllowDownload(newType)) {
            MEDIA_LOGI("OnNetworkChanged: resuming taskId=%{public}s", pair.first.c_str());
            (void)downloader->Resume();
        } else {
            MEDIA_LOGI("OnNetworkChanged: pausing taskId=%{public}s", pair.first.c_str());
            (void)downloader->Pause();
        }
    }
}

bool AVDownloaderManagerImpl::IsNetworkAllowDownload(MediaSourceUtils::NetConnType newType)
{
    if (newType == MediaSourceUtils::NetConnType::NET_CONN_NONE ||
        newType == MediaSourceUtils::NetConnType::NET_CONN_UNKNOWN) {
        MEDIA_LOGI("IsNetworkAllowDownload: no network available");
        return false;
    }

    if (allowCellularAccess_ && newType == MediaSourceUtils::NetConnType::NET_CONN_CELLULAR) {
        MEDIA_LOGI("IsNetworkAllowDownload: Mobile data network allowed");
        return true;
    }
    if (newType == MediaSourceUtils::NetConnType::NET_CONN_WIFI) {
        MEDIA_LOGI("IsNetworkAllowDownload: WiFi network allowed");
        return true;
    }

    MEDIA_LOGI("IsNetworkAllowDownload: network type %{public}d not allowed", newType);
    return false;
}

MediaSourceUtils::NetConnType AVDownloaderManagerImpl::GetNetworkType()
{
    return MediaSourceUtils::NetworkUtils::GetInstance().GetCurrentNetworkType();
}

} // namespace Media
} // namespace OHOS
