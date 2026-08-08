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
#include "path_utils.h"
#include <cerrno>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include "common/log.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "AVDownloaderManagerImpl"};
constexpr int32_t MAX_DOWNLOADER_COUNT = 3;
constexpr const char *DOWNLOAD_CACHE_BASE_DIR = "/data/storage/el2/base/cache/avplayer_downloaded_cache/";
constexpr auto PAUSE_RETRY_INTERVAL = std::chrono::milliseconds(10);
constexpr auto PAUSE_RETRY_TIMEOUT = std::chrono::milliseconds(200);
constexpr size_t MAX_CACHE_FILENAME_LEN = 100;
constexpr size_t MAX_EXTENSION_LEN = 20;
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
    std::lock_guard<std::mutex> lock(manager->mapMutex_);
    AVDownloadTaskState downloadState = AVDownloaderManagerImpl::ConvertToAVDownloadTaskState(state);
    manager->NotifyStatusChangeLocked(std::to_string(downloaderId), downloadState);
}

void DownloadTaskCallback::OnCompleted(uint64_t downloaderId, int64_t downloadedSize)
{
    MEDIA_LOGI("OnCompleted TaskId: %{public}" PRIu64 ", size: %{public}" PRId64, downloaderId, downloadedSize);
    auto manager = manager_.lock();
    if (manager == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(manager->mapMutex_);
    auto taskIter = manager->taskMap_.find(std::to_string(downloaderId));
    if (taskIter == manager->taskMap_.end()) {
        return;
    }
    auto& taskInfo = taskIter->second;
    bool hasFilesToParse = false;
    for (auto& info : taskInfo->fileList) {
        info.downloaded = true;
        if (info.needParse && !hasFilesToParse) {
            hasFilesToParse = true;
        }
    }
    auto downloaderIter = manager->downloaderMap_.find(std::to_string(downloaderId));
    if (downloaderIter == manager->downloaderMap_.end()) {
        return;
    }
    if (!hasFilesToParse) {
        if (!taskInfo->mappingFileCreated) {
            GenerateMappingFile(taskInfo);
        }
        ProcessDownloadFinish(downloaderId, manager);
        return;
    }

    HandleParseCompleted(downloaderId, downloaderIter, taskInfo, manager);
}

void DownloadTaskCallback::HandleParseCompleted(uint64_t downloaderId,
    std::map<std::string, std::shared_ptr<MediaDownload::Downloader>>::iterator &downloaderIter,
    std::shared_ptr<AVDownloadTaskInfo> taskInfo, std::shared_ptr<AVDownloaderManagerImpl> manager)
{
    std::vector<DownloadFileInfo> filesToAdd;
    ParseFiles(downloaderId, taskInfo, filesToAdd, manager);
    for (const auto& fileInfo : filesToAdd) {
        taskInfo->fileList.push_back(fileInfo);
    }

    bool hasMoreToParse = false;
    for (const auto& info : taskInfo->fileList) {
        if (info.needParse) {
            hasMoreToParse = true;
            break;
        }
    }
    if (!hasMoreToParse) {
        MEDIA_LOGI("TaskId: %{public}" PRIu64 ", has no more files to parse", downloaderId);
        taskInfo->parseCompleted = true;
    }
    if (!hasMoreToParse && !taskInfo->mappingFileCreated) {
        GenerateMappingFile(taskInfo);
    }
    SubmitRemainingTasks(downloaderIter->second, taskInfo, manager);
}

void DownloadTaskCallback::ProcessDownloadFinish(uint64_t downloaderId,
    std::shared_ptr<AVDownloaderManagerImpl> manager)
{
    MEDIA_LOGI("TaskId: %{public}" PRIu64 ", all files downloaded, task completed", downloaderId);
    manager->NotifyStatusChangeLocked(std::to_string(downloaderId), AVDownloadTaskState::COMPLETED);
    manager->NotifyProgressChangeLocked(std::to_string(downloaderId), 1.0);
    MediaDownload::Message releaseMsg;
    releaseMsg.type = MediaDownload::MSG_RELEASE_DOWNLOADER;
    releaseMsg.downloaderId = downloaderId;
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
    for (auto& fileInfo : taskInfo->fileList) {
        if (!fileInfo.needParse) {
            continue;
        }
        ParseSingleFile(downloaderId, fileInfo, taskInfo, filesToAdd, manager);
    }
    SourceParseAgent::Destroy();
}

bool DownloadTaskCallback::ReadFileToBuffer(const std::string &filePath, std::vector<uint8_t> &buffer)
{
    int fd = open(filePath.c_str(), O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        MEDIA_LOGE("failed to open file");
        return false;
    }
    FILE* fp = fdopen(fd, "rb");
    if (fp == nullptr) {
        close(fd);
        MEDIA_LOGE("failed to fdopen");
        return false;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        if (fclose(fp) != 0) {
            MEDIA_LOGE("fclose failed after fseek SEEK_END failed");
        }
        MEDIA_LOGE("fseek SEEK_END failed");
        return false;
    }
    long fileSize = ftell(fp);
    if (fseek(fp, 0, SEEK_SET) != 0) {
        if (fclose(fp) != 0) {
            MEDIA_LOGE("fclose failed after fseek SEEK_SET failed");
        }
        MEDIA_LOGE("fseek SEEK_SET failed");
        return false;
    }
    constexpr long MAX_PARSE_FILE_SIZE = 64 * 1024 * 1024; // 64MB
    if (fileSize <= 0 || fileSize > MAX_PARSE_FILE_SIZE) {
        if (fclose(fp) != 0) {
            MEDIA_LOGE("fclose failed after file size check");
        }
        MEDIA_LOGE("file size invalid or too large: %{public}ld", fileSize);
        return false;
    }
    buffer.resize(fileSize);
    size_t readLen = fread(buffer.data(), 1, fileSize, fp);
    if (fclose(fp) != 0) {
        MEDIA_LOGE("fclose failed after fread");
        return false;
    }
    if (readLen != static_cast<size_t>(fileSize)) {
        MEDIA_LOGE("failed to read full file");
        return false;
    }
    return true;
}

void DownloadTaskCallback::ParseSingleFile(uint64_t downloaderId, DownloadFileInfo &fileInfo,
    std::shared_ptr<AVDownloadTaskInfo> taskInfo, std::vector<DownloadFileInfo> &filesToAdd,
    std::shared_ptr<AVDownloaderManagerImpl> manager)
{
    std::string normalizedPath;
    auto validateRet = MediaSourceUtils::PathUtils::ValidateAndNormalizePath(
        fileInfo.filePath, normalizedPath);
    if (validateRet != MediaSourceUtils::PATH_VALIDATE_OK) {
        MEDIA_LOGE("ParseFiles: path validation failed for %{public}s, ret=%{public}d",
            fileInfo.filePath.c_str(), static_cast<int32_t>(validateRet));
        return;
    }

    MEDIA_LOGI("TaskId: %{public}" PRIu64 ", parsing file: %{public}s", downloaderId, normalizedPath.c_str());

    std::vector<uint8_t> buffer;
    if (!ReadFileToBuffer(normalizedPath, buffer)) {
        return;
    }

    auto parser = SourceParseAgent::GetStreamResourceParser(buffer.data(), buffer.size(),
        taskInfo->detectedProtocol, fileInfo.url);
    FALSE_RETURN_MSG(parser != nullptr, "GetStreamResourceParser failed");

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

// generate mapping file
uint32_t DownloadTaskCallback::WriteMappingEntries(std::ofstream& f,
    std::shared_ptr<AVDownloadTaskInfo> taskInfo, std::streamoff baseOffset)
{
    constexpr std::streamoff URL_HASH_SIZE = 32;
    constexpr std::streamoff PATH_LENGTH_SIZE = 4;
    constexpr std::streamoff ENTRY_HEADER_PREFIX = URL_HASH_SIZE + PATH_LENGTH_SIZE;
    std::streamoff currentOffset = baseOffset;
    uint32_t writtenCount = 0;
    for (const auto& v : taskInfo->fileList) {
        DownloadedCache::CacheMappingEntry entry {};
        auto urlHash = DownloadedCache::SHA256Hasher::GenerateHash(v.url);
        std::copy_n(urlHash.data(), urlHash.size(), entry.header.urlHash);
        std::string relPath;
        if (v.filePath.size() > taskInfo->cacheDir.size() &&
            v.filePath.compare(0, taskInfo->cacheDir.size(), taskInfo->cacheDir) == 0) {
            relPath = v.filePath.substr(taskInfo->cacheDir.size());
        } else {
            relPath = v.filePath;
        }
        entry.header.pathLength = relPath.length();
        uint64_t fileSize = 0;
        if (v.downloaded) {
            struct stat st;
            if (stat(v.filePath.c_str(), &st) == 0) {
                fileSize = static_cast<uint64_t>(st.st_size);
            }
        }
        entry.header.fileSize = fileSize;
        entry.filePath = relPath;

        if (!DownloadedCache::CacheMappingSerializer::WriteEntry(f, entry, taskInfo->cacheDir)) {
            MEDIA_LOGE("WriteMappingEntries: WriteEntry failed for %{private}s", v.url.c_str());
            continue;
        }

        taskInfo->urlToFileSizeOffset_[v.url] = currentOffset + ENTRY_HEADER_PREFIX;
        currentOffset += sizeof(DownloadedCache::CacheMappingEntryHeader) + relPath.length();
        writtenCount++;
        MEDIA_LOGD("Serialize: %{private}s, hash: %{public}s, tmp path: %{public}s, value path: %{public}s",
            v.url.c_str(), DownloadedCache::SHA256Hasher::HashToString(urlHash).c_str(),
            relPath.c_str(), v.filePath.c_str());
    }
    return writtenCount;
}

void DownloadTaskCallback::GenerateMappingFile(std::shared_ptr<AVDownloadTaskInfo> taskInfo)
{
    if (taskInfo == nullptr || taskInfo->cacheDir.empty()) {
        MEDIA_LOGE("GenerateMappingFile failed: taskInfo is null or cacheDir is empty");
        return;
    }

    std::string normalizedCacheDir;
    auto validateRet = MediaSourceUtils::PathUtils::ValidateAndNormalizePath(
        taskInfo->cacheDir, normalizedCacheDir);
    if (validateRet != MediaSourceUtils::PATH_VALIDATE_OK) {
        MEDIA_LOGE("GenerateMappingFile failed: cacheDir validation failed, ret=%{public}d",
            static_cast<int32_t>(validateRet));
        return;
    }

    DownloadedCache::CacheMappingHeader mappingHeader {};
    std::copy_n(DownloadedCache::CACHE_MAPPING_MAGIC, 4, mappingHeader.magic);
    mappingHeader.version = 1;
    mappingHeader.entryCount = taskInfo->fileList.size();

    taskInfo->urlToFileSizeOffset_.clear();

    std::string mappingFilePath = normalizedCacheDir + "/cache_mapping.txt";
    std::ofstream f(mappingFilePath, std::ios::out | std::ios::trunc | std::ios::binary);
    FALSE_RETURN_MSG(f.is_open(),
        "GenerateMappingFile failed: unable to open file %{private}s", mappingFilePath.c_str());
    DownloadedCache::CacheMappingSerializer::CalculateHeaderChecksum(mappingHeader);
    DownloadedCache::CacheMappingSerializer::WriteHeader(f, mappingHeader);

    std::vector<uint8_t> playbackParam;
    DownloadedCache::PlayStrategySerializer::Serialize(taskInfo->url, taskInfo->strategy, taskInfo->filter,
        playbackParam);
    DownloadedCache::CacheMappingSerializer::WritePlaybackParamData(f, playbackParam.data(), playbackParam.size());

    std::streamoff entriesBaseOffset = sizeof(DownloadedCache::CacheMappingHeader) +
        DownloadedCache::PLAYBACK_PARAM_DATA_LENGTH_SIZE + playbackParam.size();
    uint32_t writtenCount = WriteMappingEntries(f, taskInfo, entriesBaseOffset);

    if (writtenCount != taskInfo->fileList.size()) {
        mappingHeader.entryCount = writtenCount;
        DownloadedCache::CacheMappingSerializer::CalculateHeaderChecksum(mappingHeader);
        f.seekp(0, std::ios::beg);
        DownloadedCache::CacheMappingSerializer::WriteHeader(f, mappingHeader);
    }

    if (!f.good()) {
        MEDIA_LOGE("GenerateMappingFile: write failed for %{public}s", normalizedCacheDir.c_str());
        f.close();
        return;
    }
    f.close();
    taskInfo->mappingFileCreated = true;
}

void DownloadTaskCallback::SubmitRemainingTasks(std::shared_ptr<MediaDownload::Downloader> downloader,
    std::shared_ptr<AVDownloadTaskInfo> taskInfo, std::shared_ptr<AVDownloaderManagerImpl> manager)
{
    if (downloader == nullptr) {
        MEDIA_LOGE("SubmitRemainingTasks: downloader is nullptr");
        return;
    }
    MediaDownload::DownloadConfig config;
    config.timeoutMs = manager->requestTimeoutMs_.load();
    config.allowMobileData = manager->allowCellularAccess_.load();
    config.allowWifi = true;
    for (const auto& fileInfo : taskInfo->fileList) {
        if (fileInfo.downloaded) {
            continue;
        }
        downloader->SetConfig(config);
        downloader->AddFileTask(fileInfo.url, fileInfo.filePath, config);
    }
    auto ret = downloader->Start();
    if (ret != MSERR_OK) {
        MEDIA_LOGE("SubmitRemainingTasks: Start failed, ret=%{public}d", ret);
    }
}

void DownloadTaskCallback::OnFileCompleted(uint64_t downloaderId, const std::string &url, int64_t fileSize)
{
    MEDIA_LOGI("OnFileCompleted: downloaderId=%{public}" PRIu64 ", fileSize=%{public}" PRId64,
        downloaderId, fileSize);
    if (fileSize < 0) {
        MEDIA_LOGE("OnFileCompleted: invalid fileSize=%{public}" PRId64, fileSize);
        return;
    }
    auto manager = manager_.lock();
    if (manager == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(manager->mapMutex_);
    auto taskIter = manager->taskMap_.find(std::to_string(downloaderId));
    if (taskIter == manager->taskMap_.end()) {
        return;
    }
    auto& taskInfo = taskIter->second;

    auto fileIter = std::find_if(taskInfo->fileList.begin(), taskInfo->fileList.end(),
        [&url](const DownloadFileInfo& info) { return info.url == url; });
    if (fileIter != taskInfo->fileList.end()) {
        fileIter->fileSize = static_cast<uint64_t>(fileSize);
    }

    auto offsetIter = taskInfo->urlToFileSizeOffset_.find(url);
    if (offsetIter == taskInfo->urlToFileSizeOffset_.end()) {
        MEDIA_LOGW("OnFileCompleted: no offset for url, mapping file may not exist yet");
        return;
    }
    std::string mappingFilePath = taskInfo->cacheDir + "/cache_mapping.txt";
    DownloadedCache::CacheMappingSerializer::UpdateFileSize(
        mappingFilePath, offsetIter->second, static_cast<uint64_t>(fileSize));
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
    std::lock_guard<std::mutex> lock(manager->mapMutex_);
    if (!manager->IsNetworkAllowDownload(manager->GetNetworkType())) {
        MEDIA_LOGI("OnFailed: network unavailable, taskId=%{public}" PRIu64 " set PAUSED", downloaderId);
        manager->NotifyStatusChangeLocked(std::to_string(downloaderId), AVDownloadTaskState::PAUSED);
        return;
    }
    manager->NotifyStatusChangeLocked(std::to_string(downloaderId), AVDownloadTaskState::ERROR);
    auto downloaderIter = manager->downloaderMap_.find(std::to_string(downloaderId));
    if (downloaderIter != manager->downloaderMap_.end()) {
        MediaDownload::Message msg;
        msg.type = MediaDownload::MSG_RELEASE_DOWNLOADER;
        msg.downloaderId = downloaderId;
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

    std::lock_guard<std::mutex> lock(manager->mapMutex_);
    auto taskIter = manager->taskMap_.find(std::to_string(downloaderId));
    if (taskIter == manager->taskMap_.end()) {
        return;
    }
    auto& taskInfo = taskIter->second;
    bool shouldReportProgress = taskInfo->parseCompleted ||
        (taskInfo->protocolSniffed && taskInfo->detectedProtocol == Plugins::HttpPlugin::StreamProtocolType::HTTP);
    if (shouldReportProgress) {
        manager->NotifyProgressChangeLocked(std::to_string(downloaderId), progressValue);
    }
    if (taskInfo->protocolSniffed) {
        return;
    }

    auto downloaderIter = manager->downloaderMap_.find(std::to_string(downloaderId));
    if (downloaderIter == manager->downloaderMap_.end()) {
        return;
    }
    if (downloaderIter->second == nullptr) {
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

bool DownloadTaskCallback::ReadFileData(const std::string &filePath, std::vector<uint8_t> &buffer, size_t readSize)
{
    std::string normalizedPath;
    auto validateRet = MediaSourceUtils::PathUtils::ValidateAndNormalizePath(filePath, normalizedPath);
    if (validateRet != MediaSourceUtils::PATH_VALIDATE_OK) {
        MEDIA_LOGE("ReadFileData: path validation failed, ret=%{public}d", static_cast<int32_t>(validateRet));
        return false;
    }

    int fd = open(normalizedPath.c_str(), O_RDONLY | O_NOFOLLOW);
    FALSE_RETURN_V_MSG_E(fd >= 0, false, "ReadFileData: failed to open file %{public}s", filePath.c_str());
    FILE* fp = fdopen(fd, "rb");
    if (fp == nullptr) {
        close(fd);
        MEDIA_LOGE("ReadFileData: failed to fdopen");
        return false;
    }
    buffer.resize(readSize);
    size_t readLen = fread(buffer.data(), 1, readSize, fp);
    fclose(fp);
    MEDIA_LOGI("ReadFileData: readLen=%{public}zu", readLen);
    return readLen >= readSize;
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

        std::vector<uint8_t> buffer;
        if (!ReadFileData(currentFilePath, buffer, sniffSize)) {
            break;
        }

        auto protocol = SourceParseAgent::SniffStreamProtocol(buffer.data(), buffer.size());
        taskInfo->detectedProtocol = protocol;
        taskInfo->protocolSniffed = true;
        taskInfo->currentFilePath = currentFilePath;
        if (protocol == Plugins::HttpPlugin::StreamProtocolType::HLS ||
            protocol == Plugins::HttpPlugin::StreamProtocolType::DASH) {
            if (!taskInfo->fileList.empty()) {
                taskInfo->fileList.front().needParse = true;
                MEDIA_LOGI("TaskId: %{public}" PRIu64 ", protocol is HLS/DASH, needParse", downloaderId);
            }
        }
        MEDIA_LOGI("TaskId: %{public}" PRIu64 ", protocol: %{public}d", downloaderId, static_cast<int>(protocol));
    } while (0);
    SourceParseAgent::Destroy();
    if (taskInfo->protocolSniffed && !taskInfo->mappingFileCreated &&
        taskInfo->detectedProtocol != Plugins::HttpPlugin::StreamProtocolType::HLS &&
        taskInfo->detectedProtocol != Plugins::HttpPlugin::StreamProtocolType::DASH) {
        GenerateMappingFile(taskInfo);
    }
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
        if (mkdir(subPath.c_str(), S_IRWXU | S_IRGRP | S_IXGRP) != 0 && errno != EEXIST) {
            MEDIA_LOGE("Create dir failed: %{public}s", subPath.c_str());
            subPath[i] = '/';
            return false;
        }
        subPath[i] = '/';
    }

    if (mkdir(path.c_str(), S_IRWXU | S_IRGRP | S_IXGRP) != 0 && errno != EEXIST) {
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
    MediaSourceUtils::PathUtils::SetAllowedRootDir(DOWNLOAD_CACHE_BASE_DIR);
    MEDIA_LOGI("AVDownloaderManagerImpl: messageQueue_ started");
    StartNetworkListening();
}

AVDownloaderManagerImpl::~AVDownloaderManagerImpl()
{
    MEDIA_LOGI("~AVDownloaderManagerImpl");
    Release();
}

std::string AVDownloaderManagerImpl::GetDefaultCacheDir(const std::string& url)
{
    std::string baseDir = DOWNLOAD_CACHE_BASE_DIR;
    auto hash = DownloadedCache::SHA256Hasher::GenerateHash(url);
    std::string hashStr = DownloadedCache::SHA256Hasher::HashToString(hash);
    baseDir += hashStr;
    if (!CreateDirRecursive(baseDir)) {
        MEDIA_LOGE("Create base cache dir failed: %{public}s", baseDir.c_str());
    }
    return baseDir;
}

std::string AVDownloaderManagerImpl::GetFilePath(const std::string& rootDir, const std::string& url)
{
    size_t lastSlashPos = url.find_last_of("/\\");
    std::string fileName = (lastSlashPos != std::string::npos) ? url.substr(lastSlashPos + 1) : url;
    size_t queryPos = fileName.find('?');
    if (queryPos != std::string::npos) {
        fileName = fileName.substr(0, queryPos);
    }

    if (fileName.empty() || !MediaSourceUtils::PathUtils::IsPathTraversalSafe(fileName)) {
        auto hash = DownloadedCache::SHA256Hasher::GenerateHash(url);
        fileName = DownloadedCache::SHA256Hasher::HashToString(hash);
    }

    if (fileName.length() > MAX_CACHE_FILENAME_LEN) {
        size_t extPos = fileName.rfind('.');
        if (extPos != std::string::npos && fileName.length() - extPos < MAX_EXTENSION_LEN) {
            size_t extLen = fileName.length() - extPos;
            fileName = fileName.substr(0, MAX_CACHE_FILENAME_LEN - extLen) + fileName.substr(extPos);
        } else {
            fileName = fileName.substr(0, MAX_CACHE_FILENAME_LEN);
        }
    }
    std::string filePath = rootDir + "/1/" + fileName;
    std::string dirPath = rootDir + "/1";
    if (!CreateDirRecursive(dirPath)) {
        MEDIA_LOGE("Create file dir failed: %{public}s", dirPath.c_str());
    }
    return filePath;
}

int32_t AVDownloaderManagerImpl::SetAllowCellularAccess(bool allow)
{
    MEDIA_LOGI("SetAllowCellularAccess: %{public}d", allow);
    allowCellularAccess_.store(allow);
    return MSERR_OK;
}

int32_t AVDownloaderManagerImpl::SetRequestTimeout(int32_t timeoutMs)
{
    MEDIA_LOGI("SetRequestTimeout: %{public}d", timeoutMs);
    requestTimeoutMs_.store(timeoutMs);
    return MSERR_OK;
}

std::string AVDownloaderManagerImpl::AddDownloadTask(std::shared_ptr<Plugins::MediaSource> source)
{
    auto url = source->GetSourceUri();
    MEDIA_LOGI("AddDownloadTask url: %{private}s", url.c_str());

    if (url.empty()) {
        MEDIA_LOGE("AddDownloadTask failed: url is empty");
        return "";
    }

    std::string existingTaskId;
    {
        std::lock_guard<std::mutex> lock(mapMutex_);
        existingTaskId = FindExistingTask(url);
        if (!existingTaskId.empty()) {
            auto taskIter = taskMap_.find(existingTaskId);
            if (taskIter != taskMap_.end() && taskIter->second->state == AVDownloadTaskState::PAUSED) {
                pendingTaskQueue_.push_back({taskIter->second->url, existingTaskId});
                taskIter->second->state = AVDownloadTaskState::QUEUED;
                NotifyStatusChangeLocked(existingTaskId, AVDownloadTaskState::QUEUED);
                MediaDownload::Message nextMsg;
                nextMsg.type = MediaDownload::MSG_PROCESS_NEXT_TASK;
                messageQueue_->PostMessage(nextMsg);
            }
        } else {
            auto [taskId, taskInfo, downloader, filePath] = CreateNewDownloaderAndTask(source, url);
            if (taskId.empty()) {
                return "";
            }

            taskMap_[taskId] = taskInfo;
            downloaderMap_[taskId] = downloader;
            HandleTaskAdded(taskId, url);
            existingTaskId = taskId;
            MEDIA_LOGI("AddDownloadTask success: taskId=%{public}s, url=%{private}s, state=%{public}d",
                taskId.c_str(), url.c_str(), static_cast<int>(taskInfo->state));
        }
    }

    return existingTaskId;
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
        MEDIA_LOGI("AddDownloadTask: found paused task, taskId=%{public}s", pair.first.c_str());
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
    taskInfo->filter = Plugins::TrackSelectionFilter{};
    MEDIA_LOGI("GetDefaultCacheDir: %{public}s, file path: %{public}s", cacheDir.c_str(), filePath.c_str());
    taskInfo->state = AVDownloadTaskState::INIT;

    DownloadFileInfo fileInfo;
    fileInfo.url = url;
    fileInfo.filePath = filePath;
    taskInfo->fileList.push_back(fileInfo);

    return {taskId, taskInfo, downloader, filePath};
}
 
void AVDownloaderManagerImpl::HandleTaskAdded(std::string taskId, std::string url)
{
    pendingTaskQueue_.push_back({url, taskId});
    auto taskIter = taskMap_.find(taskId);
    if (taskIter != taskMap_.end()) {
        taskIter->second->state = AVDownloadTaskState::QUEUED;
    }
    NotifyStatusChangeLocked(taskId, AVDownloadTaskState::QUEUED);
    MediaDownload::Message nextMsg;
    nextMsg.type = MediaDownload::MSG_PROCESS_NEXT_TASK;
    messageQueue_->PostMessage(nextMsg);
}

int32_t AVDownloaderManagerImpl::RemoveDownloadTask(const std::string &taskId)
{
    MEDIA_LOGI("RemoveDownloadTask taskId: %{public}s", taskId.c_str());
    std::shared_ptr<MediaDownload::Downloader> downloader;
    AVDownloadTaskState oldState = AVDownloadTaskState::INIT;
    {
        std::lock_guard<std::mutex> lock(mapMutex_);
        auto taskIter = taskMap_.find(taskId);
        if (taskIter != taskMap_.end()) {
            oldState = taskIter->second->state;
            taskIter->second->state = AVDownloadTaskState::REMOVING;
        }

        pendingTaskQueue_.remove_if(
            [&taskId](const auto& pair) { return pair.second == taskId; });

        auto downloaderIter = downloaderMap_.find(taskId);
        if (downloaderIter != downloaderMap_.end()) {
            downloader = downloaderIter->second;
            downloaderMap_.erase(downloaderIter);
        }

        if (taskIter != taskMap_.end()) {
            taskMap_.erase(taskIter);
        }

        NotifyStatusChangeLocked(taskId, AVDownloadTaskState::REMOVING);
    }

    if (downloader != nullptr) {
        RetryWithDeadline(downloader, [&downloader]() { return downloader->Cancel(); });
        downloader->Release();
    }

    if (oldState == AVDownloadTaskState::RUNNING ||
        oldState == AVDownloadTaskState::QUEUED) {
        MediaDownload::Message nextMsg;
        nextMsg.type = MediaDownload::MSG_PROCESS_NEXT_TASK;
        messageQueue_->PostMessage(nextMsg);
    }
    return MSERR_OK;
}

int32_t AVDownloaderManagerImpl::PauseDownloadTask(const std::string &taskId)
{
    MEDIA_LOGI("PauseDownloadTask taskId: %{public}s", taskId.c_str());
    std::shared_ptr<MediaDownload::Downloader> downloader;
    {
        std::lock_guard<std::mutex> lock(mapMutex_);
        auto taskIter = taskMap_.find(taskId);
        if (taskIter == taskMap_.end()) {
            MEDIA_LOGE("PauseDownloadTask failed: task not found");
            return MSERR_INVALID_VAL;
        }

        if (taskIter->second->state == AVDownloadTaskState::QUEUED) {
            pendingTaskQueue_.remove_if(
                [&taskId](const auto& pair) { return pair.second == taskId; });
            taskIter->second->state = AVDownloadTaskState::PAUSED;
            NotifyStatusChangeLocked(taskId, AVDownloadTaskState::PAUSED);
            return MSERR_OK;
        }

        if (taskIter->second->state != AVDownloadTaskState::RUNNING) {
            return MSERR_INVALID_OPERATION;
        }

        auto downloaderIter = downloaderMap_.find(taskId);
        if (downloaderIter == downloaderMap_.end() || downloaderIter->second == nullptr) {
            return MSERR_INVALID_VAL;
        }
        downloader = downloaderIter->second;
    }

    int32_t ret = RetryWithDeadline(downloader, [&downloader]() { return downloader->Pause(); });
    {
        std::lock_guard<std::mutex> lock(mapMutex_);
        if (ret == MSERR_OK) {
            auto taskIter = taskMap_.find(taskId);
            if (taskIter != taskMap_.end()) {
                NotifyStatusChangeLocked(taskId, AVDownloadTaskState::PAUSED);
            }
            MediaDownload::Message nextMsg;
            nextMsg.type = MediaDownload::MSG_PROCESS_NEXT_TASK;
            messageQueue_->PostMessage(nextMsg);
        }
    }
    return ret;
}

int32_t AVDownloaderManagerImpl::RetryWithDeadline(
    std::shared_ptr<MediaDownload::Downloader> downloader,
    std::function<int32_t()> operation)
{
    int32_t ret = MSERR_OK;
    auto deadline = std::chrono::steady_clock::now() + PAUSE_RETRY_TIMEOUT;
    while (std::chrono::steady_clock::now() < deadline) {
        ret = operation();
        if (ret == MSERR_OK) {
            break;
        }
        auto state = downloader->GetState();
        if (state == MediaDownload::DOWNLOAD_COMPLETED ||
            state == MediaDownload::DOWNLOAD_FAILED ||
            state == MediaDownload::DOWNLOAD_CANCELED) {
            break;
        }
        std::this_thread::sleep_for(PAUSE_RETRY_INTERVAL);
    }
    return ret;
}

int32_t AVDownloaderManagerImpl::ResumeDownloadTask(const std::string &taskId)
{
    MEDIA_LOGI("ResumeDownloadTask taskId: %{public}s", taskId.c_str());
    std::lock_guard<std::mutex> lock(mapMutex_);

    auto taskIter = taskMap_.find(taskId);
    if (taskIter == taskMap_.end()) {
        MEDIA_LOGE("ResumeDownloadTask failed: task not found");
        return MSERR_INVALID_VAL;
    }

    if (taskIter->second->state != AVDownloadTaskState::PAUSED) {
        MEDIA_LOGE("ResumeDownloadTask failed: state is not PAUSED, state=%{public}d",
            static_cast<int>(taskIter->second->state));
        return MSERR_INVALID_OPERATION;
    }

    pendingTaskQueue_.push_back({taskIter->second->url, taskId});
    taskIter->second->state = AVDownloadTaskState::QUEUED;
    NotifyStatusChangeLocked(taskId, AVDownloadTaskState::QUEUED);

    MediaDownload::Message nextMsg;
    nextMsg.type = MediaDownload::MSG_PROCESS_NEXT_TASK;
    messageQueue_->PostMessage(nextMsg);
    return MSERR_OK;
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
    std::lock_guard<std::mutex> lock(cbMutex_);
    callback_ = callback;
    return MSERR_OK;
}

int32_t AVDownloaderManagerImpl::Release()
{
    MEDIA_LOGI("Release");
    if (released_.exchange(true)) {
        return MSERR_OK;
    }
    StopNetworkListening();

    std::vector<std::shared_ptr<MediaDownload::Downloader>> downloaders;
    {
        std::lock_guard<std::mutex> lock(mapMutex_);
        for (auto &pair : downloaderMap_) {
            if (pair.second != nullptr) {
                downloaders.push_back(pair.second);
            }
        }
        downloaderMap_.clear();
        taskMap_.clear();
        callback_.reset();
    }

    if (messageQueue_) {
        messageQueue_->Stop();
    }

    for (auto &dl : downloaders) {
        dl->Cancel();
        dl->Release();
    }
    return MSERR_OK;
}

void AVDownloaderManagerImpl::NotifyStatusChange(const std::string &taskId, AVDownloadTaskState state)
{
    MEDIA_LOGI("NotifyStatusChange: %{public}s, Task state: %{public}d", taskId.c_str(), state);
    {
        std::lock_guard<std::mutex> lock(mapMutex_);
        auto taskIter = taskMap_.find(taskId);
        if (taskIter != taskMap_.end()) {
            taskIter->second->state = state;
        }
    }
    std::lock_guard<std::mutex> lock(cbMutex_);
    auto callback = callback_.lock();
    if (callback != nullptr) {
        MEDIA_LOGI("NotifyStatusChange: %{public}s, callback not null", taskId.c_str());
        callback->OnStatusChange(taskId, state);
    }
}

void AVDownloaderManagerImpl::NotifyStatusChangeLocked(const std::string &taskId, AVDownloadTaskState state)
{
    MEDIA_LOGI("NotifyStatusChangeLocked: %{public}s, Task state: %{public}d", taskId.c_str(), state);
    auto taskIter = taskMap_.find(taskId);
    if (taskIter != taskMap_.end()) {
        taskIter->second->state = state;
    }
    std::lock_guard<std::mutex> lock(cbMutex_);
    auto callback = callback_.lock();
    if (callback != nullptr) {
        MEDIA_LOGI("NotifyStatusChangeLocked: %{public}s, callback not null", taskId.c_str());
        callback->OnStatusChange(taskId, state);
    }
}

void AVDownloaderManagerImpl::NotifyProgressChange(const std::string &taskId, double progress)
{
    MEDIA_LOGI("NotifyProgressChange: %{public}s, progress: %{public}f", taskId.c_str(), progress);
    {
        std::lock_guard<std::mutex> lock(mapMutex_);
        auto taskIter = taskMap_.find(taskId);
        if (taskIter != taskMap_.end()) {
            taskIter->second->progress = progress;
        }
    }
    std::lock_guard<std::mutex> lock(cbMutex_);
    auto callback = callback_.lock();
    if (callback != nullptr) {
        MEDIA_LOGI("NotifyProgressChange: %{public}s, callback not null", taskId.c_str());
        callback->OnProgressChange(taskId, progress);
    }
}

void AVDownloaderManagerImpl::NotifyProgressChangeLocked(const std::string &taskId, double progress)
{
    MEDIA_LOGI("NotifyProgressChangeLocked: %{public}s, progress: %{public}f", taskId.c_str(), progress);
    auto taskIter = taskMap_.find(taskId);
    if (taskIter != taskMap_.end()) {
        taskIter->second->progress = progress;
    }
    std::lock_guard<std::mutex> lock(cbMutex_);
    auto callback = callback_.lock();
    if (callback != nullptr) {
        MEDIA_LOGI("NotifyProgressChangeLocked: %{public}s, callback not null", taskId.c_str());
        callback->OnProgressChange(taskId, progress);
    }
}

void AVDownloaderManagerImpl::ProcessNextPendingTask()
{
    std::lock_guard<std::mutex> lock(mapMutex_);
    while (GetActiveCountLocked() < MAX_DOWNLOADER_COUNT && !pendingTaskQueue_.empty()) {
        auto [url, taskId] = pendingTaskQueue_.front();
        pendingTaskQueue_.pop_front();

        auto taskIter = taskMap_.find(taskId);
        if (taskIter == taskMap_.end()) {
            continue;
        }

        auto downloaderIter = downloaderMap_.find(taskId);
        if (downloaderIter == downloaderMap_.end() || downloaderIter->second == nullptr) {
            continue;
        }

        auto downloader = downloaderIter->second;
        auto state = downloader->GetState();
        int32_t ret;

        if (state == MediaDownload::DOWNLOAD_PAUSED) {
            ret = downloader->Resume();
        } else if (state == MediaDownload::DOWNLOAD_IDLE) {
            if (taskCallback_ == nullptr) {
                taskCallback_ = std::make_shared<DownloadTaskCallback>(weak_from_this());
            }
            downloader->SetDownloadCallback(taskCallback_);
            MediaDownload::DownloadConfig config;
            config.timeoutMs = requestTimeoutMs_.load();
            config.allowMobileData = allowCellularAccess_.load();
            config.allowWifi = true;
            downloader->AddFileTask(url, taskIter->second->currentFilePath, config);
            downloader->SetConfig(config);
            ret = downloader->Start();
        } else {
            continue;
        }

        if (ret == MSERR_OK) {
            taskIter->second->state = AVDownloadTaskState::RUNNING;
            MEDIA_LOGI("ProcessNextPendingTask: started taskId=%{public}s", taskId.c_str());
        } else {
            taskIter->second->state = AVDownloadTaskState::ERROR;
            NotifyStatusChangeLocked(taskId, AVDownloadTaskState::ERROR);
            MEDIA_LOGE("ProcessNextPendingTask: Start/Resume failed for taskId=%{public}s, ret=%{public}d",
                taskId.c_str(), ret);
        }
        break;
    }
}

int32_t AVDownloaderManagerImpl::GetActiveCountLocked() const
{
    return static_cast<int32_t>(std::count_if(taskMap_.begin(), taskMap_.end(),
        [](const auto& pair) {
            return pair.second->state == AVDownloadTaskState::RUNNING;
        }));
}

void AVDownloaderManagerImpl::HandleMessage(const MediaDownload::Message &msg)
{
    switch (msg.type) {
        case MediaDownload::MSG_RELEASE_DOWNLOADER:
            {
                std::string taskId = std::to_string(msg.downloaderId);
                MEDIA_LOGI("HandleMessage: releasing downloader: %{public}s", taskId.c_str());
                std::shared_ptr<MediaDownload::Downloader> downloader;
                {
                    std::lock_guard<std::mutex> lock(mapMutex_);
                    auto iter = downloaderMap_.find(taskId);
                    if (iter != downloaderMap_.end()) {
                        downloader = iter->second;
                        downloaderMap_.erase(iter);
                    }
                }
                if (downloader != nullptr) {
                    downloader->Release();
                }
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
    if (released_.load()) {
        MEDIA_LOGI("OnNetworkChanged: already released, ignoring");
        return;
    }
    if (IsNetworkAllowDownload(newType)) {
        OnNetworkRestored();
    } else {
        OnNetworkLost();
    }
}

void AVDownloaderManagerImpl::OnNetworkRestored()
{
    MEDIA_LOGI("OnNetworkRestored: network restored, queuing paused tasks");
    std::lock_guard<std::mutex> lock(mapMutex_);
    for (auto& pair : taskMap_) {
        if (pair.second->state != AVDownloadTaskState::PAUSED) {
            continue;
        }
        MEDIA_LOGI("OnNetworkRestored: queuing paused taskId=%{public}s", pair.first.c_str());
        pendingTaskQueue_.push_back({pair.second->url, pair.first});
        pair.second->state = AVDownloadTaskState::QUEUED;
        NotifyStatusChangeLocked(pair.first, AVDownloadTaskState::QUEUED);
    }
    MediaDownload::Message nextMsg;
    nextMsg.type = MediaDownload::MSG_PROCESS_NEXT_TASK;
    messageQueue_->PostMessage(nextMsg);
}

void AVDownloaderManagerImpl::OnNetworkLost()
{
    MEDIA_LOGI("OnNetworkLost: network lost, pausing running tasks");
    std::lock_guard<std::mutex> lock(mapMutex_);
    for (auto& pair : taskMap_) {
        if (pair.second->state != AVDownloadTaskState::RUNNING) {
            continue;
        }
        auto downloaderIter = downloaderMap_.find(pair.first);
        if (downloaderIter == downloaderMap_.end() || downloaderIter->second == nullptr) {
            continue;
        }
        MEDIA_LOGI("OnNetworkLost: pausing taskId=%{public}s", pair.first.c_str());
        (void)downloaderIter->second->Pause();
        NotifyStatusChangeLocked(pair.first, AVDownloadTaskState::PAUSED);
    }
}

bool AVDownloaderManagerImpl::IsNetworkAllowDownload(MediaSourceUtils::NetConnType newType)
{
    if (newType == MediaSourceUtils::NetConnType::NET_CONN_NONE ||
        newType == MediaSourceUtils::NetConnType::NET_CONN_UNKNOWN) {
        MEDIA_LOGI("IsNetworkAllowDownload: no network available");
        return false;
    }

    if (allowCellularAccess_.load() && newType == MediaSourceUtils::NetConnType::NET_CONN_CELLULAR) {
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
