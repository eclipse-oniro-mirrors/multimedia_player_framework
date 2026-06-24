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

#ifndef DOWNLOADER_H
#define DOWNLOADER_H

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>

namespace OHOS {
namespace Media {
namespace MediaDownload {

constexpr uint64_t INVALID_TASK_ID = static_cast<uint64_t>(-1);

enum DownloadState : int32_t {
    DOWNLOAD_IDLE = 0,
    DOWNLOAD_PREPARING,
    DOWNLOAD_RUNNING,
    DOWNLOAD_PAUSING,
    DOWNLOAD_PAUSED,
    DOWNLOAD_RESUMING,
    DOWNLOAD_CANCELING,
    DOWNLOAD_COMPLETED,
    DOWNLOAD_FAILED,
    DOWNLOAD_CANCELED,
};

const std::unordered_map<DownloadState, const char*> DOWNLOAD_STATE_MAP = {
    {DOWNLOAD_IDLE, "DOWNLOAD_IDLE"},
    {DOWNLOAD_PREPARING, "DOWNLOAD_PREPARING"},
    {DOWNLOAD_RUNNING, "DOWNLOAD_RUNNING"},
    {DOWNLOAD_PAUSING, "DOWNLOAD_PAUSING"},
    {DOWNLOAD_PAUSED, "DOWNLOAD_PAUSED"},
    {DOWNLOAD_RESUMING, "DOWNLOAD_RESUMING"},
    {DOWNLOAD_CANCELING, "DOWNLOAD_CANCELING"},
    {DOWNLOAD_COMPLETED, "DOWNLOAD_COMPLETED"},
    {DOWNLOAD_FAILED, "DOWNLOAD_FAILED"},
    {DOWNLOAD_CANCELED, "DOWNLOAD_CANCELED"},
};

inline const char* DownloadStateLog(DownloadState state)
{
    auto it = DOWNLOAD_STATE_MAP.find(state);
    if (it != DOWNLOAD_STATE_MAP.end()) {
        return it->second;
    }
    return "DOWNLOAD_STATE_UNKNOWN";
}

enum DownloadErrorType : int32_t {
    DOWNLOAD_ERROR_NONE = 0,
    DOWNLOAD_ERROR_NETWORK,
    DOWNLOAD_ERROR_FILE_IO,
    DOWNLOAD_ERROR_INVALID_URL,
    DOWNLOAD_ERROR_DISK_SPACE,
    DOWNLOAD_ERROR_TIMEOUT,
    DOWNLOAD_ERROR_INTERNAL,
};

enum DownloadErrorCode : int32_t {
    DOWNLOAD_RET_OK = 0,
    DOWNLOAD_ERROR_INVALID_OPERATION = -1,
    DOWNLOAD_ERROR_INVALID_PARAM = -2,
    DOWNLOAD_ERROR_NOT_SET_URL = -3,
    DOWNLOAD_ERROR_NOT_SET_PATH = -4,
    DOWNLOAD_ERROR_ALREADY_RUNNING = -5,
    DOWNLOAD_ERROR_CREATE_FAILED = -6,
};

struct DownloadProgress {
    int64_t downloadedSize = 0;
    int64_t totalSize = -1;
    int32_t progressPercent = 0;
    int64_t downloadSpeed = 0;
};

struct DownloadConfig {
    int32_t progressCallbackIntervalMs = 1000;
    int32_t timeoutMs = 60000;
    int32_t retryCount = 3;
    int32_t bufferSize = 8192;
    bool allowWifi = true;
    bool allowMobileData = false;
    bool continueOnNetworkChange = true;
};

class DownloadCallback {
public:
    virtual ~DownloadCallback() = default;

    virtual void OnStateChanged(uint64_t downloaderId, DownloadState state) = 0;
    virtual void OnCompleted(uint64_t downloaderId, int64_t downloadedSize) = 0;
    virtual void OnFailed(uint64_t downloaderId, DownloadErrorType errorType, int32_t errorCode,
                          const std::string &errorMsg) = 0;
    virtual void OnProgress(uint64_t downloaderId, const DownloadProgress &progress) = 0;
};

class __attribute__((visibility("default"))) Downloader {
public:
    virtual ~Downloader() = default;

    virtual uint64_t GetDownloaderId() = 0;
    virtual uint64_t GetCurrentTaskId() = 0;

    virtual int32_t SetUrl(const std::string &url) = 0;
    virtual int32_t SetOutputPath(const std::string &path) = 0;
    virtual int32_t SetHeader(const std::map<std::string, std::string> &header) = 0;
    virtual int32_t SetConfig(const DownloadConfig &config) = 0;
    virtual int32_t AddFileTask(const std::string &url, const std::string &path, const DownloadConfig &config) = 0;
    virtual int32_t SetDownloadCallback(const std::shared_ptr<DownloadCallback> &callback) = 0;

    virtual int32_t Start() = 0;
    virtual int32_t Pause() = 0;
    virtual int32_t Resume() = 0;
    virtual int32_t Cancel() = 0;
    virtual int32_t Release() = 0;

    virtual DownloadState GetState() = 0;
    virtual int32_t GetProgress(DownloadProgress &progress) = 0;
    virtual std::string GetCurrentFilePath() const = 0;
};

class __attribute__((visibility("default"))) DownloaderFactory {
public:
#ifdef UNSUPPORT_DOWNLOADER
    static std::shared_ptr<Downloader> CreateDownloader()
    {
        return nullptr;
    }
#else
    static std::shared_ptr<Downloader> CreateDownloader();
#endif
private:
    DownloaderFactory() = default;
    ~DownloaderFactory() = default;
};

} // namespace MediaDownload
} // namespace Media
} // namespace OHOS

#endif // DOWNLOADER_H