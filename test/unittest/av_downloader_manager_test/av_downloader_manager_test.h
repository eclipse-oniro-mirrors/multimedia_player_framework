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

#ifndef AVDOWNLOADER_MANAGER_TEST_H
#define AVDOWNLOADER_MANAGER_TEST_H

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <string>
#include <memory>
#include <vector>
#include <map>
#include "av_downloader_manager.h"
#include "av_downloader_manager_impl.h"
#include "downloader_impl.h"
#include "network_utils.h"

namespace OHOS {
namespace Media {

class MockAVDownloaderManagerCallback : public AVDownloaderManagerCallback {
public:
    MOCK_METHOD(void, OnStatusChange, (const std::string &taskId, AVDownloadTaskState state), (override));
    MOCK_METHOD(void, OnProgressChange, (const std::string &taskId, double progress), (override));
};

class MockDownloader : public MediaDownload::Downloader {
public:
    MOCK_METHOD(uint64_t, GetDownloaderId, (), (override));
    MOCK_METHOD(uint64_t, GetCurrentTaskId, (), (override));
    MOCK_METHOD(int32_t, SetUrl, (const std::string &url), (override));
    MOCK_METHOD(int32_t, SetOutputPath, (const std::string &path), (override));
    MOCK_METHOD(int32_t, SetHeader, (const std::map<std::string, std::string> &header), (override));
    MOCK_METHOD(int32_t, SetConfig, (const MediaDownload::DownloadConfig &config), (override));
    MOCK_METHOD(int32_t, AddFileTask, (const std::string &url, const std::string &path,
        const MediaDownload::DownloadConfig &config), (override));
    MOCK_METHOD(int32_t, SetDownloadCallback,
        (const std::shared_ptr<MediaDownload::DownloadCallback> &callback), (override));
    MOCK_METHOD(int32_t, Start, (), (override));
    MOCK_METHOD(int32_t, Pause, (), (override));
    MOCK_METHOD(int32_t, Resume, (), (override));
    MOCK_METHOD(int32_t, Cancel, (), (override));
    MOCK_METHOD(int32_t, Release, (), (override));
    MOCK_METHOD(MediaDownload::DownloadState, GetState, (), (override));
    MOCK_METHOD(int32_t, GetProgress, (MediaDownload::DownloadProgress &progress), (override));
    MOCK_METHOD(std::string, GetCurrentFilePath, (), (const, override));
};

class MockDownloaderImpl : public MediaDownload::DownloaderImpl {
public:
    MOCK_METHOD(int32_t, SetConfig, (const MediaDownload::DownloadConfig &config), (override));
    MOCK_METHOD(int32_t, AddFileTask, (const std::string &url, const std::string &path,
        const MediaDownload::DownloadConfig &config), (override));
    MOCK_METHOD(int32_t, Start, (), (override));
};

class TestableAVDownloaderManager : public AVDownloaderManagerImpl {
protected:
    MediaSourceUtils::NetConnType GetNetworkType() override
    {
        return simulatedNetworkType_;
    }
public:
    MediaSourceUtils::NetConnType simulatedNetworkType_ = MediaSourceUtils::NetConnType::NET_CONN_WIFI;
};

class AVDownloaderManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void) {}
    void TearDown(void) {}

protected:
    std::shared_ptr<AVDownloaderManagerImpl> managerImpl_;
    std::shared_ptr<MockAVDownloaderManagerCallback> mockCallback_;
};

} // namespace Media
} // namespace OHOS

#endif // AVDOWNLOADER_MANAGER_TEST_H
