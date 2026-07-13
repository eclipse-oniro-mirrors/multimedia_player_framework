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

#include <gtest/gtest.h>
#include <string>
#include <memory>
#include <vector>
#include <map>
#include <thread>
#include <future>
#include "net_downloader_test_common.h"
#include "downloader.h"
#include "downloader_impl.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {
namespace MediaDownload {

class StubDownloadCallback : public DownloadCallback {
public:
    void OnStateChanged(uint64_t downloaderId, DownloadState state) override {}
    void OnCompleted(uint64_t downloaderId, int64_t downloadedSize) override {}
    void OnFailed(uint64_t downloaderId, DownloadErrorType errorType, int32_t errorCode,
                  const std::string &errorMsg) override {}
    void OnProgress(uint64_t downloaderId, const DownloadProgress &progress) override {}
    void OnFileCompleted(uint64_t downloaderId, const std::string &url, int64_t fileSize) override {}
};

class DownloaderImplSuppTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void)
    {
        testDir_ = TestCommon::GetTestCacheDir("downloader_impl_supp_test");
        TestCommon::SetupTestDirectory(testDir_);
    }
    void TearDown(void)
    {
        TestCommon::CleanupTestDirectory(testDir_);
    }
protected:
    std::string testDir_;
};

HWTEST_F(DownloaderImplSuppTest, AddFileTask_ValidParams_Success_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    int32_t ret = downloader->SetOutputPath(testDir_ + "/test.mp4");
    EXPECT_EQ(ret, DOWNLOAD_RET_OK);
    ret = downloader->AddFileTask("http://example.com/test.mp4", testDir_ + "/test.mp4", DownloadConfig());
    EXPECT_EQ(ret, DOWNLOAD_RET_OK);
}

HWTEST_F(DownloaderImplSuppTest, AddFileTask_InvalidUrl_Fail_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    int32_t ret = downloader->AddFileTask("", testDir_ + "/test.mp4", DownloadConfig());
    EXPECT_NE(ret, DOWNLOAD_RET_OK);
}

HWTEST_F(DownloaderImplSuppTest, AddFileTask_InvalidPath_Fail_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    int32_t ret = downloader->AddFileTask("http://example.com/test.mp4", "", DownloadConfig());
    EXPECT_NE(ret, DOWNLOAD_RET_OK);
}

HWTEST_F(DownloaderImplSuppTest, Concurrent_SetUrl_ThreadSafe_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    std::vector<std::future<int32_t>> results;
    for (int i = 0; i < 10; ++i) {
        results.push_back(std::async(std::launch::async, [downloader, i]() {
            return downloader->SetUrl("http://example.com/test" + std::to_string(i) + ".mp4");
        }));
    }
    int successCount = 0;
    for (auto& result : results) {
        if (result.get() == DOWNLOAD_RET_OK) {
            ++successCount;
        }
    }
    EXPECT_GE(successCount, 1);
}

HWTEST_F(DownloaderImplSuppTest, Concurrent_SetOutputPath_ThreadSafe_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    std::vector<std::future<int32_t>> results;
    for (int i = 0; i < 10; ++i) {
        results.push_back(std::async(std::launch::async, [downloader, i, this]() {
            return downloader->SetOutputPath(testDir_ + "/test" + std::to_string(i) + ".mp4");
        }));
    }
    int successCount = 0;
    for (auto& result : results) {
        if (result.get() == DOWNLOAD_RET_OK) {
            ++successCount;
        }
    }
    EXPECT_GE(successCount, 1);
}

HWTEST_F(DownloaderImplSuppTest, Concurrent_StartAndCancel_ThreadSafe_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    (void)downloader->SetUrl("http://example.com/test.mp4");
    (void)downloader->SetOutputPath(testDir_ + "/test.mp4");
    (void)downloader->SetDownloadCallback(std::make_shared<StubDownloadCallback>());

    auto startFuture = std::async(std::launch::async, [downloader]() {
        return downloader->Start();
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    auto cancelFuture = std::async(std::launch::async, [downloader]() {
        return downloader->Cancel();
    });

    int32_t startRet = startFuture.get();
    int32_t cancelRet = cancelFuture.get();
    DownloadState state = downloader->GetState();
    EXPECT_TRUE(state == DOWNLOAD_COMPLETED || state == DOWNLOAD_FAILED || state == DOWNLOAD_CANCELED);
}

HWTEST_F(DownloaderImplSuppTest, Progress_MutexProtection_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    (void)downloader->SetUrl("http://example.com/test.mp4");
    (void)downloader->SetOutputPath(testDir_ + "/test.mp4");
    (void)downloader->SetDownloadCallback(std::make_shared<StubDownloadCallback>());
    (void)downloader->Start();

    std::vector<std::future<void>> results;
    for (int i = 0; i < 5; ++i) {
        results.push_back(std::async(std::launch::async, [downloader]() {
            DownloadProgress progress;
            (void)downloader->GetProgress(progress);
        }));
    }
    for (auto& result : results) {
        result.get();
    }
    (void)downloader->Cancel();
}

HWTEST_F(DownloaderImplSuppTest, GetState_ThreadSafe_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    (void)downloader->SetUrl("http://example.com/test.mp4");
    (void)downloader->SetOutputPath(testDir_ + "/test.mp4");
    (void)downloader->SetDownloadCallback(std::make_shared<StubDownloadCallback>());
    (void)downloader->Start();

    std::vector<std::future<DownloadState>> results;
    for (int i = 0; i < 10; ++i) {
        results.push_back(std::async(std::launch::async, [downloader]() {
            return downloader->GetState();
        }));
    }
    for (auto& result : results) {
        DownloadState state = result.get();
        (void)state;
    }
    (void)downloader->Cancel();
}

HWTEST_F(DownloaderImplSuppTest, DownloadConfig_AllFields_001, TestSize.Level0)
{
    DownloadConfig config;
    config.timeoutMs = 60000;
    config.retryCount = 3;
    config.bufferSize = 8192;
    config.allowWifi = true;
    config.allowMobileData = false;
    config.continueOnNetworkChange = true;
    config.callbackInterval = 1000;

    EXPECT_EQ(config.timeoutMs, 60000);
    EXPECT_EQ(config.retryCount, 3);
    EXPECT_EQ(config.bufferSize, 8192);
    EXPECT_TRUE(config.allowWifi);
    EXPECT_FALSE(config.allowMobileData);
    EXPECT_TRUE(config.continueOnNetworkChange);
    EXPECT_EQ(config.callbackInterval, 1000);
}

HWTEST_F(DownloaderImplSuppTest, DownloadProgress_Struct_001, TestSize.Level0)
{
    DownloadProgress progress;
    progress.downloadedSize = 1024;
    progress.totalSize = 2048;
    progress.progressPercent = 50.0;
    progress.downloadSpeed = 512;

    EXPECT_EQ(progress.downloadedSize, 1024);
    EXPECT_EQ(progress.totalSize, 2048);
    EXPECT_EQ(progress.progressPercent, 50.0);
    EXPECT_EQ(progress.downloadSpeed, 512);
}

HWTEST_F(DownloaderImplSuppTest, DownloadErrorType_Values_001, TestSize.Level0)
{
    EXPECT_EQ(static_cast<int32_t>(DownloadErrorType::NONE), 0);
    EXPECT_EQ(static_cast<int32_t>(DownloadErrorType::NETWORK_ERROR), 1);
    EXPECT_EQ(static_cast<int32_t>(DownloadErrorType::FILE_IO_ERROR), 2);
    EXPECT_EQ(static_cast<int32_t>(DownloadErrorType::INVALID_URL), 3);
    EXPECT_EQ(static_cast<int32_t>(DownloadErrorType::INVALID_PARAMETER), 4);
    EXPECT_EQ(static_cast<int32_t>(DownloadErrorType::UNKNOWN), 5);
}

HWTEST_F(DownloaderImplSuppTest, DownloadState_Values_001, TestSize.Level0)
{
    EXPECT_EQ(static_cast<int32_t>(DownloadState::IDLE), 0);
    EXPECT_EQ(static_cast<int32_t>(DownloadState::PREPARING), 1);
    EXPECT_EQ(static_cast<int32_t>(DownloadState::RUNNING), 2);
    EXPECT_EQ(static_cast<int32_t>(DownloadState::PAUSING), 3);
    EXPECT_EQ(static_cast<int32_t>(DownloadState::PAUSED), 4);
    EXPECT_EQ(static_cast<int32_t>(DownloadState::RESUMING), 5);
    EXPECT_EQ(static_cast<int32_t>(DownloadState::CANCELING), 6);
    EXPECT_EQ(static_cast<int32_t>(DownloadState::COMPLETED), 7);
    EXPECT_EQ(static_cast<int32_t>(DownloadState::FAILED), 8);
    EXPECT_EQ(static_cast<int32_t>(DownloadState::CANCELED), 9);
}

HWTEST_F(DownloaderImplSuppTest, SetUrl_WithSpecialCharacters_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    int32_t ret = downloader->SetUrl("http://example.com/test%20file.mp4?param=value&foo=bar");
    EXPECT_EQ(ret, DOWNLOAD_RET_OK);
}

HWTEST_F(DownloaderImplSuppTest, SetUrl_WithIPv6_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    int32_t ret = downloader->SetUrl("http://[::1]:8080/test.mp4");
    EXPECT_EQ(ret, DOWNLOAD_RET_OK);
}

HWTEST_F(DownloaderImplSuppTest, SetUrl_WithPort_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    int32_t ret = downloader->SetUrl("http://example.com:8080/test.mp4");
    EXPECT_EQ(ret, DOWNLOAD_RET_OK);
}

HWTEST_F(DownloaderImplSuppTest, SetHeader_WithMultipleValues_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    std::map<std::string, std::string> header;
    header["User-Agent"] = "TestAgent";
    header["Accept"] = "*/*";
    header["Referer"] = "http://example.com";
    int32_t ret = downloader->SetHeader(header);
    EXPECT_EQ(ret, DOWNLOAD_RET_OK);
}

HWTEST_F(DownloaderImplSuppTest, SetConfig_WithAllOptions_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    DownloadConfig config;
    config.timeoutMs = 120000;
    config.retryCount = 5;
    config.bufferSize = 16384;
    config.allowWifi = true;
    config.allowMobileData = true;
    config.continueOnNetworkChange = false;
    config.callbackInterval = 500;
    int32_t ret = downloader->SetConfig(config);
    EXPECT_EQ(ret, DOWNLOAD_RET_OK);
}

HWTEST_F(DownloaderImplSuppTest, GetCurrentFilePath_Initial_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    std::string path = downloader->GetCurrentFilePath();
    EXPECT_EQ(path, "");
}

HWTEST_F(DownloaderImplSuppTest, GetCurrentFilePath_AfterSetOutput_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    (void)downloader->SetOutputPath(testDir_ + "/test.mp4");
    std::string path = downloader->GetCurrentFilePath();
    EXPECT_EQ(path, testDir_ + "/test.mp4");
}

HWTEST_F(DownloaderImplSuppTest, Start_WithoutUrl_Fail_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    (void)downloader->SetOutputPath(testDir_ + "/test.mp4");
    int32_t ret = downloader->Start();
    EXPECT_NE(ret, DOWNLOAD_RET_OK);
}

HWTEST_F(DownloaderImplSuppTest, Start_WithoutOutputPath_Fail_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    (void)downloader->SetUrl("http://example.com/test.mp4");
    int32_t ret = downloader->Start();
    EXPECT_NE(ret, DOWNLOAD_RET_OK);
}

} // namespace MediaDownload
} // namespace Media
} // namespace OHOS
