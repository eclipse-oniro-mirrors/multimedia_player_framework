/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <algorithm>
#include <chrono>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "net_downloader_test_common.h"
#include "downloader.h"
#include "downloader_impl.h"
#include "network_utils_fake.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {
namespace MediaDownload {

namespace {
// 并发压力参数
constexpr int32_t CONCURRENT_READER_COUNT = 8;
constexpr int32_t CONCURRENT_WRITER_COUNT = 4;
constexpr int32_t CONCURRENT_READ_ITERATIONS = 100;
constexpr int32_t CONCURRENT_READ_ITERATIONS_DURING_PROCESSING = 50;
constexpr auto LOCK_WAIT_TIMEOUT = std::chrono::milliseconds(100);

// DownloadConfig 默认契约
constexpr int32_t DEFAULT_PROGRESS_CALLBACK_INTERVAL_MS = 1000;
constexpr int32_t DEFAULT_TIMEOUT_MS = 60000;
constexpr int32_t DEFAULT_RETRY_COUNT = 3;
constexpr int32_t DEFAULT_BUFFER_SIZE = 8192;

// 自定义测试配置
constexpr int32_t TEST_PROGRESS_INTERVAL_MS = 500;
constexpr int32_t TEST_TIMEOUT_MS = 120000;
constexpr int32_t TEST_RETRY_COUNT = 5;
constexpr int32_t TEST_BUFFER_SIZE = 16384;
constexpr int32_t FAST_TIMEOUT_MS = 1000;
constexpr int32_t NO_RETRY = 0;

// MakeConcurrentConfig 区分性基值/步长
constexpr int32_t CFG_PROGRESS_BASE = 500;
constexpr int32_t CFG_PROGRESS_STEP = 100;
constexpr int32_t CFG_TIMEOUT_BASE = 10000;
constexpr int32_t CFG_TIMEOUT_STEP = 1000;
constexpr int32_t CFG_BUFFER_BASE = 2048;
constexpr int32_t CFG_BUFFER_STEP = 1024;

// MakeConcurrentConfig 的 bool 组合（4 writer 各不同，保证配置两两不同）
struct ConcurrentConfigFlags {
    bool allowWifi;
    bool allowMobileData;
    bool continueOnNetworkChange;
};
constexpr ConcurrentConfigFlags CONCURRENT_CONFIG_FLAGS[] = {
    {true, false, true},
    {false, true, false},
    {true, true, false},
    {false, false, true},
};

class DescTestCallback : public DownloadCallback {
public:
    void OnStateChanged(uint64_t downloaderId, DownloadState state) override {}
    void OnCompleted(uint64_t downloaderId, int64_t downloadedSize) override {}
    void OnFailed(uint64_t downloaderId, DownloadErrorType errorType, int32_t errorCode,
                   const std::string &errorMsg) override {}
    void OnProgress(uint64_t downloaderId, const DownloadProgress &progress) override {}
    void OnFileCompleted(uint64_t downloaderId, const std::string &url, int64_t fileSize) override {}
};

DownloadConfig MakeConcurrentConfig(int i)
{
    DownloadConfig c;
    c.progressCallbackIntervalMs = CFG_PROGRESS_BASE + i * CFG_PROGRESS_STEP;
    c.timeoutMs = CFG_TIMEOUT_BASE + i * CFG_TIMEOUT_STEP;
    c.retryCount = i;
    c.bufferSize = CFG_BUFFER_BASE + i * CFG_BUFFER_STEP;
    c.allowWifi = CONCURRENT_CONFIG_FLAGS[i].allowWifi;
    c.allowMobileData = CONCURRENT_CONFIG_FLAGS[i].allowMobileData;
    c.continueOnNetworkChange = CONCURRENT_CONFIG_FLAGS[i].continueOnNetworkChange;
    return c;
}

bool ConfigEquals(const DownloadConfig &a, const DownloadConfig &b)
{
    return a.progressCallbackIntervalMs == b.progressCallbackIntervalMs &&
           a.timeoutMs == b.timeoutMs &&
           a.retryCount == b.retryCount &&
           a.bufferSize == b.bufferSize &&
           a.allowWifi == b.allowWifi &&
           a.allowMobileData == b.allowMobileData &&
           a.continueOnNetworkChange == b.continueOnNetworkChange;
}
} // namespace

class DownloaderDescriptorTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void)
    {
        testDir_ = TestCommon::GetTestCacheDir("downloader_descriptor_test");
        TestCommon::SetupTestDirectory(testDir_);
        MediaSourceUtils::ResetFakeNetworkType();
    }
    void TearDown(void)
    {
        TestCommon::CleanupTestDirectory(testDir_);
        MediaSourceUtils::ResetFakeNetworkType();
    }

protected:
    std::string testDir_;
};

HWTEST_F(DownloaderDescriptorTest, GetConfig_ReturnsDefault_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    DownloadConfig cfg = downloader->GetConfig();
    EXPECT_EQ(cfg.progressCallbackIntervalMs, DEFAULT_PROGRESS_CALLBACK_INTERVAL_MS);
    EXPECT_EQ(cfg.timeoutMs, DEFAULT_TIMEOUT_MS);
    EXPECT_EQ(cfg.retryCount, DEFAULT_RETRY_COUNT);
    EXPECT_EQ(cfg.bufferSize, DEFAULT_BUFFER_SIZE);
    EXPECT_TRUE(cfg.allowWifi);
    EXPECT_FALSE(cfg.allowMobileData);
    EXPECT_TRUE(cfg.continueOnNetworkChange);
}

HWTEST_F(DownloaderDescriptorTest, GetConfig_ReturnsSetConfig_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    DownloadConfig cfg;
    cfg.progressCallbackIntervalMs = TEST_PROGRESS_INTERVAL_MS;
    cfg.timeoutMs = TEST_TIMEOUT_MS;
    cfg.retryCount = TEST_RETRY_COUNT;
    cfg.bufferSize = TEST_BUFFER_SIZE;
    cfg.allowWifi = true;
    cfg.allowMobileData = true;
    cfg.continueOnNetworkChange = false;
    ASSERT_EQ(downloader->SetConfig(cfg), DOWNLOAD_RET_OK);

    DownloadConfig got = downloader->GetConfig();
    EXPECT_EQ(got.progressCallbackIntervalMs, TEST_PROGRESS_INTERVAL_MS);
    EXPECT_EQ(got.timeoutMs, TEST_TIMEOUT_MS);
    EXPECT_EQ(got.retryCount, TEST_RETRY_COUNT);
    EXPECT_EQ(got.bufferSize, TEST_BUFFER_SIZE);
    EXPECT_TRUE(got.allowMobileData);
    EXPECT_FALSE(got.continueOnNetworkChange);
}

HWTEST_F(DownloaderDescriptorTest, GetUrl_ReturnsSetUrl_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    ASSERT_EQ(downloader->SetUrl("http://example.com/test.mp4"), DOWNLOAD_RET_OK);
    EXPECT_EQ(downloader->GetUrl(), "http://example.com/test.mp4");
}

HWTEST_F(DownloaderDescriptorTest, GetOutputPath_ReturnsSetOutputPath_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    ASSERT_EQ(downloader->SetOutputPath(testDir_ + "/test.mp4"), DOWNLOAD_RET_OK);
    EXPECT_EQ(downloader->GetOutputPath(), testDir_ + "/test.mp4");
}

HWTEST_F(DownloaderDescriptorTest, GetHeader_ReturnsSetHeader_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    std::map<std::string, std::string> header;
    header["User-Agent"] = "TestAgent";
    header["Accept"] = "*/*";
    ASSERT_EQ(downloader->SetHeader(header), DOWNLOAD_RET_OK);

    auto got = downloader->GetHeader();
    EXPECT_EQ(got.size(), header.size());
    EXPECT_EQ(got["User-Agent"], "TestAgent");
    EXPECT_EQ(got["Accept"], "*/*");
}

HWTEST_F(DownloaderDescriptorTest, GetOutputPath_EmptyByDefault_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    EXPECT_EQ(downloader->GetOutputPath(), "");
}

HWTEST_F(DownloaderDescriptorTest, GetCurrentFilePath_UsesAccessor_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    ASSERT_EQ(downloader->SetOutputPath(testDir_ + "/test.mp4"), DOWNLOAD_RET_OK);
    EXPECT_EQ(downloader->GetCurrentFilePath(), testDir_ + "/test.mp4");
}

HWTEST_F(DownloaderDescriptorTest, GetConfig_AcquiresDescriptorMutex_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    DownloadConfig cfg;
    cfg.timeoutMs = TEST_TIMEOUT_MS;
    ASSERT_EQ(downloader->SetConfig(cfg), DOWNLOAD_RET_OK);

    std::unique_lock<std::mutex> hold(downloader->descriptorMutex_);
    auto fut = std::async(std::launch::async, [&downloader]() { return downloader->GetConfig(); });
    EXPECT_EQ(fut.wait_for(LOCK_WAIT_TIMEOUT), std::future_status::timeout);
    hold.unlock();
    EXPECT_EQ(fut.get().timeoutMs, TEST_TIMEOUT_MS);
}

HWTEST_F(DownloaderDescriptorTest, GetUrl_AcquiresDescriptorMutex_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    ASSERT_EQ(downloader->SetUrl("http://example.com/test.mp4"), DOWNLOAD_RET_OK);

    std::unique_lock<std::mutex> hold(downloader->descriptorMutex_);
    auto fut = std::async(std::launch::async, [&downloader]() { return downloader->GetUrl(); });
    EXPECT_EQ(fut.wait_for(LOCK_WAIT_TIMEOUT), std::future_status::timeout);
    hold.unlock();
    EXPECT_EQ(fut.get(), "http://example.com/test.mp4");
}

HWTEST_F(DownloaderDescriptorTest, GetOutputPath_AcquiresDescriptorMutex_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    ASSERT_EQ(downloader->SetOutputPath(testDir_ + "/test.mp4"), DOWNLOAD_RET_OK);

    std::unique_lock<std::mutex> hold(downloader->descriptorMutex_);
    auto fut = std::async(std::launch::async, [&downloader]() { return downloader->GetOutputPath(); });
    EXPECT_EQ(fut.wait_for(LOCK_WAIT_TIMEOUT), std::future_status::timeout);
    hold.unlock();
    EXPECT_EQ(fut.get(), testDir_ + "/test.mp4");
}

HWTEST_F(DownloaderDescriptorTest, GetHeader_AcquiresDescriptorMutex_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    std::map<std::string, std::string> header;
    header["User-Agent"] = "TestAgent";
    ASSERT_EQ(downloader->SetHeader(header), DOWNLOAD_RET_OK);

    std::unique_lock<std::mutex> hold(downloader->descriptorMutex_);
    auto fut = std::async(std::launch::async, [&downloader]() { return downloader->GetHeader(); });
    EXPECT_EQ(fut.wait_for(LOCK_WAIT_TIMEOUT), std::future_status::timeout);
    hold.unlock();
    EXPECT_EQ(fut.get()["User-Agent"], "TestAgent");
}

HWTEST_F(DownloaderDescriptorTest, GetCurrentFilePath_AcquiresDescriptorMutex_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    ASSERT_EQ(downloader->SetOutputPath(testDir_ + "/test.mp4"), DOWNLOAD_RET_OK);

    std::unique_lock<std::mutex> hold(downloader->descriptorMutex_);
    auto fut = std::async(std::launch::async, [&downloader]() { return downloader->GetCurrentFilePath(); });
    EXPECT_EQ(fut.wait_for(LOCK_WAIT_TIMEOUT), std::future_status::timeout);
    hold.unlock();
    EXPECT_EQ(fut.get(), testDir_ + "/test.mp4");
}

HWTEST_F(DownloaderDescriptorTest, SetConfig_AcquiresDescriptorMutex_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    std::unique_lock<std::mutex> hold(downloader->descriptorMutex_);
    auto fut = std::async(std::launch::async, [&downloader]() {
        return downloader->SetConfig(DownloadConfig{});
    });
    EXPECT_EQ(fut.wait_for(LOCK_WAIT_TIMEOUT), std::future_status::timeout);
    hold.unlock();
    EXPECT_EQ(fut.get(), DOWNLOAD_RET_OK);
}

HWTEST_F(DownloaderDescriptorTest, SetUrl_AcquiresDescriptorMutex_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    std::unique_lock<std::mutex> hold(downloader->descriptorMutex_);
    auto fut = std::async(std::launch::async, [&downloader]() {
        return downloader->SetUrl("http://example.com/test.mp4");
    });
    EXPECT_EQ(fut.wait_for(LOCK_WAIT_TIMEOUT), std::future_status::timeout);
    hold.unlock();
    EXPECT_EQ(fut.get(), DOWNLOAD_RET_OK);
}

HWTEST_F(DownloaderDescriptorTest, SetOutputPath_AcquiresDescriptorMutex_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    std::unique_lock<std::mutex> hold(downloader->descriptorMutex_);
    auto fut = std::async(std::launch::async, [downloader, this]() {
        return downloader->SetOutputPath(testDir_ + "/test.mp4");
    });
    EXPECT_EQ(fut.wait_for(LOCK_WAIT_TIMEOUT), std::future_status::timeout);
    hold.unlock();
    EXPECT_EQ(fut.get(), DOWNLOAD_RET_OK);
}

HWTEST_F(DownloaderDescriptorTest, SetHeader_AcquiresDescriptorMutex_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    std::map<std::string, std::string> header;
    header["User-Agent"] = "TestAgent";
    std::unique_lock<std::mutex> hold(downloader->descriptorMutex_);
    auto fut = std::async(std::launch::async, [downloader, header]() {
        return downloader->SetHeader(header);
    });
    EXPECT_EQ(fut.wait_for(LOCK_WAIT_TIMEOUT), std::future_status::timeout);
    hold.unlock();
    EXPECT_EQ(fut.get(), DOWNLOAD_RET_OK);
}

HWTEST_F(DownloaderDescriptorTest, ProcessNextTaskInQueue_AcquiresDescriptorMutex_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    DownloadConfig cfg;
    cfg.allowWifi = false;
    cfg.allowMobileData = false;
    ASSERT_EQ(downloader->SetConfig(cfg), DOWNLOAD_RET_OK);
    ASSERT_EQ(downloader->AddFileTask("http://example.com/a.mp4", testDir_ + "/a.mp4", cfg), DOWNLOAD_RET_OK);

    std::unique_lock<std::mutex> hold(downloader->descriptorMutex_);
    auto fut = std::async(std::launch::async, [&downloader]() {
        return downloader->ProcessNextTaskInQueue();
    });
    EXPECT_EQ(fut.wait_for(LOCK_WAIT_TIMEOUT), std::future_status::timeout);
    hold.unlock();
    EXPECT_EQ(fut.get(), DOWNLOAD_ERROR_NETWORK);
}

HWTEST_F(DownloaderDescriptorTest, Concurrent_GetCurrentFilePathVsSetOutputPath_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    std::vector<std::string> paths;
    for (int i = 0; i < CONCURRENT_WRITER_COUNT; ++i) {
        paths.push_back(testDir_ + "/p" + std::to_string(i) + ".mp4");
    }
    std::vector<std::future<void>> readers;
    for (int i = 0; i < CONCURRENT_READER_COUNT; ++i) {
        readers.push_back(std::async(std::launch::async, [downloader]() {
            for (int k = 0; k < CONCURRENT_READ_ITERATIONS; ++k) {
                (void)downloader->GetCurrentFilePath();
            }
        }));
    }
    std::vector<std::future<int32_t>> writers;
    for (int i = 0; i < CONCURRENT_WRITER_COUNT; ++i) {
        writers.push_back(std::async(std::launch::async, [downloader, &paths, i]() {
            return downloader->SetOutputPath(paths[i]);
        }));
    }
    for (auto &r : readers) {
        r.get();
    }
    for (auto &w : writers) {
        (void)w.get();
    }
    std::string finalPath = downloader->GetCurrentFilePath();
    EXPECT_FALSE(finalPath.empty());
    EXPECT_NE(std::find(paths.begin(), paths.end(), finalPath), paths.end());
}

HWTEST_F(DownloaderDescriptorTest, Concurrent_GetConfigVsSetConfig_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    std::vector<DownloadConfig> expected;
    for (int i = 0; i < CONCURRENT_WRITER_COUNT; ++i) {
        expected.push_back(MakeConcurrentConfig(i));
    }
    std::vector<std::future<void>> readers;
    for (int i = 0; i < CONCURRENT_READER_COUNT; ++i) {
        readers.push_back(std::async(std::launch::async, [downloader]() {
            for (int k = 0; k < CONCURRENT_READ_ITERATIONS; ++k) {
                DownloadConfig g = downloader->GetConfig();
                (void)g;
            }
        }));
    }
    std::vector<std::future<int32_t>> writers;
    for (int i = 0; i < CONCURRENT_WRITER_COUNT; ++i) {
        writers.push_back(std::async(std::launch::async, [downloader, i]() {
            return downloader->SetConfig(MakeConcurrentConfig(i));
        }));
    }
    for (auto &r : readers) {
        r.get();
    }
    for (auto &w : writers) {
        (void)w.get();
    }
    DownloadConfig finalCfg = downloader->GetConfig();
    bool found = false;
    for (const auto &e : expected) {
        if (ConfigEquals(finalCfg, e)) {
            found = true;
            break;
        }
    }
    EXPECT_TRUE(found);
}

HWTEST_F(DownloaderDescriptorTest, Concurrent_GetCurrentFilePathDuringProcessing_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    (void)downloader->SetDownloadCallback(std::make_shared<DescTestCallback>());
    DownloadConfig cfg;
    cfg.timeoutMs = FAST_TIMEOUT_MS;
    cfg.retryCount = NO_RETRY;
    (void)downloader->SetConfig(cfg);
    (void)downloader->AddFileTask("http://host.invalid/a.mp4", testDir_ + "/a.mp4", cfg);
    (void)downloader->AddFileTask("http://host.invalid/b.mp4", testDir_ + "/b.mp4", cfg);

    MediaSourceUtils::FakeNetworkTypeGuard guard(MediaSourceUtils::NetConnType::NET_CONN_WIFI);
    (void)downloader->Start();
    std::vector<std::future<void>> readers;
    for (int i = 0; i < CONCURRENT_READER_COUNT; ++i) {
        readers.push_back(std::async(std::launch::async, [downloader]() {
            for (int k = 0; k < CONCURRENT_READ_ITERATIONS_DURING_PROCESSING; ++k) {
                (void)downloader->GetCurrentFilePath();
            }
        }));
    }
    for (auto &r : readers) {
        r.get();
    }
    (void)downloader->Cancel();
    (void)downloader->Release();
    EXPECT_EQ(downloader->GetState(), DOWNLOAD_IDLE);
}

HWTEST_F(DownloaderDescriptorTest, IsNetworkAllowDownload_NoneNetwork_ReturnsFalse_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    DownloadConfig cfg;
    cfg.allowWifi = true;
    cfg.allowMobileData = true;
    EXPECT_FALSE(downloader->IsNetworkAllowDownload(
        cfg, MediaSourceUtils::NetConnType::NET_CONN_NONE));
}

HWTEST_F(DownloaderDescriptorTest, IsNetworkAllowDownload_UnknownNetwork_ReturnsFalse_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    DownloadConfig cfg;
    cfg.allowWifi = true;
    EXPECT_FALSE(downloader->IsNetworkAllowDownload(
        cfg, MediaSourceUtils::NetConnType::NET_CONN_UNKNOWN));
}

HWTEST_F(DownloaderDescriptorTest, IsNetworkAllowDownload_WifiAllowed_ReturnsTrue_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    DownloadConfig cfg;
    cfg.allowWifi = true;
    EXPECT_TRUE(downloader->IsNetworkAllowDownload(
        cfg, MediaSourceUtils::NetConnType::NET_CONN_WIFI));
}

HWTEST_F(DownloaderDescriptorTest, IsNetworkAllowDownload_WifiDisabled_WifiNetwork_ReturnsFalse_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    DownloadConfig cfg;
    cfg.allowWifi = false;
    EXPECT_FALSE(downloader->IsNetworkAllowDownload(
        cfg, MediaSourceUtils::NetConnType::NET_CONN_WIFI));
}

HWTEST_F(DownloaderDescriptorTest, IsNetworkAllowDownload_WifiEnabled_CellularNetwork_ReturnsFalse_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    DownloadConfig cfg;
    cfg.allowWifi = true;
    cfg.allowMobileData = false;
    EXPECT_FALSE(downloader->IsNetworkAllowDownload(
        cfg, MediaSourceUtils::NetConnType::NET_CONN_CELLULAR));
}

HWTEST_F(DownloaderDescriptorTest, IsNetworkAllowDownload_MobileAllowed_Cellular_ReturnsTrue_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    DownloadConfig cfg;
    cfg.allowWifi = false;
    cfg.allowMobileData = true;
    EXPECT_TRUE(downloader->IsNetworkAllowDownload(
        cfg, MediaSourceUtils::NetConnType::NET_CONN_CELLULAR));
}

HWTEST_F(DownloaderDescriptorTest, IsNetworkAllowDownload_MobileEnabled_WifiNetwork_ReturnsFalse_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    DownloadConfig cfg;
    cfg.allowWifi = false;
    cfg.allowMobileData = true;
    EXPECT_FALSE(downloader->IsNetworkAllowDownload(
        cfg, MediaSourceUtils::NetConnType::NET_CONN_WIFI));
}

HWTEST_F(DownloaderDescriptorTest, IsNetworkAllowDownload_BluetoothNetwork_ReturnsFalse_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    DownloadConfig cfg;
    cfg.allowWifi = true;
    cfg.allowMobileData = true;
    EXPECT_FALSE(downloader->IsNetworkAllowDownload(
        cfg, MediaSourceUtils::NetConnType::NET_CONN_BLUETOOTH));
}

HWTEST_F(DownloaderDescriptorTest, ProcessNextTaskInQueue_EmptyQueue_ReturnsOk_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    EXPECT_EQ(downloader->ProcessNextTaskInQueue(), DOWNLOAD_RET_OK);
}

HWTEST_F(DownloaderDescriptorTest, ProcessNextTaskInQueue_NetworkAllowed_ProceedsAndWritesDescriptor_001,
         TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    (void)downloader->SetDownloadCallback(std::make_shared<DescTestCallback>());
    DownloadConfig cfg;
    cfg.timeoutMs = FAST_TIMEOUT_MS;
    cfg.retryCount = NO_RETRY;
    (void)downloader->SetConfig(cfg);
    std::string url = "http://host.invalid/a.mp4";
    std::string path = testDir_ + "/a.mp4";
    ASSERT_EQ(downloader->AddFileTask(url, path, cfg), DOWNLOAD_RET_OK);

    MediaSourceUtils::FakeNetworkTypeGuard guard(MediaSourceUtils::NetConnType::NET_CONN_WIFI);
    int32_t ret = downloader->Start();
    EXPECT_EQ(ret, DOWNLOAD_RET_OK);
    EXPECT_EQ(downloader->GetUrl(), url);
    EXPECT_EQ(downloader->GetOutputPath(), path);
    EXPECT_EQ(downloader->GetConfig().retryCount, NO_RETRY);
    (void)downloader->Release();
}

HWTEST_F(DownloaderDescriptorTest, HandleTaskNetChanged_NetworkDisallowed_NotifiesPaused_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    DownloadConfig cfg;
    cfg.allowWifi = false;
    cfg.allowMobileData = false;
    ASSERT_EQ(downloader->SetConfig(cfg), DOWNLOAD_RET_OK);
    MediaSourceUtils::FakeNetworkTypeGuard guard(MediaSourceUtils::NetConnType::NET_CONN_WIFI);
    downloader->HandleTaskNetChanged();
    EXPECT_EQ(downloader->GetState(), DOWNLOAD_PAUSED);
}

HWTEST_F(DownloaderDescriptorTest, HandleTaskNetChanged_NetworkAllowed_InvokesResume_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    (void)downloader->SetDownloadCallback(std::make_shared<DescTestCallback>());
    DownloadConfig cfg;
    (void)downloader->SetConfig(cfg);
    MediaSourceUtils::FakeNetworkTypeGuard guard(MediaSourceUtils::NetConnType::NET_CONN_WIFI);
    downloader->HandleTaskNetChanged();
    EXPECT_EQ(downloader->GetState(), DOWNLOAD_COMPLETED);
}

HWTEST_F(DownloaderDescriptorTest, Resume_NetworkDisallowed_ReturnsNetworkError_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    DownloadConfig cfg;
    (void)downloader->SetConfig(cfg);
    downloader->state_.store(DOWNLOAD_PAUSED);
    MediaSourceUtils::FakeNetworkTypeGuard guard(MediaSourceUtils::NetConnType::NET_CONN_NONE);
    int32_t ret = downloader->Resume();
    EXPECT_EQ(ret, DOWNLOAD_ERROR_NETWORK);
    EXPECT_EQ(downloader->GetState(), DOWNLOAD_PAUSED);
}

HWTEST_F(DownloaderDescriptorTest, Resume_NetworkAllowed_NoTask_Completes_001, TestSize.Level0)
{
    auto downloader = std::make_shared<DownloaderImpl>();
    (void)downloader->SetDownloadCallback(std::make_shared<DescTestCallback>());
    DownloadConfig cfg;
    (void)downloader->SetConfig(cfg);
    downloader->state_.store(DOWNLOAD_PAUSED);
    MediaSourceUtils::FakeNetworkTypeGuard guard(MediaSourceUtils::NetConnType::NET_CONN_WIFI);
    int32_t ret = downloader->Resume();
    EXPECT_EQ(ret, DOWNLOAD_RET_OK);
    EXPECT_EQ(downloader->GetState(), DOWNLOAD_COMPLETED);
}

} // namespace MediaDownload
} // namespace Media
} // namespace OHOS
