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
#include "net_downloader_test_common.h"
#include "downloader.h"

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
};

class DownloaderTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void)
    {
        testDir_ = TestCommon::GetTestCacheDir("downloader_test");
        TestCommon::SetupTestDirectory(testDir_);
    }
    void TearDown(void)
    {
        TestCommon::CleanupTestDirectory(testDir_);
    }
protected:
    std::string testDir_;
};

HWTEST_F(DownloaderTest, GetDownloaderId_001, TestSize.Level0)
{
    auto downloader = DownloaderFactory::CreateDownloader();
    ASSERT_NE(downloader, nullptr);
    uint64_t id = downloader->GetDownloaderId();
    EXPECT_GT(id, 0);
}

HWTEST_F(DownloaderTest, GetCurrentTaskId_Initial_001, TestSize.Level0)
{
    auto downloader = DownloaderFactory::CreateDownloader();
    ASSERT_NE(downloader, nullptr);
    uint64_t taskId = downloader->GetCurrentTaskId();
    EXPECT_EQ(taskId, INVALID_TASK_ID);
}

HWTEST_F(DownloaderTest, SetUrl_InvalidUrl_001, TestSize.Level0)
{
    auto downloader = DownloaderFactory::CreateDownloader();
    ASSERT_NE(downloader, nullptr);

    int32_t ret = downloader->SetUrl("");
    EXPECT_NE(ret, DOWNLOAD_RET_OK);
}

HWTEST_F(DownloaderTest, SetUrl_InvalidUrl_002, TestSize.Level0)
{
    auto downloader = DownloaderFactory::CreateDownloader();
    ASSERT_NE(downloader, nullptr);

    int32_t ret = downloader->SetUrl("ftp://example.com/test.mp4");
    EXPECT_NE(ret, DOWNLOAD_RET_OK);
}

HWTEST_F(DownloaderTest, SetUrl_ValidUrl_001, TestSize.Level0)
{
    auto downloader = DownloaderFactory::CreateDownloader();
    ASSERT_NE(downloader, nullptr);

    int32_t ret = downloader->SetUrl("http://example.com/test.mp4");
    EXPECT_EQ(ret, DOWNLOAD_RET_OK);
}

HWTEST_F(DownloaderTest, SetUrl_ValidUrl_Https_001, TestSize.Level0)
{
    auto downloader = DownloaderFactory::CreateDownloader();
    ASSERT_NE(downloader, nullptr);

    int32_t ret = downloader->SetUrl("https://example.com/test.mp4");
    EXPECT_EQ(ret, DOWNLOAD_RET_OK);
}

HWTEST_F(DownloaderTest, SetUrl_AfterStart_001, TestSize.Level0)
{
    auto downloader = DownloaderFactory::CreateDownloader();
    ASSERT_NE(downloader, nullptr);

    (void)downloader->SetUrl("http://example.com/test.mp4");
    (void)downloader->SetOutputPath(testDir_ + "/test.mp4");

    int32_t ret = downloader->SetUrl("http://example.com/new.mp4");
    EXPECT_EQ(ret, DOWNLOAD_RET_OK);
}

HWTEST_F(DownloaderTest, SetOutputPath_InvalidPath_001, TestSize.Level0)
{
    auto downloader = DownloaderFactory::CreateDownloader();
    ASSERT_NE(downloader, nullptr);

    int32_t ret = downloader->SetOutputPath("");
    EXPECT_NE(ret, DOWNLOAD_RET_OK);
}

HWTEST_F(DownloaderTest, SetOutputPath_ValidPath_001, TestSize.Level0)
{
    auto downloader = DownloaderFactory::CreateDownloader();
    ASSERT_NE(downloader, nullptr);

    std::string outputPath = testDir_ + "/test.mp4";
    int32_t ret = downloader->SetOutputPath(outputPath);
    EXPECT_EQ(ret, DOWNLOAD_RET_OK);
}

HWTEST_F(DownloaderTest, SetOutputPath_AfterStart_001, TestSize.Level0)
{
    auto downloader = DownloaderFactory::CreateDownloader();
    ASSERT_NE(downloader, nullptr);

    (void)downloader->SetUrl("http://example.com/test.mp4");
    (void)downloader->SetOutputPath(testDir_ + "/test.mp4");

    int32_t ret = downloader->SetOutputPath(testDir_ + "/new.mp4");
    EXPECT_EQ(ret, DOWNLOAD_RET_OK);
}

HWTEST_F(DownloaderTest, SetHeader_001, TestSize.Level0)
{
    auto downloader = DownloaderFactory::CreateDownloader();
    ASSERT_NE(downloader, nullptr);

    std::map<std::string, std::string> header;
    header["User-Agent"] = "TestAgent";
    header["Accept"] = "*/*";

    int32_t ret = downloader->SetHeader(header);
    EXPECT_EQ(ret, DOWNLOAD_RET_OK);
}

HWTEST_F(DownloaderTest, SetConfig_001, TestSize.Level0)
{
    auto downloader = DownloaderFactory::CreateDownloader();
    ASSERT_NE(downloader, nullptr);

    DownloadConfig config;
    config.timeoutMs = 60000;
    config.retryCount = 5;
    config.progressCallbackIntervalMs = 500;

    int32_t ret = downloader->SetConfig(config);
    EXPECT_EQ(ret, DOWNLOAD_RET_OK);
}

HWTEST_F(DownloaderTest, SetDownloadCallback_001, TestSize.Level0)
{
    auto downloader = DownloaderFactory::CreateDownloader();
    ASSERT_NE(downloader, nullptr);

    auto callback = std::make_shared<StubDownloadCallback>();
    int32_t ret = downloader->SetDownloadCallback(callback);
    EXPECT_EQ(ret, DOWNLOAD_RET_OK);
}

HWTEST_F(DownloaderTest, Start_WithoutUrl_001, TestSize.Level0)
{
    auto downloader = DownloaderFactory::CreateDownloader();
    ASSERT_NE(downloader, nullptr);

    int32_t ret = downloader->Start();
    EXPECT_NE(ret, DOWNLOAD_RET_OK);
}

HWTEST_F(DownloaderTest, Start_WithoutPath_001, TestSize.Level0)
{
    auto downloader = DownloaderFactory::CreateDownloader();
    ASSERT_NE(downloader, nullptr);

    (void)downloader->SetUrl("http://example.com/test.mp4");
    int32_t ret = downloader->Start();
    EXPECT_NE(ret, DOWNLOAD_RET_OK);
}

HWTEST_F(DownloaderTest, GetState_Initial_001, TestSize.Level0)
{
    auto downloader = DownloaderFactory::CreateDownloader();
    ASSERT_NE(downloader, nullptr);

    DownloadState state = downloader->GetState();
    EXPECT_EQ(state, DOWNLOAD_IDLE);
}

HWTEST_F(DownloaderTest, GetProgress_Initial_001, TestSize.Level0)
{
    auto downloader = DownloaderFactory::CreateDownloader();
    ASSERT_NE(downloader, nullptr);

    DownloadProgress progress;
    int32_t ret = downloader->GetProgress(progress);
    EXPECT_NE(ret, DOWNLOAD_RET_OK);
}

HWTEST_F(DownloaderTest, Pause_NotStarted_001, TestSize.Level0)
{
    auto downloader = DownloaderFactory::CreateDownloader();
    ASSERT_NE(downloader, nullptr);

    int32_t ret = downloader->Pause();
    EXPECT_NE(ret, DOWNLOAD_RET_OK);
}

HWTEST_F(DownloaderTest, Resume_NotStarted_001, TestSize.Level0)
{
    auto downloader = DownloaderFactory::CreateDownloader();
    ASSERT_NE(downloader, nullptr);

    int32_t ret = downloader->Resume();
    EXPECT_NE(ret, DOWNLOAD_RET_OK);
}

HWTEST_F(DownloaderTest, Cancel_NotStarted_001, TestSize.Level0)
{
    auto downloader = DownloaderFactory::CreateDownloader();
    ASSERT_NE(downloader, nullptr);

    int32_t ret = downloader->Cancel();
    EXPECT_NE(ret, DOWNLOAD_RET_OK);
}

HWTEST_F(DownloaderTest, Release_Initial_001, TestSize.Level0)
{
    auto downloader = DownloaderFactory::CreateDownloader();
    ASSERT_NE(downloader, nullptr);

    int32_t ret = downloader->Release();
    EXPECT_EQ(ret, DOWNLOAD_RET_OK);
}

HWTEST_F(DownloaderTest, SetUrlAfterRelease_001, TestSize.Level0)
{
    auto downloader = DownloaderFactory::CreateDownloader();
    ASSERT_NE(downloader, nullptr);

    (void)downloader->Release();

    int32_t ret = downloader->SetUrl("http://example.com/test.mp4");
    EXPECT_EQ(ret, DOWNLOAD_RET_OK);
}

} // namespace MediaDownload
} // namespace Media
} // namespace OHOS
