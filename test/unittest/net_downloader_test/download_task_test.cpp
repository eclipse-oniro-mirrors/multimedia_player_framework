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
#include <fstream>
#include "net_downloader_test_common.h"
#include "downloader.h"
#include "download_task.h"
#include "http_server_demo.h"

std::unique_ptr<::OHOS::MediaAVCodec::HttpServerDemo> g_httpServer;
const std::string TEST_MEDIA_URL = "http://127.0.0.1:46666/test.mp4";
const std::string BIG_FILE_URL = "http://127.0.0.1:46666/big_file.mp4";

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {
namespace MediaDownload {

class StubDownloadTaskCallback : public DownloadTaskCallback {
public:
    void OnStateChanged(DownloadState state) override {}
    void OnCompleted(int64_t downloadedSize) override {}
    void OnFailed(DownloadErrorType errorType, int32_t errorCode, const std::string &errorMsg) override {}
    void OnProgress(const DownloadProgress &progress) override {}
};

class DownloadTaskTest : public testing::Test {
public:
    static void SetUpTestCase(void) {
        g_httpServer = std::make_unique<MediaAVCodec::HttpServerDemo>();
        g_httpServer->StartServer();
    }
    static void TearDownTestCase(void) {
        g_httpServer->StopServer();
        g_httpServer = nullptr;
    }
    void SetUp(void)
    {
        testDir_ = TestCommon::GetTestCacheDir("download_task_test");
        TestCommon::SetupTestDirectory(testDir_);
    }
    void TearDown(void)
    {
        TestCommon::CleanupTestDirectory(testDir_);
    }
protected:
    std::string testDir_;
};

HWTEST_F(DownloadTaskTest, Constructor_001, TestSize.Level0)
{
    DownloadTaskInfo info;
    info.taskId = 1;
    info.url = TEST_MEDIA_URL;
    info.outputPath = testDir_ + "/test.mp4";
    info.header = {};

    DownloadConfig config;
    auto callback = std::make_shared<StubDownloadTaskCallback>();

    auto task = std::make_shared<DownloadTask>(info, config, callback);
    ASSERT_NE(task, nullptr);
}

HWTEST_F(DownloadTaskTest, GetState_Initial_001, TestSize.Level0)
{
    DownloadTaskInfo info;
    info.taskId = 1;
    info.url = TEST_MEDIA_URL;
    info.outputPath = testDir_ + "/test.mp4";

    DownloadConfig config;
    auto callback = std::make_shared<StubDownloadTaskCallback>();

    auto task = std::make_shared<DownloadTask>(info, config, callback);
    DownloadState state = task->GetState();
    EXPECT_EQ(state, DOWNLOAD_IDLE);
}

HWTEST_F(DownloadTaskTest, GetProgress_Initial_001, TestSize.Level0)
{
    DownloadTaskInfo info;
    info.taskId = 1;
    info.url = TEST_MEDIA_URL;
    info.outputPath = testDir_ + "/test.mp4";

    DownloadConfig config;
    auto callback = std::make_shared<StubDownloadTaskCallback>();

    auto task = std::make_shared<DownloadTask>(info, config, callback);
    DownloadProgress progress = task->GetProgress();
    EXPECT_EQ(progress.downloadedSize, 0);
    EXPECT_EQ(progress.totalSize, -1);
}

HWTEST_F(DownloadTaskTest, Start_001, TestSize.Level0)
{
    DownloadTaskInfo info;
    info.taskId = 1;
    info.url = TEST_MEDIA_URL;
    info.outputPath = testDir_ + "/test.mp4";
    info.header = {};

    DownloadConfig config;
    auto callback = std::make_shared<StubDownloadTaskCallback>();

    auto task = std::make_shared<DownloadTask>(info, config, callback);
    int32_t ret = task->Start();
    EXPECT_EQ(ret, DOWNLOAD_RET_OK);

    (void)task->Cancel();
}

HWTEST_F(DownloadTaskTest, Start_AlreadyRunning_001, TestSize.Level0)
{
    DownloadTaskInfo info;
    info.taskId = 1;
    info.url = TEST_MEDIA_URL;
    info.outputPath = testDir_ + "/test.mp4";
    info.header = {};

    DownloadConfig config;
    auto callback = std::make_shared<StubDownloadTaskCallback>();

    auto task = std::make_shared<DownloadTask>(info, config, callback);
    (void)task->Start();

    int32_t ret = task->Start();
    EXPECT_NE(ret, DOWNLOAD_RET_OK);

    (void)task->Cancel();
}

HWTEST_F(DownloadTaskTest, Pause_NotRunning_001, TestSize.Level0)
{
    DownloadTaskInfo info;
    info.taskId = 1;
    info.url = TEST_MEDIA_URL;
    info.outputPath = testDir_ + "/test.mp4";
    info.header = {};

    DownloadConfig config;
    auto callback = std::make_shared<StubDownloadTaskCallback>();

    auto task = std::make_shared<DownloadTask>(info, config, callback);
    int32_t ret = task->Pause();
    EXPECT_NE(ret, DOWNLOAD_RET_OK);
}

HWTEST_F(DownloadTaskTest, Resume_NotPaused_001, TestSize.Level0)
{
    DownloadTaskInfo info;
    info.taskId = 1;
    info.url = TEST_MEDIA_URL;
    info.outputPath = testDir_ + "/test.mp4";
    info.header = {};

    DownloadConfig config;
    auto callback = std::make_shared<StubDownloadTaskCallback>();

    auto task = std::make_shared<DownloadTask>(info, config, callback);
    int32_t ret = task->Resume();
    EXPECT_NE(ret, DOWNLOAD_RET_OK);
}

HWTEST_F(DownloadTaskTest, Cancel_NotRunning_001, TestSize.Level0)
{
    DownloadTaskInfo info;
    info.taskId = 1;
    info.url = TEST_MEDIA_URL;
    info.outputPath = testDir_ + "/test.mp4";
    info.header = {};

    DownloadConfig config;
    auto callback = std::make_shared<StubDownloadTaskCallback>();

    auto task = std::make_shared<DownloadTask>(info, config, callback);
    int32_t ret = task->Cancel();
    EXPECT_EQ(ret, DOWNLOAD_ERROR_INVALID_OPERATION);
}

HWTEST_F(DownloadTaskTest, Pause_AlreadyPaused_001, TestSize.Level0)
{
    DownloadTaskInfo info;
    info.taskId = 1;
    info.url = TEST_MEDIA_URL;
    info.outputPath = testDir_ + "/test.mp4";
    info.header = {};

    DownloadConfig config;
    auto callback = std::make_shared<StubDownloadTaskCallback>();

    auto task = std::make_shared<DownloadTask>(info, config, callback);
    (void)task->Start();

    std::this_thread::sleep_for(std::chrono::milliseconds(2000));

    DownloadState state = task->GetState();
    if (state == DOWNLOAD_RUNNING) {
        (void)task->Pause();
        int32_t ret = task->Pause();
        EXPECT_NE(ret, DOWNLOAD_RET_OK);
    }

    (void)task->Cancel();
}

HWTEST_F(DownloadTaskTest, GetProgress_TotalSizeZero_001, TestSize.Level0)
{
    DownloadTaskInfo info;
    info.taskId = 1;
    info.url = TEST_MEDIA_URL;
    info.outputPath = testDir_ + "/test.mp4";
    info.header = {};

    DownloadConfig config;
    auto callback = std::make_shared<StubDownloadTaskCallback>();

    auto task = std::make_shared<DownloadTask>(info, config, callback);
    (void)task->Start();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    DownloadProgress progress = task->GetProgress();
    EXPECT_GE(progress.totalSize, -1);

    (void)task->Cancel();
}

HWTEST_F(DownloadTaskTest, GetProgress_TotalSizeNeg_001, TestSize.Level0)
{
    DownloadTaskInfo info;
    info.taskId = 1;
    info.url = TEST_MEDIA_URL;
    info.outputPath = testDir_ + "/test.mp4";
    info.header = {};

    DownloadConfig config;
    auto callback = std::make_shared<StubDownloadTaskCallback>();

    auto task = std::make_shared<DownloadTask>(info, config, callback);
    DownloadProgress progress = task->GetProgress();
    EXPECT_EQ(progress.progressPercent, 0);
}

HWTEST_F(DownloadTaskTest, GetFileSize_ExistingFile_001, TestSize.Level0)
{
    std::string testFile = testDir_ + "/size_test.txt";
    std::ofstream ofs(testFile);
    ofs << "test content";
    ofs.close();

    int64_t size = DownloadTask::GetFileSize(testFile);
    EXPECT_GT(size, 0);
}

HWTEST_F(DownloadTaskTest, GetFileSize_NonExistingFile_001, TestSize.Level0)
{
    std::string nonExistingFile = testDir_ + "/nonexistent_file.txt";
    int64_t size = DownloadTask::GetFileSize(nonExistingFile);
    EXPECT_EQ(size, 0);
}

HWTEST_F(DownloadTaskTest, Start_PreparingState_001, TestSize.Level0)
{
    DownloadTaskInfo info;
    info.taskId = 1;
    info.url = TEST_MEDIA_URL;
    info.outputPath = testDir_ + "/test.mp4";
    info.header = {};

    DownloadConfig config;
    auto callback = std::make_shared<StubDownloadTaskCallback>();

    auto task = std::make_shared<DownloadTask>(info, config, callback);
    DownloadState state = task->GetState();
    EXPECT_EQ(state, DOWNLOAD_IDLE);
}

HWTEST_F(DownloadTaskTest, GetProgress_Initial_002, TestSize.Level0)
{
    DownloadTaskInfo info;
    info.taskId = 1;
    info.url = TEST_MEDIA_URL;
    info.outputPath = testDir_ + "/test.mp4";
    info.header = {};

    DownloadConfig config;
    auto callback = std::make_shared<StubDownloadTaskCallback>();

    auto task = std::make_shared<DownloadTask>(info, config, callback);
    DownloadProgress progress = task->GetProgress();
    EXPECT_EQ(progress.downloadedSize, 0);
    EXPECT_EQ(progress.totalSize, -1);
    EXPECT_EQ(progress.downloadSpeed, 0);
}

HWTEST_F(DownloadTaskTest, Cancel_FromPreparing_001, TestSize.Level0)
{
    DownloadTaskInfo info;
    info.taskId = 1;
    info.url = TEST_MEDIA_URL;
    info.outputPath = testDir_ + "/test.mp4";
    info.header = {};

    DownloadConfig config;
    auto callback = std::make_shared<StubDownloadTaskCallback>();

    auto task = std::make_shared<DownloadTask>(info, config, callback);
    (void)task->Start();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    (void)task->Cancel();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    DownloadState state = task->GetState();
    EXPECT_TRUE(state == DOWNLOAD_COMPLETED || state == DOWNLOAD_FAILED || state == DOWNLOAD_CANCELED);
}

HWTEST_F(DownloadTaskTest, Resume_NotRunning_001, TestSize.Level0)
{
    DownloadTaskInfo info;
    info.taskId = 1;
    info.url = TEST_MEDIA_URL;
    info.outputPath = testDir_ + "/test.mp4";
    info.header = {};

    DownloadConfig config;
    auto callback = std::make_shared<StubDownloadTaskCallback>();

    auto task = std::make_shared<DownloadTask>(info, config, callback);
    int32_t ret = task->Resume();
    EXPECT_NE(ret, DOWNLOAD_RET_OK);
}

HWTEST_F(DownloadTaskTest, Cancel_AlreadyCanceled_001, TestSize.Level0)
{
    DownloadTaskInfo info;
    info.taskId = 1;
    info.url = TEST_MEDIA_URL;
    info.outputPath = testDir_ + "/test.mp4";
    info.header = {};

    DownloadConfig config;
    auto callback = std::make_shared<StubDownloadTaskCallback>();

    auto task = std::make_shared<DownloadTask>(info, config, callback);
    int32_t ret1 = task->Cancel();
    EXPECT_EQ(ret1, DOWNLOAD_ERROR_INVALID_OPERATION);
    int32_t ret2 = task->Cancel();
    EXPECT_EQ(ret2, DOWNLOAD_ERROR_INVALID_OPERATION);
}

HWTEST_F(DownloadTaskTest, ProgressReporterThread_001, TestSize.Level0)
{
    DownloadTaskInfo info;
    info.taskId = 1;
    info.url = TEST_MEDIA_URL;
    info.outputPath = testDir_ + "/test.mp4";
    info.header = {};

    DownloadConfig config;
    config.progressCallbackIntervalMs = 100;
    auto callback = std::make_shared<StubDownloadTaskCallback>();

    auto task = std::make_shared<DownloadTask>(info, config, callback);
    
    int32_t ret = task->Start();
    EXPECT_EQ(ret, DOWNLOAD_RET_OK);
    
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    DownloadProgress progress = task->GetProgress();
    EXPECT_GE(progress.downloadedSize, 0);
    
    (void)task->Cancel();
}

HWTEST_F(DownloadTaskTest, CalculateSpeed_001, TestSize.Level0)
{
    DownloadTaskInfo info;
    info.taskId = 1;
    info.url = TEST_MEDIA_URL;
    info.outputPath = testDir_ + "/test.mp4";
    info.header = {};

    DownloadConfig config;
    auto callback = std::make_shared<StubDownloadTaskCallback>();

    auto task = std::make_shared<DownloadTask>(info, config, callback);
    
    int32_t ret = task->Start();
    EXPECT_EQ(ret, DOWNLOAD_RET_OK);
    
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    
    int64_t downloadedSize = task->GetProgress().downloadedSize;
    int64_t speed = task->CalculateSpeed();
    EXPECT_GT(downloadedSize, 0);
    EXPECT_GT(speed, 0);
    
    (void)task->Cancel();
}

HWTEST_F(DownloadTaskTest, Start_Http404_001, TestSize.Level0)
{
    DownloadTaskInfo info;
    info.taskId = 1;
    info.url = "http://127.0.0.1:46666/nonexistent.mp4";
    info.outputPath = testDir_ + "/404_test.mp4";
    info.header = {};

    DownloadConfig config;
    config.progressCallbackIntervalMs = 100;
    auto callback = std::make_shared<StubDownloadTaskCallback>();

    auto task = std::make_shared<DownloadTask>(info, config, callback);
    (void)task->Start();
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    DownloadState state = task->GetState();
    EXPECT_TRUE(state == DOWNLOAD_FAILED || state == DOWNLOAD_CANCELED);
    (void)task->Cancel();
}

HWTEST_F(DownloadTaskTest, Start_Http416_001, TestSize.Level0)
{
    g_httpServer->SetResponseDelay(5000);
    g_httpServer->SetResponseHeaderDelay(2000);

    DownloadTaskInfo info;
    info.taskId = 1;
    info.url = BIG_FILE_URL;
    info.outputPath = testDir_ + "/416_test.mp4";
    info.header = {};

    DownloadConfig config;
    config.progressCallbackIntervalMs = 100;
    auto callback = std::make_shared<StubDownloadTaskCallback>();

    auto task = std::make_shared<DownloadTask>(info, config, callback);
    (void)task->Start();
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
    DownloadState state = task->GetState();
    EXPECT_TRUE(state == DOWNLOAD_RUNNING || state == DOWNLOAD_COMPLETED);
    (void)task->Cancel();
    g_httpServer->SetResponseDelay(0);
    g_httpServer->SetResponseHeaderDelay(0);
}

HWTEST_F(DownloadTaskTest, Start_Http416_NoContentRange_001, TestSize.Level0)
{
    DownloadTaskInfo info;
    info.taskId = 1;
    info.url = BIG_FILE_URL;
    info.outputPath = testDir_ + "/416_no_header_test.mp4";
    info.header = {};

    DownloadConfig config;
    config.progressCallbackIntervalMs = 100;
    auto callback = std::make_shared<StubDownloadTaskCallback>();

    auto task = std::make_shared<DownloadTask>(info, config, callback);
    
    (void)task->Start();
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    
    DownloadState state = task->GetState();
    EXPECT_TRUE(state == DOWNLOAD_FAILED || state == DOWNLOAD_COMPLETED);
    
    (void)task->Cancel();
}

HWTEST_F(DownloadTaskTest, Resume_ThreadDetach_001, TestSize.Level0)
{
    DownloadTaskInfo info;
    info.taskId = 1;
    info.url = TEST_MEDIA_URL;
    info.outputPath = testDir_ + "/resume_detach_test.mp4";
    info.header = {};

    DownloadConfig config;
    auto callback = std::make_shared<StubDownloadTaskCallback>();

    auto task = std::make_shared<DownloadTask>(info, config, callback);
    (void)task->Start();
    
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    
    DownloadState state = task->GetState();
    if (state == DOWNLOAD_RUNNING) {
        (void)task->Pause();
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        
        state = task->GetState();
        if (state == DOWNLOAD_PAUSED) {
            int32_t ret = task->Resume();
            EXPECT_EQ(ret, DOWNLOAD_RET_OK);
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    }
    
    (void)task->Cancel();
}

HWTEST_F(DownloadTaskTest, ExecuteDownload_PathError_001, TestSize.Level0)
{
    DownloadTaskInfo info;
    info.taskId = 1;
    info.url = TEST_MEDIA_URL;
    info.outputPath = "/nonexistent_dir_12345/invalid/path/test.mp4";
    info.header = {};

    DownloadConfig config;
    auto callback = std::make_shared<StubDownloadTaskCallback>();

    auto task = std::make_shared<DownloadTask>(info, config, callback);
    (void)task->Start();
    
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    DownloadState state = task->GetState();
    EXPECT_TRUE(state == DOWNLOAD_FAILED || state == DOWNLOAD_CANCELED);
    
    (void)task->Cancel();
}

HWTEST_F(DownloadTaskTest, Start_Http416_InvalidFormat_001, TestSize.Level0)
{
    g_httpServer->SetResponseDelay(5000);
    g_httpServer->SetResponseHeaderDelay(2000);
    g_httpServer->SetCustom416Response("bytes 100-200/abc");
    
    DownloadTaskInfo info;
    info.taskId = 1;
    info.url = BIG_FILE_URL;
    info.outputPath = testDir_ + "/416_invalid_format_test.mp4";
    info.header = {};

    DownloadConfig config;
    config.progressCallbackIntervalMs = 100;
    auto callback = std::make_shared<StubDownloadTaskCallback>();

    auto task = std::make_shared<DownloadTask>(info, config, callback);
    (void)task->Start();
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
    
    DownloadState state = task->GetState();
    EXPECT_TRUE(state == DOWNLOAD_FAILED || state == DOWNLOAD_COMPLETED || state == DOWNLOAD_RUNNING);
    
    (void)task->Cancel();
    
    g_httpServer->SetCustom416Response("");
    g_httpServer->SetResponseDelay(0);
    g_httpServer->SetResponseHeaderDelay(0);
}

HWTEST_F(DownloadTaskTest, Start_Http416_ParseError_001, TestSize.Level0)
{
    g_httpServer->SetCustom416Response("bytes */*");
    
    DownloadTaskInfo info;
    info.taskId = 1;
    info.url = BIG_FILE_URL;
    info.outputPath = testDir_ + "/416_parse_error_test.mp4";
    info.header = {};

    DownloadConfig config;
    config.progressCallbackIntervalMs = 100;
    auto callback = std::make_shared<StubDownloadTaskCallback>();

    auto task = std::make_shared<DownloadTask>(info, config, callback);
    (void)task->Start();
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    
    DownloadState state = task->GetState();
    EXPECT_TRUE(state == DOWNLOAD_FAILED || state == DOWNLOAD_COMPLETED);
    
    (void)task->Cancel();
    
    g_httpServer->SetCustom416Response("");
}

HWTEST_F(DownloadTaskTest, GetStartPosition_M3U8Manifest_001, TestSize.Level0)
{
    std::string manifestUrl = "http://127.0.0.1:46666/test.m3u8";
    DownloadTaskInfo info;
    info.taskId = 100;
    info.url = manifestUrl;
    info.outputPath = testDir_ + "/test.m3u8";
    info.header = {};

    DownloadConfig config;
    auto callback = std::make_shared<StubDownloadTaskCallback>();

    auto task = std::make_shared<DownloadTask>(info, config, callback);
    
    (void)task->Start();
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    DownloadState state = task->GetState();
    EXPECT_TRUE(state == DOWNLOAD_RUNNING || state == DOWNLOAD_COMPLETED || state == DOWNLOAD_FAILED);
    
    (void)task->Cancel();
}

HWTEST_F(DownloadTaskTest, GetStartPosition_MPDManifest_001, TestSize.Level0)
{
    std::string manifestUrl = "http://127.0.0.1:46666/test.mpd";
    DownloadTaskInfo info;
    info.taskId = 101;
    info.url = manifestUrl;
    info.outputPath = testDir_ + "/test.mpd";
    info.header = {};

    DownloadConfig config;
    auto callback = std::make_shared<StubDownloadTaskCallback>();

    auto task = std::make_shared<DownloadTask>(info, config, callback);
    
    (void)task->Start();
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    DownloadState state = task->GetState();
    EXPECT_TRUE(state == DOWNLOAD_RUNNING || state == DOWNLOAD_COMPLETED || state == DOWNLOAD_FAILED);
    
    (void)task->Cancel();
}

HWTEST_F(DownloadTaskTest, GetStartPosition_NormalFile_001, TestSize.Level0)
{
    DownloadTaskInfo info;
    info.taskId = 102;
    info.url = TEST_MEDIA_URL;
    info.outputPath = testDir_ + "/normal_start_test.mp4";
    info.header = {};

    DownloadConfig config;
    auto callback = std::make_shared<StubDownloadTaskCallback>();

    auto task = std::make_shared<DownloadTask>(info, config, callback);
    
    (void)task->Start();
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    DownloadProgress progress = task->GetProgress();
    EXPECT_GT(progress.downloadedSize, 0);
    
    (void)task->Cancel();
}

HWTEST_F(DownloadTaskTest, GetStartPosition_NormalFile_WithExistingFile_001, TestSize.Level0)
{
    std::string existingFile = testDir_ + "/existing_file.mp4";
    {
        std::ofstream ofs(existingFile);
        ofs << "existing partial content";
        ofs.close();
    }

    struct stat originalStat;
    EXPECT_EQ(stat(existingFile.c_str(), &originalStat), 0);
    int64_t originalSize = originalStat.st_size;
    EXPECT_GT(originalSize, 0);

    DownloadTaskInfo info;
    info.taskId = 103;
    info.url = TEST_MEDIA_URL;
    info.outputPath = existingFile;
    info.header = {};

    DownloadConfig config;
    auto callback = std::make_shared<StubDownloadTaskCallback>();

    auto task = std::make_shared<DownloadTask>(info, config, callback);
    
    (void)task->Start();
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    (void)task->Cancel();

    struct stat newStat;
    EXPECT_EQ(stat(existingFile.c_str(), &newStat), 0);
    EXPECT_GT(newStat.st_size, originalSize);
}

HWTEST_F(DownloadTaskTest, GetStartPosition_ResumeScenario_001, TestSize.Level0)
{
    DownloadTaskInfo info;
    info.taskId = 104;
    info.url = TEST_MEDIA_URL;
    info.outputPath = testDir_ + "/resume_test.mp4";
    info.header = {};

    DownloadConfig config;
    auto callback = std::make_shared<StubDownloadTaskCallback>();

    auto task = std::make_shared<DownloadTask>(info, config, callback);
    
    (void)task->Start();
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    
    DownloadState state = task->GetState();
    if (state == DOWNLOAD_RUNNING) {
        int64_t downloadedBeforePause = task->GetProgress().downloadedSize;
        EXPECT_GT(downloadedBeforePause, 0);

        (void)task->Pause();
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        
        state = task->GetState();
        EXPECT_EQ(state, DOWNLOAD_PAUSED);

        if (state == DOWNLOAD_PAUSED) {
            (void)task->Resume();
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            int64_t downloadedAfterResume = task->GetProgress().downloadedSize;
            EXPECT_GT(downloadedAfterResume, downloadedBeforePause);
        }
    }
    
    (void)task->Cancel();
}

HWTEST_F(DownloadTaskTest, GetStartPosition_NonManifestEdgeCase_M3U8_001, TestSize.Level0)
{
    std::string trickyUrl = "http://127.0.0.1:46666/file.abc.m3u8";
    DownloadTaskInfo info;
    info.taskId = 105;
    info.url = trickyUrl;
    info.outputPath = testDir_ + "/tricky.m3u8";
    info.header = {};

    DownloadConfig config;
    auto callback = std::make_shared<StubDownloadTaskCallback>();

    auto task = std::make_shared<DownloadTask>(info, config, callback);
    
    (void)task->Start();
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    DownloadState state = task->GetState();
    EXPECT_TRUE(state == DOWNLOAD_RUNNING || state == DOWNLOAD_COMPLETED || state == DOWNLOAD_FAILED);
    
    (void)task->Cancel();
}

HWTEST_F(DownloadTaskTest, GetStartPosition_NonManifestEdgeCase_MPD_001, TestSize.Level0)
{
    std::string trickyUrl = "http://127.0.0.1:46666/file.test.mpd";
    DownloadTaskInfo info;
    info.taskId = 106;
    info.url = trickyUrl;
    info.outputPath = testDir_ + "/tricky.mpd";
    info.header = {};

    DownloadConfig config;
    auto callback = std::make_shared<StubDownloadTaskCallback>();

    auto task = std::make_shared<DownloadTask>(info, config, callback);
    
    (void)task->Start();
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    DownloadState state = task->GetState();
    EXPECT_TRUE(state == DOWNLOAD_RUNNING || state == DOWNLOAD_COMPLETED || state == DOWNLOAD_FAILED);
    
    (void)task->Cancel();
}
HWTEST_F(DownloadTaskTest, Constructor_PathTraversal_OutputPathCleared_001, TestSize.Level0)
{
    DownloadTaskInfo info;
    info.taskId = 200;
    info.url = TEST_MEDIA_URL;
    info.outputPath = testDir_ + "/../../etc/passwd";
    info.header = {};

    DownloadConfig config;
    auto callback = std::make_shared<StubDownloadTaskCallback>();

    auto task = std::make_shared<DownloadTask>(info, config, callback);
    (void)task->Start();
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    DownloadState state = task->GetState();
    EXPECT_TRUE(state == DOWNLOAD_FAILED || state == DOWNLOAD_CANCELED);

    (void)task->Cancel();
}

HWTEST_F(DownloadTaskTest, GetFileSize_PathTraversal_001, TestSize.Level0)
{
    std::string traversalPath = testDir_ + "/../../etc/passwd";
    int64_t size = DownloadTask::GetFileSize(traversalPath);
    EXPECT_EQ(size, 0);
}

HWTEST_F(DownloadTaskTest, GetFileSize_EmptyPath_001, TestSize.Level0)
{
    int64_t size = DownloadTask::GetFileSize("");
    EXPECT_EQ(size, 0);
}

} // namespace MediaDownload
} // namespace Media
} // namespace OHOS
