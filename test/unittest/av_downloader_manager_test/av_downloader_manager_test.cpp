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

#include "av_downloader_manager_test.h"
#include "media_errors.h"
#include "net_downloader_test_common.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {

HWTEST_F(AVDownloaderManagerTest, SetAllowCellularAccess_True_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto result = manager->SetAllowCellularAccess(true);
    EXPECT_EQ(result, 0);
}

HWTEST_F(AVDownloaderManagerTest, SetAllowCellularAccess_False_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto result = manager->SetAllowCellularAccess(false);
    EXPECT_EQ(result, 0);
}

HWTEST_F(AVDownloaderManagerTest, SetRequestTimeout_ValidValue_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto result = manager->SetRequestTimeout(50000);
    EXPECT_EQ(result, 0);
}

HWTEST_F(AVDownloaderManagerTest, SetRequestTimeout_DefaultValue_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto result = manager->SetRequestTimeout(30000);
    EXPECT_EQ(result, 0);
}

HWTEST_F(AVDownloaderManagerTest, GetDownloadTasks_Empty_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto result = manager->GetDownloadTasks();
    EXPECT_TRUE(result.empty());
}

HWTEST_F(AVDownloaderManagerTest, GetTaskCacheDirectory_NoTask_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto result = manager->GetTaskCacheDirectory("nonexistent");
    EXPECT_EQ(result, "");
}

HWTEST_F(AVDownloaderManagerTest, GetTaskStatus_NoTask_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto result = manager->GetTaskStatus("nonexistent");
    EXPECT_EQ(result, AVDownloadTaskState::ERROR);
}

HWTEST_F(AVDownloaderManagerTest, GetTaskProgress_NoTask_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto result = manager->GetTaskProgress("nonexistent");
    EXPECT_EQ(result, 0.0);
}

HWTEST_F(AVDownloaderManagerTest, RemoveDownloadTask_NoTask_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto result = manager->RemoveDownloadTask("nonexistent");
    EXPECT_EQ(result, MSERR_OK);
    EXPECT_TRUE(manager->taskMap_.empty());
    EXPECT_TRUE(manager->downloaderMap_.empty());
}

HWTEST_F(AVDownloaderManagerTest, PauseDownloadTask_NoTask_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto result = manager->PauseDownloadTask("nonexistent");
    EXPECT_EQ(result, MSERR_INVALID_VAL);
}

HWTEST_F(AVDownloaderManagerTest, ResumeDownloadTask_NoTask_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto result = manager->ResumeDownloadTask("nonexistent");
    EXPECT_EQ(result, MSERR_INVALID_VAL);
}

HWTEST_F(AVDownloaderManagerTest, IsNetworkAllowDownload_None_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    bool result = manager->IsNetworkAllowDownload(MediaSourceUtils::NetConnType::NET_CONN_NONE);
    EXPECT_FALSE(result);
}

HWTEST_F(AVDownloaderManagerTest, IsNetworkAllowDownload_Unknown_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    bool result = manager->IsNetworkAllowDownload(MediaSourceUtils::NetConnType::NET_CONN_UNKNOWN);
    EXPECT_FALSE(result);
}

HWTEST_F(AVDownloaderManagerTest, IsNetworkAllowDownload_Cellular_NotAllowed_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    (void)manager->SetAllowCellularAccess(false);
    bool result = manager->IsNetworkAllowDownload(MediaSourceUtils::NetConnType::NET_CONN_CELLULAR);
    EXPECT_FALSE(result);
}

HWTEST_F(AVDownloaderManagerTest, IsNetworkAllowDownload_Cellular_Allowed_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    (void)manager->SetAllowCellularAccess(true);
    bool result = manager->IsNetworkAllowDownload(MediaSourceUtils::NetConnType::NET_CONN_CELLULAR);
    EXPECT_TRUE(result);
}

HWTEST_F(AVDownloaderManagerTest, IsNetworkAllowDownload_Wifi_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    bool result = manager->IsNetworkAllowDownload(MediaSourceUtils::NetConnType::NET_CONN_WIFI);
    EXPECT_TRUE(result);
}

HWTEST_F(AVDownloaderManagerTest, IsNetworkAllowDownload_Bluetooth_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    bool result = manager->IsNetworkAllowDownload(MediaSourceUtils::NetConnType::NET_CONN_BLUETOOTH);
    EXPECT_FALSE(result);
}

HWTEST_F(AVDownloaderManagerTest, IsNetworkAllowDownload_Ethernet_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    bool result = manager->IsNetworkAllowDownload(MediaSourceUtils::NetConnType::NET_CONN_ETHERNET);
    EXPECT_FALSE(result);
}

HWTEST_F(AVDownloaderManagerTest, IsNetworkAllowDownload_Vpn_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    bool result = manager->IsNetworkAllowDownload(MediaSourceUtils::NetConnType::NET_CONN_VPN);
    EXPECT_FALSE(result);
}

HWTEST_F(AVDownloaderManagerTest, SetManagerCallback_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto callback = std::make_shared<MockAVDownloaderManagerCallback>();
    auto result = manager->SetManagerCallback(callback);
    EXPECT_EQ(result, 0);
}

HWTEST_F(AVDownloaderManagerTest, ConvertToAVDownloadTaskState_INIT_001, TestSize.Level0)
{
    auto state = AVDownloaderManagerImpl::ConvertToAVDownloadTaskState(MediaDownload::DownloadState::DOWNLOAD_IDLE);
    EXPECT_EQ(state, AVDownloadTaskState::INIT);
}

HWTEST_F(AVDownloaderManagerTest, ConvertToAVDownloadTaskState_RUNNING_001, TestSize.Level0)
{
    auto state = AVDownloaderManagerImpl::ConvertToAVDownloadTaskState(MediaDownload::DownloadState::DOWNLOAD_RUNNING);
    EXPECT_EQ(state, AVDownloadTaskState::RUNNING);
}

HWTEST_F(AVDownloaderManagerTest, ConvertToAVDownloadTaskState_PAUSED_001, TestSize.Level0)
{
    auto state = AVDownloaderManagerImpl::ConvertToAVDownloadTaskState(MediaDownload::DownloadState::DOWNLOAD_PAUSED);
    EXPECT_EQ(state, AVDownloadTaskState::PAUSED);
}

HWTEST_F(AVDownloaderManagerTest, ConvertToAVDownloadTaskState_COMPLETED_001, TestSize.Level0)
{
    auto state =
        AVDownloaderManagerImpl::ConvertToAVDownloadTaskState(MediaDownload::DownloadState::DOWNLOAD_COMPLETED);
    EXPECT_EQ(state, AVDownloadTaskState::COMPLETED);
}

HWTEST_F(AVDownloaderManagerTest, ConvertToAVDownloadTaskState_ERROR_001, TestSize.Level0)
{
    auto state = AVDownloaderManagerImpl::ConvertToAVDownloadTaskState(MediaDownload::DownloadState::DOWNLOAD_FAILED);
    EXPECT_EQ(state, AVDownloadTaskState::ERROR);
}

HWTEST_F(AVDownloaderManagerTest, GetFilePath_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto result = manager->GetFilePath("/cache", "http://example.com/test.mp4");
    EXPECT_EQ(result, "/cache/1/test.mp4");
}

HWTEST_F(AVDownloaderManagerTest, Release_Twice_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    (void)manager->Release();
    auto result = manager->Release();
    EXPECT_EQ(result, 0);
}

HWTEST_F(AVDownloaderManagerTest, SetManagerCallback_MultipleTimes_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto callback1 = std::make_shared<MockAVDownloaderManagerCallback>();
    auto callback2 = std::make_shared<MockAVDownloaderManagerCallback>();
    (void)manager->SetManagerCallback(callback1);
    auto result = manager->SetManagerCallback(callback2);
    EXPECT_EQ(result, 0);
}

HWTEST_F(AVDownloaderManagerTest, FindExistingTask_EmptyUrl_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = "task_non_empty_url";
    taskInfo->url = "http://example.com/test.mp4";
    taskInfo->state = AVDownloadTaskState::RUNNING;
    manager->taskMap_["task_non_empty_url"] = taskInfo;

    std::string result = manager->FindExistingTask("");

    EXPECT_EQ(result, "");
}

HWTEST_F(AVDownloaderManagerTest, FindExistingTask_EmptyTaskMap_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    std::string result = manager->FindExistingTask("http://example.com/test.mp4");
    EXPECT_EQ(result, "");
}

HWTEST_F(AVDownloaderManagerTest, FindExistingTask_TaskNotMatch_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = "task1";
    taskInfo->url = "http://example.com/other.mp4";
    taskInfo->state = AVDownloadTaskState::RUNNING;
    manager->taskMap_["task1"] = taskInfo;
    
    std::string result = manager->FindExistingTask("http://example.com/test.mp4");
    EXPECT_EQ(result, "");
    
    manager->taskMap_.erase("task1");
}

HWTEST_F(AVDownloaderManagerTest, FindExistingTask_FindRunningTask_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = "task_running";
    taskInfo->url = "http://example.com/test.mp4";
    taskInfo->state = AVDownloadTaskState::RUNNING;
    manager->taskMap_["task_running"] = taskInfo;
    
    std::string result = manager->FindExistingTask("http://example.com/test.mp4");
    EXPECT_EQ(result, "task_running");
    
    manager->taskMap_.erase("task_running");
}

HWTEST_F(AVDownloaderManagerTest, FindExistingTask_FindQueuedTask_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = "task_queued";
    taskInfo->url = "http://example.com/test.mp4";
    taskInfo->state = AVDownloadTaskState::QUEUED;
    manager->taskMap_["task_queued"] = taskInfo;
    
    std::string result = manager->FindExistingTask("http://example.com/test.mp4");
    EXPECT_EQ(result, "task_queued");
    
    manager->taskMap_.erase("task_queued");
}

HWTEST_F(AVDownloaderManagerTest, FindExistingTask_FindInitTask_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = "task_init";
    taskInfo->url = "http://example.com/test.mp4";
    taskInfo->state = AVDownloadTaskState::INIT;
    manager->taskMap_["task_init"] = taskInfo;
    
    std::string result = manager->FindExistingTask("http://example.com/test.mp4");
    EXPECT_EQ(result, "task_init");
    
    manager->taskMap_.erase("task_init");
}

HWTEST_F(AVDownloaderManagerTest, FindExistingTask_PausedTask_ReturnsTaskId_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    manager->simulatedNetworkType_ = MediaSourceUtils::NetConnType::NET_CONN_WIFI;
    
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = "task_paused_no_downloader";
    taskInfo->url = "http://example.com/test.mp4";
    taskInfo->state = AVDownloadTaskState::PAUSED;
    manager->taskMap_["task_paused_no_downloader"] = taskInfo;
    
    std::string result = manager->FindExistingTask("http://example.com/test.mp4");
    EXPECT_EQ(result, "task_paused_no_downloader");
    
    manager->taskMap_.erase("task_paused_no_downloader");
}

HWTEST_F(AVDownloaderManagerTest, FindExistingTask_CompletedTask_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = "task_completed";
    taskInfo->url = "http://example.com/test.mp4";
    taskInfo->state = AVDownloadTaskState::COMPLETED;
    manager->taskMap_["task_completed"] = taskInfo;
    
    std::string result = manager->FindExistingTask("http://example.com/test.mp4");
    EXPECT_EQ(result, "task_completed");
    
    manager->taskMap_.erase("task_completed");
}

HWTEST_F(AVDownloaderManagerTest, FindExistingTask_ErrorTask_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = "task_error";
    taskInfo->url = "http://example.com/test.mp4";
    taskInfo->state = AVDownloadTaskState::ERROR;
    manager->taskMap_["task_error"] = taskInfo;
    
    std::string result = manager->FindExistingTask("http://example.com/test.mp4");
    EXPECT_EQ(result, "");
    
    manager->taskMap_.erase("task_error");
}

HWTEST_F(AVDownloaderManagerTest, CreateNewDownloaderAndTask_BasicCreate_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    
    auto source = std::make_shared<Plugins::MediaSource>("http://example.com/test.mp4");
    auto [taskId, taskInfo, downloader, filePath] =
        manager->CreateNewDownloaderAndTask(source, "http://example.com/test.mp4");
    
    EXPECT_FALSE(taskId.empty());
    EXPECT_NE(taskInfo, nullptr);
    EXPECT_NE(downloader, nullptr);
    EXPECT_FALSE(filePath.empty());
    EXPECT_EQ(taskInfo->taskId, taskId);
    EXPECT_EQ(taskInfo->url, "http://example.com/test.mp4");
    EXPECT_EQ(taskInfo->state, AVDownloadTaskState::INIT);
    EXPECT_FALSE(taskInfo->cacheDir.empty());
    EXPECT_EQ(taskInfo->currentFilePath, filePath);
    EXPECT_FALSE(taskInfo->fileList.empty());
}

HWTEST_F(AVDownloaderManagerTest, CreateNewDownloaderAndTask_WithPlayStrategy_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    
    auto source = std::make_shared<Plugins::MediaSource>("http://example.com/test.mp4");
    auto strategy = std::make_shared<Plugins::PlayStrategy>();
    strategy->duration = 5000;
    (void)source->SetPlayStrategy(strategy);

    auto [taskId, taskInfo, downloader, filePath] =
        manager->CreateNewDownloaderAndTask(source, "http://example.com/test.mp4");

    EXPECT_FALSE(taskId.empty());
    EXPECT_NE(taskInfo, nullptr);
    EXPECT_EQ(taskInfo->strategy.duration, 5000);
}

HWTEST_F(AVDownloaderManagerTest, CreateNewDownloaderAndTask_FileListPopulated_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    
    std::string testUrl = "http://example.com/test.mp4";
    auto source = std::make_shared<Plugins::MediaSource>(testUrl);
    auto [taskId, taskInfo, downloader, filePath] = manager->CreateNewDownloaderAndTask(source, testUrl);
    
    EXPECT_NE(taskInfo, nullptr);
    EXPECT_EQ(taskInfo->fileList.size(), 1U);
    auto it = std::find_if(taskInfo->fileList.begin(), taskInfo->fileList.end(),
        [&testUrl](const DownloadFileInfo &info) { return info.url == testUrl; });
    EXPECT_NE(it, taskInfo->fileList.end());
    EXPECT_EQ(it->url, testUrl);
    EXPECT_EQ(it->filePath, filePath);
    EXPECT_FALSE(it->downloaded);
    EXPECT_FALSE(it->needParse);
}

HWTEST_F(AVDownloaderManagerTest, SubmitRemainingTasks_AllFilesDownloaded_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    auto mockDownloader = std::make_shared<MockDownloader>();

    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    DownloadFileInfo fileInfo;
    fileInfo.url = "http://example.com/file1.mp4";
    fileInfo.filePath = "/cache/file1.mp4";
    fileInfo.downloaded = true;
    taskInfo->fileList.push_back(fileInfo);

    int32_t startCount = 0;
    EXPECT_CALL(*mockDownloader, SetConfig(_)).Times(0);
    EXPECT_CALL(*mockDownloader, AddFileTask(_, _, _)).Times(0);
    EXPECT_CALL(*mockDownloader, Start()).WillOnce(testing::Invoke([&startCount]() {
        startCount++;
        return 0;
    }));

    auto callback = std::make_shared<DownloadTaskCallback>(std::weak_ptr<AVDownloaderManagerImpl>(manager));
    callback->SubmitRemainingTasks(mockDownloader, taskInfo, manager);
    EXPECT_EQ(startCount, 1);
}

HWTEST_F(AVDownloaderManagerTest, SubmitRemainingTasks_OneFileNotDownloaded_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    auto mockDownloader = std::make_shared<MockDownloader>();

    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    DownloadFileInfo fileInfo;
    fileInfo.url = "http://example.com/file1.mp4";
    fileInfo.filePath = "/cache/file1.mp4";
    fileInfo.downloaded = false;
    taskInfo->fileList.push_back(fileInfo);

    int32_t startCount = 0;
    std::vector<std::string> submittedUrls;
    EXPECT_CALL(*mockDownloader, SetConfig(_)).Times(1);
    EXPECT_CALL(*mockDownloader, AddFileTask(_, _, _)).WillOnce(
        testing::Invoke([&submittedUrls](const std::string &url, const std::string &path,
            const MediaDownload::DownloadConfig &config) {
            (void)path;
            (void)config;
            submittedUrls.push_back(url);
            return 0;
        }));
    EXPECT_CALL(*mockDownloader, Start()).WillOnce(testing::Invoke([&startCount]() {
        startCount++;
        return 0;
    }));

    auto callback = std::make_shared<DownloadTaskCallback>(std::weak_ptr<AVDownloaderManagerImpl>(manager));
    callback->SubmitRemainingTasks(mockDownloader, taskInfo, manager);
    ASSERT_EQ(submittedUrls.size(), 1U);
    EXPECT_EQ(submittedUrls[0], "http://example.com/file1.mp4");
    EXPECT_EQ(startCount, 1);
}

HWTEST_F(AVDownloaderManagerTest, SubmitRemainingTasks_MixDownloadedAndNot_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    auto mockDownloader = std::make_shared<MockDownloader>();

    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();

    DownloadFileInfo fileInfo1;
    fileInfo1.url = "http://example.com/file1.mp4";
    fileInfo1.filePath = "/cache/file1.mp4";
    fileInfo1.downloaded = true;
    taskInfo->fileList.push_back(fileInfo1);

    DownloadFileInfo fileInfo2;
    fileInfo2.url = "http://example.com/sub.m3u8";
    fileInfo2.filePath = "/cache/sub.m3u8";
    fileInfo2.downloaded = false;
    taskInfo->fileList.push_back(fileInfo2);

    DownloadFileInfo fileInfo3;
    fileInfo3.url = "http://example.com/file3.ts";
    fileInfo3.filePath = "/cache/file3.ts";
    fileInfo3.downloaded = false;
    taskInfo->fileList.push_back(fileInfo3);

    int32_t startCount = 0;
    std::vector<std::string> submittedUrls;
    EXPECT_CALL(*mockDownloader, SetConfig(_)).Times(2);
    EXPECT_CALL(*mockDownloader, AddFileTask(_, _, _)).Times(2).WillRepeatedly(
        testing::Invoke([&submittedUrls](const std::string &url, const std::string &path,
            const MediaDownload::DownloadConfig &config) {
            (void)path;
            (void)config;
            submittedUrls.push_back(url);
            return 0;
        }));
    EXPECT_CALL(*mockDownloader, Start()).WillOnce(testing::Invoke([&startCount]() {
        startCount++;
        return 0;
    }));

    auto callback = std::make_shared<DownloadTaskCallback>(std::weak_ptr<AVDownloaderManagerImpl>(manager));
    callback->SubmitRemainingTasks(mockDownloader, taskInfo, manager);
    ASSERT_EQ(submittedUrls.size(), 2U);
    EXPECT_NE(std::find(submittedUrls.begin(), submittedUrls.end(), "http://example.com/sub.m3u8"),
        submittedUrls.end());
    EXPECT_NE(std::find(submittedUrls.begin(), submittedUrls.end(), "http://example.com/file3.ts"),
        submittedUrls.end());
    EXPECT_EQ(std::find(submittedUrls.begin(), submittedUrls.end(), "http://example.com/file1.mp4"),
        submittedUrls.end());
    EXPECT_EQ(startCount, 1);
}

HWTEST_F(AVDownloaderManagerTest, SubmitRemainingTasks_EmptyFileList_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    auto mockDownloader = std::make_shared<MockDownloader>();

    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();

    int32_t startCount = 0;
    EXPECT_CALL(*mockDownloader, SetConfig(_)).Times(0);
    EXPECT_CALL(*mockDownloader, AddFileTask(_, _, _)).Times(0);
    EXPECT_CALL(*mockDownloader, Start()).WillOnce(testing::Invoke([&startCount]() {
        startCount++;
        return 0;
    }));

    auto callback = std::make_shared<DownloadTaskCallback>(std::weak_ptr<AVDownloaderManagerImpl>(manager));
    callback->SubmitRemainingTasks(mockDownloader, taskInfo, manager);
    EXPECT_EQ(startCount, 1);
}

HWTEST_F(AVDownloaderManagerTest, SubmitRemainingTasks_ConfigValues_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    (void)manager->SetRequestTimeout(5000);
    (void)manager->SetAllowCellularAccess(true);
    auto mockDownloader = std::make_shared<MockDownloader>();

    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    DownloadFileInfo fileInfo;
    fileInfo.url = "http://example.com/file.mp4";
    fileInfo.filePath = "/cache/file.mp4";
    fileInfo.downloaded = false;
    taskInfo->fileList.push_back(fileInfo);

    EXPECT_CALL(*mockDownloader, SetConfig(_)).WillOnce(
        testing::Invoke([](const MediaDownload::DownloadConfig &config) {
            EXPECT_EQ(config.timeoutMs, 5000);
            EXPECT_TRUE(config.allowMobileData);
            EXPECT_TRUE(config.allowWifi);
            return 0;
        }));
    EXPECT_CALL(*mockDownloader, AddFileTask("http://example.com/file.mp4", "/cache/file.mp4", _)).Times(1);
    EXPECT_CALL(*mockDownloader, Start()).WillOnce(Return(0));

    auto callback = std::make_shared<DownloadTaskCallback>(std::weak_ptr<AVDownloaderManagerImpl>(manager));
    callback->SubmitRemainingTasks(mockDownloader, taskInfo, manager);
}

HWTEST_F(AVDownloaderManagerTest, GenerateMappingFile_ValidCacheDir_CreatesMappingFile_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto callback = std::make_shared<DownloadTaskCallback>(std::weak_ptr<AVDownloaderManagerImpl>(manager));
    std::string testDir = MediaDownload::TestCommon::GetTestCacheDir("mapping_ok");
    ASSERT_FALSE(testDir.empty());
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->cacheDir = testDir;
    DownloadFileInfo fileInfo;
    fileInfo.url = "http://example.com/test.mp4";
    fileInfo.filePath = testDir + "/test.mp4";
    fileInfo.downloaded = true;
    taskInfo->fileList.push_back(fileInfo);

    callback->GenerateMappingFile(taskInfo);

    EXPECT_TRUE(taskInfo->mappingFileCreated);
    EXPECT_EQ(taskInfo->urlToFileSizeOffset_.count(fileInfo.url), 1U);
    MediaDownload::TestCommon::CleanupTestDirectory(testDir);
}

HWTEST_F(AVDownloaderManagerTest, ReadFileData_SmallFile_ReadsFullContent_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto callback = std::make_shared<DownloadTaskCallback>(std::weak_ptr<AVDownloaderManagerImpl>(manager));

    std::string testDir = MediaDownload::TestCommon::GetTestCacheDir("readfile_small");
    ASSERT_FALSE(testDir.empty());
    std::string filePath = testDir + "/small.m3u8";
    std::vector<uint8_t> content = {'#', 'E', 'X', 'T', 'M', '3', 'U', '\n'};
    ASSERT_LT(content.size(), static_cast<size_t>(256));
    ASSERT_TRUE(MediaDownload::TestCommon::CreateTestFile(filePath, content));

    std::vector<uint8_t> buffer;
    bool ret = callback->ReadFileData(filePath, buffer, 256);
    EXPECT_TRUE(ret);
    EXPECT_EQ(buffer.size(), content.size());
    EXPECT_EQ(buffer, content);

    MediaDownload::TestCommon::CleanupTestDirectory(testDir);
}

HWTEST_F(AVDownloaderManagerTest, ReadFileData_NormalFile_ReadsSniffSize_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto callback = std::make_shared<DownloadTaskCallback>(std::weak_ptr<AVDownloaderManagerImpl>(manager));

    std::string testDir = MediaDownload::TestCommon::GetTestCacheDir("readfile_normal");
    ASSERT_FALSE(testDir.empty());
    std::string filePath = testDir + "/normal.bin";
    std::vector<uint8_t> content(512, 'A');
    ASSERT_TRUE(MediaDownload::TestCommon::CreateTestFile(filePath, content));

    std::vector<uint8_t> buffer;
    bool ret = callback->ReadFileData(filePath, buffer, 256);
    EXPECT_TRUE(ret);
    EXPECT_EQ(buffer.size(), static_cast<size_t>(256));
    std::vector<uint8_t> expected(content.begin(), content.begin() + 256);
    EXPECT_EQ(buffer, expected);

    MediaDownload::TestCommon::CleanupTestDirectory(testDir);
}

HWTEST_F(AVDownloaderManagerTest, OnCompleted_SniffAtCompletion_WhenNotSniffed_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);

    std::string testDir = MediaDownload::TestCommon::GetTestCacheDir("oncompleted_sniff");
    ASSERT_FALSE(testDir.empty());
    std::string m3u8Path = testDir + "/test.m3u8";
    std::vector<uint8_t> content(300, '#');
    ASSERT_TRUE(MediaDownload::TestCommon::CreateTestFile(m3u8Path, content));

    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = "1";
    taskInfo->cacheDir = testDir;
    DownloadFileInfo fileInfo;
    fileInfo.url = "http://example.com/test.m3u8";
    fileInfo.filePath = m3u8Path;
    fileInfo.downloaded = true;
    fileInfo.needParse = false;
    taskInfo->fileList.push_back(fileInfo);
    manager->taskMap_["1"] = taskInfo;

    auto mockDownloader = std::make_shared<MockDownloader>();
    manager->downloaderMap_["1"] = mockDownloader;

    auto callback = std::make_shared<DownloadTaskCallback>(std::weak_ptr<AVDownloaderManagerImpl>(manager));
    callback->OnCompleted(1, 0);

    EXPECT_TRUE(taskInfo->protocolSniffed);
    EXPECT_EQ(taskInfo->detectedProtocol, Plugins::HttpPlugin::StreamProtocolType::HTTP);

    MediaDownload::TestCommon::CleanupTestDirectory(testDir);
}

HWTEST_F(AVDownloaderManagerTest, GetFilePath_NormalFilename_002, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto result = manager->GetFilePath("/data/storage/el2/base/cache/test",
        "http://example.com/normal.mp4");
    EXPECT_EQ(result, "/data/storage/el2/base/cache/test/1/normal.mp4");
}

HWTEST_F(AVDownloaderManagerTest, GetFilePath_EmptyFilename_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto result = manager->GetFilePath("/data/storage/el2/base/cache/test",
        "http://example.com/");
    EXPECT_EQ(result.find("/data/storage/el2/base/cache/test/1/"), 0U);
    size_t lastSlash = result.find_last_of('/');
    ASSERT_NE(lastSlash, std::string::npos);
    std::string fileNamePart = result.substr(lastSlash + 1);
    // An empty file name falls back to the SHA256 hash of the url (64 hex chars)
    EXPECT_EQ(fileNamePart.size(), 64U);
}

HWTEST_F(AVDownloaderManagerTest, Release_FirstRelease_ClearsMaps_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto mockDownloader = std::make_shared<MockDownloader>();
    EXPECT_CALL(*mockDownloader, Cancel()).WillOnce(Return(MSERR_OK));
    EXPECT_CALL(*mockDownloader, Release()).WillOnce(Return(MSERR_OK));
    manager->downloaderMap_["task1"] = mockDownloader;
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = "task1";
    manager->taskMap_["task1"] = taskInfo;

    auto result = manager->Release();
    EXPECT_EQ(result, MSERR_OK);
    EXPECT_TRUE(manager->downloaderMap_.empty());
    EXPECT_TRUE(manager->taskMap_.empty());
}

HWTEST_F(AVDownloaderManagerTest, Release_SecondRelease_ReturnsEarly_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto mockDownloader = std::make_shared<MockDownloader>();
    EXPECT_CALL(*mockDownloader, Cancel()).WillOnce(Return(MSERR_OK));
    EXPECT_CALL(*mockDownloader, Release()).WillOnce(Return(MSERR_OK));
    manager->downloaderMap_["task1"] = mockDownloader;
    manager->Release();
    EXPECT_TRUE(manager->downloaderMap_.empty());
    auto result2 = manager->Release();
    EXPECT_EQ(result2, MSERR_OK);
}

HWTEST_F(AVDownloaderManagerTest, Release_MessageQueueNull_SkipsStop_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = "task1";
    manager->taskMap_["task1"] = taskInfo;
    manager->messageQueue_.reset();

    auto result = manager->Release();

    EXPECT_EQ(result, MSERR_OK);
    EXPECT_TRUE(manager->taskMap_.empty());
}

HWTEST_F(AVDownloaderManagerTest, Release_WithNullDownloaderEntry_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    manager->downloaderMap_["null_task"] = nullptr;
    auto result = manager->Release();
    EXPECT_EQ(result, MSERR_OK);
    EXPECT_TRUE(manager->downloaderMap_.empty());
}

HWTEST_F(AVDownloaderManagerTest, Destructor_CallsRelease_001, TestSize.Level0)
{
    auto mockDownloader = std::make_shared<MockDownloader>();
    EXPECT_CALL(*mockDownloader, Cancel()).WillOnce(Return(MSERR_OK));
    EXPECT_CALL(*mockDownloader, Release()).WillOnce(Return(MSERR_OK));
    {
        auto manager = std::make_shared<AVDownloaderManagerImpl>();
        ASSERT_NE(manager, nullptr);
        manager->downloaderMap_["task1"] = mockDownloader;
    }
    EXPECT_TRUE(mockDownloader.unique());
}

HWTEST_F(AVDownloaderManagerTest, Destructor_AfterExplicitRelease_NoDoubleRelease_001, TestSize.Level0)
{
    auto mockDownloader = std::make_shared<MockDownloader>();
    EXPECT_CALL(*mockDownloader, Cancel()).WillOnce(Return(MSERR_OK));
    EXPECT_CALL(*mockDownloader, Release()).WillOnce(Return(MSERR_OK));
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    manager->downloaderMap_["task1"] = mockDownloader;
    manager->Release();
    EXPECT_TRUE(manager->downloaderMap_.empty());
    manager.reset();
    EXPECT_TRUE(mockDownloader.unique());
}

HWTEST_F(AVDownloaderManagerTest, NotifyStatusChange_TaskInMap_UpdatesState_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto callback = std::make_shared<MockAVDownloaderManagerCallback>();
    (void)manager->SetManagerCallback(callback);
    EXPECT_CALL(*callback, OnStatusChange("task1", AVDownloadTaskState::RUNNING)).Times(1);
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = "task1";
    taskInfo->state = AVDownloadTaskState::INIT;
    manager->taskMap_["task1"] = taskInfo;

    manager->NotifyStatusChange("task1", AVDownloadTaskState::RUNNING);
    EXPECT_EQ(taskInfo->state, AVDownloadTaskState::RUNNING);
}

HWTEST_F(AVDownloaderManagerTest, NotifyStatusChange_NoCallback_StillUpdatesState_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = "task1";
    taskInfo->state = AVDownloadTaskState::INIT;
    manager->taskMap_["task1"] = taskInfo;

    manager->NotifyStatusChange("task1", AVDownloadTaskState::PAUSED);
    EXPECT_EQ(taskInfo->state, AVDownloadTaskState::PAUSED);
}

HWTEST_F(AVDownloaderManagerTest, NotifyProgressChange_TaskInMap_UpdatesProgress_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto callback = std::make_shared<MockAVDownloaderManagerCallback>();
    (void)manager->SetManagerCallback(callback);
    EXPECT_CALL(*callback, OnProgressChange("task1", 75.0)).Times(1);
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = "task1";
    taskInfo->progress = 0.0;
    manager->taskMap_["task1"] = taskInfo;

    manager->NotifyProgressChange("task1", 75.0);
    EXPECT_DOUBLE_EQ(taskInfo->progress, 75.0);
}

HWTEST_F(AVDownloaderManagerTest, NotifyProgressChange_NoCallback_StillUpdatesProgress_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = "task1";
    taskInfo->progress = 0.0;
    manager->taskMap_["task1"] = taskInfo;

    manager->NotifyProgressChange("task1", 42.5);
    EXPECT_DOUBLE_EQ(taskInfo->progress, 42.5);
}

HWTEST_F(AVDownloaderManagerTest, NotifyStatusChangeLocked_TaskInMap_UpdatesState_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto callback = std::make_shared<MockAVDownloaderManagerCallback>();
    (void)manager->SetManagerCallback(callback);
    EXPECT_CALL(*callback, OnStatusChange("task1", AVDownloadTaskState::RUNNING)).Times(1);
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = "task1";
    taskInfo->state = AVDownloadTaskState::INIT;
    manager->taskMap_["task1"] = taskInfo;

    manager->NotifyStatusChangeLocked("task1", AVDownloadTaskState::RUNNING);
    EXPECT_EQ(taskInfo->state, AVDownloadTaskState::RUNNING);
}

HWTEST_F(AVDownloaderManagerTest, NotifyStatusChangeLocked_NoCallback_StillUpdatesState_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = "task1";
    taskInfo->state = AVDownloadTaskState::INIT;
    manager->taskMap_["task1"] = taskInfo;

    manager->NotifyStatusChangeLocked("task1", AVDownloadTaskState::PAUSED);
    EXPECT_EQ(taskInfo->state, AVDownloadTaskState::PAUSED);
}

HWTEST_F(AVDownloaderManagerTest, NotifyProgressChangeLocked_TaskInMap_UpdatesProgress_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto callback = std::make_shared<MockAVDownloaderManagerCallback>();
    (void)manager->SetManagerCallback(callback);
    EXPECT_CALL(*callback, OnProgressChange("task1", 80.0)).Times(1);
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = "task1";
    taskInfo->progress = 0.0;
    manager->taskMap_["task1"] = taskInfo;

    manager->NotifyProgressChangeLocked("task1", 80.0);
    EXPECT_DOUBLE_EQ(taskInfo->progress, 80.0);
}

HWTEST_F(AVDownloaderManagerTest, NotifyProgressChangeLocked_NoCallback_StillUpdatesProgress_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = "task1";
    taskInfo->progress = 0.0;
    manager->taskMap_["task1"] = taskInfo;

    manager->NotifyProgressChangeLocked("task1", 33.0);
    EXPECT_DOUBLE_EQ(taskInfo->progress, 33.0);
}

HWTEST_F(AVDownloaderManagerTest, FindExistingTask_NewNoKey_ExistingHasKey_SameUrl_Match, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);

    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = "task_with_key";
    taskInfo->url = "https://cdn1.example.com/path/video.m3u8";
    taskInfo->retrieveKey = "mykey";
    taskInfo->state = AVDownloadTaskState::RUNNING;
    manager->taskMap_["task_with_key"] = taskInfo;

    std::string result = manager->FindExistingTask("https://cdn1.example.com/path/video.m3u8", "");
    EXPECT_EQ(result, "task_with_key");

    manager->taskMap_.erase("task_with_key");
}

HWTEST_F(AVDownloaderManagerTest, FindExistingTask_SameKeySameUrl_Match, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);

    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = "task_same_key";
    taskInfo->url = "https://cdn1.example.com/path/video.m3u8";
    taskInfo->retrieveKey = "mykey";
    taskInfo->state = AVDownloadTaskState::RUNNING;
    manager->taskMap_["task_same_key"] = taskInfo;

    std::string result = manager->FindExistingTask("https://cdn1.example.com/path/video.m3u8", "mykey");
    EXPECT_EQ(result, "task_same_key");

    manager->taskMap_.erase("task_same_key");
}

HWTEST_F(AVDownloaderManagerTest, FindExistingTask_BothHaveKey_DiffKey_SameUrl_NoMatch, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);

    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = "task_key_a";
    taskInfo->url = "https://cdn1.example.com/path/video.m3u8";
    taskInfo->retrieveKey = "keyA";
    taskInfo->state = AVDownloadTaskState::RUNNING;
    manager->taskMap_["task_key_a"] = taskInfo;

    std::string result = manager->FindExistingTask("https://cdn1.example.com/path/video.m3u8", "keyB");
    EXPECT_EQ(result, "");

    manager->taskMap_.erase("task_key_a");
}

HWTEST_F(AVDownloaderManagerTest, FindExistingTask_BothHaveKey_SameKey_DiffUrl_Match, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);

    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = "task_cdn1";
    taskInfo->url = "https://cdn1.example.com/path/video.m3u8";
    taskInfo->retrieveKey = "mykey";
    taskInfo->state = AVDownloadTaskState::RUNNING;
    manager->taskMap_["task_cdn1"] = taskInfo;

    std::string result = manager->FindExistingTask("https://cdn2.example.com/path/video.m3u8", "mykey");
    EXPECT_EQ(result, "task_cdn1");

    manager->taskMap_.erase("task_cdn1");
}

HWTEST_F(AVDownloaderManagerTest, CreateNewDownloaderAndTask_FilterPopulatedFromSource, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);

    auto source = std::make_shared<Plugins::MediaSource>("http://example.com/test.m3u8");
    Plugins::TrackSelectionFilter filter;
    filter.maxVideoBitrate = 2000000;
    filter.maxVideoResolution = {1920, 1080};
    filter.preferredAudioLanguages = {"chi"};
    source->SetTrackSelectFilter(filter);

    auto [taskId, taskInfo, downloader, filePath] =
        manager->CreateNewDownloaderAndTask(source, "http://example.com/test.m3u8");

    EXPECT_NE(taskInfo, nullptr);
    EXPECT_EQ(taskInfo->filter.maxVideoBitrate, 2000000);
    EXPECT_EQ(taskInfo->filter.maxVideoResolution.first, 1920);
    EXPECT_EQ(taskInfo->filter.maxVideoResolution.second, 1080);
    EXPECT_EQ(taskInfo->filter.preferredAudioLanguages.size(), 1);
    EXPECT_EQ(taskInfo->filter.preferredAudioLanguages[0], "chi");
}

HWTEST_F(AVDownloaderManagerTest, CreateNewDownloaderAndTask_NoFilter_DefaultValues, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);

    auto source = std::make_shared<Plugins::MediaSource>("http://example.com/test.m3u8");

    auto [taskId, taskInfo, downloader, filePath] =
        manager->CreateNewDownloaderAndTask(source, "http://example.com/test.m3u8");

    EXPECT_NE(taskInfo, nullptr);
    EXPECT_EQ(taskInfo->filter.maxVideoBitrate, -1);
    EXPECT_EQ(taskInfo->filter.minVideoBitrate, -1);
    EXPECT_TRUE(taskInfo->filter.preferredAudioLanguages.empty());
    EXPECT_TRUE(taskInfo->filter.preferredVideoMimeTypes.empty());
}

HWTEST_F(AVDownloaderManagerTest, CreateNewDownloaderAndTask_RetrieveKeyPopulatedFromSource, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);

    auto source = std::make_shared<Plugins::MediaSource>("http://example.com/test.m3u8");
    source->SetRetrieveKey("testkey123");

    auto [taskId, taskInfo, downloader, filePath] =
        manager->CreateNewDownloaderAndTask(source, "http://example.com/test.m3u8");

    EXPECT_NE(taskInfo, nullptr);
    EXPECT_EQ(taskInfo->retrieveKey, "testkey123");
}

HWTEST_F(AVDownloaderManagerTest, FindExistingTask_PausedTask_WithKey_ReturnsTaskId, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);

    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = "task_paused_key";
    taskInfo->url = "https://cdn1.example.com/path/video.m3u8";
    taskInfo->retrieveKey = "mykey";
    taskInfo->state = AVDownloadTaskState::PAUSED;
    manager->taskMap_["task_paused_key"] = taskInfo;

    std::string result = manager->FindExistingTask("https://cdn2.example.com/path/video.m3u8", "mykey");
    EXPECT_EQ(result, "task_paused_key");

    manager->taskMap_.erase("task_paused_key");
}

HWTEST_F(AVDownloaderManagerTest, AddDownloadTask_EmptyUrl_ReturnsEmpty_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto source = std::make_shared<Plugins::MediaSource>("");

    auto taskId = manager->AddDownloadTask(source);
    EXPECT_EQ(taskId, "");
    EXPECT_TRUE(manager->taskMap_.empty());
}

HWTEST_F(AVDownloaderManagerTest, AddDownloadTask_ExistingPausedTask_Requeues_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    const std::string url = "http://example.com/paused.mp4";
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = "paused_task";
    taskInfo->url = url;
    taskInfo->state = AVDownloadTaskState::PAUSED;
    manager->taskMap_["paused_task"] = taskInfo;

    auto source = std::make_shared<Plugins::MediaSource>(url);
    auto taskId = manager->AddDownloadTask(source);

    EXPECT_EQ(taskId, "paused_task");
    EXPECT_EQ(taskInfo->state, AVDownloadTaskState::QUEUED);
}

HWTEST_F(AVDownloaderManagerTest, AddDownloadTask_ExistingRunningTask_ReturnsId_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    const std::string url = "http://example.com/running.mp4";
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = "running_task";
    taskInfo->url = url;
    taskInfo->state = AVDownloadTaskState::RUNNING;
    manager->taskMap_["running_task"] = taskInfo;

    auto source = std::make_shared<Plugins::MediaSource>(url);
    auto taskId = manager->AddDownloadTask(source);

    EXPECT_EQ(taskId, "running_task");
    EXPECT_EQ(taskInfo->state, AVDownloadTaskState::RUNNING);
    EXPECT_TRUE(manager->pendingTaskQueue_.empty());
}

HWTEST_F(AVDownloaderManagerTest, ProcessNextPendingTask_IdleTask_StartsAndMarksRunning_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    const std::string taskId = "100";
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = taskId;
    taskInfo->url = "http://example.com/idle.mp4";
    taskInfo->currentFilePath = "/cache/1/idle.mp4";
    taskInfo->state = AVDownloadTaskState::QUEUED;
    manager->taskMap_[taskId] = taskInfo;
    auto mockDownloader = std::make_shared<MockDownloader>();
    manager->downloaderMap_[taskId] = mockDownloader;
    manager->pendingTaskQueue_.push_back({taskInfo->url, taskId});

    EXPECT_CALL(*mockDownloader, GetState()).WillRepeatedly(Return(MediaDownload::DOWNLOAD_IDLE));
    EXPECT_CALL(*mockDownloader, SetDownloadCallback(_)).Times(1);
    EXPECT_CALL(*mockDownloader, AddFileTask(taskInfo->url, taskInfo->currentFilePath, _)).Times(1);
    EXPECT_CALL(*mockDownloader, SetConfig(_)).Times(1);
    EXPECT_CALL(*mockDownloader, Start()).WillOnce(Return(MSERR_OK));

    manager->ProcessNextPendingTask();

    EXPECT_EQ(taskInfo->state, AVDownloadTaskState::RUNNING);
    EXPECT_TRUE(manager->pendingTaskQueue_.empty());
}

HWTEST_F(AVDownloaderManagerTest, ProcessNextPendingTask_StartFails_MarksError_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    const std::string taskId = "101";
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = taskId;
    taskInfo->url = "http://example.com/fail.mp4";
    taskInfo->currentFilePath = "/cache/1/fail.mp4";
    taskInfo->state = AVDownloadTaskState::QUEUED;
    manager->taskMap_[taskId] = taskInfo;
    auto mockDownloader = std::make_shared<MockDownloader>();
    manager->downloaderMap_[taskId] = mockDownloader;
    manager->pendingTaskQueue_.push_back({taskInfo->url, taskId});
    auto callback = std::make_shared<MockAVDownloaderManagerCallback>();
    (void)manager->SetManagerCallback(callback);

    EXPECT_CALL(*mockDownloader, GetState()).WillRepeatedly(Return(MediaDownload::DOWNLOAD_IDLE));
    EXPECT_CALL(*mockDownloader, Start()).WillOnce(Return(MSERR_INVALID_OPERATION));
    EXPECT_CALL(*callback, OnStatusChange(taskId, AVDownloadTaskState::ERROR)).Times(1);

    manager->ProcessNextPendingTask();

    EXPECT_EQ(taskInfo->state, AVDownloadTaskState::ERROR);
}

HWTEST_F(AVDownloaderManagerTest, ProcessNextPendingTask_PausedTask_ResumesAndMarksRunning_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    const std::string taskId = "102";
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = taskId;
    taskInfo->url = "http://example.com/resume.mp4";
    taskInfo->state = AVDownloadTaskState::QUEUED;
    manager->taskMap_[taskId] = taskInfo;
    auto mockDownloader = std::make_shared<MockDownloader>();
    manager->downloaderMap_[taskId] = mockDownloader;
    manager->pendingTaskQueue_.push_back({taskInfo->url, taskId});

    EXPECT_CALL(*mockDownloader, GetState()).WillRepeatedly(Return(MediaDownload::DOWNLOAD_PAUSED));
    EXPECT_CALL(*mockDownloader, SetConfig(_)).Times(1);
    EXPECT_CALL(*mockDownloader, Resume()).WillOnce(Return(MSERR_OK));

    manager->ProcessNextPendingTask();

    EXPECT_EQ(taskInfo->state, AVDownloadTaskState::RUNNING);
}

HWTEST_F(AVDownloaderManagerTest, ProcessNextPendingTask_ActiveLimitReached_KeepsQueued_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    for (int32_t i = 0; i < 2; ++i) {
        auto runningTask = std::make_shared<AVDownloadTaskInfo>();
        runningTask->taskId = std::to_string(i);
        runningTask->state = AVDownloadTaskState::RUNNING;
        manager->taskMap_[runningTask->taskId] = runningTask;
    }
    auto startedTask = std::make_shared<AVDownloadTaskInfo>();
    startedTask->taskId = "started_task";
    startedTask->url = "http://example.com/started.mp4";
    startedTask->currentFilePath = "/cache/1/started.mp4";
    startedTask->state = AVDownloadTaskState::QUEUED;
    manager->taskMap_[startedTask->taskId] = startedTask;
    auto startedDownloader = std::make_shared<MockDownloader>();
    manager->downloaderMap_[startedTask->taskId] = startedDownloader;
    manager->pendingTaskQueue_.push_back({startedTask->url, startedTask->taskId});
    EXPECT_CALL(*startedDownloader, GetState()).WillRepeatedly(Return(MediaDownload::DOWNLOAD_IDLE));
    EXPECT_CALL(*startedDownloader, Start()).WillOnce(Return(MSERR_OK));

    manager->ProcessNextPendingTask();
    ASSERT_EQ(startedTask->state, AVDownloadTaskState::RUNNING);

    auto thirdRunningTask = std::make_shared<AVDownloadTaskInfo>();
    thirdRunningTask->taskId = "third_running";
    thirdRunningTask->state = AVDownloadTaskState::RUNNING;
    manager->taskMap_[thirdRunningTask->taskId] = thirdRunningTask;
    auto queuedTask = std::make_shared<AVDownloadTaskInfo>();
    queuedTask->taskId = "queued_task";
    queuedTask->url = "http://example.com/queued.mp4";
    queuedTask->state = AVDownloadTaskState::QUEUED;
    manager->taskMap_[queuedTask->taskId] = queuedTask;
    manager->pendingTaskQueue_.push_back({queuedTask->url, queuedTask->taskId});

    manager->ProcessNextPendingTask();

    EXPECT_EQ(queuedTask->state, AVDownloadTaskState::QUEUED);
    EXPECT_EQ(manager->pendingTaskQueue_.size(), 1U);
}

HWTEST_F(AVDownloaderManagerTest, RemoveDownloadTask_ExistingTask_RemovesAndCancels_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    const std::string taskId = "200";
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = taskId;
    taskInfo->state = AVDownloadTaskState::RUNNING;
    manager->taskMap_[taskId] = taskInfo;
    auto mockDownloader = std::make_shared<MockDownloader>();
    manager->downloaderMap_[taskId] = mockDownloader;
    auto callback = std::make_shared<MockAVDownloaderManagerCallback>();
    (void)manager->SetManagerCallback(callback);

    EXPECT_CALL(*mockDownloader, Cancel()).WillRepeatedly(Return(MSERR_OK));
    EXPECT_CALL(*mockDownloader, Release()).Times(1);
    EXPECT_CALL(*callback, OnStatusChange(taskId, AVDownloadTaskState::REMOVING)).Times(1);

    auto ret = manager->RemoveDownloadTask(taskId);

    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_TRUE(manager->taskMap_.empty());
    EXPECT_TRUE(manager->downloaderMap_.empty());
}

HWTEST_F(AVDownloaderManagerTest, PauseDownloadTask_QueuedTask_Pauses_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    const std::string taskId = "201";
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = taskId;
    taskInfo->url = "http://example.com/queued.mp4";
    taskInfo->state = AVDownloadTaskState::QUEUED;
    manager->taskMap_[taskId] = taskInfo;
    manager->pendingTaskQueue_.push_back({taskInfo->url, taskId});

    auto ret = manager->PauseDownloadTask(taskId);

    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(taskInfo->state, AVDownloadTaskState::PAUSED);
    EXPECT_TRUE(manager->pendingTaskQueue_.empty());
}

HWTEST_F(AVDownloaderManagerTest, PauseDownloadTask_RunningTask_PausesViaDownloader_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    const std::string taskId = "202";
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = taskId;
    taskInfo->state = AVDownloadTaskState::RUNNING;
    manager->taskMap_[taskId] = taskInfo;
    auto mockDownloader = std::make_shared<MockDownloader>();
    manager->downloaderMap_[taskId] = mockDownloader;

    EXPECT_CALL(*mockDownloader, Pause()).WillRepeatedly(Return(MSERR_OK));

    auto ret = manager->PauseDownloadTask(taskId);

    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(taskInfo->state, AVDownloadTaskState::PAUSED);
}

HWTEST_F(AVDownloaderManagerTest, PauseDownloadTask_WrongState_ReturnsInvalidOperation_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    const std::string taskId = "203";
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = taskId;
    taskInfo->state = AVDownloadTaskState::INIT;
    manager->taskMap_[taskId] = taskInfo;

    auto ret = manager->PauseDownloadTask(taskId);

    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
    EXPECT_EQ(taskInfo->state, AVDownloadTaskState::INIT);
}

HWTEST_F(AVDownloaderManagerTest, PauseDownloadTask_RunningWithoutDownloader_ReturnsInvalidVal_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    const std::string taskId = "204";
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = taskId;
    taskInfo->state = AVDownloadTaskState::RUNNING;
    manager->taskMap_[taskId] = taskInfo;

    auto ret = manager->PauseDownloadTask(taskId);

    EXPECT_EQ(ret, MSERR_INVALID_VAL);
    EXPECT_EQ(taskInfo->state, AVDownloadTaskState::RUNNING);
}

HWTEST_F(AVDownloaderManagerTest, ResumeDownloadTask_PausedTask_Queues_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    const std::string taskId = "205";
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = taskId;
    taskInfo->url = "http://example.com/paused.mp4";
    taskInfo->state = AVDownloadTaskState::PAUSED;
    manager->taskMap_[taskId] = taskInfo;

    auto ret = manager->ResumeDownloadTask(taskId);

    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(taskInfo->state, AVDownloadTaskState::QUEUED);
}

HWTEST_F(AVDownloaderManagerTest, ResumeDownloadTask_NotPaused_ReturnsInvalidOperation_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    const std::string taskId = "206";
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = taskId;
    taskInfo->state = AVDownloadTaskState::RUNNING;
    manager->taskMap_[taskId] = taskInfo;

    auto ret = manager->ResumeDownloadTask(taskId);

    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
    EXPECT_EQ(taskInfo->state, AVDownloadTaskState::RUNNING);
}

HWTEST_F(AVDownloaderManagerTest, GetDownloadTasks_WithTasks_ReturnsIds_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    for (const auto &taskId : {"task_a", "task_b"}) {
        auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
        taskInfo->taskId = taskId;
        manager->taskMap_[taskId] = taskInfo;
    }

    auto taskIds = manager->GetDownloadTasks();

    EXPECT_EQ(taskIds.size(), 2U);
    EXPECT_NE(std::find(taskIds.begin(), taskIds.end(), "task_a"), taskIds.end());
    EXPECT_NE(std::find(taskIds.begin(), taskIds.end(), "task_b"), taskIds.end());
}

HWTEST_F(AVDownloaderManagerTest, GetTaskCacheDirectory_ExistingTask_ReturnsDir_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = "task_dir";
    taskInfo->cacheDir = "/cache/hash_dir";
    manager->taskMap_["task_dir"] = taskInfo;

    auto cacheDir = manager->GetTaskCacheDirectory("task_dir");

    EXPECT_EQ(cacheDir, "/cache/hash_dir");
}

HWTEST_F(AVDownloaderManagerTest, GetTaskStatus_ExistingTask_ReturnsState_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = "task_status";
    taskInfo->state = AVDownloadTaskState::PAUSED;
    manager->taskMap_["task_status"] = taskInfo;

    auto state = manager->GetTaskStatus("task_status");

    EXPECT_EQ(state, AVDownloadTaskState::PAUSED);
}

HWTEST_F(AVDownloaderManagerTest, GetTaskProgress_ExistingTask_ReturnsProgress_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = "task_progress";
    taskInfo->progress = 0.75;
    manager->taskMap_["task_progress"] = taskInfo;

    auto progress = manager->GetTaskProgress("task_progress");

    EXPECT_DOUBLE_EQ(progress, 0.75);
}

HWTEST_F(AVDownloaderManagerTest, ConvertToAVDownloadTaskState_Preparing_ReturnsQueued_001, TestSize.Level0)
{
    auto state = AVDownloaderManagerImpl::ConvertToAVDownloadTaskState(
        MediaDownload::DownloadState::DOWNLOAD_PREPARING);
    EXPECT_EQ(state, AVDownloadTaskState::QUEUED);
}

HWTEST_F(AVDownloaderManagerTest, ConvertToAVDownloadTaskState_Canceled_ReturnsRemoving_001, TestSize.Level0)
{
    auto state = AVDownloaderManagerImpl::ConvertToAVDownloadTaskState(
        MediaDownload::DownloadState::DOWNLOAD_CANCELED);
    EXPECT_EQ(state, AVDownloadTaskState::REMOVING);
}

HWTEST_F(AVDownloaderManagerTest, ConvertToAVDownloadTaskState_Unknown_ReturnsError_001, TestSize.Level0)
{
    auto state = AVDownloaderManagerImpl::ConvertToAVDownloadTaskState(
        static_cast<MediaDownload::DownloadState>(99));
    EXPECT_EQ(state, AVDownloadTaskState::ERROR);
}

HWTEST_F(AVDownloaderManagerTest, OnStateChanged_UpdatesTaskState_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    const std::string taskId = "300";
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = taskId;
    taskInfo->state = AVDownloadTaskState::INIT;
    manager->taskMap_[taskId] = taskInfo;
    auto callback = std::make_shared<MockAVDownloaderManagerCallback>();
    (void)manager->SetManagerCallback(callback);
    auto taskCallback = std::make_shared<DownloadTaskCallback>(
        std::weak_ptr<AVDownloaderManagerImpl>(manager));

    EXPECT_CALL(*callback, OnStatusChange(taskId, AVDownloadTaskState::RUNNING)).Times(1);

    taskCallback->OnStateChanged(300, MediaDownload::DownloadState::DOWNLOAD_RUNNING);

    EXPECT_EQ(taskInfo->state, AVDownloadTaskState::RUNNING);
}

HWTEST_F(AVDownloaderManagerTest, OnFailed_NetworkAllowed_MarksError_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    manager->simulatedNetworkType_ = MediaSourceUtils::NetConnType::NET_CONN_WIFI;
    const std::string taskId = "301";
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = taskId;
    taskInfo->state = AVDownloadTaskState::RUNNING;
    manager->taskMap_[taskId] = taskInfo;
    auto mockDownloader = std::make_shared<MockDownloader>();
    manager->downloaderMap_[taskId] = mockDownloader;
    auto callback = std::make_shared<MockAVDownloaderManagerCallback>();
    (void)manager->SetManagerCallback(callback);
    auto taskCallback = std::make_shared<DownloadTaskCallback>(
        std::weak_ptr<AVDownloaderManagerImpl>(manager));

    EXPECT_CALL(*callback, OnStatusChange(taskId, AVDownloadTaskState::ERROR)).Times(1);

    taskCallback->OnFailed(301, MediaDownload::DOWNLOAD_ERROR_NETWORK, -1, "network error");

    EXPECT_EQ(taskInfo->state, AVDownloadTaskState::ERROR);
}

HWTEST_F(AVDownloaderManagerTest, OnFailed_NetworkNotAllowed_MarksPaused_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    manager->simulatedNetworkType_ = MediaSourceUtils::NetConnType::NET_CONN_NONE;
    const std::string taskId = "302";
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = taskId;
    taskInfo->state = AVDownloadTaskState::RUNNING;
    manager->taskMap_[taskId] = taskInfo;
    auto callback = std::make_shared<MockAVDownloaderManagerCallback>();
    (void)manager->SetManagerCallback(callback);
    auto taskCallback = std::make_shared<DownloadTaskCallback>(
        std::weak_ptr<AVDownloaderManagerImpl>(manager));

    EXPECT_CALL(*callback, OnStatusChange(taskId, AVDownloadTaskState::PAUSED)).Times(1);

    taskCallback->OnFailed(302, MediaDownload::DOWNLOAD_ERROR_NETWORK, -1, "network lost");

    EXPECT_EQ(taskInfo->state, AVDownloadTaskState::PAUSED);
}

HWTEST_F(AVDownloaderManagerTest, OnProgress_ParseCompleted_ReportsProgress_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    const std::string taskId = "303";
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = taskId;
    taskInfo->parseCompleted = true;
    manager->taskMap_[taskId] = taskInfo;
    auto callback = std::make_shared<MockAVDownloaderManagerCallback>();
    (void)manager->SetManagerCallback(callback);
    auto taskCallback = std::make_shared<DownloadTaskCallback>(
        std::weak_ptr<AVDownloaderManagerImpl>(manager));
    MediaDownload::DownloadProgress progress;
    progress.progressPercent = 50;

    EXPECT_CALL(*callback, OnProgressChange(taskId, 0.5)).Times(1);

    taskCallback->OnProgress(303, progress);

    EXPECT_DOUBLE_EQ(taskInfo->progress, 0.5);
}

HWTEST_F(AVDownloaderManagerTest, OnFileCompleted_UpdatesFileSize_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    const std::string taskId = "304";
    const std::string url = "http://example.com/file.mp4";
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = taskId;
    DownloadFileInfo fileInfo;
    fileInfo.url = url;
    taskInfo->fileList.push_back(fileInfo);
    manager->taskMap_[taskId] = taskInfo;
    auto taskCallback = std::make_shared<DownloadTaskCallback>(
        std::weak_ptr<AVDownloaderManagerImpl>(manager));

    taskCallback->OnFileCompleted(304, url, 1234);

    EXPECT_EQ(taskInfo->fileList[0].fileSize, 1234U);
}

HWTEST_F(AVDownloaderManagerTest, OnFileCompleted_NegativeSize_NoUpdate_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    const std::string taskId = "305";
    const std::string url = "http://example.com/file.mp4";
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = taskId;
    DownloadFileInfo fileInfo;
    fileInfo.url = url;
    taskInfo->fileList.push_back(fileInfo);
    manager->taskMap_[taskId] = taskInfo;
    auto taskCallback = std::make_shared<DownloadTaskCallback>(
        std::weak_ptr<AVDownloaderManagerImpl>(manager));

    taskCallback->OnFileCompleted(305, url, 2048);
    ASSERT_EQ(taskInfo->fileList[0].fileSize, 2048U);

    taskCallback->OnFileCompleted(305, url, -1);

    EXPECT_EQ(taskInfo->fileList[0].fileSize, 2048U);
}

HWTEST_F(AVDownloaderManagerTest, OnCompleted_AllDownloaded_NotifiesCompleted_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    const std::string taskId = "306";
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = taskId;
    taskInfo->mappingFileCreated = true;
    DownloadFileInfo fileInfo;
    fileInfo.url = "http://example.com/done.mp4";
    fileInfo.downloaded = false;
    fileInfo.needParse = false;
    taskInfo->fileList.push_back(fileInfo);
    manager->taskMap_[taskId] = taskInfo;
    auto mockDownloader = std::make_shared<MockDownloader>();
    manager->downloaderMap_[taskId] = mockDownloader;
    auto callback = std::make_shared<MockAVDownloaderManagerCallback>();
    (void)manager->SetManagerCallback(callback);
    auto taskCallback = std::make_shared<DownloadTaskCallback>(
        std::weak_ptr<AVDownloaderManagerImpl>(manager));

    EXPECT_CALL(*callback, OnStatusChange(taskId, AVDownloadTaskState::COMPLETED)).Times(1);
    EXPECT_CALL(*callback, OnProgressChange(taskId, 1.0)).Times(1);

    taskCallback->OnCompleted(306, 4096);

    EXPECT_TRUE(taskInfo->fileList[0].downloaded);
    EXPECT_EQ(taskInfo->state, AVDownloadTaskState::COMPLETED);
    EXPECT_DOUBLE_EQ(taskInfo->progress, 1.0);
}

HWTEST_F(AVDownloaderManagerTest, GetFilePath_QueryStripped_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);

    auto result = manager->GetFilePath("/cache", "http://example.com/a.mp4?token=1");

    EXPECT_EQ(result, "/cache/1/a.mp4");
}

HWTEST_F(AVDownloaderManagerTest, GetFilePath_LongFilename_Truncated_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    std::string fileName(120, 'a');
    fileName += ".mp4";

    auto result = manager->GetFilePath("/cache", "http://example.com/" + fileName);

    EXPECT_EQ(result.find("/cache/1/"), 0U);
    EXPECT_EQ(result.size(), std::string("/cache/1/").size() + 100U);
    EXPECT_EQ(result.substr(result.size() - 4), ".mp4");
}

HWTEST_F(AVDownloaderManagerTest, GetFilePath_PathTraversal_FallsBackToHash_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);

    auto result = manager->GetFilePath("/cache", "http://example.com/..");

    EXPECT_EQ(result.find("/cache/1/"), 0U);
    EXPECT_EQ(result.size(), std::string("/cache/1/").size() + 64U);
}

HWTEST_F(AVDownloaderManagerTest, SetRequestTimeout_Zero_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);

    auto ret = manager->SetRequestTimeout(0);

    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(manager->requestTimeoutMs_.load(), 0);
}

HWTEST_F(AVDownloaderManagerTest, SetAllowCellularAccess_UpdatesAtomic_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);

    auto ret = manager->SetAllowCellularAccess(true);

    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_TRUE(manager->allowCellularAccess_.load());
}

HWTEST_F(AVDownloaderManagerTest, SetRequestTimeout_UpdatesAtomic_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);

    auto ret = manager->SetRequestTimeout(50000);

    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(manager->requestTimeoutMs_.load(), 50000);
}

HWTEST_F(AVDownloaderManagerTest, SetManagerCallback_ReplacesPreviousCallback_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = "cb_task";
    manager->taskMap_["cb_task"] = taskInfo;
    auto oldCallback = std::make_shared<MockAVDownloaderManagerCallback>();
    auto newCallback = std::make_shared<MockAVDownloaderManagerCallback>();
    (void)manager->SetManagerCallback(oldCallback);
    (void)manager->SetManagerCallback(newCallback);

    EXPECT_CALL(*oldCallback, OnStatusChange(_, _)).Times(0);
    EXPECT_CALL(*newCallback, OnStatusChange("cb_task", AVDownloadTaskState::RUNNING)).Times(1);

    manager->NotifyStatusChange("cb_task", AVDownloadTaskState::RUNNING);

    EXPECT_EQ(taskInfo->state, AVDownloadTaskState::RUNNING);
}

HWTEST_F(AVDownloaderManagerTest, AVDownloaderManagerFactory_Create_ReturnsManager_001, TestSize.Level0)
{
    auto manager = AVDownloaderManagerFactory::Create();

    ASSERT_NE(manager, nullptr);
    EXPECT_TRUE(manager->GetDownloadTasks().empty());
}

HWTEST_F(AVDownloaderManagerTest, HandleTaskAdded_QueuesTask_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    const std::string taskId = "400";
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = taskId;
    taskInfo->url = "http://example.com/added.mp4";
    taskInfo->state = AVDownloadTaskState::INIT;
    manager->taskMap_[taskId] = taskInfo;
    auto callback = std::make_shared<MockAVDownloaderManagerCallback>();
    (void)manager->SetManagerCallback(callback);

    EXPECT_CALL(*callback, OnStatusChange(taskId, AVDownloadTaskState::QUEUED)).Times(1);

    manager->HandleTaskAdded(taskId, taskInfo->url);

    EXPECT_EQ(taskInfo->state, AVDownloadTaskState::QUEUED);
    EXPECT_EQ(manager->pendingTaskQueue_.size(), 1U);
}

HWTEST_F(AVDownloaderManagerTest, OnNetworkChanged_Allowed_RestoresPausedTasks_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = "401";
    taskInfo->url = "http://example.com/paused.mp4";
    taskInfo->state = AVDownloadTaskState::PAUSED;
    manager->taskMap_["401"] = taskInfo;

    manager->OnNetworkChanged(MediaSourceUtils::NetConnType::NET_CONN_WIFI);

    EXPECT_EQ(taskInfo->state, AVDownloadTaskState::QUEUED);
}

HWTEST_F(AVDownloaderManagerTest, OnNetworkChanged_NotAllowed_PausesQueuedTasks_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = "402";
    taskInfo->url = "http://example.com/queued.mp4";
    taskInfo->state = AVDownloadTaskState::QUEUED;
    manager->taskMap_["402"] = taskInfo;
    manager->pendingTaskQueue_.push_back({taskInfo->url, taskInfo->taskId});

    manager->OnNetworkChanged(MediaSourceUtils::NetConnType::NET_CONN_NONE);

    EXPECT_EQ(taskInfo->state, AVDownloadTaskState::PAUSED);
    EXPECT_TRUE(manager->pendingTaskQueue_.empty());
}

HWTEST_F(AVDownloaderManagerTest, OnNetworkLost_PausesRunningTaskViaDownloader_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = "404";
    taskInfo->state = AVDownloadTaskState::RUNNING;
    manager->taskMap_["404"] = taskInfo;
    auto mockDownloader = std::make_shared<MockDownloader>();
    manager->downloaderMap_["404"] = mockDownloader;

    EXPECT_CALL(*mockDownloader, Pause()).WillRepeatedly(Return(MSERR_OK));

    manager->OnNetworkLost();

    EXPECT_EQ(taskInfo->state, AVDownloadTaskState::PAUSED);
}

HWTEST_F(AVDownloaderManagerTest, OnProgress_ProtocolSniffedHttp_ReportsProgress_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = "405";
    taskInfo->protocolSniffed = true;
    taskInfo->detectedProtocol = Plugins::HttpPlugin::StreamProtocolType::HTTP;
    manager->taskMap_["405"] = taskInfo;
    auto callback = std::make_shared<MockAVDownloaderManagerCallback>();
    (void)manager->SetManagerCallback(callback);
    auto taskCallback = std::make_shared<DownloadTaskCallback>(
        std::weak_ptr<AVDownloaderManagerImpl>(manager));
    MediaDownload::DownloadProgress progress;
    progress.progressPercent = 40;

    EXPECT_CALL(*callback, OnProgressChange("405", 0.4)).Times(1);

    taskCallback->OnProgress(405, progress);

    EXPECT_DOUBLE_EQ(taskInfo->progress, 0.4);
}

HWTEST_F(AVDownloaderManagerTest, OnCompleted_ParseChain_SubmitsRemaining_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    const std::string taskId = "407";
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = taskId;
    taskInfo->cacheDir = "/data/test/cache";
    DownloadFileInfo fileInfo;
    fileInfo.url = "http://example.com/index.m3u8";
    fileInfo.filePath = "/invalid/path/index.m3u8";
    fileInfo.downloaded = false;
    fileInfo.needParse = true;
    taskInfo->fileList.push_back(fileInfo);
    manager->taskMap_[taskId] = taskInfo;
    auto mockDownloader = std::make_shared<MockDownloader>();
    manager->downloaderMap_[taskId] = mockDownloader;
    auto taskCallback = std::make_shared<DownloadTaskCallback>(
        std::weak_ptr<AVDownloaderManagerImpl>(manager));
    int32_t startCount = 0;
    EXPECT_CALL(*mockDownloader, AddFileTask(_, _, _)).Times(0);
    EXPECT_CALL(*mockDownloader, Start()).WillOnce(testing::Invoke([&startCount]() {
        startCount++;
        return MSERR_OK;
    }));

    taskCallback->OnCompleted(407, 1024);

    EXPECT_TRUE(taskInfo->fileList[0].downloaded);
    EXPECT_TRUE(taskInfo->fileList[0].needParse);
    EXPECT_EQ(startCount, 1);
}

HWTEST_F(AVDownloaderManagerTest, OnFileCompleted_UrlNotInList_NoUpdate_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = "408";
    DownloadFileInfo fileInfo;
    fileInfo.url = "http://example.com/known.mp4";
    taskInfo->fileList.push_back(fileInfo);
    manager->taskMap_["408"] = taskInfo;
    auto taskCallback = std::make_shared<DownloadTaskCallback>(
        std::weak_ptr<AVDownloaderManagerImpl>(manager));

    taskCallback->OnFileCompleted(408, "http://example.com/known.mp4", 100);
    ASSERT_EQ(taskInfo->fileList[0].fileSize, 100U);

    taskCallback->OnFileCompleted(408, "http://example.com/unknown.mp4", 200);

    EXPECT_EQ(taskInfo->fileList[0].fileSize, 100U);
}

HWTEST_F(AVDownloaderManagerTest, GetFilePath_BackslashSeparator_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);

    auto result = manager->GetFilePath("/cache", "http:\\\\example.com\\\\file.mp4");

    EXPECT_EQ(result, "/cache/1/file.mp4");
}

HWTEST_F(AVDownloaderManagerTest, GetFilePath_EmptyRootDir_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);

    auto result = manager->GetFilePath("", "http://example.com/file.mp4");

    EXPECT_EQ(result, "/1/file.mp4");
}

HWTEST_F(AVDownloaderManagerTest, GetFilePath_LongNameWithoutExtension_Truncated_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    std::string fileName(120, 'b');

    auto result = manager->GetFilePath("/cache", "http://example.com/" + fileName);

    EXPECT_EQ(result.find("/cache/1/"), 0U);
    EXPECT_EQ(result.size(), std::string("/cache/1/").size() + 100U);
}

HWTEST_F(AVDownloaderManagerTest, AddDownloadTask_NewTask_CreatesAndQueues_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    auto source = std::make_shared<Plugins::MediaSource>("http://example.com/new_task.mp4");

    auto taskId = manager->AddDownloadTask(source);

    EXPECT_FALSE(taskId.empty());
    EXPECT_EQ(manager->taskMap_.count(taskId), 1U);
    EXPECT_EQ(manager->downloaderMap_.count(taskId), 1U);
    manager->Release();
}

HWTEST_F(AVDownloaderManagerTest, HandleMessage_ProcessNextTask_StartsTask_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    const std::string taskId = "500";
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = taskId;
    taskInfo->url = "http://example.com/msg.mp4";
    taskInfo->currentFilePath = "/cache/1/msg.mp4";
    taskInfo->state = AVDownloadTaskState::QUEUED;
    manager->taskMap_[taskId] = taskInfo;
    auto mockDownloader = std::make_shared<MockDownloader>();
    manager->downloaderMap_[taskId] = mockDownloader;
    manager->pendingTaskQueue_.push_back({taskInfo->url, taskId});
    EXPECT_CALL(*mockDownloader, GetState()).WillRepeatedly(Return(MediaDownload::DOWNLOAD_IDLE));
    EXPECT_CALL(*mockDownloader, Start()).WillOnce(Return(MSERR_OK));
    MediaDownload::Message msg;
    msg.type = MediaDownload::MSG_PROCESS_NEXT_TASK;

    manager->HandleMessage(msg);

    EXPECT_EQ(taskInfo->state, AVDownloadTaskState::RUNNING);
}

HWTEST_F(AVDownloaderManagerTest, HandleMessage_ReleaseDownloader_RemovesEntry_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    const std::string taskId = "501";
    auto mockDownloader = std::make_shared<MockDownloader>();
    manager->downloaderMap_[taskId] = mockDownloader;
    EXPECT_CALL(*mockDownloader, Release()).Times(1);
    MediaDownload::Message msg;
    msg.type = MediaDownload::MSG_RELEASE_DOWNLOADER;
    msg.downloaderId = 501;

    manager->HandleMessage(msg);

    EXPECT_TRUE(manager->downloaderMap_.empty());
}

HWTEST_F(AVDownloaderManagerTest, OnCompleted_DownloaderMissing_EarlyReturn_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = "502";
    DownloadFileInfo fileInfo;
    fileInfo.url = "http://example.com/no_downloader.mp4";
    fileInfo.downloaded = false;
    fileInfo.needParse = false;
    taskInfo->fileList.push_back(fileInfo);
    manager->taskMap_["502"] = taskInfo;
    auto taskCallback = std::make_shared<DownloadTaskCallback>(
        std::weak_ptr<AVDownloaderManagerImpl>(manager));

    taskCallback->OnCompleted(502, 100);

    EXPECT_TRUE(taskInfo->fileList[0].downloaded);
    EXPECT_EQ(taskInfo->state, AVDownloadTaskState::INIT);
}

HWTEST_F(AVDownloaderManagerTest, SniffProtocolFromFile_HlsPlaylist_SetsNeedParse_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    std::string testDir = MediaDownload::TestCommon::GetTestCacheDir("sniff_hls");
    ASSERT_FALSE(testDir.empty());
    std::string m3u8Path = testDir + "/playlist.m3u8";
    std::vector<uint8_t> content(300, '#');
    const std::string header = "#EXTM3U\n";
    std::copy(header.begin(), header.end(), content.begin());
    ASSERT_TRUE(MediaDownload::TestCommon::CreateTestFile(m3u8Path, content));
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = "503";
    DownloadFileInfo fileInfo;
    fileInfo.url = "http://example.com/sniff.m3u8";
    fileInfo.needParse = false;
    taskInfo->fileList.push_back(fileInfo);
    auto taskCallback = std::make_shared<DownloadTaskCallback>(
        std::weak_ptr<AVDownloaderManagerImpl>(manager));

    taskCallback->SniffProtocolFromFile(taskInfo, m3u8Path);

    EXPECT_TRUE(taskInfo->protocolSniffed);
    EXPECT_EQ(taskInfo->detectedProtocol, Plugins::HttpPlugin::StreamProtocolType::HLS);
    EXPECT_TRUE(taskInfo->fileList[0].needParse);
    MediaDownload::TestCommon::CleanupTestDirectory(testDir);
}

HWTEST_F(AVDownloaderManagerTest, SniffStreamProtocol_EnoughBuffer_SniffsHls_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    std::string testDir = MediaDownload::TestCommon::GetTestCacheDir("sniff_stream_hls");
    ASSERT_FALSE(testDir.empty());
    std::string m3u8Path = testDir + "/playlist.m3u8";
    std::vector<uint8_t> content(300, '#');
    const std::string header = "#EXTM3U\n";
    std::copy(header.begin(), header.end(), content.begin());
    ASSERT_TRUE(MediaDownload::TestCommon::CreateTestFile(m3u8Path, content));
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = "504";
    auto taskCallback = std::make_shared<DownloadTaskCallback>(
        std::weak_ptr<AVDownloaderManagerImpl>(manager));
    MediaDownload::DownloadProgress progress;
    progress.downloadedSize = 4096;

    taskCallback->SniffStreamProtocol(504, progress, m3u8Path, taskInfo);

    EXPECT_TRUE(taskInfo->protocolSniffed);
    EXPECT_EQ(taskInfo->detectedProtocol, Plugins::HttpPlugin::StreamProtocolType::HLS);
    MediaDownload::TestCommon::CleanupTestDirectory(testDir);
}

} // namespace Media
} // namespace OHOS
