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

HWTEST_F(AVDownloaderManagerTest, Release_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto result = manager->Release();
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

HWTEST_F(AVDownloaderManagerTest, NotifyStatusChange_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto callback = std::make_shared<MockAVDownloaderManagerCallback>();
    (void)manager->SetManagerCallback(callback);
    EXPECT_CALL(*callback, OnStatusChange("task1", AVDownloadTaskState::RUNNING)).Times(1);
    manager->NotifyStatusChange("task1", AVDownloadTaskState::RUNNING);
}

HWTEST_F(AVDownloaderManagerTest, NotifyProgressChange_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto callback = std::make_shared<MockAVDownloaderManagerCallback>();
    (void)manager->SetManagerCallback(callback);
    EXPECT_CALL(*callback, OnProgressChange("task1", 50.0)).Times(1);
    manager->NotifyProgressChange("task1", 50.0);
}

HWTEST_F(AVDownloaderManagerTest, GetFilePath_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto result = manager->GetFilePath("/cache", "http://example.com/test.mp4");
    EXPECT_FALSE(result.empty());
}

HWTEST_F(AVDownloaderManagerTest, AVDownloadTaskInfo_001, TestSize.Level0)
{
    AVDownloadTaskInfo taskInfo;
    taskInfo.taskId = "task1";
    taskInfo.url = "http://example.com/test.mp4";
    taskInfo.cacheDir = "/cache";
    taskInfo.state = AVDownloadTaskState::INIT;
    taskInfo.progress = 0.0;

    EXPECT_EQ(taskInfo.taskId, "task1");
    EXPECT_EQ(taskInfo.url, "http://example.com/test.mp4");
    EXPECT_EQ(taskInfo.cacheDir, "/cache");
    EXPECT_EQ(taskInfo.state, AVDownloadTaskState::INIT);
    EXPECT_EQ(taskInfo.progress, 0.0);
}

HWTEST_F(AVDownloaderManagerTest, DownloadFileInfo_001, TestSize.Level0)
{
    DownloadFileInfo fileInfo;
    fileInfo.url = "http://example.com/test.mp4";
    fileInfo.filePath = "/cache/test.mp4";
    fileInfo.downloaded = false;
    fileInfo.needParse = true;

    EXPECT_EQ(fileInfo.url, "http://example.com/test.mp4");
    EXPECT_EQ(fileInfo.filePath, "/cache/test.mp4");
    EXPECT_FALSE(fileInfo.downloaded);
    EXPECT_TRUE(fileInfo.needParse);
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

HWTEST_F(AVDownloaderManagerTest, FindExistingTask_PausedTask_DownloaderNotFound_001, TestSize.Level0)
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
    EXPECT_EQ(result, "");
    
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
    EXPECT_EQ(result, "");
    
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

    EXPECT_CALL(*mockDownloader, SetConfig(_)).Times(0);
    EXPECT_CALL(*mockDownloader, AddFileTask(_, _, _)).Times(0);
    EXPECT_CALL(*mockDownloader, Start()).WillOnce(Return(0));

    auto callback = std::make_shared<DownloadTaskCallback>(std::weak_ptr<AVDownloaderManagerImpl>(manager));
    callback->SubmitRemainingTasks(mockDownloader, taskInfo, manager);
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

    EXPECT_CALL(*mockDownloader, SetConfig(_)).Times(1);
    EXPECT_CALL(*mockDownloader, AddFileTask("http://example.com/file1.mp4", "/cache/file1.mp4", _)).Times(1);
    EXPECT_CALL(*mockDownloader, Start()).WillOnce(Return(0));

    auto callback = std::make_shared<DownloadTaskCallback>(std::weak_ptr<AVDownloaderManagerImpl>(manager));
    callback->SubmitRemainingTasks(mockDownloader, taskInfo, manager);
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

    EXPECT_CALL(*mockDownloader, SetConfig(_)).Times(2);
    EXPECT_CALL(*mockDownloader, AddFileTask("http://example.com/file3.ts", "/cache/file3.ts", _)).Times(1);
    EXPECT_CALL(*mockDownloader, AddFileTask("http://example.com/sub.m3u8", "/cache/sub.m3u8", _)).Times(1);
    EXPECT_CALL(*mockDownloader, Start()).WillOnce(Return(0));

    auto callback = std::make_shared<DownloadTaskCallback>(std::weak_ptr<AVDownloaderManagerImpl>(manager));
    callback->SubmitRemainingTasks(mockDownloader, taskInfo, manager);
}

HWTEST_F(AVDownloaderManagerTest, SubmitRemainingTasks_EmptyFileList_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    auto mockDownloader = std::make_shared<MockDownloader>();

    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();

    EXPECT_CALL(*mockDownloader, SetConfig(_)).Times(0);
    EXPECT_CALL(*mockDownloader, AddFileTask(_, _, _)).Times(0);
    EXPECT_CALL(*mockDownloader, Start()).WillOnce(Return(0));

    auto callback = std::make_shared<DownloadTaskCallback>(std::weak_ptr<AVDownloaderManagerImpl>(manager));
    callback->SubmitRemainingTasks(mockDownloader, taskInfo, manager);
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

HWTEST_F(AVDownloaderManagerTest, GenerateMappingFile_NullTaskInfo_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    auto callback = std::make_shared<DownloadTaskCallback>(std::weak_ptr<AVDownloaderManagerImpl>(manager));
    callback->GenerateMappingFile(nullptr);
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->cacheDir = "/data/../etc";
    DownloadFileInfo fileInfo;
    fileInfo.url = "http://example.com/test.mp4";
    fileInfo.filePath = "/data/../etc/test.mp4";
    fileInfo.downloaded = true;
    taskInfo->fileList.push_back(fileInfo);
    callback->GenerateMappingFile(taskInfo);
    EXPECT_FALSE(taskInfo->mappingFileCreated);
}

HWTEST_F(AVDownloaderManagerTest, GenerateMappingFile_EmptyCacheDir_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto callback = std::make_shared<DownloadTaskCallback>(std::weak_ptr<AVDownloaderManagerImpl>(manager));
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->cacheDir = "";
    callback->GenerateMappingFile(taskInfo);
    EXPECT_FALSE(taskInfo->mappingFileCreated);
}

HWTEST_F(AVDownloaderManagerTest, GenerateMappingFile_PathTraversal_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto callback = std::make_shared<DownloadTaskCallback>(std::weak_ptr<AVDownloaderManagerImpl>(manager));
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->cacheDir = "/data/../etc";
    DownloadFileInfo fileInfo;
    fileInfo.url = "http://example.com/test.mp4";
    fileInfo.filePath = "/data/../etc/test.mp4";
    fileInfo.downloaded = true;
    taskInfo->fileList.push_back(fileInfo);
    callback->GenerateMappingFile(taskInfo);
    EXPECT_FALSE(taskInfo->mappingFileCreated);
}

HWTEST_F(AVDownloaderManagerTest, GenerateMappingFile_OfstreamOpenFail_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto callback = std::make_shared<DownloadTaskCallback>(std::weak_ptr<AVDownloaderManagerImpl>(manager));
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->cacheDir = "/proc";
    DownloadFileInfo fileInfo;
    fileInfo.url = "http://example.com/test.mp4";
    fileInfo.filePath = "/proc/test.mp4";
    fileInfo.downloaded = true;
    taskInfo->fileList.push_back(fileInfo);
    callback->GenerateMappingFile(taskInfo);
    EXPECT_FALSE(taskInfo->mappingFileCreated);
}

HWTEST_F(AVDownloaderManagerTest, ParseSingleFile_PathTraversal_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto callback = std::make_shared<DownloadTaskCallback>(std::weak_ptr<AVDownloaderManagerImpl>(manager));
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    DownloadFileInfo fileInfo;
    fileInfo.url = "http://example.com/test.m3u8";
    fileInfo.filePath = "/cache/../etc/passwd";
    fileInfo.needParse = true;
    std::vector<DownloadFileInfo> filesToAdd;
    callback->ParseSingleFile(1, fileInfo, taskInfo, filesToAdd, manager);
    EXPECT_TRUE(filesToAdd.empty());
    EXPECT_TRUE(fileInfo.needParse);
}

HWTEST_F(AVDownloaderManagerTest, SniffStreamProtocol_PathTraversal_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto callback = std::make_shared<DownloadTaskCallback>(std::weak_ptr<AVDownloaderManagerImpl>(manager));
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    MediaDownload::DownloadProgress progress;
    progress.downloadedSize = 4096;
    callback->SniffStreamProtocol(1, progress, "/cache/../etc/passwd", taskInfo);
    EXPECT_FALSE(taskInfo->protocolSniffed);
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
    fileInfo.needParse = true;
    taskInfo->fileList.push_back(fileInfo);
    manager->taskMap_["1"] = taskInfo;

    auto mockDownloader = std::make_shared<MockDownloader>();
    EXPECT_CALL(*mockDownloader, SetConfig(_)).Times(0);
    EXPECT_CALL(*mockDownloader, AddFileTask(_, _, _)).Times(0);
    EXPECT_CALL(*mockDownloader, Start()).WillOnce(Return(0));
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
    EXPECT_NE(result.find("normal.mp4"), std::string::npos);
}

HWTEST_F(AVDownloaderManagerTest, GetFilePath_EmptyFilename_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto result = manager->GetFilePath("/data/storage/el2/base/cache/test",
        "http://example.com/");
    EXPECT_FALSE(result.empty());
    size_t lastSlash = result.find_last_of('/');
    std::string fileNamePart = result.substr(lastSlash + 1);
    EXPECT_FALSE(fileNamePart.empty());
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
    manager->messageQueue_.reset();
    auto result = manager->Release();
    EXPECT_EQ(result, MSERR_OK);
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

HWTEST_F(AVDownloaderManagerTest, NotifyStatusChange_TaskNotInMap_CallbackOnly_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto callback = std::make_shared<MockAVDownloaderManagerCallback>();
    (void)manager->SetManagerCallback(callback);
    EXPECT_CALL(*callback, OnStatusChange("unknown", AVDownloadTaskState::RUNNING)).Times(1);
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = "task1";
    taskInfo->state = AVDownloadTaskState::INIT;
    manager->taskMap_["task1"] = taskInfo;

    manager->NotifyStatusChange("unknown", AVDownloadTaskState::RUNNING);
    EXPECT_EQ(taskInfo->state, AVDownloadTaskState::INIT);
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

HWTEST_F(AVDownloaderManagerTest, NotifyProgressChange_TaskNotInMap_CallbackOnly_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto callback = std::make_shared<MockAVDownloaderManagerCallback>();
    (void)manager->SetManagerCallback(callback);
    EXPECT_CALL(*callback, OnProgressChange("unknown", 50.0)).Times(1);
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = "task1";
    taskInfo->progress = 0.0;
    manager->taskMap_["task1"] = taskInfo;

    manager->NotifyProgressChange("unknown", 50.0);
    EXPECT_DOUBLE_EQ(taskInfo->progress, 0.0);
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

HWTEST_F(AVDownloaderManagerTest, IsNetworkAllowDownload_CellularAllowed_CellType_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    (void)manager->SetAllowCellularAccess(true);
    EXPECT_TRUE(manager->TestIsNetworkAllowDownload(MediaSourceUtils::NetConnType::NET_CONN_CELLULAR));
}

HWTEST_F(AVDownloaderManagerTest, IsNetworkAllowDownload_CellularAllowed_WifiType_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    (void)manager->SetAllowCellularAccess(true);
    EXPECT_TRUE(manager->TestIsNetworkAllowDownload(MediaSourceUtils::NetConnType::NET_CONN_WIFI));
}

HWTEST_F(AVDownloaderManagerTest, IsNetworkAllowDownload_CellularNotAllowed_CellType_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    (void)manager->SetAllowCellularAccess(false);
    EXPECT_FALSE(manager->TestIsNetworkAllowDownload(MediaSourceUtils::NetConnType::NET_CONN_CELLULAR));
}

HWTEST_F(AVDownloaderManagerTest, IsNetworkAllowDownload_CellularNotAllowed_BluetoothType_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    (void)manager->SetAllowCellularAccess(false);
    EXPECT_FALSE(manager->TestIsNetworkAllowDownload(MediaSourceUtils::NetConnType::NET_CONN_BLUETOOTH));
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

HWTEST_F(AVDownloaderManagerTest, NotifyStatusChangeLocked_TaskNotInMap_CallbackOnly_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto callback = std::make_shared<MockAVDownloaderManagerCallback>();
    (void)manager->SetManagerCallback(callback);
    EXPECT_CALL(*callback, OnStatusChange("unknown", AVDownloadTaskState::COMPLETED)).Times(1);
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = "task1";
    taskInfo->state = AVDownloadTaskState::INIT;
    manager->taskMap_["task1"] = taskInfo;

    manager->NotifyStatusChangeLocked("unknown", AVDownloadTaskState::COMPLETED);
    EXPECT_EQ(taskInfo->state, AVDownloadTaskState::INIT);
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

HWTEST_F(AVDownloaderManagerTest, NotifyProgressChangeLocked_TaskNotInMap_CallbackOnly_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto callback = std::make_shared<MockAVDownloaderManagerCallback>();
    (void)manager->SetManagerCallback(callback);
    EXPECT_CALL(*callback, OnProgressChange("unknown", 12.0)).Times(1);
    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = "task1";
    taskInfo->progress = 0.0;
    manager->taskMap_["task1"] = taskInfo;

    manager->NotifyProgressChangeLocked("unknown", 12.0);
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

} // namespace Media
} // namespace OHOS
