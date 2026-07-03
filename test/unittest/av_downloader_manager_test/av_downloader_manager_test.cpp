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

using namespace testing;
using namespace testing::Ext;

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
    EXPECT_EQ(result, AVDownloadTaskState::INIT);
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
    EXPECT_EQ(result, -1);
}

HWTEST_F(AVDownloaderManagerTest, PauseDownloadTask_NoTask_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto result = manager->PauseDownloadTask("nonexistent");
    EXPECT_EQ(result, -1);
}

HWTEST_F(AVDownloaderManagerTest, ResumeDownloadTask_NoTask_001, TestSize.Level0)
{
    auto manager = std::make_shared<AVDownloaderManagerImpl>();
    ASSERT_NE(manager, nullptr);
    auto result = manager->ResumeDownloadTask("nonexistent");
    EXPECT_EQ(result, -1);
}

HWTEST_F(AVDownloaderManagerTest, ResumeDownloadTask_NetworkNotAllow_None_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    manager->simulatedNetworkType_ = MediaSourceUtils::NetConnType::NET_CONN_NONE;

    auto mockDownloader = std::make_shared<MockDownloader>();
    EXPECT_CALL(*mockDownloader, Resume()).Times(0);
    std::string taskId = "test_task_network_none";
    manager->downloaderMap_[taskId] = mockDownloader;

    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = taskId;
    taskInfo->state = AVDownloadTaskState::PAUSED;
    manager->taskMap_[taskId] = taskInfo;

    auto result = manager->ResumeDownloadTask(taskId);
    EXPECT_EQ(result, MSERR_IO_NETWORK_UNAVAILABLE);

    manager->downloaderMap_.erase(taskId);
    manager->taskMap_.erase(taskId);
}

HWTEST_F(AVDownloaderManagerTest, ResumeDownloadTask_NetworkNotAllow_Unknown_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    manager->simulatedNetworkType_ = MediaSourceUtils::NetConnType::NET_CONN_UNKNOWN;

    auto mockDownloader = std::make_shared<MockDownloader>();
    EXPECT_CALL(*mockDownloader, Resume()).Times(0);
    std::string taskId = "test_task_network_unknown";
    manager->downloaderMap_[taskId] = mockDownloader;

    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = taskId;
    taskInfo->state = AVDownloadTaskState::PAUSED;
    manager->taskMap_[taskId] = taskInfo;

    auto result = manager->ResumeDownloadTask(taskId);
    EXPECT_EQ(result, MSERR_IO_NETWORK_UNAVAILABLE);

    manager->downloaderMap_.erase(taskId);
    manager->taskMap_.erase(taskId);
}

HWTEST_F(AVDownloaderManagerTest, ResumeDownloadTask_CellularNotAllowed_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    manager->simulatedNetworkType_ = MediaSourceUtils::NetConnType::NET_CONN_CELLULAR;
    (void)manager->SetAllowCellularAccess(false);

    auto mockDownloader = std::make_shared<MockDownloader>();
    EXPECT_CALL(*mockDownloader, Resume()).Times(0);
    std::string taskId = "test_task_cellular_not_allowed";
    manager->downloaderMap_[taskId] = mockDownloader;

    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = taskId;
    taskInfo->state = AVDownloadTaskState::PAUSED;
    manager->taskMap_[taskId] = taskInfo;

    auto result = manager->ResumeDownloadTask(taskId);
    EXPECT_EQ(result, MSERR_IO_NETWORK_UNAVAILABLE);

    manager->downloaderMap_.erase(taskId);
    manager->taskMap_.erase(taskId);
}

HWTEST_F(AVDownloaderManagerTest, ResumeDownloadTask_CellularAllowed_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    manager->simulatedNetworkType_ = MediaSourceUtils::NetConnType::NET_CONN_CELLULAR;
    (void)manager->SetAllowCellularAccess(true);

    auto mockDownloader = std::make_shared<MockDownloader>();
    EXPECT_CALL(*mockDownloader, Resume()).WillOnce(testing::Return(MSERR_OK));
    std::string taskId = "test_task_cellular_allowed";
    manager->downloaderMap_[taskId] = mockDownloader;

    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = taskId;
    taskInfo->state = AVDownloadTaskState::PAUSED;
    manager->taskMap_[taskId] = taskInfo;

    auto result = manager->ResumeDownloadTask(taskId);
    EXPECT_EQ(result, MSERR_OK);
    EXPECT_EQ(taskInfo->state, AVDownloadTaskState::RUNNING);

    manager->downloaderMap_.erase(taskId);
    manager->taskMap_.erase(taskId);
}

HWTEST_F(AVDownloaderManagerTest, ResumeDownloadTask_Wifi_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    manager->simulatedNetworkType_ = MediaSourceUtils::NetConnType::NET_CONN_WIFI;

    auto mockDownloader = std::make_shared<MockDownloader>();
    EXPECT_CALL(*mockDownloader, Resume()).WillOnce(testing::Return(MSERR_OK));
    std::string taskId = "test_task_wifi";
    manager->downloaderMap_[taskId] = mockDownloader;

    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = taskId;
    taskInfo->state = AVDownloadTaskState::PAUSED;
    manager->taskMap_[taskId] = taskInfo;

    auto result = manager->ResumeDownloadTask(taskId);
    EXPECT_EQ(result, MSERR_OK);
    EXPECT_EQ(taskInfo->state, AVDownloadTaskState::RUNNING);

    manager->downloaderMap_.erase(taskId);
    manager->taskMap_.erase(taskId);
}

HWTEST_F(AVDownloaderManagerTest, ResumeDownloadTask_Bluetooth_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    manager->simulatedNetworkType_ = MediaSourceUtils::NetConnType::NET_CONN_BLUETOOTH;

    auto mockDownloader = std::make_shared<MockDownloader>();
    EXPECT_CALL(*mockDownloader, Resume()).Times(0);
    std::string taskId = "test_task_bluetooth";
    manager->downloaderMap_[taskId] = mockDownloader;

    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = taskId;
    taskInfo->state = AVDownloadTaskState::PAUSED;
    manager->taskMap_[taskId] = taskInfo;

    auto result = manager->ResumeDownloadTask(taskId);
    EXPECT_EQ(result, MSERR_IO_NETWORK_UNAVAILABLE);

    manager->downloaderMap_.erase(taskId);
    manager->taskMap_.erase(taskId);
}

HWTEST_F(AVDownloaderManagerTest, ResumeDownloadTask_Ethernet_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    manager->simulatedNetworkType_ = MediaSourceUtils::NetConnType::NET_CONN_ETHERNET;

    auto mockDownloader = std::make_shared<MockDownloader>();
    EXPECT_CALL(*mockDownloader, Resume()).Times(0);
    std::string taskId = "test_task_ethernet";
    manager->downloaderMap_[taskId] = mockDownloader;

    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = taskId;
    taskInfo->state = AVDownloadTaskState::PAUSED;
    manager->taskMap_[taskId] = taskInfo;

    auto result = manager->ResumeDownloadTask(taskId);
    EXPECT_EQ(result, MSERR_IO_NETWORK_UNAVAILABLE);

    manager->downloaderMap_.erase(taskId);
    manager->taskMap_.erase(taskId);
}

HWTEST_F(AVDownloaderManagerTest, ResumeDownloadTask_Vpn_001, TestSize.Level0)
{
    auto manager = std::make_shared<TestableAVDownloaderManager>();
    ASSERT_NE(manager, nullptr);
    manager->simulatedNetworkType_ = MediaSourceUtils::NetConnType::NET_CONN_VPN;

    auto mockDownloader = std::make_shared<MockDownloader>();
    EXPECT_CALL(*mockDownloader, Resume()).Times(0);
    std::string taskId = "test_task_vpn";
    manager->downloaderMap_[taskId] = mockDownloader;

    auto taskInfo = std::make_shared<AVDownloadTaskInfo>();
    taskInfo->taskId = taskId;
    taskInfo->state = AVDownloadTaskState::PAUSED;
    manager->taskMap_[taskId] = taskInfo;

    auto result = manager->ResumeDownloadTask(taskId);
    EXPECT_EQ(result, MSERR_IO_NETWORK_UNAVAILABLE);

    manager->downloaderMap_.erase(taskId);
    manager->taskMap_.erase(taskId);
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
    auto state = AVDownloaderManagerImpl::ConvertToAVDownloadTaskState(MediaDownload::DownloadState::IDLE);
    EXPECT_EQ(state, AVDownloadTaskState::INIT);
}

HWTEST_F(AVDownloaderManagerTest, ConvertToAVDownloadTaskState_RUNNING_001, TestSize.Level0)
{
    auto state = AVDownloaderManagerImpl::ConvertToAVDownloadTaskState(MediaDownload::DownloadState::RUNNING);
    EXPECT_EQ(state, AVDownloadTaskState::RUNNING);
}

HWTEST_F(AVDownloaderManagerTest, ConvertToAVDownloadTaskState_PAUSED_001, TestSize.Level0)
{
    auto state = AVDownloaderManagerImpl::ConvertToAVDownloadTaskState(MediaDownload::DownloadState::PAUSED);
    EXPECT_EQ(state, AVDownloadTaskState::PAUSED);
}

HWTEST_F(AVDownloaderManagerTest, ConvertToAVDownloadTaskState_COMPLETED_001, TestSize.Level0)
{
    auto state = AVDownloaderManagerImpl::ConvertToAVDownloadTaskState(MediaDownload::DownloadState::COMPLETED);
    EXPECT_EQ(state, AVDownloadTaskState::COMPLETED);
}

HWTEST_F(AVDownloaderManagerTest, ConvertToAVDownloadTaskState_ERROR_001, TestSize.Level0)
{
    auto state = AVDownloaderManagerImpl::ConvertToAVDownloadTaskState(MediaDownload::DownloadState::FAILED);
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

} // namespace Media
} // namespace OHOS
