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

#include "avdownloader_manager_napi_test.h"
#include "avdownloader_manager_napi.cpp"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {

class AVDownloaderManagerNapiTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void)
    {
        mockDownloaderManager_ = std::make_shared<MockAVDownloaderManager>();
    }
    void TearDown(void)
    {
        mockDownloaderManager_ = nullptr;
    }

protected:
    std::shared_ptr<MockAVDownloaderManager> mockDownloaderManager_;
};

HWTEST_F(AVDownloaderManagerNapiTest, CreateAVDownloaderManager_001, TestSize.Level0)
{
    EXPECT_NE(mockDownloaderManager_, nullptr);
}

HWTEST_F(AVDownloaderManagerNapiTest, CreateAVDownloaderManager_ReturnsValidObject_001, TestSize.Level0)
{
    EXPECT_CALL(*mockDownloaderManager_, SetAllowCellularAccess(_)).WillOnce(Return(0));
    EXPECT_CALL(*mockDownloaderManager_, SetRequestTimeout(_)).WillOnce(Return(0));

    auto result = mockDownloaderManager_->SetAllowCellularAccess(true);
    EXPECT_EQ(result, 0);

    result = mockDownloaderManager_->SetRequestTimeout(30000);
    EXPECT_EQ(result, 0);
}

HWTEST_F(AVDownloaderManagerNapiTest, AllowsCellularAccess_True_001, TestSize.Level0)
{
    EXPECT_CALL(*mockDownloaderManager_, SetAllowCellularAccess(true)).WillOnce(Return(0));
    auto result = mockDownloaderManager_->SetAllowCellularAccess(true);
    EXPECT_EQ(result, 0);
}

HWTEST_F(AVDownloaderManagerNapiTest, AllowsCellularAccess_False_001, TestSize.Level0)
{
    EXPECT_CALL(*mockDownloaderManager_, SetAllowCellularAccess(false)).WillOnce(Return(0));
    auto result = mockDownloaderManager_->SetAllowCellularAccess(false);
    EXPECT_EQ(result, 0);
}

HWTEST_F(AVDownloaderManagerNapiTest, SetRequestTimeout_ValidValue_001, TestSize.Level0)
{
    EXPECT_CALL(*mockDownloaderManager_, SetRequestTimeout(50000)).WillOnce(Return(0));
    auto result = mockDownloaderManager_->SetRequestTimeout(50000);
    EXPECT_EQ(result, 0);
}

HWTEST_F(AVDownloaderManagerNapiTest, SetRequestTimeout_DefaultValue_001, TestSize.Level0)
{
    EXPECT_CALL(*mockDownloaderManager_, SetRequestTimeout(30000)).WillOnce(Return(0));
    auto result = mockDownloaderManager_->SetRequestTimeout(30000);
    EXPECT_EQ(result, 0);
}

HWTEST_F(AVDownloaderManagerNapiTest, GetDownloadTasks_Empty_001, TestSize.Level0)
{
    EXPECT_CALL(*mockDownloaderManager_, GetDownloadTasks()).WillOnce(Return(std::vector<std::string>{}));
    auto result = mockDownloaderManager_->GetDownloadTasks();
    EXPECT_TRUE(result.empty());
}

HWTEST_F(AVDownloaderManagerNapiTest, GetDownloadTasks_WithTasks_001, TestSize.Level0)
{
    std::vector<std::string> taskIds = {"task1", "task2", "task3"};
    EXPECT_CALL(*mockDownloaderManager_, GetDownloadTasks()).WillOnce(Return(taskIds));
    auto result = mockDownloaderManager_->GetDownloadTasks();
    EXPECT_EQ(result.size(), 3);
    EXPECT_EQ(result[0], "task1");
    EXPECT_EQ(result[1], "task2");
    EXPECT_EQ(result[2], "task3");
}

HWTEST_F(AVDownloaderManagerNapiTest, GetTaskCacheDirectory_ValidTaskId_001, TestSize.Level0)
{
    std::string taskId = "task1";
    std::string cacheDir = "/data/cache/task1";
    EXPECT_CALL(*mockDownloaderManager_, GetTaskCacheDirectory(taskId)).WillOnce(Return(cacheDir));
    auto result = mockDownloaderManager_->GetTaskCacheDirectory(taskId);
    EXPECT_EQ(result, cacheDir);
}

HWTEST_F(AVDownloaderManagerNapiTest, GetTaskCacheDirectory_InvalidTaskId_001, TestSize.Level0)
{
    std::string taskId = "nonexistent";
    EXPECT_CALL(*mockDownloaderManager_, GetTaskCacheDirectory(taskId)).WillOnce(Return(""));
    auto result = mockDownloaderManager_->GetTaskCacheDirectory(taskId);
    EXPECT_EQ(result, "");
}

HWTEST_F(AVDownloaderManagerNapiTest, GetTaskStatus_Init_001, TestSize.Level0)
{
    std::string taskId = "task1";
    EXPECT_CALL(*mockDownloaderManager_, GetTaskStatus(taskId)).WillOnce(Return(AVDownloadTaskState::INIT));
    auto result = mockDownloaderManager_->GetTaskStatus(taskId);
    EXPECT_EQ(result, AVDownloadTaskState::INIT);
}

HWTEST_F(AVDownloaderManagerNapiTest, GetTaskStatus_Running_001, TestSize.Level0)
{
    std::string taskId = "task1";
    EXPECT_CALL(*mockDownloaderManager_, GetTaskStatus(taskId)).WillOnce(Return(AVDownloadTaskState::RUNNING));
    auto result = mockDownloaderManager_->GetTaskStatus(taskId);
    EXPECT_EQ(result, AVDownloadTaskState::RUNNING);
}

HWTEST_F(AVDownloaderManagerNapiTest, GetTaskStatus_Paused_001, TestSize.Level0)
{
    std::string taskId = "task1";
    EXPECT_CALL(*mockDownloaderManager_, GetTaskStatus(taskId)).WillOnce(Return(AVDownloadTaskState::PAUSED));
    auto result = mockDownloaderManager_->GetTaskStatus(taskId);
    EXPECT_EQ(result, AVDownloadTaskState::PAUSED);
}

HWTEST_F(AVDownloaderManagerNapiTest, GetTaskStatus_Completed_001, TestSize.Level0)
{
    std::string taskId = "task1";
    EXPECT_CALL(*mockDownloaderManager_, GetTaskStatus(taskId)).WillOnce(Return(AVDownloadTaskState::COMPLETED));
    auto result = mockDownloaderManager_->GetTaskStatus(taskId);
    EXPECT_EQ(result, AVDownloadTaskState::COMPLETED);
}

HWTEST_F(AVDownloaderManagerNapiTest, GetTaskStatus_Error_001, TestSize.Level0)
{
    std::string taskId = "task1";
    EXPECT_CALL(*mockDownloaderManager_, GetTaskStatus(taskId)).WillOnce(Return(AVDownloadTaskState::ERROR));
    auto result = mockDownloaderManager_->GetTaskStatus(taskId);
    EXPECT_EQ(result, AVDownloadTaskState::ERROR);
}

HWTEST_F(AVDownloaderManagerNapiTest, GetTaskProgress_ValidTaskId_001, TestSize.Level0)
{
    std::string taskId = "task1";
    EXPECT_CALL(*mockDownloaderManager_, GetTaskProgress(taskId)).WillOnce(Return(50.5));
    auto result = mockDownloaderManager_->GetTaskProgress(taskId);
    EXPECT_EQ(result, 50.5);
}

HWTEST_F(AVDownloaderManagerNapiTest, GetTaskProgress_InvalidTaskId_001, TestSize.Level0)
{
    std::string taskId = "nonexistent";
    EXPECT_CALL(*mockDownloaderManager_, GetTaskProgress(taskId)).WillOnce(Return(0.0));
    auto result = mockDownloaderManager_->GetTaskProgress(taskId);
    EXPECT_EQ(result, 0.0);
}

HWTEST_F(AVDownloaderManagerNapiTest, RemoveDownloadTask_ByTaskId_001, TestSize.Level0)
{
    std::string taskId = "task1";
    EXPECT_CALL(*mockDownloaderManager_, RemoveDownloadTask(taskId)).WillOnce(Return(0));
    auto result = mockDownloaderManager_->RemoveDownloadTask(taskId);
    EXPECT_EQ(result, 0);
}

HWTEST_F(AVDownloaderManagerNapiTest, PauseDownloadTask_ValidTaskId_001, TestSize.Level0)
{
    std::string taskId = "task1";
    EXPECT_CALL(*mockDownloaderManager_, PauseDownloadTask(taskId)).WillOnce(Return(0));
    auto result = mockDownloaderManager_->PauseDownloadTask(taskId);
    EXPECT_EQ(result, 0);
}

HWTEST_F(AVDownloaderManagerNapiTest, ResumeDownloadTask_ValidTaskId_001, TestSize.Level0)
{
    std::string taskId = "task1";
    EXPECT_CALL(*mockDownloaderManager_, ResumeDownloadTask(taskId)).WillOnce(Return(0));
    auto result = mockDownloaderManager_->ResumeDownloadTask(taskId);
    EXPECT_EQ(result, 0);
}

HWTEST_F(AVDownloaderManagerNapiTest, Release_001, TestSize.Level0)
{
    EXPECT_CALL(*mockDownloaderManager_, Release()).WillOnce(Return(0));
    auto result = mockDownloaderManager_->Release();
    EXPECT_EQ(result, 0);
}

HWTEST_F(AVDownloaderManagerNapiTest, AVDownloadTaskState_Values_001, TestSize.Level0)
{
    EXPECT_EQ(static_cast<int32_t>(AVDownloadTaskState::INIT), 0);
    EXPECT_EQ(static_cast<int32_t>(AVDownloadTaskState::QUEUED), 1);
    EXPECT_EQ(static_cast<int32_t>(AVDownloadTaskState::RUNNING), 2);
    EXPECT_EQ(static_cast<int32_t>(AVDownloadTaskState::COMPLETED), 3);
    EXPECT_EQ(static_cast<int32_t>(AVDownloadTaskState::PAUSED), 4);
    EXPECT_EQ(static_cast<int32_t>(AVDownloadTaskState::REMOVING), 5);
    EXPECT_EQ(static_cast<int32_t>(AVDownloadTaskState::ERROR), 6);
}

HWTEST_F(AVDownloaderManagerNapiTest, SetManagerCallback_001, TestSize.Level0)
{
    std::weak_ptr<AVDownloaderManagerCallback> callback;
    EXPECT_CALL(*mockDownloaderManager_, SetManagerCallback(_)).WillOnce(Return(0));
    auto result = mockDownloaderManager_->SetManagerCallback(callback);
    EXPECT_EQ(result, 0);
}

HWTEST_F(AVDownloaderManagerNapiTest, MultipleTaskOperations_001, TestSize.Level0)
{
    std::vector<std::string> taskIds = {"task1", "task2"};
    EXPECT_CALL(*mockDownloaderManager_, GetDownloadTasks()).WillOnce(Return(taskIds));
    EXPECT_CALL(*mockDownloaderManager_, GetTaskStatus("task1")).WillOnce(Return(AVDownloadTaskState::RUNNING));
    EXPECT_CALL(*mockDownloaderManager_, GetTaskStatus("task2")).WillOnce(Return(AVDownloadTaskState::PAUSED));
    EXPECT_CALL(*mockDownloaderManager_, GetTaskProgress("task1")).WillOnce(Return(75.0));
    EXPECT_CALL(*mockDownloaderManager_, GetTaskProgress("task2")).WillOnce(Return(30.0));

    auto tasks = mockDownloaderManager_->GetDownloadTasks();
    EXPECT_EQ(tasks.size(), 2);

    auto status1 = mockDownloaderManager_->GetTaskStatus("task1");
    EXPECT_EQ(status1, AVDownloadTaskState::RUNNING);

    auto status2 = mockDownloaderManager_->GetTaskStatus("task2");
    EXPECT_EQ(status2, AVDownloadTaskState::PAUSED);

    auto progress1 = mockDownloaderManager_->GetTaskProgress("task1");
    EXPECT_EQ(progress1, 75.0);

    auto progress2 = mockDownloaderManager_->GetTaskProgress("task2");
    EXPECT_EQ(progress2, 30.0);
}

HWTEST_F(AVDownloaderManagerNapiTest, TaskStateTransition_001, TestSize.Level0)
{
    std::string taskId = "task1";

    EXPECT_CALL(*mockDownloaderManager_, GetTaskStatus(taskId)).WillOnce(Return(AVDownloadTaskState::INIT));
    EXPECT_CALL(*mockDownloaderManager_, PauseDownloadTask(taskId)).WillOnce(Return(0));
    EXPECT_CALL(*mockDownloaderManager_, GetTaskStatus(taskId)).WillOnce(Return(AVDownloadTaskState::PAUSED));
    EXPECT_CALL(*mockDownloaderManager_, ResumeDownloadTask(taskId)).WillOnce(Return(0));
    EXPECT_CALL(*mockDownloaderManager_, GetTaskStatus(taskId)).WillOnce(Return(AVDownloadTaskState::RUNNING));

    EXPECT_EQ(mockDownloaderManager_->GetTaskStatus(taskId), AVDownloadTaskState::INIT);
    mockDownloaderManager_->PauseDownloadTask(taskId);
    EXPECT_EQ(mockDownloaderManager_->GetTaskStatus(taskId), AVDownloadTaskState::PAUSED);
    mockDownloaderManager_->ResumeDownloadTask(taskId);
    EXPECT_EQ(mockDownloaderManager_->GetTaskStatus(taskId), AVDownloadTaskState::RUNNING);
}

} // namespace Media
} // namespace OHOS
