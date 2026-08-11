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

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {

HWTEST_F(AVDownloaderManagerNapiTest, SetManagerCallback_001, TestSize.Level0)
{
    mockManager_ = std::make_shared<MockAVDownloaderManager>();
    callback_ = std::make_shared<TestCallback>();
    auto weakCb = std::weak_ptr<AVDownloaderManagerCallback>(callback_);
    EXPECT_CALL(*mockManager_, SetManagerCallback(_)).WillOnce(Return(0));
    int32_t ret = mockManager_->SetManagerCallback(weakCb);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AVDownloaderManagerNapiTest, SetAllowCellularAccess_001, TestSize.Level0)
{
    mockManager_ = std::make_shared<MockAVDownloaderManager>();
    EXPECT_CALL(*mockManager_, SetAllowCellularAccess(true)).WillOnce(Return(0));
    int32_t ret = mockManager_->SetAllowCellularAccess(true);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AVDownloaderManagerNapiTest, SetAllowCellularAccess_False_001, TestSize.Level0)
{
    mockManager_ = std::make_shared<MockAVDownloaderManager>();
    EXPECT_CALL(*mockManager_, SetAllowCellularAccess(false)).WillOnce(Return(0));
    int32_t ret = mockManager_->SetAllowCellularAccess(false);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AVDownloaderManagerNapiTest, SetRequestTimeout_001, TestSize.Level0)
{
    mockManager_ = std::make_shared<MockAVDownloaderManager>();
    EXPECT_CALL(*mockManager_, SetRequestTimeout(50000)).WillOnce(Return(0));
    int32_t ret = mockManager_->SetRequestTimeout(50000);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AVDownloaderManagerNapiTest, AddDownloadTask_001, TestSize.Level0)
{
    mockManager_ = std::make_shared<MockAVDownloaderManager>();
    EXPECT_CALL(*mockManager_, AddDownloadTask(_)).WillOnce(Return("task-001"));
    std::string taskId = mockManager_->AddDownloadTask(nullptr);
    EXPECT_EQ(taskId, "task-001");
}

HWTEST_F(AVDownloaderManagerNapiTest, RemoveDownloadTask_001, TestSize.Level0)
{
    mockManager_ = std::make_shared<MockAVDownloaderManager>();
    EXPECT_CALL(*mockManager_, RemoveDownloadTask("task-001")).WillOnce(Return(0));
    int32_t ret = mockManager_->RemoveDownloadTask("task-001");
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AVDownloaderManagerNapiTest, PauseDownloadTask_001, TestSize.Level0)
{
    mockManager_ = std::make_shared<MockAVDownloaderManager>();
    EXPECT_CALL(*mockManager_, PauseDownloadTask("task-001")).WillOnce(Return(0));
    int32_t ret = mockManager_->PauseDownloadTask("task-001");
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AVDownloaderManagerNapiTest, ResumeDownloadTask_001, TestSize.Level0)
{
    mockManager_ = std::make_shared<MockAVDownloaderManager>();
    EXPECT_CALL(*mockManager_, ResumeDownloadTask("task-001")).WillOnce(Return(0));
    int32_t ret = mockManager_->ResumeDownloadTask("task-001");
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AVDownloaderManagerNapiTest, GetDownloadTasks_001, TestSize.Level0)
{
    mockManager_ = std::make_shared<MockAVDownloaderManager>();
    std::vector<std::string> expected = {"task-001", "task-002"};
    EXPECT_CALL(*mockManager_, GetDownloadTasks()).WillOnce(Return(expected));
    auto tasks = mockManager_->GetDownloadTasks();
    EXPECT_EQ(tasks.size(), 2);
    EXPECT_EQ(tasks[0], "task-001");
}

HWTEST_F(AVDownloaderManagerNapiTest, GetTaskCacheDirectory_001, TestSize.Level0)
{
    mockManager_ = std::make_shared<MockAVDownloaderManager>();
    EXPECT_CALL(*mockManager_, GetTaskCacheDirectory("task-001")).WillOnce(Return("/data/cache/task1"));
    std::string dir = mockManager_->GetTaskCacheDirectory("task-001");
    EXPECT_EQ(dir, "/data/cache/task1");
}

HWTEST_F(AVDownloaderManagerNapiTest, GetTaskStatus_001, TestSize.Level0)
{
    mockManager_ = std::make_shared<MockAVDownloaderManager>();
    EXPECT_CALL(*mockManager_, GetTaskStatus("task-001")).WillOnce(Return(AVDownloadTaskState::RUNNING));
    auto state = mockManager_->GetTaskStatus("task-001");
    EXPECT_EQ(state, AVDownloadTaskState::RUNNING);
}

HWTEST_F(AVDownloaderManagerNapiTest, GetTaskProgress_001, TestSize.Level0)
{
    mockManager_ = std::make_shared<MockAVDownloaderManager>();
    EXPECT_CALL(*mockManager_, GetTaskProgress("task-001")).WillOnce(Return(75.5));
    double progress = mockManager_->GetTaskProgress("task-001");
    EXPECT_DOUBLE_EQ(progress, 75.5);
}

HWTEST_F(AVDownloaderManagerNapiTest, Release_001, TestSize.Level0)
{
    mockManager_ = std::make_shared<MockAVDownloaderManager>();
    EXPECT_CALL(*mockManager_, Release()).WillOnce(Return(0));
    int32_t ret = mockManager_->Release();
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AVDownloaderManagerNapiTest, Callback_OnStatusChange_001, TestSize.Level0)
{
    callback_ = std::make_shared<TestCallback>();
    callback_->OnStatusChange("task-001", AVDownloadTaskState::RUNNING);
    EXPECT_EQ(callback_->lastTaskId_, "task-001");
    EXPECT_EQ(callback_->lastState_, AVDownloadTaskState::RUNNING);
    EXPECT_EQ(callback_->statusCallCount_, 1);
}

HWTEST_F(AVDownloaderManagerNapiTest, Callback_OnProgressChange_001, TestSize.Level0)
{
    callback_ = std::make_shared<TestCallback>();
    callback_->OnProgressChange("task-001", 50.0);
    EXPECT_EQ(callback_->lastTaskId_, "task-001");
    EXPECT_DOUBLE_EQ(callback_->lastProgress_, 50.0);
    EXPECT_EQ(callback_->progressCallCount_, 1);
}

HWTEST_F(AVDownloaderManagerNapiTest, Callback_MultipleStatusChanges_001, TestSize.Level0)
{
    callback_ = std::make_shared<TestCallback>();
    callback_->OnStatusChange("task1", AVDownloadTaskState::INIT);
    callback_->OnStatusChange("task1", AVDownloadTaskState::RUNNING);
    callback_->OnStatusChange("task1", AVDownloadTaskState::PAUSED);
    callback_->OnStatusChange("task1", AVDownloadTaskState::COMPLETED);
    EXPECT_EQ(callback_->lastState_, AVDownloadTaskState::COMPLETED);
    EXPECT_EQ(callback_->statusCallCount_, 4);
}

HWTEST_F(AVDownloaderManagerNapiTest, Callback_ProgressIncreasing_001, TestSize.Level0)
{
    callback_ = std::make_shared<TestCallback>();
    callback_->OnProgressChange("task1", 10.0);
    callback_->OnProgressChange("task1", 50.0);
    callback_->OnProgressChange("task1", 90.0);
    EXPECT_DOUBLE_EQ(callback_->lastProgress_, 90.0);
    EXPECT_EQ(callback_->progressCallCount_, 3);
}

HWTEST_F(AVDownloaderManagerNapiTest, Callback_AllStates_001, TestSize.Level0)
{
    callback_ = std::make_shared<TestCallback>();
    std::vector<AVDownloadTaskState> states = {
        AVDownloadTaskState::INIT,
        AVDownloadTaskState::QUEUED,
        AVDownloadTaskState::RUNNING,
        AVDownloadTaskState::COMPLETED,
        AVDownloadTaskState::PAUSED,
        AVDownloadTaskState::REMOVING,
        AVDownloadTaskState::ERROR,
    };
    for (size_t i = 0; i < states.size(); i++) {
        std::string taskId = "task" + std::to_string(i);
        callback_->OnStatusChange(taskId, states[i]);
        EXPECT_EQ(callback_->lastState_, states[i]);
    }
    EXPECT_EQ(callback_->statusCallCount_, static_cast<int32_t>(states.size()));
}

} // namespace Media
} // namespace OHOS
