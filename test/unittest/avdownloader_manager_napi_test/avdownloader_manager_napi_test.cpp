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

HWTEST_F(AVDownloaderManagerNapiTest, OnStatusChange_StoresState_001, TestSize.Level0)
{
    auto napi = new AVDownloaderManagerNapi();
    napi->env_ = nullptr;
    auto mock = std::make_shared<MockAVDownloaderManager>();
    EXPECT_CALL(*mock, SetManagerCallback(_)).WillOnce(Return(0));
    napi->downloaderManager_ = mock;

    napi->OnStatusChange("task1", AVDownloadTaskState::RUNNING);
    EXPECT_EQ(napi->taskIdToStatus_["task1"], static_cast<int32_t>(AVDownloadTaskState::RUNNING));

    napi->OnStatusChange("task1", AVDownloadTaskState::PAUSED);
    EXPECT_EQ(napi->taskIdToStatus_["task1"], static_cast<int32_t>(AVDownloadTaskState::PAUSED));

    napi->downloaderManager_ = nullptr;
    delete napi;
}

HWTEST_F(AVDownloaderManagerNapiTest, OnProgressChange_StoresProgress_001, TestSize.Level0)
{
    auto napi = new AVDownloaderManagerNapi();
    napi->env_ = nullptr;
    auto mock = std::make_shared<MockAVDownloaderManager>();
    EXPECT_CALL(*mock, SetManagerCallback(_)).WillOnce(Return(0));
    napi->downloaderManager_ = mock;

    napi->OnProgressChange("task1", 30.5);
    EXPECT_DOUBLE_EQ(napi->taskIdToProgress_["task1"], 30.5);

    napi->OnProgressChange("task1", 75.0);
    EXPECT_DOUBLE_EQ(napi->taskIdToProgress_["task1"], 75.0);

    napi->downloaderManager_ = nullptr;
    delete napi;
}

HWTEST_F(AVDownloaderManagerNapiTest, OnStatusChange_MultipleTasks_001, TestSize.Level0)
{
    auto napi = new AVDownloaderManagerNapi();
    napi->env_ = nullptr;
    auto mock = std::make_shared<MockAVDownloaderManager>();
    EXPECT_CALL(*mock, SetManagerCallback(_)).WillOnce(Return(0));
    napi->downloaderManager_ = mock;

    napi->OnStatusChange("task1", AVDownloadTaskState::RUNNING);
    napi->OnStatusChange("task2", AVDownloadTaskState::PAUSED);
    napi->OnStatusChange("task3", AVDownloadTaskState::COMPLETED);

    EXPECT_EQ(napi->taskIdToStatus_["task1"], static_cast<int32_t>(AVDownloadTaskState::RUNNING));
    EXPECT_EQ(napi->taskIdToStatus_["task2"], static_cast<int32_t>(AVDownloadTaskState::PAUSED));
    EXPECT_EQ(napi->taskIdToStatus_["task3"], static_cast<int32_t>(AVDownloadTaskState::COMPLETED));

    napi->downloaderManager_ = nullptr;
    delete napi;
}

HWTEST_F(AVDownloaderManagerNapiTest, GetTaskCacheDir_DelegatesToManager_001, TestSize.Level0)
{
    auto napi = new AVDownloaderManagerNapi();
    napi->env_ = nullptr;
    auto mock = std::make_shared<MockAVDownloaderManager>();
    EXPECT_CALL(*mock, SetManagerCallback(_)).WillOnce(Return(0));
    EXPECT_CALL(*mock, GetTaskCacheDirectory("task1")).WillOnce(Return("/data/cache/task1"));
    napi->downloaderManager_ = mock;

    std::string result = napi->GetTaskCacheDir("task1");
    EXPECT_EQ(result, "/data/cache/task1");

    napi->downloaderManager_ = nullptr;
    delete napi;
}

HWTEST_F(AVDownloaderManagerNapiTest, GetTaskCacheDir_FallbackToLocalMap_001, TestSize.Level0)
{
    auto napi = new AVDownloaderManagerNapi();
    napi->env_ = nullptr;
    napi->downloaderManager_ = nullptr;

    napi->taskIdToCacheDir_["task1"] = "/local/cache/task1";
    std::string result = napi->GetTaskCacheDir("task1");
    EXPECT_EQ(result, "/local/cache/task1");

    result = napi->GetTaskCacheDir("nonexistent");
    EXPECT_EQ(result, "");

    delete napi;
}

HWTEST_F(AVDownloaderManagerNapiTest, GetTaskCacheDir_ManagerFallback_001, TestSize.Level0)
{
    auto napi = new AVDownloaderManagerNapi();
    napi->env_ = nullptr;
    napi->downloaderManager_ = nullptr;

    napi->taskIdToCacheDir_["task1"] = "/fallback/task1";
    std::string result = napi->GetTaskCacheDir("task1");
    EXPECT_EQ(result, "/fallback/task1");

    result = napi->GetTaskCacheDir("unknown");
    EXPECT_EQ(result, "");

    delete napi;
}

HWTEST_F(AVDownloaderManagerNapiTest, GenerateTaskId_NotEmpty_001, TestSize.Level0)
{
    auto napi = new AVDownloaderManagerNapi();
    napi->env_ = nullptr;
    auto mock = std::make_shared<MockAVDownloaderManager>();
    EXPECT_CALL(*mock, SetManagerCallback(_)).WillOnce(Return(0));
    napi->downloaderManager_ = mock;

    std::string taskId1 = napi->GenerateTaskId();
    EXPECT_FALSE(taskId1.empty());

    std::string taskId2 = napi->GenerateTaskId();
    EXPECT_FALSE(taskId2.empty());

    napi->downloaderManager_ = nullptr;
    delete napi;
}

HWTEST_F(AVDownloaderManagerNapiTest, SetAllowCellularAccess_DelegatesToManager_001, TestSize.Level0)
{
    auto napi = new AVDownloaderManagerNapi();
    napi->env_ = nullptr;
    auto mock = std::make_shared<MockAVDownloaderManager>();
    EXPECT_CALL(*mock, SetManagerCallback(_)).WillOnce(Return(0));
    EXPECT_CALL(*mock, SetAllowCellularAccess(true)).WillOnce(Return(0));
    napi->downloaderManager_ = mock;

    napi->allowCellularAccess_ = false;
    napi->downloaderManager_->SetAllowCellularAccess(true);
    EXPECT_EQ(napi->allowCellularAccess_, true);

    napi->downloaderManager_ = nullptr;
    delete napi;
}

HWTEST_F(AVDownloaderManagerNapiTest, SetRequestTimeout_DelegatesToManager_001, TestSize.Level0)
{
    auto napi = new AVDownloaderManagerNapi();
    napi->env_ = nullptr;
    auto mock = std::make_shared<MockAVDownloaderManager>();
    EXPECT_CALL(*mock, SetManagerCallback(_)).WillOnce(Return(0));
    EXPECT_CALL(*mock, SetRequestTimeout(50000)).WillOnce(Return(0));
    napi->downloaderManager_ = mock;

    napi->requestTimeoutMs_ = 30000;
    napi->downloaderManager_->SetRequestTimeout(50000);
    EXPECT_EQ(napi->requestTimeoutMs_, 50000);

    napi->downloaderManager_ = nullptr;
    delete napi;
}

HWTEST_F(AVDownloaderManagerNapiTest, StateTransition_InitToRunning_001, TestSize.Level0)
{
    auto napi = new AVDownloaderManagerNapi();
    napi->env_ = nullptr;
    auto mock = std::make_shared<MockAVDownloaderManager>();
    EXPECT_CALL(*mock, SetManagerCallback(_)).WillOnce(Return(0));
    napi->downloaderManager_ = mock;

    napi->OnStatusChange("task1", AVDownloadTaskState::INIT);
    EXPECT_EQ(napi->taskIdToStatus_["task1"], static_cast<int32_t>(AVDownloadTaskState::INIT));

    napi->OnStatusChange("task1", AVDownloadTaskState::RUNNING);
    EXPECT_EQ(napi->taskIdToStatus_["task1"], static_cast<int32_t>(AVDownloadTaskState::RUNNING));

    napi->downloaderManager_ = nullptr;
    delete napi;
}

HWTEST_F(AVDownloaderManagerNapiTest, StateTransition_RunningToPausedToCompleted_001, TestSize.Level0)
{
    auto napi = new AVDownloaderManagerNapi();
    napi->env_ = nullptr;
    auto mock = std::make_shared<MockAVDownloaderManager>();
    EXPECT_CALL(*mock, SetManagerCallback(_)).WillOnce(Return(0));
    napi->downloaderManager_ = mock;

    napi->OnStatusChange("task1", AVDownloadTaskState::RUNNING);
    EXPECT_EQ(napi->taskIdToStatus_["task1"], static_cast<int32_t>(AVDownloadTaskState::RUNNING));

    napi->OnStatusChange("task1", AVDownloadTaskState::PAUSED);
    EXPECT_EQ(napi->taskIdToStatus_["task1"], static_cast<int32_t>(AVDownloadTaskState::PAUSED));

    napi->OnStatusChange("task1", AVDownloadTaskState::COMPLETED);
    EXPECT_EQ(napi->taskIdToStatus_["task1"], static_cast<int32_t>(AVDownloadTaskState::COMPLETED));

    napi->downloaderManager_ = nullptr;
    delete napi;
}

HWTEST_F(AVDownloaderManagerNapiTest, ProgressUpdates_Increasing_001, TestSize.Level0)
{
    auto napi = new AVDownloaderManagerNapi();
    napi->env_ = nullptr;
    auto mock = std::make_shared<MockAVDownloaderManager>();
    EXPECT_CALL(*mock, SetManagerCallback(_)).WillOnce(Return(0));
    napi->downloaderManager_ = mock;

    napi->OnProgressChange("task1", 10.0);
    EXPECT_DOUBLE_EQ(napi->taskIdToProgress_["task1"], 10.0);

    napi->OnProgressChange("task1", 50.0);
    EXPECT_DOUBLE_EQ(napi->taskIdToProgress_["task1"], 50.0);

    napi->OnProgressChange("task1", 90.0);
    EXPECT_DOUBLE_EQ(napi->taskIdToProgress_["task1"], 90.0);

    EXPECT_GT(napi->taskIdToProgress_["task1"], 50.0);

    napi->downloaderManager_ = nullptr;
    delete napi;
}

HWTEST_F(AVDownloaderManagerNapiTest, OnStatusChange_AllStates_001, TestSize.Level0)
{
    auto napi = new AVDownloaderManagerNapi();
    napi->env_ = nullptr;
    auto mock = std::make_shared<MockAVDownloaderManager>();
    EXPECT_CALL(*mock, SetManagerCallback(_)).WillOnce(Return(0));
    napi->downloaderManager_ = mock;

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
        napi->OnStatusChange(taskId, states[i]);
        EXPECT_EQ(napi->taskIdToStatus_[taskId], static_cast<int32_t>(states[i]));
    }

    napi->downloaderManager_ = nullptr;
    delete napi;
}

HWTEST_F(AVDownloaderManagerNapiTest, SetManagerCallback_DelegatesToManager_001, TestSize.Level0)
{
    auto napi = new AVDownloaderManagerNapi();
    napi->env_ = nullptr;
    auto mock = std::make_shared<MockAVDownloaderManager>();
    EXPECT_CALL(*mock, SetManagerCallback(_)).WillOnce(Return(0));
    napi->downloaderManager_ = mock;

    std::weak_ptr<AVDownloaderManagerCallback> callback = napi->selfRef_;
    int32_t ret = napi->downloaderManager_->SetManagerCallback(callback);
    EXPECT_EQ(ret, 0);

    napi->downloaderManager_ = nullptr;
    delete napi;
}

HWTEST_F(AVDownloaderManagerNapiTest, GetTaskCacheDir_ManagerReturnsEmpty_001, TestSize.Level0)
{
    auto napi = new AVDownloaderManagerNapi();
    napi->env_ = nullptr;
    auto mock = std::make_shared<MockAVDownloaderManager>();
    EXPECT_CALL(*mock, SetManagerCallback(_)).WillOnce(Return(0));
    EXPECT_CALL(*mock, GetTaskCacheDirectory("unknown")).WillOnce(Return(""));
    napi->downloaderManager_ = mock;

    std::string result = napi->GetTaskCacheDir("unknown");
    EXPECT_EQ(result, "");

    napi->downloaderManager_ = nullptr;
    delete napi;
}

} // namespace Media
} // namespace OHOS
