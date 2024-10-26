/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "util/task/task_manager.h"

using namespace testing;
using namespace testing::ext;

class TaskManagerTest : public testing::Test {
protected:
    TaskManager* taskManager;
    void SetUp() override
    {
        taskManager = new TaskManager("testTaskManager", TaskManagerTimeOpt::SEQUENTIAL);
    }
    void TearDown() override
    {
        delete taskManager;
        taskManager = nullptr;
    }
};

/**
 * @tc.name   : TaskManager_Submit_ShouldSubmit_WhenFunctionIsValid
 * @tc.number : TaskManagerTest_001
 * @tc.desc   : Test if function is submitted correctly when function is valid
 */
HWTEST_F(TaskManagerTest, TaskManager_Submit_ShouldSubmit_WhenFunctionIsValid, TestSize.Level0)
{
    std::function<void()> func = []() {
        // some function logic
    };
    taskManager->Submit(func, "testFunction");
    EXPECT_GT(taskManager->GetTaskCount(), 0);
}

/**
 * @tc.name   : TaskManager_SubmitH_ShouldSubmitH_WhenFunctionIsValid
 * @tc.number : TaskManagerTest_002
 * @tc.desc   : Test if function is submitted correctly when function is valid
 */
HWTEST_F(TaskManagerTest, TaskManager_SubmitH_ShouldSubmitH_WhenFunctionIsValid, TestSize.Level0)
{
    std::function<void()> func = []() {
        // some function logic
    };
    TaskHandle handle = taskManager->SubmitH(func, "testFunction");
    EXPECT_NE(handle, nullptr);
}

/**
 * @tc.name   : TaskManager_Wait_ShouldWait_WhenTaskHandlesAreValid
 * @tc.number : TaskManagerTest_003
 * @tc.desc   : Test if function is submitted correctly when function is valid
 */
HWTEST_F(TaskManagerTest, TaskManager_Wait_ShouldWait_WhenTaskHandlesAreValid, TestSize.Level0)
{
    std::function<void()> func = []() {
        // some function logic
    };
    std::vector<TaskHandle> taskHandles;
    for (int i = 0; i < 5; i++) {
        taskHandles.push_back(taskManager->SubmitH(func, "testFunction"));
    }
    taskManager->Wait(taskHandles);
    EXPECT_EQ(taskManager->GetTaskCount(), 0);
}

/**
 * @tc.name   : TaskManager_RunTask_ShouldRunTask_WhenFunctionIsValid
 * @tc.number : TaskManagerTest_004
 * @tc.desc   : Test if function is submitted correctly when function is valid
 */
HWTEST_F(TaskManagerTest, TaskManager_RunTask_ShouldRunTask_WhenFunctionIsValid, TestSize.Level0)
{
    std::function<void()> func = []() {
        // some function logic
    };
    taskManager->RunTask(func, "testFunction");
    EXPECT_EQ(taskManager->GetTaskCount(), 0);
}