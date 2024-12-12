/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "task_queue_unit_test.h"

#include <chrono>

using namespace OHOS;
using namespace OHOS::Media;
using namespace std;
using namespace testing::ext;


namespace OHOS {
namespace Media {
namespace Test {

namespace {
    static constexpr uint64_t WAIT_TIME = 1e6; // 1s
    static constexpr uint32_t UINT32_TASK_RESULT = 10;
}

void TaskQueueUnitTest::SetUpTestCase(void) {}

void TaskQueueUnitTest::TearDownTestCase(void) {}

void TaskQueueUnitTest::SetUp(void)
{
    taskQueue_ = std::make_shared<TaskQueue>("test_name");
}

void TaskQueueUnitTest::TearDown(void)
{
    taskQueue_ = nullptr;
}

HWTEST_F(TaskQueueUnitTest, Stop_000, TestSize.Level0) {
    taskQueue_->isExit_ = true;
    int32_t result = -1;
    taskQueue_->thread_ = std::make_unique<std::thread>([&]() {
        result = taskQueue_->Stop();
    });
    if (taskQueue_->thread_->joinable()) {
        taskQueue_->thread_->join();
    }
    ASSERT_EQ(result, MSERR_OK);
}

HWTEST_F(TaskQueueUnitTest, Stop_001, TestSize.Level0) {
    taskQueue_->isExit_ = false;
    int32_t result = -1;
    taskQueue_->thread_ = std::make_unique<std::thread>([&]() {
        result = taskQueue_->Stop();
    });
    if (taskQueue_->thread_->joinable()) {
        taskQueue_->thread_->join();
    }
    ASSERT_EQ(result, MSERR_INVALID_OPERATION);
}

HWTEST_F(TaskQueueUnitTest, CancelNotExecutedTaskLocked_001, TestSize.Level0) {
    taskQueue_->isExit_ = false;
    TaskQueue::TaskHandlerItem taskItem;
    taskItem.task_ = nullptr;
    taskQueue_->taskList_.push_back(taskItem);
    taskQueue_->thread_ = std::make_unique<std::thread>([&]() {
        taskQueue_->CancelNotExecutedTaskLocked();
    });
    if (taskQueue_->thread_->joinable()) {
        taskQueue_->thread_->join();
    }
    ASSERT_TRUE(taskQueue_->taskList_.empty());
}
 
HWTEST_F(TaskQueueUnitTest, CancelNotExecutedTaskLocked_002, TestSize.Level0) {
    taskQueue_->isExit_ = false;
    uint32_t count = 0;

    auto task1 = make_shared<TaskHandler<uint32_t>>(
        [&] () -> uint32_t {
            count++;
            return count;
        }
    );
    ASSERT_EQ(taskQueue_->EnqueueTask(task1), 0);

    auto task2 = make_shared<TaskHandler<void>>(
        [&] () -> void {
            count++;
            return;
        }
    );
    ASSERT_EQ(taskQueue_->EnqueueTask(task2), 0);

    taskQueue_->thread_ = std::make_unique<std::thread>([&]() {
        taskQueue_->CancelNotExecutedTaskLocked();
    });
    if (taskQueue_->thread_->joinable()) {
        taskQueue_->thread_->join();
    }

    auto result1 = task1->GetResult();
    auto result2 = task2->GetResult();

    ASSERT_TRUE(taskQueue_->taskList_.empty());
    ASSERT_EQ(count, 0);
    ASSERT_TRUE(task1->IsCanceled());
    ASSERT_TRUE(task2->IsCanceled());
    ASSERT_FALSE(result1.HasResult());
    ASSERT_FALSE(result2.HasResult());
}

HWTEST_F(TaskQueueUnitTest, TaskProcessor_001, TestSize.Level0) {
    taskQueue_->Start();

    TaskQueue::TaskHandlerItem taskItem;
    taskItem.task_ = nullptr;
    taskQueue_->taskList_.push_back(taskItem);

    auto task = make_shared<TaskHandler<uint32_t>>(
        [] () -> uint32_t {
            return UINT32_TASK_RESULT;
        }
    );
    ASSERT_EQ(taskQueue_->EnqueueTask(task, false, WAIT_TIME), 0);

    auto result = task->GetResult();
    ASSERT_TRUE(taskQueue_->taskList_.empty());
    ASSERT_TRUE(result.HasResult());
    ASSERT_EQ(result.Value(), UINT32_TASK_RESULT);
}

HWTEST_F(TaskQueueUnitTest, TaskProcessor_002, TestSize.Level0) {
    taskQueue_->Start();

    TaskQueue::TaskHandlerItem taskItem;
    taskItem.task_ = nullptr;
    taskQueue_->taskList_.push_back(taskItem);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    ASSERT_TRUE(taskQueue_->taskList_.empty());
}

HWTEST_F(TaskQueueUnitTest, TaskProcessor_003, TestSize.Level0) {
    taskQueue_->Start();

    auto task = make_shared<TaskHandler<uint32_t>>(
        [] () -> uint32_t {
            return UINT32_TASK_RESULT;
        }
    );
    ASSERT_EQ(taskQueue_->EnqueueTask(task, false, WAIT_TIME), 0);
    task->Cancel();

    std::this_thread::sleep_for(std::chrono::seconds(5));
    ASSERT_TRUE(task->IsCanceled());
    ASSERT_TRUE(taskQueue_->taskList_.empty());
    auto result = task->GetResult();
    ASSERT_FALSE(result.HasResult());
}

HWTEST_F(TaskQueueUnitTest, IsTaskExecuting_001, TestSize.Level0) {
    taskQueue_->isTaskExecuting_ = true;
    bool ret;
    ret = taskQueue_->IsTaskExecuting();
    ASSERT_TRUE(ret);
}

HWTEST_F(TaskQueueUnitTest, IsTaskExecuting_002, TestSize.Level0) {
    taskQueue_->isTaskExecuting_ = false;
    bool ret;
    ret = taskQueue_->IsTaskExecuting();
    ASSERT_FALSE(ret);
}

HWTEST_F(TaskQueueUnitTest, FullProgress_001, TestSize.Level0) {
    taskQueue_->SetQos(OHOS::QOS::QosLevel::QOS_USER_INTERACTIVE);
    taskQueue_->ResetQos();
    ASSERT_EQ(taskQueue_->tid_, -1);

    taskQueue_->Start();

    auto task1 = make_shared<TaskHandler<uint32_t>>(
        [] () -> uint32_t {
            return UINT32_TASK_RESULT;
        }
    );
    ASSERT_EQ(taskQueue_->EnqueueTask(task1, false, WAIT_TIME), 0);
    task1->Cancel();

    auto task2 = make_shared<TaskHandler<uint32_t>>(
        [] () -> uint32_t {
            return UINT32_TASK_RESULT;
        }
    );
    ASSERT_EQ(taskQueue_->EnqueueTask(task2), 0);

    auto task3 = make_shared<TaskHandler<uint32_t>>(
        [] () -> uint32_t {
            return UINT32_TASK_RESULT;
        }
    );
    ASSERT_EQ(taskQueue_->EnqueueTask(task3, false, WAIT_TIME), 0);

    ASSERT_TRUE(task1->IsCanceled());
    auto result2 = task2->GetResult();
    ASSERT_TRUE(result2.HasResult());
    ASSERT_EQ(result2.Value(), UINT32_TASK_RESULT);
    auto result3 = task3->GetResult();
    ASSERT_TRUE(result3.HasResult());
    ASSERT_EQ(result3.Value(), UINT32_TASK_RESULT);

    ASSERT_TRUE(taskQueue_->taskList_.empty());
}

}  // namespace Test
}  // namespace Media
}  // namespace OHOS
