/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OH_VEF_TASK_MANAGER
#define OH_VEF_TASK_MANAGER

#include <atomic>
#include "ffrt.h"

namespace OHOS {
namespace Media {
using TaskHandle = ffrt::task_handle;

enum class TaskManagerTimeOpt {
    CONCURRENT,
    SEQUENTIAL
};

class TaskManager {
public:
    TaskManager(std::string name, TaskManagerTimeOpt opt);
    ~TaskManager();

public:
    void Submit(const std::function<void()>& func, std::string funcName = "");

    void Wait(std::vector<TaskHandle>& taskHandles);
    void Wait();

    uint32_t GetTaskCount() const;

private:
    void Init();
    void RunTask(const std::function<void()>& func, const std::string& funcName);

private:
    std::string taskName_;

    ffrt::mutex m_taskCntLock;
    ffrt::condition_variable m_taskCv;
    std::atomic<uint32_t> m_taskCnt{ 0 };

    TaskManagerTimeOpt m_timeOpt{ TaskManagerTimeOpt::CONCURRENT};
    std::shared_ptr<ffrt::queue> m_taskQueue{ nullptr };
};
} // namespace Media
} // namespace OHOS

#endif // OH_VEF_TASK_MANAGER