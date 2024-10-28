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

#include "util/task/task_manager.h"
#include <atomic>
#include "ffrt.h"

namespace OHOS {
namespace Media {
TaskManager::TaskManager(std::string name, TaskManagerTimeOpt opt) : taskName_(std::move(name)), m_timeOpt(opt)
{
    Init();
}

TaskManager::~TaskManager()
{
    Wait();
}

void TaskManager::Init()
{
    if (m_timeOpt == TaskManagerTimeOpt::SEQUENTIAL) {
        m_taskQueue = std::make_shared<ffrt::queue>(taskName_.c_str(), ffrt::queue_attr().qos(ffrt_qos_utility));
    }
}

void TaskManager::Submit(const std::function<void()>& func, std::string funcName)
{
    m_taskCnt++;
    if (m_timeOpt == TaskManagerTimeOpt::SEQUENTIAL && m_taskQueue) {
        m_taskQueue->submit([this, func, funcName]() { this->RunTask(func, funcName); });
    } else {
        ffrt::submit([this, func, funcName]() { this->RunTask(func, funcName); });
    }
}

uint32_t TaskManager::GetTaskCount() const
{
    return m_taskCnt;
}

void TaskManager::Wait(std::vector<TaskHandle>& taskHandles)
{
    if (m_timeOpt == TaskManagerTimeOpt::SEQUENTIAL && m_taskQueue) {
        for (TaskHandle& taskHandle : taskHandles) {
            m_taskQueue->wait(taskHandle);
        }
    } else {
        std::vector<ffrt::dependence> deps;
        deps.insert(deps.end(), taskHandles.begin(), taskHandles.end());
        ffrt::wait(deps);
    }
}

void TaskManager::RunTask(const std::function<void()>& func, const std::string&)
{
    func();
    {
        std::unique_lock lk(m_taskCntLock);
        m_taskCnt--;
    }

    m_taskCv.notify_all();
}

void TaskManager::Wait()
{
    if (m_timeOpt == TaskManagerTimeOpt::SEQUENTIAL && m_taskQueue) {
        auto handle = m_taskQueue->submit_h([&] { });
        m_taskQueue->wait(handle);
    } else {
        std::unique_lock lk(m_taskCntLock);
        if (m_taskCnt > 0) {
            m_taskCv.wait(lk, [&] { return m_taskCnt == 0; });
        }
    }
}
} // namespace Media
} // namespace OHOS