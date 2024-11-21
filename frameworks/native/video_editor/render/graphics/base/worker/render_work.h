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
#ifndef OH_VEF_RENDER_THREAD_H
#define OH_VEF_RENDER_THREAD_H

#include "render/graphics/base/queue/RenderFifoQueue.h"
#include "render/graphics/base/task/render_task_interface.h"
#include "render/graphics/base/worker/render_work_interface.h"
#include <thread>

#define RENDER_QUEUE_SIZE 4
#define COMMON_TASK_TAG 0
#define PREVIEW_TASK_TAG 1
#define EXPORT_TASK_TAG 2
#define SLEEP_TIMEOUT 1000

namespace OHOS {
namespace Media {
template <typename QUEUE = RenderFifoQueue<RenderTaskPtr<void>>>
class RenderThread : public RenderWorkerItf<typename QUEUE::DataType> {
public:
    typedef typename QUEUE::DataType LocalTaskType;
    static_assert(std::is_base_of<RenderQueueItf<LocalTaskType>, QUEUE>::value,
        "QUEUE should be derived from RenderQueueItf");

    explicit RenderThread(
        size_t, std::function<void()> idleTsk = []() {});
    ~RenderThread();
    void AddTask(
        const LocalTaskType&, bool overwrite = false, std::function<void()> callback = []() {}) override;
    void Start() override;
    void Stop() override;
    void ClearTaskQueue();

protected:
    void Run() override;

    QUEUE* localMsgQueue_ = nullptr;
    volatile bool isWorking_ = false;
    volatile bool isStopped_ = true;

    std::mutex cvMutex_;
    std::condition_variable cvFull_;
    std::condition_variable cvEmpty_;
    std::function<void()> idleTask_;

    std::thread* thread_{ nullptr };
    size_t qSize_;
};

template <typename QUEUE>
RenderThread<QUEUE>::RenderThread(size_t queueSize, std::function<void()> idleTsk)
    : idleTask_(idleTsk), qSize_(queueSize)
{
    localMsgQueue_ = new (std::nothrow) QUEUE();
}

template <typename QUEUE> RenderThread<QUEUE>::~RenderThread()
{
    Stop();
    thread_->join();
    delete thread_;
    thread_ = nullptr;
    if (localMsgQueue_ != nullptr) {
        delete localMsgQueue_;
        localMsgQueue_ = nullptr;
    }
}

template <typename QUEUE>
void RenderThread<QUEUE>::AddTask(const LocalTaskType& task, bool overwrite, std::function<void()> callback)
{
    std::unique_lock<std::mutex> lk(cvMutex_);
    if (localMsgQueue_ == nullptr) {
        return;
    }
    cvFull_.wait(lk, [this, &task]() {
        return (GetTag(task) == PREVIEW_TASK_TAG) || (localMsgQueue_->GetSize() < this->qSize_) || (!isWorking_);
    });
    if (isWorking_) {
        if (overwrite) {
            LocalTaskType thread_ = localMsgQueue_->Find(task);
            if (thread_ != nullptr) {
                SetFunc(thread_, callback);
                SetTag(thread_, COMMON_TASK_TAG);
            }
        }
        localMsgQueue_->Push(task);
        lk.unlock();
        cvEmpty_.notify_one();
    }
}

template <typename QUEUE> void RenderThread<QUEUE>::Start()
{
    if (isStopped_) {
        {
            std::unique_lock<std::mutex> lk(cvMutex_);
            isWorking_ = true;
        }
        thread_ = new (std::nothrow) std::thread([this]() {
            this->isStopped_ = false;
            this->Run();
            this->isStopped_ = true;
        });
        while (isStopped_) {
            std::this_thread::sleep_for(std::chrono::microseconds(SLEEP_TIMEOUT));
        }
    }
}

template <typename QUEUE> void RenderThread<QUEUE>::Stop()
{
    {
        std::unique_lock<std::mutex> lk(cvMutex_);
        isWorking_ = false;
    }
    cvEmpty_.notify_all();
    while (!isStopped_) {
        std::this_thread::sleep_for(std::chrono::microseconds(SLEEP_TIMEOUT));
    }
}

template <typename QUEUE> void RenderThread<QUEUE>::ClearTaskQueue()
{
    std::unique_lock<std::mutex> lk(cvMutex_);
    if (localMsgQueue_ == nullptr) {
        return;
    }
    localMsgQueue_->RemoveAll();
}

template <typename QUEUE> void RenderThread<QUEUE>::Run()
{
    while (isWorking_) {
        std::unique_lock<std::mutex> lk(cvMutex_);
        if (localMsgQueue_ == nullptr) {
            return;
        }
        bool cvRet = cvEmpty_.wait_for(lk, std::chrono::milliseconds(2500),
            [this]() { return (localMsgQueue_->GetSize() > 0) || (!isWorking_); });
        if (cvRet) {
            LocalTaskType task;
            bool ret = localMsgQueue_->Pop(task);
            lk.unlock();
            cvFull_.notify_one();
            if (ret) {
                task->Run();
            }
        } else {
            lk.unlock();
            idleTask_();
        }
    }
};
}
}

#endif