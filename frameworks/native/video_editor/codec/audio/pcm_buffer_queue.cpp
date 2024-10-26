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

#include "codec/audio/pcm_buffer_queue.h"

namespace OHOS {
namespace Media {

PcmBufferQueue::PcmBufferQueue(size_t capacity) : capacity_(capacity) {}

void PcmBufferQueue::Enqueue(const std::shared_ptr<PcmData>& data)
{
    std::unique_lock<ffrt::mutex> lock(mutex_);
    condFull_.wait(lock, [this]() { return queue_.size() < capacity_ || cancelEnqueueFlag_ == true; });
    if (cancelEnqueueFlag_) {
        return;
    }
    queue_.push(data);
    condEmpty_.notify_one();
}

std::shared_ptr<PcmData> PcmBufferQueue::Dequeue()
{
    std::unique_lock<ffrt::mutex> lock(mutex_);
    condEmpty_.wait(lock, [this]() { return !queue_.empty() || cancelDequeueFlag_ == true; });
    if (cancelDequeueFlag_) {
        return nullptr;
    }
    auto data = queue_.front();
    queue_.pop();
    condFull_.notify_one();
    return data;
}

void PcmBufferQueue::CancelEnqueue()
{
    std::unique_lock<ffrt::mutex> lock(mutex_);
    cancelEnqueueFlag_ = true;
    condFull_.notify_all();
}

void PcmBufferQueue::CancelDequeue()
{
    std::unique_lock<ffrt::mutex> lock(mutex_);
    cancelDequeueFlag_ = true;
    condEmpty_.notify_all();
}

} // namespace Media
} // namespace OHOS