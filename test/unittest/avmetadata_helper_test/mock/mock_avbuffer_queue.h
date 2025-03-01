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

#ifndef MOCK_HISTREAMER_FOUNDATION_AVBUFFER_QUEUE_H
#define MOCK_HISTREAMER_FOUNDATION_AVBUFFER_QUEUE_H

#include "avbuffer_queue.h"
#include "gmock/gmock.h"

namespace OHOS {
namespace Media {

class MockAVBufferQueue : public AVBufferQueue {
public:
    MockAVBufferQueue() = default;
    ~MockAVBufferQueue() override {};

    MOCK_METHOD(std::shared_ptr<AVBufferQueueProducer>, GetLocalProducer, (), (override));
    MOCK_METHOD(std::shared_ptr<AVBufferQueueConsumer>, GetLocalConsumer, (), (override));

    // 跨进程对象智能指针
    MOCK_METHOD(sptr<AVBufferQueueProducer>, GetProducer, (), (override));
    MOCK_METHOD(sptr<AVBufferQueueConsumer>, GetConsumer, (), (override));

    MOCK_METHOD(sptr<Surface>, GetSurfaceAsProducer, (), (override));
    MOCK_METHOD(sptr<Surface>, GetSurfaceAsConsumer, (), (override));

    MOCK_METHOD(uint32_t, GetQueueSize, (), (override));
    MOCK_METHOD(Status, SetQueueSize, (uint32_t size), (override));
    MOCK_METHOD(Status, SetLargerQueueSize, (uint32_t size), (override));
    MOCK_METHOD(bool, IsBufferInQueue, (const std::shared_ptr<AVBuffer>& buffer), (override));
    MOCK_METHOD(Status, Clear, (), (override));
    MOCK_METHOD(Status, ClearBufferIf, (std::function<bool(const std::shared_ptr<AVBuffer> &)> pred), (override));
    MOCK_METHOD(Status, SetQueueSizeAndAttachBuffer,
                (uint32_t size, std::shared_ptr<AVBuffer>& buffer, bool isFilled), (override));
};

} // namespace Media
} // namespace OHOS

#endif // MOCK_HISTREAMER_FOUNDATION_AVBUFFER_QUEUE_H
