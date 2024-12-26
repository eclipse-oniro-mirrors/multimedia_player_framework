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

#ifndef MOCK_HISTREAMER_FOUNDATION_AVBUFFER_QUEUE_CONSUMER_H
#define MOCK_HISTREAMER_FOUNDATION_AVBUFFER_QUEUE_CONSUMER_H

#include "avbuffer_queue_consumer.h"
#include "gmock/gmock.h"

namespace OHOS {
namespace Media {

class MockAVBufferQueueConsumer : public AVBufferQueueConsumer {
public:
    MockAVBufferQueueConsumer() = default;
    ~MockAVBufferQueueConsumer() override {};

    MOCK_METHOD(uint32_t, GetQueueSize, (), (override));
    MOCK_METHOD(Status, SetQueueSize, (uint32_t size), (override));
    MOCK_METHOD(bool, IsBufferInQueue, (const std::shared_ptr<AVBuffer>& buffer), (override));

    MOCK_METHOD(Status, AcquireBuffer, (std::shared_ptr<AVBuffer>& outBuffer), (override));
    MOCK_METHOD(Status, ReleaseBuffer, (const std::shared_ptr<AVBuffer>& inBuffer), (override));

    MOCK_METHOD(Status, AttachBuffer, (std::shared_ptr<AVBuffer>& inBuffer, bool isFilled), (override));
    MOCK_METHOD(Status, DetachBuffer, (const std::shared_ptr<AVBuffer>& outBuffer), (override));

    MOCK_METHOD(Status, SetBufferAvailableListener, (sptr<IConsumerListener>& listener), (override));

    MOCK_METHOD(Status, SetQueueSizeAndAttachBuffer, (uint32_t size, std::shared_ptr<AVBuffer>& buffer,
                bool isFilled), (override));
};

} // namespace Media
} // namespace OHOS

#endif // MOCK_HISTREAMER_FOUNDATION_AVBUFFER_QUEUE_CONSUMER_H