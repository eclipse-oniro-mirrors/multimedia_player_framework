/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef MOCK_AVBUFFER_QUEUE_PRODUCER_H
#define MOCK_AVBUFFER_QUEUE_PRODUCER_H

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "pipeline/pipeline.h"

namespace OHOS {
namespace Media {
class MockAVBufferQueueProducer : public IRemoteStub<Media::AVBufferQueueProducer> {
public:
    MOCK_METHOD(Status, RequestBuffer, (std::shared_ptr<AVBuffer>& outBuffer,
        const AVBufferConfig& config, int32_t timeoutMs), (override));
    MOCK_METHOD(Status, PushBuffer, (const std::shared_ptr<AVBuffer>& inBuffer, bool available), (override));
    MOCK_METHOD(Status, SetBufferAvailableListener, (sptr<IProducerListener>& listener), (override));
    MOCK_METHOD(uint32_t, GetQueueSize, (), (override));
    MOCK_METHOD(Status, SetQueueSize, (uint32_t size), (override));
    MOCK_METHOD(Status, ReturnBuffer, (const std::shared_ptr<AVBuffer>& inBuffer, bool available), (override));
    MOCK_METHOD(Status, AttachBuffer, (std::shared_ptr<AVBuffer>& inBuffer, bool isFilled), (override));
    MOCK_METHOD(Status, DetachBuffer, (const std::shared_ptr<AVBuffer>& outBuffer), (override));
    MOCK_METHOD(Status, SetBufferFilledListener, (sptr<IBrokerListener>& listener), (override));
    MOCK_METHOD(Status, RemoveBufferFilledListener, (sptr<IBrokerListener>& listener), (override));
    MOCK_METHOD(Status, Clear, (), (override));
    MOCK_METHOD(Status, ClearBufferIf, (std::function<bool(const std::shared_ptr<AVBuffer>&)> pred), (override));
};
}  // namespace Media
}  // namespace OHOS
#endif  // MOCK_AVBUFFER_QUEUE_PRODUCER_H