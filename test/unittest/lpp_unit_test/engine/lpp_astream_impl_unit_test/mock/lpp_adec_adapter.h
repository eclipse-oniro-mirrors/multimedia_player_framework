/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef LPP_ADEC_ADAPTER_H
#define LPP_ADEC_ADAPTER_H
#include "pipeline/pipeline.h"
#include "media_codec.h"

namespace OHOS {
namespace Media {
using namespace Pipeline;

class LppAudioDecoderAdapter : public std::enable_shared_from_this<LppAudioDecoderAdapter> {
public:
    LppAudioDecoderAdapter(const std::string &streamerId) {}

    ~LppAudioDecoderAdapter() = default;

    MOCK_METHOD(int32_t, SetParameter, (const Format &params));
    MOCK_METHOD(int32_t, Init, (const std::string &name));
    MOCK_METHOD(int32_t, Configure, (const Format &params));
    MOCK_METHOD(int32_t, SetOutputBufferQueue, (const sptr<Media::AVBufferQueueProducer> &bufferQueueProducer));
    MOCK_METHOD(int32_t, Prepare, ());
    MOCK_METHOD(int32_t, Start, ());
    MOCK_METHOD(int32_t, Pause, ());
    MOCK_METHOD(int32_t, Flush, ());
    MOCK_METHOD(int32_t, Resume, ());
    MOCK_METHOD(int32_t, Stop, ());
    MOCK_METHOD(sptr<Media::AVBufferQueueProducer>, GetInputBufferQueue, ());
    MOCK_METHOD(void, OnBufferAvailable, (bool isOutputBuffer));
    MOCK_METHOD(void, HandleBufferAvailable, (bool isOutputBuffer, bool isFlushed));
    MOCK_METHOD(void, OnError, (CodecErrorType errorType, int32_t errorCode));
    MOCK_METHOD(void, SetEventReceiver, (std::shared_ptr<EventReceiver> eventReceiver));
};
}
}
#endif // LPP_ADEC_ADAPTER_H