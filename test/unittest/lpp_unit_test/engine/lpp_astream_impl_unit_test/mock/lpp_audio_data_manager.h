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

#ifndef LPP_AUDIO_DATA_MANAGER_H
#define LPP_AUDIO_DATA_MANAGER_H
#include "pipeline/pipeline.h"
#include "lpp_common.h"

namespace OHOS {
namespace Media {
using namespace Pipeline;
class LppAudioDataManager : public std::enable_shared_from_this<LppAudioDataManager> {
public:
    LppAudioDataManager(const std::string &streamerId) {}
    ~LppAudioDataManager() = default;

    MOCK_METHOD(int32_t, Stop, ());
    MOCK_METHOD(int32_t, Reset, ());
    MOCK_METHOD(int32_t, Prepare, ());
    MOCK_METHOD(int32_t, Start, ());
    MOCK_METHOD(int32_t, Pause, ());
    MOCK_METHOD(int32_t, Resume, ());
    MOCK_METHOD(int32_t, Flush, ());
    MOCK_METHOD(int32_t, ProcessNewData, (sptr<LppDataPacket> framePacket));
    MOCK_METHOD(int32_t, SetDecoderInputProducer, (sptr<Media::AVBufferQueueProducer> producer));
    MOCK_METHOD(void, OnBufferAvailable, ());
    MOCK_METHOD(void, SetEventReceiver, (std::shared_ptr<EventReceiver> eventReceiver));
};
}  // namespace Media
}  // namespace OHOS
#endif