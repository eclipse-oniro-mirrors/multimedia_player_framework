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

#ifndef LPP_AUDIO_CALLBACK_LOOPER
#define LPP_AUDIO_CALLBACK_LOOPER

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "i_lpp_audio_streamer.h"
namespace OHOS {
namespace Media {

class LppAudioCallbackLooper {
public:
    LppAudioCallbackLooper(std::string lppAudioStreamerId) {}
    MOCK_METHOD(void, OnDataNeeded, (const int32_t maxBufferSize));
    MOCK_METHOD(void, OnPositionUpdated, (const int64_t currentPositionMs));
    MOCK_METHOD(void, OnError, (const int32_t errCode, const std::string &errMsg));
    MOCK_METHOD(void, OnEos, ());
    MOCK_METHOD(void, OnInterrupted, (const int64_t forceType, const int64_t hint));
    MOCK_METHOD(void, OnDeviceChanged, (const int64_t reason));
    MOCK_METHOD(void, Stop, ());
    MOCK_METHOD(void, Reset, ());
    MOCK_METHOD(void, SetEngine, (std::weak_ptr<ILppAudioStreamerEngine> engine));
    MOCK_METHOD(void, StartWithLppAudioStreamerEngineObs, (const std::weak_ptr<ILppAudioStreamerEngineObs> &obs));
    MOCK_METHOD(void, StartPositionUpdate, ());
    MOCK_METHOD(void, StopPositionUpdate, ());
};
}  // namespace Media
}  // namespace OHOS
#endif  // LPP_AUDIO_CALLBACK_LOOPER