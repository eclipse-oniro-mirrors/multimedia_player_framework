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
#ifndef MOCK_ILPP_AUDIO_STREAMER_ENGINE
#define MOCK_ILPP_AUDIO_STREAMER_ENGINE

#include <gmock/gmock.h>
#include "avbuffer_queue_producer.h"


namespace OHOS {
namespace Media {
class MockILppAudioStreamerEngine : public ILppAudioStreamerEngine, 
                                    public std::enable_shared_from_this<MockILppAudioStreamerEngine>{
public:
    MOCK_METHOD(int32_t, Init, (const std::string &mime), ());
    MOCK_METHOD(int32_t, SetObs, (const std::weak_ptr<ILppAudioStreamerEngineObs> &obs), ());
    MOCK_METHOD(int32_t, Configure, (const Format &param), ());
    MOCK_METHOD(int32_t, Prepare, (), ());
    MOCK_METHOD(int32_t, Start, (), ());
    MOCK_METHOD(int32_t, Pause, (), ());
    MOCK_METHOD(int32_t, Resume, (), ());
    MOCK_METHOD(int32_t, Flush, (), ());
    MOCK_METHOD(int32_t, Stop, (), ());
    MOCK_METHOD(int32_t, Reset, (), ());
    MOCK_METHOD(int32_t, SetVolume, (const float volume), ());
    MOCK_METHOD(int32_t, SetPlaybackSpeed, (const float playbackSpeed), ());
    MOCK_METHOD(int32_t, ReturnFrames, (sptr<LppDataPacket> framePacket), ());
    MOCK_METHOD(int32_t, SetLppVideoStreamerId, (std::string videoStreamerId), ());
    MOCK_METHOD(std::string, GetStreamerId, (), ());
    MOCK_METHOD(int32_t, GetCurrentPosition, (int64_t &currentPositionMs), ());
};
}  // namespace Media
}  // namespace OHOS
#endif