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

#ifndef I_LPP_AUDIO_STREAMER_H
#define I_LPP_AUDIO_STREAMER_H

#include <string>
#include <refbase.h>
#include "format.h"
#include "lpp_common.h"
#include "media_errors.h"
namespace OHOS {
namespace Media {
class ILppAudioStreamerEngineObs : public std::enable_shared_from_this<ILppAudioStreamerEngineObs> {
public:
    virtual ~ILppAudioStreamerEngineObs() = default;
    virtual void OnDataNeeded(const int32_t maxBufferSize) = 0;
    virtual void OnPositionUpdated(const int64_t currentPositionMs) = 0;
    virtual void OnError(const MediaServiceErrCode errCode, const std::string &errMsg) = 0;
    virtual void OnEos() = 0;
    virtual void OnInterrupted(const int64_t forceType, const int64_t hint) = 0;
    virtual void OnDeviceChanged(const int64_t reason) = 0;
};

class ILppAudioStreamerEngine {
public:
    virtual ~ILppAudioStreamerEngine() = default;
    virtual int32_t Init(const std::string &mime) = 0;
    virtual int32_t SetObs(const std::weak_ptr<ILppAudioStreamerEngineObs> &obs) = 0;
    virtual int32_t Configure(const Format &param) = 0;
    virtual int32_t Prepare() = 0;
    virtual int32_t Start() = 0;
    virtual int32_t Pause() = 0;
    virtual int32_t Resume() = 0;
    virtual int32_t Flush() = 0;
    virtual int32_t Stop() = 0;
    virtual int32_t Reset() = 0;
    virtual int32_t SetVolume(const float volume) = 0;
    virtual int32_t SetLoudnessGain(const float loudnessGain) = 0;
    virtual int32_t SetPlaybackSpeed(const float playbackSpeed) = 0;
    virtual int32_t ReturnFrames(sptr<LppDataPacket> framePacket) = 0;
    virtual int32_t SetLppVideoStreamerId(std::string videoStreamerId) = 0;
    virtual std::string GetStreamerId() = 0;
    virtual int32_t GetCurrentPosition(int64_t &currentPositionMs) = 0;
};
} // namespace Media
} // namespace OHOS
#endif  // I_LPP_AUDIO_STREAMER_H