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

#ifndef I_LPP_AUDIO_PLAYER_SERVICE_H
#define I_LPP_AUDIO_PLAYER_SERVICE_H

#include "lpp_audio_streamer.h"
#include "refbase.h"
#include "lpp_common.h"
// client/server

namespace OHOS {
namespace Media {
class ILppAudioStreamerService {
public:
    virtual ~ILppAudioStreamerService() = default;

    virtual int32_t Init(const std::string &mime) = 0;

    virtual int32_t SetParameter(const Format &param) = 0;

    virtual int32_t GetParameter(Format &param) = 0;

    virtual int32_t Configure(const Format &param) = 0;

    virtual int32_t Prepare() = 0;

    virtual int32_t Start() = 0;

    virtual int32_t Pause() = 0;

    virtual int32_t Resume() = 0;

    virtual int32_t Flush() = 0;

    virtual int32_t Stop() = 0;

    virtual int32_t Reset() = 0;

    virtual int32_t Release() = 0;

    virtual int32_t SetVolume(float volume) = 0;

    virtual int32_t SetLoudnessGain(const float loudnessGain) = 0;

    virtual int32_t SetPlaybackSpeed(float speed) = 0;

    virtual int32_t ReturnFrames(sptr<LppDataPacket> framePacket) = 0;

    virtual int32_t RegisterCallback() = 0;

    virtual int32_t SetLppAudioStreamerCallback(const std::shared_ptr<AudioStreamerCallback> &callback) = 0;

    virtual int32_t SetLppVideoStreamerId(const std::string videoStreamId) = 0;

    virtual std::string GetStreamerId() = 0;
};
}  // namespace Media
}  // namespace OHOS
#endif  // I_LPP_AUDIO_PLAYER_SERVICE_H
