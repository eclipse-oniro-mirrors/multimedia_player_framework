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

#ifndef LPP_AUDIO_PLAYER_SERVICE_CLIENT_H
#define LPP_AUDIO_PLAYER_SERVICE_CLIENT_H

#include "i_lpp_audio_streamer_service.h"
#include "i_standard_lpp_audio_streamer_service.h"
#include "lpp_audio_streamer_listener_stub.h"

namespace OHOS {
namespace Media {
class LppAudioStreamerClient : public ILppAudioStreamerService {
public:
    static std::shared_ptr<LppAudioStreamerClient> Create(const sptr<IStandardLppAudioStreamerService> &ipcProxy);
    explicit LppAudioStreamerClient(const sptr<IStandardLppAudioStreamerService> &ipcProxy);
    ~LppAudioStreamerClient();

    int32_t Init(const std::string &mime) override;

    int32_t SetParameter(const Format &param) override;

    int32_t GetParameter(Format &param) override;

    int32_t Configure(const Format &param) override;

    int32_t Prepare() override;

    int32_t Start() override;

    int32_t Pause() override;

    int32_t Resume() override;

    int32_t Flush() override;

    int32_t Stop() override;

    int32_t Reset() override;

    int32_t Release() override;

    int32_t SetVolume(float volume) override;

    int32_t SetLoudnessGain(const float loudnessGain) override;

    int32_t SetPlaybackSpeed(float speed) override;

    int32_t ReturnFrames(sptr<LppDataPacket> framePacket) override;

    int32_t RegisterCallback() override;

    int32_t SetLppAudioStreamerCallback(const std::shared_ptr<AudioStreamerCallback> &callback) override;

    int32_t SetLppVideoStreamerId(const std::string videoStreamId) override;

    std::string GetStreamerId() override;

    void MediaServerDied();

private:
    int32_t CreateListenerObject();

    sptr<IStandardLppAudioStreamerService> playerProxy_ = nullptr;
    sptr<LppAudioStreamerListenerStub> listenerStub_ = nullptr;
    std::shared_ptr<AudioStreamerCallback> callback_ = nullptr;
    std::mutex mutex_;
};
} // namespace Media
} // namespace OHOS
#endif // PLAYER_SERVICE_CLIENT_H
