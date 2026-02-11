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

#ifndef LPP_PLAYER_SERVICE_SERVER_H
#define LPP_PLAYER_SERVICE_SERVER_H

#include <mutex>

#include "i_lpp_audio_streamer_service.h"
#include "i_lpp_audio_streamer.h"
#include "media_errors.h"
#include "nocopyable.h"

namespace OHOS {
namespace Media {

enum class LppAudioState : int32_t {
    CREATED = 0,
    INITIALIZED = 1,
    READY = 2,
    STARTING = 3,
    PAUSED = 4,
    EOS = 5,
    STOPPED = 6,
    RELEASED = 7,
    ERROR = 32,
};

class LppAudioStreamerServer
    : public ILppAudioStreamerService,
      public ILppAudioStreamerEngineObs,
      public NoCopyable {
public:
    static std::shared_ptr<ILppAudioStreamerService> Create();
    LppAudioStreamerServer();
    virtual ~LppAudioStreamerServer();

    int32_t Init(const std::string &mime) override;

    int32_t SetParameter(const Format &param) override;

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

    std::string GetStreamerId() override;

    void OnDataNeeded(const int32_t maxBufferSize) override;

    void OnPositionUpdated(const int64_t currentPositionMs) override;

    void OnError(const MediaServiceErrCode errCode, const std::string &errMsg) override;

    void OnEos() override;

    void OnInterrupted(const int64_t forceType, const int64_t hint) override;

    void OnDeviceChanged(const int64_t reason) override;

    int32_t SetLppVideoStreamerId(const std::string videoStreamId) override;

private:
    int32_t CreateStreamerEngine();
    bool StateEnter(LppAudioState targetState, const std::string funcName = "");
    bool StateCheck(LppAudioState curState);
    bool ErrorCheck(int32_t errorCode);

    LppAudioState state_ {LppAudioState::CREATED};
    std::mutex stateMutex_ {};

    std::string mime_ {};

    std::shared_ptr<AudioStreamerCallback> lppAudioStreamerCb_ = nullptr;
    
    std::shared_ptr<ILppAudioStreamerEngine> streamerEngine_ = nullptr;
    uint32_t appTokenId_ = 0;
    int32_t appUid_ = 0;
    int32_t appPid_ = 0;
    std::string appName_;
};
} // namespace Media
} // namespace OHOS
#endif // LPP_PLAYER_SERVICE_SERVER_H
