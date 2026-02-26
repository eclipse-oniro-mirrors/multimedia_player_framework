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

#ifndef I_STANDARD_LPP_AUDIO_STREAMER_SERVICE_H
#define I_STANDARD_LPP_AUDIO_STREAMER_SERVICE_H

#include "ipc_types.h"
#include "iremote_broker.h"
#include "iremote_proxy.h"
#include "iremote_stub.h"
#include "lpp_audio_streamer.h"
#include "lpp_common.h"

namespace OHOS {
namespace Media {
class IStandardLppAudioStreamerService : public IRemoteBroker {
public:
    virtual ~IStandardLppAudioStreamerService() = default;
    // virtual int32_t SetListenerObject(const sptr<IRemoteObject> &object) = 0;

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

    virtual int32_t SetLppAudioStreamerCallback() = 0;

    virtual int32_t SetListenerObject(const sptr<IRemoteObject> &object) = 0;

    virtual int32_t SetLppVideoStreamerId(const std::string videoStreamId) = 0;

    virtual std::string GetStreamerId() = 0;

    /**
     * IPC code ID
     */
    enum PlayerServiceMsg {
        SET_PARAMETER = 0,
        INIT,
        CONFIGURE,
        PREPARE,
        START,
        PAUSE,
        RESUME,
        FLUSH,
        STOP,
        RESET,
        RELEASE,
        SET_VOLUME,
        SET_PLAYBACK_SPEED,
        RETURN_FRAMES,
        REGISTER_CALLBACK,
        SET_AUDIO_STREAM_CALLBACK,
        SET_LISTENER_OBJ,
        SET_VIDOE_STREAMER_ID,
        GET_STREAM_ID,
        SET_LOUDNESS_GAIN,
        GET_PARAMETER,
        MAX_IPC_ID,                   // all IPC codes should be added before MAX_IPC_ID
    };

    DECLARE_INTERFACE_DESCRIPTOR(u"IStandardLppAudioStreamerService");
};
} // namespace Media
} // namespace OHOS
#endif // I_STANDARD_PLAYER_SERVICE_H
