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

#ifndef AUDIO_STREAM_PLAYER_H
#define AUDIO_STREAM_PLAYER_H

#include "meta/format.h"
#include "lpp_common.h"

namespace OHOS {
namespace Media {

class AudioStreamerKeys {
public:
    static constexpr std::string_view LPP_CURRENT_POSITION = "lpp_current_position";
    static constexpr std::string_view LPP_AUDIO_INTERRUPT_FORCE_TYPE = "lpp_audio_interrupt_force_type";
    static constexpr std::string_view LPP_AUDIO_INTERRUPT_HINT = "lpp_audio_interrupt_hint";
    static constexpr std::string_view LPP_AUDIO_DEVICE_CHANGE_REASON = "audio_device_change_reason";
    static constexpr std::string_view LPP_AUDIO_MAX_BUFFER_SIZE = "lpp_audio_max_buffer_size";
    static constexpr std::string_view LPP_AUDIO_MAX_FRAME_NUM = "lpp_audio_max_frame_num";
};

enum AudioStreamerOnInfoType : int32_t {
    /* audio device change. */
    INFO_TYPE_LPP_AUDIO_DEVICE_CHANGE,
    /* return the message when eos */
    INFO_TYPE_LPP_AUDIO_EOS,
    /* return the message when Interrupted */
    INFO_TYPE_LPP_AUDIO_INTERRUPT,
    /* return the message when dataNeeded */
    INFO_TYPE_LPP_AUDIO_DATA_NEEDED,
    /* return the current posion of playback automatically. */
    INFO_TYPE_LPP_AUDIO_POSITION_UPDATE,
};

class AudioStreamerCallback {
public:
    virtual ~AudioStreamerCallback() = default;

    virtual void OnError(int32_t errorCode, const std::string &errorMsg) = 0;

    virtual void OnInfo(AudioStreamerOnInfoType type, int32_t extra, const Format &infoBody) = 0;
};

class AudioStreamer {
public:
    virtual ~AudioStreamer() = default;

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

    virtual int32_t SetLppVideoStreamerId(std::string videoStreamerId) = 0;

    virtual std::string GetStreamerId() = 0;
};

class __attribute__((visibility("default"))) AudioStreamerFactory {
public:
#ifdef UNSUPPORT_LPP_AUDIO_STRAMER
    static std::shared_ptr<AudioStreamer> CreateByMime(const std::string &mime)
    {
        (void)mime;
        return nullptr;
    }
#else
    static std::shared_ptr<AudioStreamer> CreateByMime(const std::string &mime);
#endif
private:
    AudioStreamerFactory() = default;
    ~AudioStreamerFactory() = default;
};
}  // namespace Media
}  // namespace OHOS
#endif  // AUDIO_STREAM_PLAYER_H
