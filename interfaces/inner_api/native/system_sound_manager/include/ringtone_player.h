/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef RINGTONE_PLAYER_H
#define RINGTONE_PLAYER_H

#include <string>

#include "audio_info.h"

namespace OHOS {
namespace Media {
enum RingtoneState {
    /** INVALID state */
    STATE_INVALID = -1,
    /** Create New instance */
    STATE_NEW,
    /** Prepared state */
    STATE_PREPARED,
    /** Running state */
    STATE_RUNNING,
    /** Stopped state */
    STATE_STOPPED,
    /** Released state */
    STATE_RELEASED,
    /** Paused state */
    STATE_PAUSED
};

class RingtonePlayerInterruptCallback;

enum class HapticStartupMode {
    // Default mode. The audio and vibration will start at the same time.
    DEFAULT = 0,
    // Fast mode. The vibration will start quickly.
    FAST = 1,
};

enum RingtoneHapticsFeature {
    RINGTONE_GENTLE_HAPTICS
};

class RingtonePlayer {
public:
    virtual ~RingtonePlayer() = default;

    /**
     * @brief Returns the current ringtone state
     *
     * @return Returns the current state of ringtone player.
     * @since 1.0
     * @version 1.0
     */
    virtual RingtoneState GetRingtoneState() = 0;

    /**
     * @brief Configure the ringtone player before playing any audio
     *
     * @param volume Configures the volume at which the ringtone has to be played
     * @param loop Boolean parameter indicating whether to enable or disable looping
     * @return Returns {@link MSERR_OK} if the looping parameter is set successfully to player;
     * returns an error code defined in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t Configure(const float &volume, const bool &loop) = 0;

    /**
     * @brief Start playing ringtone
     *
     * @return Returns {@link MSERR_OK} if the looping parameter is set successfully to player;
     * returns an error code defined in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t Start(const HapticStartupMode startupMode = HapticStartupMode::DEFAULT) = 0;

    /**
     * @brief Stop playing ringtone
     *
     * @return Returns {@link MSERR_OK} if the looping parameter is set successfully to player;
     * returns an error code defined in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t Stop() = 0;

    /**
     * @brief Returns the audio contetnt type and stream uage details to the clients
     *
     * @return Returns {@link MSERR_OK} if the looping parameter is set successfully to player;
     * returns an error code defined in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t GetAudioRendererInfo(AudioStandard::AudioRendererInfo &rendererInfo) const = 0;

    /**
     * @brief Returns the title of the uri set.
     *
     * @return Returns title as string if the title is obtained successfully from media library.
     * returns an empty string otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual std::string GetTitle() = 0;

    /**
     * @brief Releases the ringtone client resources
     *
     * @return Returns {@link MSERR_OK} if the looping parameter is set successfully to player;
     * returns an error code defined in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t Release() = 0;

    /**
     * @brief Registers the ringtone player callback listener.
     *
     * @return Returns {@link MSERR_OK} if callback registration is successful;
     * returns an error code defined in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t SetRingtonePlayerInterruptCallback
        (const std::shared_ptr<RingtonePlayerInterruptCallback> &interruptCallback) = 0;

    /**
     * @brief Set the ringtone player haptics's feature
     *
     * @return Returns {@link MSERR_OK} if the haptics's feature set successfully;
     * returns an error code defined in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t SetRingtoneHapticsFeature(const RingtoneHapticsFeature &feature) = 0;

    /**
     * @brief Set the ringtone player haptics's ramp
     *
     * @return Returns {@link MSERR_OK} if the haptics's ramp set successfully;
     * returns an error code defined in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t SetRingtoneHapticsRamp(int32_t duration, float startIntensity, float endIntensity) = 0;
};


class RingtonePlayerInterruptCallback {
public:
    virtual ~RingtonePlayerInterruptCallback() = default;
    /**
     * Called when an interrupt is received.
     *
     * @param interruptEvent Indicates the InterruptEvent information needed by client.
     * For details, refer InterruptEventInternal struct in audio_info.h
     */
    virtual void OnInterrupt(const AudioStandard::InterruptEvent &interruptEvent) = 0;
};
} // namespace Media
} // namespace OHOS
#endif // RINGTONE_PLAYER_H
