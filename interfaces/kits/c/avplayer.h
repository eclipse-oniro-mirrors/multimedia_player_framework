/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

/**
 * @addtogroup AVPlayer
 * @{
 *
 * @brief Provides APIs of Playback capability for Media Source.
 *
 * @Syscap SystemCapability.Multimedia.Media.AVPlayer
 * @since 11
 * @version 1.0
 */

/**
 * @file avplayer.h
 *
 * @brief Defines the avplayer APIs. Uses the Native APIs provided by Media AVPlayer
 *        to play the media source.
 *
 * @kit MediaKit
 * @library libavplayer.so
 * @since 11
 * @version 1.0
 */

#ifndef MULTIMEDIA_PLAYER_FRAMEWORK_NATIVE_AVPLAYER_H
#define MULTIMEDIA_PLAYER_FRAMEWORK_NATIVE_AVPLAYER_H

#include <stdint.h>
#include <stdio.h>
#include "native_averrors.h"
#include "avplayer_base.h"
#include "native_audiostream_base.h"
#include "native_avcodec_base.h"


#ifdef __cplusplus
extern "C" {
#endif

typedef struct MediaKeySession MediaKeySession;
typedef struct DRM_MediaKeySystemInfo DRM_MediaKeySystemInfo;
typedef void (*Player_MediaKeySystemInfoCallback)(OH_AVPlayer *play, DRM_MediaKeySystemInfo* mediaKeySystemInfo);

/**
 * @brief Create a player
 * @syscap SystemCapability.Multimedia.Media.AVPlayer
 * @return Returns a pointer to an OH_AVPlayer instance
 * @since 11
 * @version 1.0
*/
OH_AVPlayer *OH_AVPlayer_Create(void);

/**
 * @brief Sets the playback source for the player. The corresponding source can be http url
 * @syscap SystemCapability.Multimedia.Media.AVPlayer
 * @param player Pointer to an OH_AVPlayer instance
 * @param url Indicates the playback source.
 * @return Returns {@link AV_ERR_OK} if the url is set successfully; returns an error code defined
 * in {@link native_averrors.h} otherwise.
 * @since 11
 * @version 1.0
 */
OH_AVErrCode OH_AVPlayer_SetURLSource(OH_AVPlayer *player, const char *url);

/**
 * @brief Sets the playback media file descriptor source for the player.
 * @syscap SystemCapability.Multimedia.Media.AVPlayer
 * @param player Pointer to an OH_AVPlayer instance
 * @param fd Indicates the file descriptor of media source.
 * @param offset Indicates the offset of media source in file descriptor.
 * @param size Indicates the size of media source.
 * @return Returns {@link AV_ERR_OK} if the fd source is set successfully; returns an error code defined
 * in {@link native_averrors.h} otherwise.
 * @since 11
 * @version 1.0
 */
OH_AVErrCode OH_AVPlayer_SetFDSource(OH_AVPlayer *player, int32_t fd, int64_t offset, int64_t size);

/**
 * @brief Prepares the playback environment and buffers media data asynchronous.
 *
 * This function must be called after {@link SetSource}.
 *
 * @syscap SystemCapability.Multimedia.Media.AVPlayer
 * @param player Pointer to an OH_AVPlayer instance
 * @return Returns {@link AV_ERR_OK} if {@link Prepare} is successfully added to the task queue;
 * returns an error code defined in {@link native_averrors.h} otherwise.
 * @since 11
 * @version 1.0
 */
OH_AVErrCode OH_AVPlayer_Prepare(OH_AVPlayer *player);

/**
 * @brief Start playback.
 *
 * This function must be called after {@link Prepare}. If the player state is <b>Prepared</b>,
 * this function is called to start playback.
 *
 * @syscap SystemCapability.Multimedia.Media.AVPlayer
 * @param player Pointer to an OH_AVPlayer instance
 * @return Returns {@link AV_ERR_OK} if the playback is started; otherwise returns an error code defined
 * in {@link native_averrors.h} otherwise.
 * @since 11
 * @version 1.0
 */
OH_AVErrCode OH_AVPlayer_Play(OH_AVPlayer *player);

/**
 * @brief Pauses playback.
 * @syscap SystemCapability.Multimedia.Media.AVPlayer
 * @param player Pointer to an OH_AVPlayer instance
 * @return Returns {@link AV_ERR_OK} if {@link Pause} is successfully added to the task queue;
 * returns an error code defined in {@link native_averrors.h} otherwise.
 * @since 11
 * @version 1.0
 */
OH_AVErrCode OH_AVPlayer_Pause(OH_AVPlayer *player);

/**
 * @brief Stop playback.
 * @syscap SystemCapability.Multimedia.Media.AVPlayer
 * @param player Pointer to an OH_AVPlayer instance
 * @return Returns {@link AV_ERR_OK} if {@link Stop} is successfully added to the task queue;
 * returns an error code defined in {@link native_averrors.h} otherwise.
 * @since 11
 * @version 1.0
 */
OH_AVErrCode OH_AVPlayer_Stop(OH_AVPlayer *player);

/**
 * @brief Restores the player to the initial state.
 *
 * After the function is called, add a playback source by calling {@link SetSource},
 * call {@link Play} to start playback again after {@link Prepare} is called.
 *
 * @syscap SystemCapability.Multimedia.Media.AVPlayer
 * @param player Pointer to an OH_AVPlayer instance
 * @return Returns {@link AV_ERR_OK} if {@link Reset} is successfully added to the task queue;
 * returns an error code defined in {@link native_averrors.h} otherwise.
 * @since 11
 * @version 1.0
 */
OH_AVErrCode OH_AVPlayer_Reset(OH_AVPlayer *player);

/**
 * @brief Releases player resources async
 *
 *  Asynchronous release guarantees the performance
 *  but cannot ensure whether the surfacebuffer is released.
 *  The caller needs to ensure the life cycle security of the surface
 *
 * @syscap SystemCapability.Multimedia.Media.AVPlayer
 * @param player Pointer to an OH_AVPlayer instance
 * @return Returns {@link AV_ERR_OK} if {@link Release} is successfully added to the task queue;
 * returns an error code defined in {@link native_averrors.h} otherwise.
 * @since 11
 * @version 1.0
 */
OH_AVErrCode OH_AVPlayer_Release(OH_AVPlayer *player);

/**
 * @brief Releases player resources sync
 *
 * Synchronous release ensures effective release of surfacebuffer
 * but this interface will take a long time (when the engine is not idle state)
 * requiring the caller to design an asynchronous mechanism by itself
 *
 * @syscap SystemCapability.Multimedia.Media.AVPlayer
 * @param player Pointer to an OH_AVPlayer instance
 * @return Returns {@link AV_ERR_OK} if the playback is released; returns an error code defined
 * in {@link native_averrors.h} otherwise.
 * @since 11
 * @version 1.0
 */
OH_AVErrCode OH_AVPlayer_ReleaseSync(OH_AVPlayer *player);

/**
 * @brief Sets the volume of the player.
 *
 * This function can be used during playback or pause. The value <b>0</b> indicates no sound,
 * and <b>1</b> indicates the original volume. If no audio device is started or no audio
 * stream exists, the value <b>-1</b> is returned.
 *
 * @syscap SystemCapability.Multimedia.Media.AVPlayer
 * @param player Pointer to an OH_AVPlayer instance
 * @param leftVolume Indicates the target volume of the left audio channel to set,
 *        ranging from 0 to 1. each step is 0.01.
 * @param rightVolume Indicates the target volume of the right audio channel to set,
 *        ranging from 0 to 1. each step is 0.01.
 * @return Returns {@link AV_ERR_OK} if the volume is set; returns an error code defined
 * in {@link native_averrors.h} otherwise.
 * @since 11
 * @version 1.0
 */
OH_AVErrCode OH_AVPlayer_SetVolume(OH_AVPlayer *player, float leftVolume, float rightVolume);

/**
 * @brief Changes the playback position.
 *
 * This function can be used during play or pause.
 *
 * @syscap SystemCapability.Multimedia.Media.AVPlayer
 * @param player Pointer to an OH_AVPlayer instance
 * @param mSeconds Indicates the target playback position, accurate to milliseconds.
 * @param mode Indicates the player seek mode. For details, see {@link AVPlayerSeekMode}.
 * @return Returns {@link AV_ERR_OK} if the seek is done; returns an error code defined
 * in {@link native_averrors.h} otherwise.
 * @since 11
 * @version 1.0
*/
OH_AVErrCode OH_AVPlayer_Seek(OH_AVPlayer *player, int32_t mSeconds, AVPlayerSeekMode mode);

/**
 * @brief Obtains the playback position, accurate to millisecond.
 * @syscap SystemCapability.Multimedia.Media.AVPlayer
 * @param player Pointer to an OH_AVPlayer instance
 * @param currentTime Indicates the playback position.
 * @return Returns {@link AV_ERR_OK} if the current position is get; returns an error code defined
 * in {@link native_averrors.h} otherwise.
 * @since 11
 * @version 1.0
 */
OH_AVErrCode OH_AVPlayer_GetCurrentTime(OH_AVPlayer *player, int32_t *currentTime);

/**
 * @brief get the video width.
 * @syscap SystemCapability.Multimedia.Media.AVPlayer
 * @param player Pointer to an OH_AVPlayer instance
 * @param videoWidth The video width
 * @return Returns {@link AV_ERR_OK} if the current position is get; returns an error code defined
 * in {@link native_averrors.h} otherwise.
 * @since 11
 * @version 1.0
 */
OH_AVErrCode OH_AVPlayer_GetVideoWidth(OH_AVPlayer *player, int32_t *videoWidth);

/**
 * @brief get the video height.
 * @syscap SystemCapability.Multimedia.Media.AVPlayer
 * @param player Pointer to an OH_AVPlayer instance
 * @param videoHeight The video height
 * @return Returns {@link AV_ERR_OK} if the current position is get; returns an error code defined
 * in {@link native_averrors.h} otherwise.
 * @since 11
 * @version 1.0
 */
OH_AVErrCode OH_AVPlayer_GetVideoHeight(OH_AVPlayer *player, int32_t *videoHeight);

/**
 * @brief set the player playback rate
 * @syscap SystemCapability.Multimedia.Media.AVPlayer
 * @param player Pointer to an OH_AVPlayer instance
 * @param speed the rate mode {@link AVPlaybackSpeed} which can set.
 * @return Returns {@link AV_ERR_OK} if the playback rate is set successful; returns an error code defined
 * in {@link native_averrors.h} otherwise.
 * @since 11
 * @version 1.0
 */
OH_AVErrCode OH_AVPlayer_SetPlaybackSpeed(OH_AVPlayer *player, AVPlaybackSpeed speed);

/**
 * @brief Sets playback parameters.
 * Supported states: prepared/playing/paused/completed.
 * @syscap SystemCapability.Multimedia.Media.AVPlayer
 * @param player Pointer to OH_AVPlayer instance
 * @param rate Playback rate
 * @return OH_AVErrCode Operation result code
 *         {@link AV_ERR_OK} if the execution is successful.
 *         {@link AV_ERR_OPERATE_NOT_PERMIT} if called in unsupported state or during live streaming.
 *         {@link AV_ERR_INVALID_VAL} if input player or params is nullptr, or parameter is out of range.
 * @since 20
 */
OH_AVErrCode OH_AVPlayer_SetPlaybackRate(OH_AVPlayer *player, float rate);

/**
 * @brief get the current player playback rate
 * @syscap SystemCapability.Multimedia.Media.AVPlayer
 * @param player Pointer to an OH_AVPlayer instance
 * @param speed the rate mode {@link AVPlaybackSpeed} which can get.
 * @return Returns {@link AV_ERR_OK} if the current player playback rate is get; returns an error code defined
 * in {@link native_averrors.h} otherwise.
 * @since 11
 * @version 1.0
 */
OH_AVErrCode OH_AVPlayer_GetPlaybackSpeed(OH_AVPlayer *player, AVPlaybackSpeed *speed);

/**
 * @brief Set the renderer information of the player's audio renderer
 * @param player Pointer to an OH_AVPlayer instance
 * @param streamUsage The value {@link OH_AudioStream_Usage} used for the stream usage of the player audio render.
 * @return Function result code.
 *     {@link AV_ERR_OK} if the execution is successful.
 *     {@link AV_ERR_INVALID_VAL} if input player is nullptr or streamUsage value is invalid.
 * @since 12
 * @version 1.0
 */
OH_AVErrCode OH_AVPlayer_SetAudioRendererInfo(OH_AVPlayer *player, OH_AudioStream_Usage streamUsage);

/**
 * @brief Set the volume mode of the player's audio renderer
 * @param player Pointer to an OH_AVPlayer instance
 * @param mode The value {@link OH_AudioStream_VolumeMode} used for the volume mode of the player audio render.
 * @return Function result code.
 *     {@link AV_ERR_OK} if the execution is successful.
 *     {@link AV_ERR_INVALID_VAL} if input player is nullptr or streamUsage value is invalid.
 * @since 16
 * @version 1.0
 */
OH_AVErrCode OH_AVPlayer_SetVolumeMode(OH_AVPlayer *player, OH_AudioStream_VolumeMode mode);

/**
 * @brief Set the interruption mode of the player's audio stream
 * @param player Pointer to an OH_AVPlayer instance
 * @param interruptMode The value {@link OH_AudioInterrupt_Mode} used for the interruption mode of
 *                      the player audio stream.
 * @return Function result code.
 *     {@link AV_ERR_OK} if the execution is successful.
 *     {@link AV_ERR_INVALID_VAL} if input player is nullptr or interruptMode value is invalid.
 * @since 12
 * @version 1.0
 */
OH_AVErrCode OH_AVPlayer_SetAudioInterruptMode(OH_AVPlayer *player, OH_AudioInterrupt_Mode interruptMode);

/**
 * @brief Set the effect mode of the player's audio stream
 * @param player Pointer to an OH_AVPlayer instance
 * @param effectMode The value {@link OH_AudioStream_AudioEffectMode} used for the effect mode of
 *                   the player audio stream.
 * @return Function result code.
 *     {@link AV_ERR_OK} if the execution is successful.
 *     {@link AV_ERR_INVALID_VAL} if input player is nullptr or effectMode value is invalid.
 * @since 12
 * @version 1.0
 */
OH_AVErrCode OH_AVPlayer_SetAudioEffectMode(OH_AVPlayer *player, OH_AudioStream_AudioEffectMode effectMode);

/**
 * @brief set the bit rate use for hls player
 *
 * the playback bitrate expressed in bits per second, expressed in bits per second,
 * which is only valid for HLS protocol network flow. By default,
 * the player will select the appropriate bit rate and speed according to the network connection.
 * report the effective bit rate linked list by "INFO_TYPE_BITRATE_COLLECT"
 * set and select the specified bit rate, and select the bit rate that is less than and closest
 * to the specified bit rate for playback. When ready, read it to query the currently selected bit rate.
 *
 * @syscap SystemCapability.Multimedia.Media.AVPlayer
 * @param player Pointer to an OH_AVPlayer instance
 * @param bitRate the bit rate, The unit is bps.
 * @return Returns {@link AV_ERR_OK} if the bit rate is set successfully; returns an error code defined
 * in {@link native_averrors.h} otherwise.
 * @since 11
 * @version 1.0
 */
OH_AVErrCode OH_AVPlayer_SelectBitRate(OH_AVPlayer *player, uint32_t bitRate);

/**
 * @brief Method to set the surface.
 * @syscap SystemCapability.Multimedia.Media.AVPlayer
 * @param player Pointer to an OH_AVPlayer instance
 * @param window A pointer to a OHNativeWindow instance, see {@link OHNativeWindow}
 * @return Returns {@link AV_ERR_OK} if the surface is set; returns an error code defined
 * in {@link native_averrors.h} otherwise.
 * @since 11
 * @version 1.0
 */
OH_AVErrCode  OH_AVPlayer_SetVideoSurface(OH_AVPlayer *player, OHNativeWindow *window);

/**
 * @brief Obtains the total duration of media files, accurate to milliseconds.
 * @syscap SystemCapability.Multimedia.Media.AVPlayer
 * @param player Pointer to an OH_AVPlayer instance
 * @param duration Indicates the total duration of media files.
 * @return Returns {@link AV_ERR_OK} if the current duration is get; returns an error code defined
 * in {@link native_averrors.h} otherwise.
 * @since 11
 * @version 1.0
 */
OH_AVErrCode OH_AVPlayer_GetDuration(OH_AVPlayer *player, int32_t *duration);

/**
 * @brief get current playback state.
 * @syscap SystemCapability.Multimedia.Media.AVPlayer
 * @param player Pointer to an OH_AVPlayer instance
 * @param state the current playback state
 * @return Returns {@link AV_ERR_OK} if the current duration is get; returns an error code defined
 * in {@link native_averrors.h} otherwise.
 * @since 11
 * @version 1.0
 */
OH_AVErrCode OH_AVPlayer_GetState(OH_AVPlayer *player, AVPlayerState *state);

/**
 * @brief Checks whether the player is playing.
 * @syscap SystemCapability.Multimedia.Media.AVPlayer
 * @param player Pointer to an OH_AVPlayer instance
 * @return Returns true if the playback is playing; false otherwise.
 * @since 11
 * @version 1.0
 */
bool OH_AVPlayer_IsPlaying(OH_AVPlayer *player);

/**
 * @brief Returns the value whether single looping is enabled or not .
 * @syscap SystemCapability.Multimedia.Media.AVPlayer
 * @param player Pointer to an OH_AVPlayer instance
 * @return Returns true if the playback is single looping; false otherwise.
 * @since 11
 * @version 1.0
 */
bool OH_AVPlayer_IsLooping(OH_AVPlayer *player);

/**
 * @brief Enables single looping of the media playback.
 * @syscap SystemCapability.Multimedia.Media.AVPlayer
 * @param player Pointer to an OH_AVPlayer instance
 * @param loop The switch to set loop
 * @return Returns {@link AV_ERR_OK} if the single looping is set; returns an error code defined
 * in {@link native_averrors.h} otherwise.
 * @since 11
 * @version 1.0
 */
OH_AVErrCode OH_AVPlayer_SetLooping(OH_AVPlayer *player, bool loop);

/**
 * @brief Method to set player callback.
 * @syscap SystemCapability.Multimedia.Media.AVPlayer
 * @param player Pointer to an OH_AVPlayer instance
 * @param callback object pointer.
 * @return Returns {@link AV_ERR_OK} if the playercallback is set; returns an error code defined
 * in {@link native_averrors.h} otherwise.
 * @since 11
 * @deprecated since 12
 * @useinstead {@link OH_AVPlayer_SetPlayerOnInfoCallback} {@link OH_AVPlayer_SetPlayerOnErrorCallback}
 * @version 1.0
 */
OH_AVErrCode OH_AVPlayer_SetPlayerCallback(OH_AVPlayer *player, AVPlayerCallback callback);

/**
 * @brief Select audio or subtitle track.
 *
 * By default, the first audio stream with data is played, and the subtitle track is not played.
 * After the settings take effect, the original track will become invalid. Please set subtitles
 * in prepared/playing/paused/completed state and set audio tracks in prepared state.
 *
 * @syscap SystemCapability.Multimedia.Media.AVPlayer
 * @param player Pointer to an OH_AVPlayer instance
 * @param index Track index
 * @return Returns {@link AV_ERR_OK} if selected successfully; returns an error code defined
 * in {@link native_averrors.h} otherwise.
 * @since 11
 * @version 1.0
*/
OH_AVErrCode OH_AVPlayer_SelectTrack(OH_AVPlayer *player, int32_t index);

/**
 * @brief Deselect the current audio or subtitle track.
 *
 * After audio is deselected, the default track will be played, and after subtitles are deselected,
 * they will not be played. Please set subtitles in prepared/playing/paused/completed state and set
 * audio tracks in prepared state.
 *
 * @syscap SystemCapability.Multimedia.Media.AVPlayer
 * @param player Pointer to an OH_AVPlayer instance
 * @param index Track index
 * @return Returns {@link AV_ERR_OK} if selected successfully; returns an error code defined
 * in {@link native_averrors.h} otherwise.
 * @since 11
 * @version 1.0
*/
OH_AVErrCode OH_AVPlayer_DeselectTrack(OH_AVPlayer *player, int32_t index);

/**
 * @brief Obtain the currently effective track index.
 *
 * Please get it in the prepared/playing/paused/completed state.
 *
 * @syscap SystemCapability.Multimedia.Media.AVPlayer
 * @param player Pointer to an OH_AVPlayer instance
 * @param trackType Media type.
 * @param index Track index
 * @return Returns {@link AV_ERR_OK} if the track index is get; returns an error code defined
 * in {@link native_averrors.h} otherwise.
 * @since 11
 * @version 1.0
 */
OH_AVErrCode OH_AVPlayer_GetCurrentTrack(OH_AVPlayer *player, int32_t trackType, int32_t *index);

/**
 * @brief Method to set player media key system info callback.
 * @syscap SystemCapability.Multimedia.Media.AVPlayer
 * @param player Pointer to an OH_AVPlayer instance
 * @param callback object pointer.
 * @return Returns {@link AV_ERR_OK} if the drm info callback is set; returns an error code defined
 * in {@link native_averrors.h} otherwise.
 * @since 12
 * @version 1.0
 */
OH_AVErrCode OH_AVPlayer_SetMediaKeySystemInfoCallback(OH_AVPlayer *player,
    Player_MediaKeySystemInfoCallback callback);

/**
 * @brief Obtains media key system info to create media key session.
 * @syscap SystemCapability.Multimedia.Media.AVPlayer
 * @param player Pointer to an OH_AVPlayer instance
 * @param mediaKeySystemInfo Media key system info.
 * @return Returns {@link AV_ERR_OK} if the current position is get; returns an error code defined
 * in {@link native_averrors.h} otherwise.
 * @since 12
 * @version 1.0
 */
OH_AVErrCode OH_AVPlayer_GetMediaKeySystemInfo(OH_AVPlayer *player, DRM_MediaKeySystemInfo *mediaKeySystemInfo);

/**
 * @brief Set decryption info.
 *
 * @syscap SystemCapability.Multimedia.Media.AVPlayer
 * @param player Pointer to an OH_AVPlayer instance
 * @param mediaKeySession A media key session instance with decryption function.
 * @param secureVideoPath Require secure decoder or not.
 * @return Returns AV_ERR_OK if the execution is successful,
 * otherwise returns a specific error code, refer to {@link OH_AVErrCode}
 * @since 12
 * @version 1.0
*/
OH_AVErrCode OH_AVPlayer_SetDecryptionConfig(OH_AVPlayer *player, MediaKeySession *mediaKeySession,
    bool secureVideoPath);

/**
 * @brief Method to set player information notify callback.
 * @syscap SystemCapability.Multimedia.Media.AVPlayer
 * @param player Pointer to an OH_AVPlayer instance.
 * @param callback Pointer to callback function, nullptr indicates unregister callback.
 * @param userData Pointer to user specific data.
 * @return Function result code.
 *         {@link AV_ERR_OK} if the execution is successful.
 *         {@link AV_ERR_INVALID_VAL} if input player is null or player SetOnInfoCallback failed.
 * @since 12
 */
OH_AVErrCode OH_AVPlayer_SetOnInfoCallback(OH_AVPlayer *player, OH_AVPlayerOnInfoCallback callback, void *userData);

/**
 * @brief Method to set player error callback.
 * @syscap SystemCapability.Multimedia.Media.AVPlayer
 * @param player Pointer to an OH_AVPlayer instance.
 * @param callback Pointer to callback function, nullptr indicates unregister callback.
 * @param userData Pointer to user specific data.
 * @return Function result code.
 *         {@link AV_ERR_OK} if the execution is successful.
 *         {@link AV_ERR_INVALID_VAL} if input player is null or player SetOnErrorCallback failed.
 * @since 12
 */
OH_AVErrCode OH_AVPlayer_SetOnErrorCallback(OH_AVPlayer *player, OH_AVPlayerOnErrorCallback callback, void *userData);

/**
 * @brief Sets the loudness gain of current media. The default gain is 0.0 dB.
 * This API can be called only when the AVPlayer is in the prepared, playing, paused completed or stopped state.
 * The default loudness gain is 0.0dB. The stream usage of the player must be
 * {@link OH_AudioStream_Usage#AUDIOSTREAM_USAGE_MUSIC}, {@link OH_AudioStream_Usage#AUDIOSTREAM_USAGE_MOVIE}
 * or {@link OH_AudioStream_Usage#AUDIOSTREAM_USAGE_AUDIOBOOK}.
 * The latency mode of the audio renderer must be {@link OH_AudioStream_LatencyMode#AUDIOSTREAM_LATENCY_MODE_NORMAL}.
 * If AudioRenderer is played through the high-resolution pipe, this operation is not supported.
 *
 * @param player Pointer to an <b>OH_AVPlayer</b> instance.
 * @param loudnessGain Loudness gain to set which changes from -90.0 to 24.0, expressing in dB.
 * @return Function result code:
 *         {@link AV_ERR_OK} If the execution is successful.
 *         {@link AV_ERR_INVALID_VAL}:The value of <b>player</b> is a null pointer or
 *                                    the value of <b>loudnessGain</b> is invalid.
 *         {@link AV_ERR_INVALID_STATE}: The function is called in an incorrect state. or the stream usage of
 *                                      audioRendererInfo is not one of {@link StreamUsage#STREAM_USAGE_MUSIC},
 *                                 {@link StreamUsage#STREAM_USAGE_MOVIE} or {@link StreamUsage#STREAM_USAGE_AUDIOBOOK}.
 *         {@link AV_ERR_SERVICE_DIED}:  System errors such as media service breakdown.
 * @since 21
 */
OH_AVErrCode OH_AVPlayer_SetLoudnessGain(OH_AVPlayer *player, float loudnessGain);

/**
 * @brief Set the media source of the player. The data of this media source is provided by the application.
 * @param {OH_AVPlayer*} player Pointer to an OH_AVPlayer instance
 * @param {OH_AVDataSourceExt*} datasrc Pointer to an OH_AVDataSourceExt instance
 * @param {void*} userData The handle passed in by the user is used to pass in the callback
 * @return Function result code.
 *         {@link AV_ERR_OK} if the execution is successful.
 *         {@link AV_ERR_INVALID_VAL} if input player is nullptr or player setDataSource failed.
 * @since 21
 */
OH_AVErrCode OH_AVPlayer_SetDataSource(OH_AVPlayer *player, OH_AVDataSourceExt* datasrc, void* userData);

#ifdef __cplusplus
}
#endif

#endif // MULTIMEDIA_PLAYER_FRAMEWORK_NATIVE_AVPLAYER_H
