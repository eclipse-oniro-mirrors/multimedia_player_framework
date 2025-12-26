/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef I_PLAYER_SERVICE_H
#define I_PLAYER_SERVICE_H

#include "player.h"
#include "refbase.h"

namespace OHOS {
namespace Media {
class IPlayerService {
public:
    virtual ~IPlayerService() = default;

    /**
     * @brief Sets the player producer type.
     *
     * @param producer Indicates the player producer type.
     * @return Returns {@link MSERR_OK} if the producer is set successfully; returns an error code defined
     * in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t SetPlayerProducer(const PlayerProducer producer) = 0;

    /**
     * @brief Sets the playback source for the player. The corresponding source can be local file url.
     *
     * @param url Indicates the playback source.
     * @return Returns {@link MSERR_OK} if the url is set successfully; returns an error code defined
     * in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t SetSource(const std::string &url) = 0;
    /**
     * @brief Sets the playback media data source for the player.
     *
     * @param dataSrc Indicates the media data source. in {@link media_data_source.h}
     * @return Returns {@link MSERR_OK} if the dataSrc is set successfully; returns an error code defined
     * in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t SetSource(const std::shared_ptr<IMediaDataSource> &dataSrc) = 0;
    /**
     * @brief Sets the playback media file descriptor source for the player.
     *
     * @param fd Indicates the file descriptor of media source.
     * @param offset Indicates the offset of media source in file descriptor.
     * @param size Indicates the size of media source.
     * @return Returns {@link MSERR_OK} if the fd source is set successfully; returns an error code defined
     * in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t SetSource(int32_t fd, int64_t offset, int64_t size) = 0;
    /**
     * @brief Add a subtitle source for the player. The corresponding source can be local file url.
     *
     * @param url Indicates the subtitle source.
     * @return Returns {@link MSERR_OK} if the url is set successfully; returns an error code defined
     * in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t AddSubSource(const std::string &url) = 0;
    /**
     * @brief Add a playback subtitle file descriptor source for the player.
     *
     * @param fd Indicates the file descriptor of subtitle source.
     * @param offset Indicates the offset of subtitle source in file descriptor.
     * @param size Indicates the size of subtitle source.
     * @return Returns {@link MSERR_OK} if the fd source is set successfully; returns an error code defined
     * in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t AddSubSource(int32_t fd, int64_t offset, int64_t size) = 0;
    /**
     * @brief Start playback.
     *
     * This function must be called after {@link Prepare}. If the player state is <b>Prepared</b>,
     * this function is called to start playback.
     *
     * @return Returns {@link MSERR_OK} if the playback is started; otherwise returns an error code defined
     * in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t Play() = 0;

    /**
     * @brief Prepares the playback environment and buffers media data asynchronous.
     *
     * This function must be called after {@link SetSource}.
     *
     * @return Returns {@link MSERR_OK} if {@link Prepare} is successfully added to the task queue;
     * returns an error code defined in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t Prepare() = 0;

    /**
     * @brief Enables render video first frame of the media playback.
     *
     * @return Returns {@link MSERR_OK} if the single display is set; returns an error code defined
     * in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t SetRenderFirstFrame(bool display)
    {
        (void)display;
        return 0;
    }

    /**
     * @brief Specify the start and end time to play
     * This function must be called after {@link SetSource}.
     * This function is called to set start and end time
     *
     * @return Returns {@link MSERR_OK} if the single display is set; returns an error code defined
     * in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t SetPlayRange(int64_t start, int64_t end)
    {
        (void)start;
        (void)end;
        return 0;
    }

    /**
     * @brief Set playback start position and end position.
     * Use the specified seek mode to jump to the playback start position,
     * currently support SEEK_PREVIOUS_SYNC and SEEK_CLOSEST, other values are invalid,
     * This function must be called after {@link SetSource}.
     *
     * @return Returns {@link MSERR_OK} if the single display is set; returns an error code defined
     * in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t SetPlayRangeWithMode(int64_t start, int64_t end, PlayerSeekMode mode)
    {
        (void)start;
        (void)end;
        (void)mode;
        return 0;
    }

    /**
     * @brief Prepares the playback environment and buffers media data asynchronous.
     *
     * This function must be called after {@link SetSource}.
     *
     * @return Returns {@link MSERR_OK} if {@link PrepareAsync} is successfully added to the task queue;
     * returns an error code defined in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t PrepareAsync() = 0;

    /**
     * @brief Pauses playback.
     *
     * @return Returns {@link MSERR_OK} if {@link Pause} is successfully added to the task queue;
     * returns an error code defined in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t Pause() = 0;

    /**
     * @brief Stop playback.
     *
     * @return Returns {@link MSERR_OK} if {@link Stop} is successfully added to the task queue;
     * returns an error code defined in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t Stop() = 0;

    /**
     * @brief Restores the player to the initial state.
     *
     * After the function is called, add a playback source by calling {@link SetSource},
     * call {@link Play} to start playback again after {@link Prepare} is called.
     *
     * @return Returns {@link MSERR_OK} if {@link Reset} is successfully added to the task queue;
     * returns an error code defined in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t Reset() = 0;

    /**
     * @brief Releases player resources async
     *
     * @return Returns {@link MSERR_OK} if {@link Release} is successfully added to the task queue;
     * returns an error code defined in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t Release() = 0;

    /**
     * @brief Releases player resources sync
     *
     * @return Returns {@link MSERR_OK} if the playback is released; returns an error code defined
     * in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t ReleaseSync()
    {
        return ERR_OK;
    }

    /**
     * @brief Sets the volume of the player.
     *
     * This function can be used during playback or pause. The value <b>0</b> indicates no sound,
     * and <b>1</b> indicates the original volume. If no audio device is started or no audio
     * stream exists, the value <b>-1</b> is returned.
     *
     * @param leftVolume Indicates the target volume of the left audio channel to set,
     *        ranging from 0 to 1. each step is 0.01.
     * @param rightVolume Indicates the target volume of the right audio channel to set,
     *        ranging from 0 to 1. each step is 0.01.
     * @return Returns {@link MSERR_OK} if the volume is set; returns an error code defined
     * in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t SetVolume(float leftVolume, float rightVolume) = 0;

    virtual int32_t SetVolumeMode(int32_t mode) = 0;

    /**
     * @brief Changes the playback position.
     *
     * This function can be used during play or pause.
     *
     * @param mSeconds Indicates the target playback position, accurate to second.
     * @param mode Indicates the player seek mode. For details, see {@link PlayerSeekMode}.
     * @return Returns {@link MSERR_OK} if the seek is done; returns an error code defined
     * in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
    */
    virtual int32_t Seek(int32_t mSeconds, PlayerSeekMode mode) = 0;

    /**
     * @brief Obtains the playback position, accurate to millisecond.
     *
     * @param currentTime Indicates the playback position.
     * @return Returns {@link MSERR_OK} if the current position is get; returns an error code defined
     * in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t GetCurrentTime(int32_t &currentTime) = 0;

    /**
     * @brief Obtains the playback position, accurate to millisecond.
     *
     * @param playbackPosition Indicates the playback position.
     * @return Returns {@link MSERR_OK} if the current position is get; returns an error code defined
     * in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t GetPlaybackPosition(int32_t &playbackPosition) = 0;

    /**
     * @brief Obtains the video track info, contains mimeType, bitRate, width, height, frameRata.
     *
     * @param video track info vec.
     * @return Returns {@link MSERR_OK} if the track info is get; returns an error code defined
     * in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t GetVideoTrackInfo(std::vector<Format> &videoTrack) = 0;

    /**
     * @brief Obtains playbackInfo, contains server_ip_address, average_download_rate,
     * download_rate, is_downloading, buffer_duration.
     *
     * @param playbackInfo.
     * @return Returns {@link MSERR_OK} if the track info is get; returns an error code defined
     * in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t GetPlaybackInfo(Format &playbackInfo) = 0;

    /**
     * @brief Obtains the audio track info, contains mimeType, bitRate, sampleRate, channels, language.
     *
     * @param audio track info vec.
     * @return Returns {@link MSERR_OK} if the track info is get; returns an error code defined
     * in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t GetAudioTrackInfo(std::vector<Format> &audioTrack) = 0;

    /**
     * @brief get the video width.
     *
     * @return Returns width if success; else returns 0
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t GetVideoWidth() = 0;

    /**
     * @brief get the video height.
     *
     * @return Returns height if success; else returns 0
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t GetVideoHeight() = 0;

    /**
     * @brief Obtains the total duration of media files, accurate to milliseconds.
     *
     * @param duration Indicates the total duration of media files.
     * @return Returns {@link MSERR_OK} if the current duration is get; returns an error code defined
     * in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t GetDuration(int32_t &duration) = 0;

    /**
     * @brief set the player playback rate
     *
     * @param mode the rate mode {@link PlaybackRateMode} which can set.
     * @return Returns {@link MSERR_OK} if the playback rate is set successfully; returns an error code defined
     * in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t SetPlaybackSpeed(PlaybackRateMode mode) = 0;

    /**
     * @brief set the player playback rate
     *
     * @param rate the rate which can set.
     * @return Returns {@link MSERR_OK} if the playback rate is set successfully; returns an error code defined
     * in {@link media_errors.h} otherwise.
     */
    virtual int32_t SetPlaybackRate(float rate) = 0;

    virtual int32_t SetMediaSource(const std::shared_ptr<AVMediaSource> &mediaSource, AVPlayStrategy strategy) = 0;
    /**
     * @brief set the bit rate use for hls player
     *
     * @param bitRate the bit rate.
     * @return Returns {@link MSERR_OK} if the bit rate is set successfully; returns an error code defined
     * in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t SelectBitRate(uint32_t bitRate) = 0;
    
    /**
     * @brief get the current player playback rate
     *
     * @param mode the rate mode {@link PlaybackRateMode} which can get.
     * @return Returns {@link MSERR_OK} if the current player playback rate is get; returns an error code defined
     * in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t GetPlaybackSpeed(PlaybackRateMode &mode) = 0;

    /**
     * @brief get the current player playback rate
     *
     * @param rate the rate which can get.
     * @return Returns {@link MSERR_OK} if the current player playback rate is get; returns an error code defined
     * in {@link media_errors.h} otherwise.
     */
    virtual int32_t GetPlaybackRate(float &rate)
    {
        (void)rate;
        return 0;
    }

    /**
     * @brief add for drm, set decrypt module
     *
     * @param keySessionProxy is the sptr will be setted to playerserver.
     * @param svp bool.
     * @return Returns {@link MSERR_OK} if set successfully; returns an error code defined
     * in {@link media_errors.h} otherwise.
     * @since
     * @version
     */
    virtual int32_t SetDecryptConfig(const sptr<DrmStandard::IMediaKeySessionService> &keySessionProxy,
        bool svp) = 0;

#ifdef SUPPORT_VIDEO
    /**
     * @brief Method to set the surface.
     *
     * @param surface pointer of the surface.
     * @return Returns {@link MSERR_OK} if the surface is set; returns an error code defined
     * in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t SetVideoSurface(sptr<Surface> surface) = 0;
#endif

    /**
     * @brief Checks whether the player is playing.
     *
     * @return Returns true if the playback is playing; false otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual bool IsPlaying() = 0;

    /**
     * @brief Returns the value whether single looping is enabled or not .
     *
     * @return Returns true if the playback is single looping; false otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual bool IsLooping() = 0;

    /**
     * @brief Enables single looping of the media playback.
     *
     * @return Returns {@link MSERR_OK} if the single looping is set; returns an error code defined
     * in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t SetLooping(bool loop) = 0;

    /**
     * @brief Enables setting the renderer descriptor for the current media
     *
     * @return Returns {@link MSERR_OK} if the renderer descriptor is set; returns an error code defined
     * in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t SetParameter(const Format &param) = 0;

    /**
     * @brief Method to set player callback.
     *
     * @param callback object pointer.
     * @return Returns {@link MSERR_OK} if the playercallback is set; returns an error code defined
     * in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t SetPlayerCallback(const std::shared_ptr<PlayerCallback> &callback) = 0;

    /**
     * @brief Select audio or subtitle track.
     * By default, the first audio stream with data is played, and the subtitle track is not played.
     * After the settings take effect, the original track will become invalid.
     * Please set it in the prepared/playing/paused/completed state.
     *
     * @param index Track index, reference {@link #GetAudioTrackInfo} and {@link #GetVideoTrackInfo}.
     * @return Returns {@link MSERR_OK} if selected successfully; returns an error code defined
     * in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
    */
    virtual int32_t SelectTrack(int32_t index, PlayerSwitchMode mode = PlayerSwitchMode::SWITCH_SMOOTH) = 0;

    /**
     * @brief Deselect the current audio or subtitle track.
     * After audio is deselected, the default track will be played, and after subtitles are deselected,
     * they will not be played. Please set it in the prepared/playing/paused/completed state.
     *
     * @param index Track index, reference {@link #GetAudioTrackInfo} and {@link #GetVideoTrackInfo}.
     * @return Returns {@link MSERR_OK} if selected successfully; returns an error code defined
     * in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
    */
    virtual int32_t DeselectTrack(int32_t index) = 0;

    /**
     * @brief Obtain the currently effective track index.
     *
     * @param trackType Media type.
     * @param index Track index, reference {@link #GetAudioTrackInfo} and {@link #GetVideoTrackInfo}.
     * @return Returns {@link MSERR_OK} if the track index is get; returns an error code defined
     * in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t GetCurrentTrack(int32_t trackType, int32_t &index) = 0;

    /**
     * @brief Obtains the subtitle track info, contains mimeType, type, language.
     *
     * @param subtitle track info vec.
     * @return Returns {@link MSERR_OK} if the track info is get; returns an error code defined
     * in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t GetSubtitleTrackInfo(std::vector<Format> &subtitleTrack) = 0;

    /**
     * @brief set the playback strategy
     * the playback strategy includes five fileds:
     * preferredWidth: Preferred width, which is of the int type, for example, 1080.
     * preferredHeight: Preferred height, which is of the int type, for example, 1920.
     * preferredBufferDuration: Preferred buffer duration, in seconds. The value ranges from 1 to 20.
     * preferredHdr: Whether HDR is preferred. The value true means that HDR is preferred, and false means the opposite.
     * mutedMediaType: The mediaType to be muted before play, which is of the MediaType type,
     * for example, MediaType::MEDIA_TYPE_AUD.
     * @param playbackStrategy the playback strategy.
     * @return Returns {@link MSERR_OK} if the playback strategy is set successfully; returns an error code defined
     * in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t SetPlaybackStrategy(AVPlayStrategy playbackStrategy)
    {
        (void)playbackStrategy;
        return 0;
    }

    virtual int32_t SetMediaMuted(MediaType mediaType, bool isMuted)
    {
        (void)mediaType;
        (void)isMuted;
        return 0;
    }

    /**
     * @brief Enable or disable super resolution.
     *
     * @return Returns {@link MSERR_OK} if super resolution is set; returns an error code defined
     * in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t SetSuperResolution(bool enabled)
    {
        (void)enabled;
        return 0;
    }

    /**
     * @brief Set video window size for super-resolution.
     *
     * @return Returns {@link MSERR_OK} if video window size is set; returns an error code defined
     * in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t SetVideoWindowSize(int32_t width, int32_t height)
    {
        (void)width;
        (void)height;
        return 0;
    }

    /**
     * @brief Set get max ampliutude callback status.
     *
     * @param status callback status.
     * @return Returns {@link MSERR_OK} if the callback status is set; returns an error code defined
     * in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t SetMaxAmplitudeCbStatus(bool status)
    {
        (void)status;
        return 0;
    }
        
    /**
     * @brief set get device change callback status.
     *
     * @return Returns {@link MSERR_OK} if the single display is set; returns an error code defined
     * in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t SetDeviceChangeCbStatus(bool status)
    {
        (void)status;
        return 0;
    }
    /**
     * @brief Obtain the api version of application.
     *
     * @return Returns {@link MSERR_OK} if the current api version is get; returns an error code defined
     * in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t GetApiVersion(int32_t &apiVersion)
    {
        (void)apiVersion;
        return 0;
    }

    /**
     * @brief Checks whether the player supports SeekContinuous.
     *
     * @return Returns true if the player supports SeekContinuous; false otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual bool IsSeekContinuousSupported() = 0;

    /**
     * @brief Obtains the playbackStatisticMetrics, contains prepare_duration, resource_connection_duration,
     * first_frame_decapsulation_duration, total_playback_time, loading_requests_count, total_loading_time,
     * total_loading_bytes, stalling_count, total_stalling_time.
     *
     * @param playbackStatisticMetrics.
     * @return Returns {@link MSERR_OK} if the statistic metrics is get; returns an error code defined
     * in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t GetPlaybackStatisticMetrics(Format& playbackStatisticMetrics)
    {
        (void)playbackStatisticMetrics;
        return 0;
    }

    /**
     * @brief Set get sei message callback status.
     *
     * @param status callback status.
     * @return Returns {@link MSERR_OK} if the callback status is set; returns an error code defined
     * in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t SetSeiMessageCbStatus(bool status, const std::vector<int32_t> &payloadTypes)
    {
        (void)status;
        (void)payloadTypes;
        return 0;
    }
    /**
     * @brief Get memory usage.
     *
     * @return Returns memory usage KB.
     * @since 1.0
     * @version 1.0
     */
    virtual uint32_t GetMemoryUsage()
    {
        return 0;
    }

    /**
     * @brief Enables or disables the report of media progress.
     *
     * @param enable Indicates whether to enable the report of media progress.
     * @return Returns {@link MSERR_OK} if the report of media progress is enabled or disabled; returns an error code
     * defined in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t EnableReportMediaProgress(bool enable)
    {
        (void)enable;
        return 0;
    }

    /**
     * @brief Enables or disables the report of audio interrupt during frozen state.
     *
     * @param enable Indicates whether to enable the report of audio interrupt during frozen state.
     * @return Returns {@link MSERR_OK} if the report of audio interrupt is enabled or disabled; returns an error code
     * defined in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t EnableReportAudioInterrupt(bool enable)
    {
        (void)enable;
        return 0;
    }

    virtual int32_t Freeze()
    {
        return 0;
    }

    virtual int32_t UnFreeze()
    {
        return 0;
    }
    
    virtual int32_t SetStartFrameRateOptEnabled(bool enabled)
    {
        (void)enabled;
        return 0;
    }

    virtual int32_t SetCameraPostprocessing(bool isOpen)
    {
        (void)isOpen;
        return 0;
    }

    virtual int32_t ForceLoadVideo(bool /* enabled */)
    {
        return 0;
    }

    /**
     * @brief Set video reopen fd.
     *
     * @return Returns {@link MSERR_OK} if video reopen fd is set; returns an error code defined
     * in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t SetReopenFd(int32_t fd)
    {
        (void)fd;
        return 0;
    }
 
    /**
     * @brief Enable or disable camera post process.
     *
     * @return Returns {@link MSERR_OK} if enable camera post process is set; returns an error code defined
     * in {@link media_errors.h} otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t EnableCameraPostprocessing()
    {
        return 0;
    }

    virtual int32_t SetLoudnessGain(float loudnessGain)
    {
        (void)loudnessGain;
        return 0;
    }
    
    virtual int32_t GetGlobalInfo(std::shared_ptr<Meta> &globalInfo)
    {
        (void)globalInfo;
        return 0;
    }
    
    virtual int32_t GetMediaDescription(Format &format)
    {
        (void)format;
        return 0;
    }

    virtual int32_t GetTrackDescription(Format &format, uint32_t trackIndex)
    {
        (void)format;
        (void)trackIndex;
        return 0;
    }

    virtual int32_t GetCurrentPresentationTimestamp(int64_t &currentPresentation)
    {
        (void) currentPresentation;
        return 0;
    }
};
} // namespace Media
} // namespace OHOS
#endif // I_PLAYER_SERVICE_H
