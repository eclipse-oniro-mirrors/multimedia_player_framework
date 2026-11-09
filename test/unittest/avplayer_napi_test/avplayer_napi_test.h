/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef AVPLAYER_NAPI_TEST_H
#define AVPLAYER_NAPI_TEST_H

#include "gtest/gtest.h"
#include <atomic>
#include <memory>
#include <string>
#include <vector>
#include "avplayer_napi.h"

namespace OHOS {
namespace Media {

class FakePlayer : public Player {
public:
    FakePlayer() = default;
    ~FakePlayer() override = default;

    void SetResult(int32_t ret)
    {
        ret_.store(ret);
    }

    void SetApiVersionValue(int32_t version)
    {
        apiVersionValue_ = version;
    }

    void SetSeekableRangeMs(int64_t startMs, int64_t endMs)
    {
        seekRangeStartUs_.store(startMs * 1000);
        seekRangeEndUs_.store(endMs * 1000);
    }

    int32_t SetSource(const std::string &url) override
    {
        lastUrl_ = url;
        setSourceUrlCnt_++;
        return ret_.load();
    }

    int32_t SetSource(const std::shared_ptr<IMediaDataSource> &dataSrc) override
    {
        (void)dataSrc;
        setSourceDataSrcCnt_++;
        return ret_.load();
    }

    int32_t SetSource(int32_t fd, int64_t offset, int64_t size) override
    {
        lastFd_ = fd;
        lastFdOffset_ = offset;
        lastFdSize_ = size;
        setSourceFdCnt_++;
        return ret_.load();
    }

    int32_t AddSubSource(const std::string &url) override
    {
        lastSubUrl_ = url;
        addSubSourceUrlCnt_++;
        return ret_.load();
    }

    int32_t AddSubSource(int32_t fd, int64_t offset, int64_t size) override
    {
        (void)fd;
        (void)offset;
        (void)size;
        addSubSourceFdCnt_++;
        return ret_.load();
    }

    int32_t Play() override
    {
        playCnt_++;
        return ret_.load();
    }

    int32_t Prepare() override
    {
        prepareCnt_++;
        return ret_.load();
    }

    int32_t PrepareAsync() override
    {
        prepareAsyncCnt_++;
        return ret_.load();
    }

    int32_t Pause() override
    {
        pauseCnt_++;
        return ret_.load();
    }

    int32_t Stop() override
    {
        stopCnt_++;
        return ret_.load();
    }

    int32_t Reset() override
    {
        resetCnt_++;
        return ret_.load();
    }

    int32_t Release() override
    {
        releaseCnt_++;
        return ret_.load();
    }

    int32_t SetVolume(float leftVolume, float rightVolume) override
    {
        (void)leftVolume;
        (void)rightVolume;
        setVolumeCnt_++;
        return ret_.load();
    }

    int32_t SetMediaSource(const std::shared_ptr<AVMediaSource> &mediaSource, AVPlayStrategy strategy) override
    {
        (void)mediaSource;
        lastStrategy_ = strategy;
        setMediaSourceCnt_++;
        return ret_.load();
    }

    int32_t Seek(int64_t mSeconds, PlayerSeekMode mode) override
    {
        lastSeekTime_ = mSeconds;
        lastSeekMode_ = mode;
        seekCnt_++;
        return ret_.load();
    }

    int32_t GetCurrentTime(int32_t &currentTime) override
    {
        currentTime = 100;
        return ret_.load();
    }

    int32_t GetVideoTrackInfo(std::vector<Format> &videoTrack) override
    {
        Format track;
        (void)track.PutIntValue("track_index", 0);
        videoTrack.push_back(track);
        return ret_.load();
    }

    int32_t GetPlaybackInfo(Format &playbackInfo) override
    {
        (void)playbackInfo;
        return ret_.load();
    }

    int32_t GetAudioTrackInfo(std::vector<Format> &audioTrack) override
    {
        Format track;
        (void)track.PutIntValue("track_index", 1);
        audioTrack.push_back(track);
        return ret_.load();
    }

    int32_t GetVideoWidth() override
    {
        return 1920;
    }

    int32_t GetVideoHeight() override
    {
        return 1080;
    }

    int32_t GetDuration(int32_t &duration) override
    {
        duration = 10000;
        return ret_.load();
    }

    int32_t SetPlaybackSpeed(PlaybackRateMode mode) override
    {
        (void)mode;
        setSpeedCnt_++;
        return ret_.load();
    }

    int32_t GetPlaybackSpeed(PlaybackRateMode &mode) override
    {
        mode = PlaybackRateMode::SPEED_FORWARD_1_00_X;
        return ret_.load();
    }

    int32_t SelectBitRate(uint32_t bitRate) override
    {
        (void)bitRate;
        selectBitRateCnt_++;
        return ret_.load();
    }

#ifndef SUPPORT_AUDIO_ONLY
    int32_t SetVideoSurface(sptr<Surface> surface) override
    {
        (void)surface;
        setVideoSurfaceCnt_++;
        return ret_.load();
    }

    int32_t SetVideoOutput(sptr<Surface> surface) override
    {
        (void)surface;
        setVideoOutputCnt_++;
        return ret_.load();
    }
#endif

    bool IsPlaying() override
    {
        return true;
    }

    bool IsLooping() override
    {
        return false;
    }

    int32_t SetLooping(bool loop) override
    {
        (void)loop;
        setLoopingCnt_++;
        return ret_.load();
    }

    int32_t SetPlayerCallback(const std::shared_ptr<PlayerCallback> &callback) override
    {
        (void)callback;
        setPlayerCallbackCnt_++;
        return ret_.load();
    }

    int32_t SetParameter(const Format &param) override
    {
        (void)param;
        setParameterCnt_++;
        return ret_.load();
    }

    int32_t ReleaseSync() override
    {
        releaseSyncCnt_++;
        return ret_.load();
    }

    int32_t SelectTrack(int32_t index, PlayerSwitchMode mode) override
    {
        (void)index;
        (void)mode;
        selectTrackCnt_++;
        return ret_.load();
    }

    int32_t DeselectTrack(int32_t index) override
    {
        (void)index;
        deselectTrackCnt_++;
        return ret_.load();
    }

    int32_t GetCurrentTrack(int32_t trackType, int32_t &index) override
    {
        (void)trackType;
        index = 1;
        return ret_.load();
    }

    int32_t GetSubtitleTrackInfo(std::vector<Format> &subtitleTrack) override
    {
        Format track;
        (void)track.PutIntValue("track_index", 2);
        subtitleTrack.push_back(track);
        return ret_.load();
    }

    int32_t SeekToDefaultPosition() override
    {
        seekToDefaultCnt_++;
        return ret_.load();
    }

    int32_t GetSeekableRanges(std::vector<Plugins::SeekRange> &seekableRanges) override
    {
        Plugins::SeekRange range {};
        range.start = seekRangeStartUs_.load();
        range.end = seekRangeEndUs_.load();
        seekableRanges.push_back(range);
        return ret_.load();
    }

    int32_t GetLoadedRanges(std::vector<Plugins::SeekRange> &loadedRanges) override
    {
        Plugins::SeekRange range {};
        range.start = 0;
        range.end = 1000;
        loadedRanges.push_back(range);
        return ret_.load();
    }

    int32_t SetPlaybackRate(float rate) override
    {
        lastRate_ = rate;
        setPlaybackRateCnt_++;
        return ret_.load();
    }

    int32_t GetPlaybackRate(float &rate) override
    {
        rate = 1.0;
        return ret_.load();
    }

    int32_t SetPlaybackStrategy(AVPlayStrategy playbackStrategy) override
    {
        lastStrategy_ = playbackStrategy;
        setPlaybackStrategyCnt_++;
        return ret_.load();
    }

    int32_t SetTrackSelectionFilter(AVPlayTrackSelectionFilter trackFilter) override
    {
        lastFilter_ = trackFilter;
        setTrackFilterCnt_++;
        return ret_.load();
    }

    int32_t GetTrackSelectionFilter(AVPlayTrackSelectionFilter &trackFilter) override
    {
        trackFilter = lastFilter_;
        getTrackFilterCnt_++;
        return ret_.load();
    }

    int32_t SetMediaMuted(OHOS::Media::MediaType type, bool isMuted) override
    {
        lastMutedType_ = type;
        lastMuted_ = isMuted;
        setMediaMutedCnt_++;
        return ret_.load();
    }

    int32_t SetMaxAmplitudeCbStatus(bool status) override
    {
        lastAmplitudeStatus_ = status;
        amplitudeCnt_++;
        return ret_.load();
    }

    int32_t SetPlayRangeWithMode(int64_t start, int64_t end, PlayerSeekMode mode) override
    {
        lastRangeStart_ = start;
        lastRangeEnd_ = end;
        lastRangeMode_ = mode;
        setPlayRangeCnt_++;
        return ret_.load();
    }

    int32_t SetDeviceChangeCbStatus(bool status) override
    {
        (void)status;
        setDeviceChangeCbCnt_++;
        return ret_.load();
    }

    int32_t SetSubtitleCbDfxStatus(bool isRegistered) override
    {
        lastSubtitleStatus_ = isRegistered;
        subtitleDfxCnt_++;
        return ret_.load();
    }

    int32_t GetApiVersion(int32_t &apiVersion) override
    {
        apiVersion = apiVersionValue_;
        apiVersionCnt_++;
        return ret_.load();
    }

    int32_t SetSeiMessageCbStatus(bool status, const std::vector<int32_t> &payloadTypes) override
    {
        lastSeiStatus_ = status;
        lastSeiPayloadTypes_ = payloadTypes;
        seiCbCnt_++;
        return ret_.load();
    }

    int32_t SetSuperResolution(bool enabled) override
    {
        lastSuperRes_ = enabled;
        setSuperResCnt_++;
        return ret_.load();
    }

    int32_t SetVideoWindowSize(int32_t width, int32_t height) override
    {
        lastWinWidth_ = width;
        lastWinHeight_ = height;
        setVideoWinCnt_++;
        return ret_.load();
    }

    int32_t EnableReportMediaProgress(bool enable) override
    {
        lastProgressStatus_ = enable;
        progressReportCnt_++;
        return ret_.load();
    }

    int32_t EnableReportAudioInterrupt(bool enable) override
    {
        lastInterruptStatus_ = enable;
        interruptReportCnt_++;
        return ret_.load();
    }

    int32_t EnableCameraPostprocessing() override
    {
        cameraPostCnt_++;
        return ret_.load();
    }

    int32_t ForceLoadVideo(bool status) override
    {
        lastForceLoad_ = status;
        forceLoadCnt_++;
        return ret_.load();
    }

    void ResetListParameters() override
    {
        resetListParamsCnt_++;
    }

    int32_t GetPlaybackPosition(int32_t &playbackPosition) override
    {
        playbackPosition = 50;
        return ret_.load();
    }

    std::atomic<int32_t> ret_ { MSERR_OK };
    std::atomic<int32_t> prepareCnt_ { 0 };
    std::atomic<int32_t> prepareAsyncCnt_ { 0 };
    std::atomic<int32_t> playCnt_ { 0 };
    std::atomic<int32_t> pauseCnt_ { 0 };
    std::atomic<int32_t> stopCnt_ { 0 };
    std::atomic<int32_t> resetCnt_ { 0 };
    std::atomic<int32_t> releaseCnt_ { 0 };
    std::atomic<int32_t> releaseSyncCnt_ { 0 };
    std::atomic<int32_t> seekCnt_ { 0 };
    std::atomic<int32_t> seekToDefaultCnt_ { 0 };
    std::atomic<int32_t> setSourceUrlCnt_ { 0 };
    std::atomic<int32_t> setSourceDataSrcCnt_ { 0 };
    std::atomic<int32_t> setSourceFdCnt_ { 0 };
    std::atomic<int32_t> addSubSourceUrlCnt_ { 0 };
    std::atomic<int32_t> addSubSourceFdCnt_ { 0 };
    std::atomic<int32_t> setVolumeCnt_ { 0 };
    std::atomic<int32_t> setMediaSourceCnt_ { 0 };
    std::atomic<int32_t> setSpeedCnt_ { 0 };
    std::atomic<int32_t> setPlaybackRateCnt_ { 0 };
    std::atomic<int32_t> selectBitRateCnt_ { 0 };
    std::atomic<int32_t> setVideoSurfaceCnt_ { 0 };
    std::atomic<int32_t> setVideoOutputCnt_ { 0 };
    std::atomic<int32_t> setLoopingCnt_ { 0 };
    std::atomic<int32_t> setPlayerCallbackCnt_ { 0 };
    std::atomic<int32_t> setParameterCnt_ { 0 };
    std::atomic<int32_t> selectTrackCnt_ { 0 };
    std::atomic<int32_t> deselectTrackCnt_ { 0 };
    std::atomic<int32_t> setPlaybackStrategyCnt_ { 0 };
    std::atomic<int32_t> setTrackFilterCnt_ { 0 };
    std::atomic<int32_t> getTrackFilterCnt_ { 0 };
    std::atomic<int32_t> setMediaMutedCnt_ { 0 };
    std::atomic<int32_t> amplitudeCnt_ { 0 };
    std::atomic<int32_t> setPlayRangeCnt_ { 0 };
    std::atomic<int32_t> setDeviceChangeCbCnt_ { 0 };
    std::atomic<int32_t> subtitleDfxCnt_ { 0 };
    std::atomic<int32_t> apiVersionCnt_ { 0 };
    std::atomic<int32_t> seiCbCnt_ { 0 };
    std::atomic<int32_t> setSuperResCnt_ { 0 };
    std::atomic<int32_t> setVideoWinCnt_ { 0 };
    std::atomic<int32_t> progressReportCnt_ { 0 };
    std::atomic<int32_t> interruptReportCnt_ { 0 };
    std::atomic<int32_t> cameraPostCnt_ { 0 };
    std::atomic<int32_t> forceLoadCnt_ { 0 };
    std::atomic<int32_t> resetListParamsCnt_ { 0 };

    std::string lastUrl_ = "";
    std::string lastSubUrl_ = "";
    int32_t lastFd_ = -1;
    int64_t lastFdOffset_ = 0;
    int64_t lastFdSize_ = 0;
    int64_t lastSeekTime_ = -1;
    PlayerSeekMode lastSeekMode_ = PlayerSeekMode::SEEK_PREVIOUS_SYNC;
    float lastRate_ = 0.0;
    MediaType lastMutedType_ = MediaType::MEDIA_TYPE_MAX_COUNT;
    bool lastMuted_ = false;
    bool lastSuperRes_ = false;
    int32_t lastWinWidth_ = 0;
    int32_t lastWinHeight_ = 0;
    bool lastForceLoad_ = false;
    int64_t lastRangeStart_ = 0;
    int64_t lastRangeEnd_ = 0;
    PlayerSeekMode lastRangeMode_ = PlayerSeekMode::SEEK_PREVIOUS_SYNC;
    bool lastAmplitudeStatus_ = false;
    bool lastProgressStatus_ = false;
    bool lastInterruptStatus_ = false;
    bool lastSubtitleStatus_ = false;
    bool lastSeiStatus_ = false;
    std::vector<int32_t> lastSeiPayloadTypes_ = {};
    int32_t apiVersionValue_ = 0;
    std::atomic<int64_t> seekRangeStartUs_ { 0 };
    std::atomic<int64_t> seekRangeEndUs_ { 20000 };
    AVPlayStrategy lastStrategy_ = {};
    AVPlayTrackSelectionFilter lastFilter_ = {};
};

class AVPlayerNapiTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void) override;
    void TearDown(void) override;

protected:
    void SyncTaskQueue(void);
    void SetState(PlayerStates state);

    AVPlayerNapi *jsPlayer_ = nullptr;
    std::shared_ptr<FakePlayer> player_ = nullptr;
};

} // namespace Media
} // namespace OHOS

#endif // AVPLAYER_NAPI_TEST_H
