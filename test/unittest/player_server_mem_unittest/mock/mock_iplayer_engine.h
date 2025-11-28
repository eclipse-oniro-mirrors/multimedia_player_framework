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

#ifndef MOCK_IPLAYER_ENGINE_H
#define MOCK_IPLAYER_ENGINE_H

#include "i_player_engine.h"
#include "gmock/gmock.h"
#include "player.h"

namespace OHOS {
namespace Media {
class MockIPlayerEngineObs : public IPlayerEngineObs {
public:
    MockIPlayerEngineObs() = default;
    ~MockIPlayerEngineObs() override = default;
    MOCK_METHOD(void, OnError, (PlayerErrorType errorType, int32_t errorCode), ());
    MOCK_METHOD(void, OnErrorMessage, (int32_t errorCode, const std::string &errorMsg), ());
    void OnSystemOperation(PlayerOnSystemOperationType type, PlayerOperationReason reason) override
    {
        onSystemOperationFlag = true;
    }
    void OnInfo(PlayerOnInfoType type, int32_t extra, const Format& infoBody) override
    {
        onInfoFlag = true;
    }
private:
    bool onInfoFlag = false;
    bool onSystemOperationFlag = false;
};

class MockIPlayerEngine : public IPlayerEngine {
public:
    MockIPlayerEngine() = default;
    ~MockIPlayerEngine() override {};
    MOCK_METHOD(int32_t, SetSource, (const std::string &url), ());
    MOCK_METHOD(int32_t, SetSource, (const std::shared_ptr<IMediaDataSource> &dataSrc), ());
    MOCK_METHOD(int32_t, SetObs, (const std::weak_ptr<IPlayerEngineObs> &obs), ());
    MOCK_METHOD(int32_t, AddSubSource, (const std::string &url), ());
    MOCK_METHOD(int32_t, Play, (), ());
    MOCK_METHOD(int32_t, Prepare, (), ());
    MOCK_METHOD(int32_t, SetRenderFirstFrame, (bool display), ());
    MOCK_METHOD(int32_t, SetPlayRange, (int64_t start, int64_t end), ());
    MOCK_METHOD(int32_t, SetPlayRangeWithMode, (int64_t start, int64_t end, PlayerSeekMode mode), ());
    MOCK_METHOD(int32_t, PrepareAsync, (), ());
    MOCK_METHOD(int32_t, Pause, (bool isSystemOperation), ());
    MOCK_METHOD(int32_t, Stop, (), ());
    MOCK_METHOD(int32_t, Reset, (), ());
    MOCK_METHOD(int32_t, Freeze, (bool &isNoNeedToFreeze), ());
    MOCK_METHOD(int32_t, UnFreeze, (), ());
    MOCK_METHOD(int32_t, SetVolume, (float leftVolume, float rightVolume), ());
    MOCK_METHOD(int32_t, SetVolumeMode, (int32_t mode), ());
    MOCK_METHOD(int32_t, Seek, (int32_t mSeconds, PlayerSeekMode mode), ());
    MOCK_METHOD(int32_t, GetCurrentTime, (int32_t &currentTime), ());
    MOCK_METHOD(int32_t, GetVideoTrackInfo, (std::vector<Format> &videoTrack), ());
    MOCK_METHOD(int32_t, GetPlaybackInfo, (Format &playbackInfo), ());
    MOCK_METHOD(int32_t, GetPlaybackStatisticMetrics, (Format &playbackStatisticMetrics), (override));
    MOCK_METHOD(int32_t, GetAudioTrackInfo, (std::vector<Format> &audioTrack), ());
    MOCK_METHOD(int32_t, GetVideoWidth, (), ());
    MOCK_METHOD(int32_t, GetVideoHeight, (), ());
    MOCK_METHOD(int32_t, GetDuration, (int32_t &duration), ());
    MOCK_METHOD(int32_t, SetPlaybackSpeed, (PlaybackRateMode mode), ());
    MOCK_METHOD(int32_t, SetPlaybackRate, (float rate), ());
    MOCK_METHOD(int32_t, GetPlaybackSpeed, (PlaybackRateMode &mode), ());
    MOCK_METHOD(int32_t, SetMediaSource, (const std::shared_ptr<AVMediaSource> &mediaSource,
        AVPlayStrategy strategy), ());
    MOCK_METHOD(int32_t, SelectBitRate, (uint32_t bitRate, bool isAutoSelect), ());
    MOCK_METHOD(int32_t, SetDecryptConfig, (const sptr<DrmStandard::IMediaKeySessionService> &keySessionProxy,
        bool svp), ());
    MOCK_METHOD(int32_t, SetVideoSurface, (sptr<Surface> surface), ());
    MOCK_METHOD(float, GetMaxAmplitude, (), ());
    MOCK_METHOD(int32_t, SetLooping, (bool loop), ());
    MOCK_METHOD(int32_t, SetParameter, (const Format &param), ());
    MOCK_METHOD(int32_t, GetCurrentTrack, (int32_t trackType, int32_t &index), ());
    MOCK_METHOD(int32_t, GetSubtitleTrackInfo, (std::vector<Format> &subtitleTrack), ());
    MOCK_METHOD(int32_t, SetPlaybackStrategy, (AVPlayStrategy playbackStrategy), ());
    MOCK_METHOD(int64_t, GetPlayRangeEndTime, (), ());
    MOCK_METHOD(int32_t, SetMaxAmplitudeCbStatus, (bool status), ());
    MOCK_METHOD(int32_t, SetVideoScaleType, (Plugins::VideoScaleType videoScaleType), ());
};
} // namespace Media
} // namespace OHOS
#endif