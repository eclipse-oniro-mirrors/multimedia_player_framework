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

#ifndef PLAYER_IMPL_UNITTEST_H
#define PLAYER_IMPL_UNITTEST_H

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "mock/fdsan_fd.h"
#include "mock/i_media_service.h"
#include "mock/media_local.h"
#include "player_impl.h"

namespace OHOS {
namespace Media {

class PlayerImplUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);
    std::shared_ptr<PlayerImpl> playerImpl_ {nullptr};
};

class MockMediaService : public IMediaService {
public:
    ~MockMediaService() override = default;
    MOCK_METHOD(std::shared_ptr<IRecorderService>, CreateRecorderService, (), (override));
    MOCK_METHOD(int32_t, DestroyRecorderService, (std::shared_ptr<IRecorderService> recorder), (override));
    MOCK_METHOD(std::shared_ptr<IRecorderProfilesService>, CreateRecorderProfilesService, (), (override));
    MOCK_METHOD(int32_t, DestroyMediaProfileService,
        (std::shared_ptr<IRecorderProfilesService> recorderProfiles), (override));
    MOCK_METHOD(std::shared_ptr<ITransCoderService>, CreateTransCoderService, (), (override));
    MOCK_METHOD(int32_t, DestroyTransCoderService, (std::shared_ptr<ITransCoderService> transCoder), (override));
    MOCK_METHOD(std::shared_ptr<IPlayerService>, CreatePlayerService, (), (override));
    MOCK_METHOD(int32_t, DestroyPlayerService, (std::shared_ptr<IPlayerService> player), (override));
    MOCK_METHOD(std::shared_ptr<IAVMetadataHelperService>, CreateAVMetadataHelperService, (), (override));
    MOCK_METHOD(int32_t, DestroyAVMetadataHelperService,
        (std::shared_ptr<IAVMetadataHelperService> avMetadataHelper), (override));
    MOCK_METHOD(std::shared_ptr<IScreenCaptureService>, CreateScreenCaptureService, (), (override));
    MOCK_METHOD(int32_t, DestroyScreenCaptureService,
        (std::shared_ptr<IScreenCaptureService> screenCaptureHelper), (override));
    MOCK_METHOD(std::shared_ptr<IScreenCaptureMonitorService>, CreateScreenCaptureMonitorService, (), (override));
    MOCK_METHOD(int32_t, DestroyScreenCaptureMonitorService,
        (std::shared_ptr<IScreenCaptureMonitorService> screenCaptureMonitor), (override));
    MOCK_METHOD(std::shared_ptr<IScreenCaptureController>, CreateScreenCaptureControllerClient, (), (override));
    MOCK_METHOD(int32_t, DestroyScreenCaptureControllerClient,
        (std::shared_ptr<IScreenCaptureController> controller), (override));
    MOCK_METHOD(std::shared_ptr<IStandardMonitorService>, GetMonitorProxy, (), (override));
    MOCK_METHOD(bool, ReleaseClientListener, (), (override));
    MOCK_METHOD(bool, CanKillMediaService, (), (override));
    MOCK_METHOD(std::vector<pid_t>, GetPlayerPids, (), (override));
    MOCK_METHOD(int32_t, ProxyForFreeze, (const std::set<int32_t>& pidList, bool isProxy), (override));
    MOCK_METHOD(int32_t, ResetAllProxy, (), (override));
};

class MockIPlayerService : public IPlayerService {
public:
    ~MockIPlayerService() override = default;
    MOCK_METHOD(int32_t, SetPlayerProducer, (const PlayerProducer producer), (override));
    MOCK_METHOD(int32_t, SetSource, (const std::string &url), (override));
    MOCK_METHOD(int32_t, SetSource, (const std::shared_ptr<IMediaDataSource> &dataSrc), (override));
    MOCK_METHOD(int32_t, SetSource, (int32_t fd, int64_t offset, int64_t size), (override));
    MOCK_METHOD(int32_t, AddSubSource, (const std::string &url), (override));
    MOCK_METHOD(int32_t, AddSubSource, (int32_t fd, int64_t offset, int64_t size), (override));
    MOCK_METHOD(int32_t, Play, (), (override));
    MOCK_METHOD(int32_t, Prepare, (), (override));
    MOCK_METHOD(int32_t, PrepareAsync, (), (override));
    MOCK_METHOD(int32_t, Pause, (), (override));
    MOCK_METHOD(int32_t, Stop, (), (override));
    MOCK_METHOD(int32_t, Reset, (), (override));
    MOCK_METHOD(int32_t, Release, (), (override));
    MOCK_METHOD(int32_t, SetVolume, (float leftVolume, float rightVolume), (override));
    MOCK_METHOD(int32_t, SetVolumeMode, (int32_t mode), (override));
    MOCK_METHOD(int32_t, Seek, (int32_t mSeconds, PlayerSeekMode mode), (override));
    MOCK_METHOD(int32_t, GetCurrentTime, (int32_t &currentTime), (override));
    MOCK_METHOD(int32_t, GetPlaybackPosition, (int32_t &playbackPosition), (override));
    MOCK_METHOD(int32_t, GetVideoTrackInfo, (std::vector<Format> &videoTrack), (override));
    MOCK_METHOD(int32_t, GetPlaybackInfo, (Format &playbackInfo), (override));
    MOCK_METHOD(int32_t, GetPlaybackStatisticMetrics, (Format &playbackStatisticMetrics), (override));
    MOCK_METHOD(int32_t, GetAudioTrackInfo, (std::vector<Format> &audioTrack), (override));
    MOCK_METHOD(int32_t, GetVideoWidth, (), (override));
    MOCK_METHOD(int32_t, GetVideoHeight, (), (override));
    MOCK_METHOD(int32_t, GetDuration, (int32_t &duration), (override));
    MOCK_METHOD(int32_t, SetPlaybackSpeed, (PlaybackRateMode mode), (override));
    MOCK_METHOD(int32_t, SetPlaybackRate, (float rate), (override));
    MOCK_METHOD(int32_t, SetMediaSource,
        (const std::shared_ptr<AVMediaSource> &mediaSource, AVPlayStrategy strategy), (override));
    MOCK_METHOD(int32_t, SelectBitRate, (uint32_t bitRate), (override));
    MOCK_METHOD(int32_t, GetPlaybackSpeed, (PlaybackRateMode &mode), (override));
    MOCK_METHOD(int32_t, SetDecryptConfig,
        (const sptr<DrmStandard::IMediaKeySessionService> &keySessionProxy, bool svp), (override));
#ifdef SUPPORT_VIDEO
    MOCK_METHOD(int32_t, SetVideoSurface, (sptr<Surface> surface), (override));
#endif
    MOCK_METHOD(bool, IsPlaying, (), (override));
    MOCK_METHOD(bool, IsLooping, (), (override));
    MOCK_METHOD(int32_t, SetLooping, (bool loop), (override));
    MOCK_METHOD(int32_t, SetParameter, (const Format &param), (override));
    MOCK_METHOD(int32_t, SetPlayerCallback, (const std::shared_ptr<PlayerCallback> &callback), (override));
    MOCK_METHOD(int32_t, SelectTrack, (int32_t index, PlayerSwitchMode mode), (override));
    MOCK_METHOD(int32_t, DeselectTrack, (int32_t index), (override));
    MOCK_METHOD(int32_t, GetCurrentTrack, (int32_t trackType, int32_t &index), (override));
    MOCK_METHOD(int32_t, GetSubtitleTrackInfo, (std::vector<Format> &subtitleTrack), (override));
    MOCK_METHOD(bool, IsSeekContinuousSupported, (), (override));
};

class MockPlayerCallback : public PlayerCallback {
public:
    ~MockPlayerCallback() override = default;
    MOCK_METHOD(void, OnInfo, (PlayerOnInfoType type, int32_t extra, const Format &infoBody), (override));
    MOCK_METHOD(void, OnError, (int32_t errorCode, const std::string &errorMsg), (override));
    MOCK_METHOD(void, SetFreezeFlag, (bool isFrozen), (override));
    MOCK_METHOD(void, SetInterruptListenerFlag, (bool isRegistered), (override));
};
} // namespace Media
} // namespace OHOS
#endif // PLAYER_IMPL_UNITTEST_H