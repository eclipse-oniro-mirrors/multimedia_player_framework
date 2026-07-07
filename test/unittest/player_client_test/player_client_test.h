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

#ifndef PLAYER_CLIENT_TEST_H
#define PLAYER_CLIENT_TEST_H

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <string>
#include <memory>
#include <vector>
#include "player_client.h"
#include "i_standard_player_service.h"

namespace OHOS {
namespace Media {

class MockIPlayerService : public IStandardPlayerService {
public:
    MOCK_METHOD(int32_t, SetListenerObject, (const sptr<IRemoteObject> &object), (override));
    MOCK_METHOD(int32_t, SetPlayerProducer, (const PlayerProducer producer), (override));
    MOCK_METHOD(int32_t, SetSource, (const std::string &url), (override));
    MOCK_METHOD(int32_t, SetSource, (const sptr<IRemoteObject> &object), (override));
    MOCK_METHOD(int32_t, SetSource, (int32_t fd, int64_t offset, int64_t size), (override));
    MOCK_METHOD(int32_t, AddSubSource, (const std::string &url), (override));
    MOCK_METHOD(int32_t, AddSubSource, (int32_t fd, int64_t offset, int64_t size), (override));
    MOCK_METHOD(int32_t, Prepare, (), (override));
    MOCK_METHOD(int32_t, PrepareAsync, (), (override));
    MOCK_METHOD(int32_t, Play, (), (override));
    MOCK_METHOD(int32_t, Pause, (), (override));
    MOCK_METHOD(int32_t, Stop, (), (override));
    MOCK_METHOD(int32_t, Reset, (), (override));
    MOCK_METHOD(int32_t, Release, (), (override));
    MOCK_METHOD(int32_t, ReleaseSync, (), (override));
    MOCK_METHOD(int32_t, DestroyStub, (), (override));
    MOCK_METHOD(int32_t, SetVolume, (float leftVolume, float rightVolume), (override));
    MOCK_METHOD(int32_t, SetVolumeMode, (int32_t mode), (override));
    MOCK_METHOD(int32_t, Seek, (int64_t mSeconds, PlayerSeekMode mode), (override));
    MOCK_METHOD(int32_t, SeekToDefaultPosition, (), (override));
    MOCK_METHOD(int32_t, SetLooping, (bool loop), (override));
    MOCK_METHOD(int32_t, SetPlaybackSpeed, (PlaybackRateMode mode), (override));
    MOCK_METHOD(int32_t, SetPlaybackRate, (float rate), (override));
    MOCK_METHOD(int32_t, SetRenderFirstFrame, (bool display), (override));
    MOCK_METHOD(int32_t, SetPlayRange, (int64_t start, int64_t end), (override));
    MOCK_METHOD(int32_t, SetPlayRangeWithMode, (int64_t start, int64_t end, PlayerSeekMode mode), (override));
    MOCK_METHOD(int32_t, SetSuperResolution, (bool enabled), (override));
    MOCK_METHOD(int32_t, SetVideoWindowSize, (int32_t width, int32_t height), (override));
    MOCK_METHOD(int32_t, SetMediaSource, (const std::shared_ptr<AVMediaSource> &mediaSource, AVPlayStrategy strategy), (override));
    MOCK_METHOD(int32_t, SetSourceLoader, (const sptr<IRemoteObject> &object), (override));
    MOCK_METHOD(int32_t, SetFilePath, (int32_t fd, std::string filePath), (override));
    MOCK_METHOD(int32_t, SetReopenFd, (int32_t fd, int32_t fdCinema), (override));
    MOCK_METHOD(int32_t, SelectBitRate, (uint32_t bitRate), (override));
    MOCK_METHOD(int32_t, SelectTrack, (int32_t index, PlayerSwitchMode mode), (override));
    MOCK_METHOD(int32_t, DeselectTrack, (int32_t index), (override));
    MOCK_METHOD(int32_t, GetCurrentTrack, (int32_t trackType, int32_t &index), (override));
    MOCK_METHOD(int32_t, GetVideoTrackInfo, (std::vector<Format> &videoTrack), (override));
    MOCK_METHOD(int32_t, GetAudioTrackInfo, (std::vector<Format> &audioTrack), (override));
    MOCK_METHOD(int32_t, GetSubtitleTrackInfo, (std::vector<Format> &subtitleTrack), (override));
    MOCK_METHOD(int32_t, GetCurrentTime, (int32_t &currentTime), (override));
    MOCK_METHOD(int32_t, GetDuration, (int32_t &duration), (override));
    MOCK_METHOD(int32_t, GetVideoWidth, (), (override));
    MOCK_METHOD(int32_t, GetVideoHeight, (), (override));
    MOCK_METHOD(bool, IsPlaying, (), (override));
    MOCK_METHOD(bool, IsLooping, (), (override));
    MOCK_METHOD(bool, IsLiveSeek, (), (override));
    MOCK_METHOD(bool, IsSeekContinuousSupported, (), (override));
    MOCK_METHOD(int32_t, GetPlaybackSpeed, (PlaybackRateMode &mode), (override));
    MOCK_METHOD(int32_t, GetPlaybackRate, (float &rate), (override));
    MOCK_METHOD(int32_t, GetPlaybackPosition, (int32_t &playbackPosition), (override));
    MOCK_METHOD(int32_t, GetCurrentPresentationTimestamp, (int64_t &currentPresentation), (override));
    MOCK_METHOD(int32_t, GetSeekableRanges, (std::vector<Plugins::SeekRange> &seekableRanges), (override));
    MOCK_METHOD(int32_t, GetLoadedRanges, (std::vector<Plugins::SeekRange> &loadedRanges), (override));
    MOCK_METHOD(int32_t, GetPlaybackInfo, (Format &playbackInfo), (override));
    MOCK_METHOD(int32_t, GetPlaybackStatisticMetrics, (Format &playbackStatisticMetrics), (override));
    MOCK_METHOD(int32_t, GetMediaDescription, (Format &format), (override));
    MOCK_METHOD(int32_t, GetTrackDescription, (Format &format, uint32_t trackIndex), (override));
    MOCK_METHOD(int32_t, GetGlobalInfo, (std::shared_ptr<Meta> &globalInfo), (override));
    MOCK_METHOD(int32_t, GetApiVersion, (int32_t &apiVersion), (override));
    MOCK_METHOD(uint32_t, GetMemoryUsage, (), (override));
    MOCK_METHOD(int32_t, SetPlayerCallback, (), (override));
    MOCK_METHOD(int32_t, SetMaxAmplitudeCbStatus, (bool status), (override));
    MOCK_METHOD(int32_t, SetDeviceChangeCbStatus, (bool status), (override));
    MOCK_METHOD(int32_t, SetSubtitleCbDfxStatus, (bool isRegistered), (override));
    MOCK_METHOD(int32_t, SetSeiMessageCbStatus, (bool status, const std::vector<int32_t> &payloadTypes), (override));
    MOCK_METHOD(int32_t, SetStartFrameRateOptEnabled, (bool enabled), (override));
    MOCK_METHOD(int32_t, EnableReportMediaProgress, (bool enable), (override));
    MOCK_METHOD(int32_t, EnableReportAudioInterrupt, (bool enable), (override));
    MOCK_METHOD(int32_t, SetDecryptConfig, (const sptr<DrmStandard::IMediaKeySessionService> &keySessionProxy, bool svp), (override));
    MOCK_METHOD(int32_t, SetVideoSurface, (sptr<Surface> surface), (override));
    MOCK_METHOD(int32_t, SetVideoOutput, (sptr<Surface> surface), (override));
    MOCK_METHOD(int32_t, GetVideoSample, (int32_t &outputResult), (override));
    MOCK_METHOD(int32_t, ForceLoadVideo, (bool enabled), (override));
    MOCK_METHOD(int32_t, EnableCameraPostprocessing, (), (override));
    MOCK_METHOD(int32_t, SetCameraPostprocessing, (bool isOpen), (override));
    MOCK_METHOD(int32_t, SetPCMCallback, (const sptr<IRemoteObject> &object), (override));
    MOCK_METHOD(int32_t, SetPCMOutputStatus, (bool isEnable), (override));
    MOCK_METHOD(int32_t, SetPCMProcessorStatus, (bool isEnable), (override));
    MOCK_METHOD(int32_t, SetPCMProcessorMaxLen, (int32_t maxProcessedPCMLen), (override));
    MOCK_METHOD(int32_t, SetParameter, (const Format &param), (override));
    MOCK_METHOD(int32_t, SetPlaybackStrategy, (AVPlayStrategy playbackStrategy), (override));
    MOCK_METHOD(int32_t, SetTrackSelectionFilter, (AVPlayTrackSelectionFilter trackFilter), (override));
    MOCK_METHOD(int32_t, GetTrackSelectionFilter, (AVPlayTrackSelectionFilter &trackFilter), (override));
    MOCK_METHOD(int32_t, SetMediaMuted, (MediaType mediaType, bool isMuted), (override));
    MOCK_METHOD(int32_t, SetLoudnessGain, (float loudnessGain), (override));
    MOCK_METHOD(int32_t, RegisterDeviceCapability, (const sptr<IRemoteObject> &object), (override));
    MOCK_METHOD(int32_t, Freeze, (bool freeze), (override));
    MOCK_METHOD(int32_t, UnFreeze, (), (override));
};

class PlayerClientTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void) override
    {
        mockService_ = sptr<MockIPlayerService>::MakeRaw();
        EXPECT_CALL(*mockService_, SetListenerObject(_)).WillOnce(Return(MSERR_OK));
        EXPECT_CALL(*mockService_, DestroyStub()).WillRepeatedly(Return(MSERR_OK));
        playerClient_ = PlayerClient::Create(mockService_);
        ASSERT_NE(playerClient_, nullptr);
    }
    void TearDown(void) override
    {
        playerClient_ = nullptr;
        mockService_ = nullptr;
    }

protected:
    sptr<MockIPlayerService> mockService_;
    std::shared_ptr<PlayerClient> playerClient_;
};

} // namespace Media
} // namespace OHOS

#endif // PLAYER_CLIENT_TEST_H
