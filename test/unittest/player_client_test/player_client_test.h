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
    // Pure virtual methods from IStandardPlayerService (must override)
    MOCK_METHOD(int32_t, SetListenerObject, (const sptr<IRemoteObject> &object), (override));
    MOCK_METHOD(int32_t, SetPlayerProducer, (const PlayerProducer producer), (override));
    MOCK_METHOD(int32_t, SetSource, (const std::string &url), (override));
    MOCK_METHOD(int32_t, SetSource, (const sptr<IRemoteObject> &object), (override));
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
    MOCK_METHOD(int32_t, Seek, (int64_t mSeconds, PlayerSeekMode mode), (override));
    MOCK_METHOD(int32_t, GetCurrentTime, (int32_t &currentTime), (override));
    MOCK_METHOD(int32_t, GetVideoTrackInfo, (std::vector<Format> &videoTrack), (override));
    MOCK_METHOD(int32_t, GetPlaybackInfo, (Format &playbackInfo), (override));
    MOCK_METHOD(int32_t, GetAudioTrackInfo, (std::vector<Format> &audioTrack), (override));
    MOCK_METHOD(int32_t, GetVideoWidth, (), (override));
    MOCK_METHOD(int32_t, GetVideoHeight, (), (override));
    MOCK_METHOD(int32_t, GetDuration, (int32_t &duration), (override));
    MOCK_METHOD(int32_t, SetPlaybackSpeed, (PlaybackRateMode mode), (override));
    MOCK_METHOD(int32_t, SetPlaybackRate, (float rate), (override));
    MOCK_METHOD(int32_t, GetPlaybackSpeed, (PlaybackRateMode &mode), (override));
    MOCK_METHOD(int32_t, SetSourceLoader, (const sptr<IRemoteObject> &object), (override));
    MOCK_METHOD(int32_t, SetMediaSource, (const std::shared_ptr<AVMediaSource> &mediaSource, AVPlayStrategy strategy), (override));
    MOCK_METHOD(int32_t, DestroyStub, (), (override));
    MOCK_METHOD(int32_t, SetPlayerCallback, (), (override));
    MOCK_METHOD(int32_t, SelectBitRate, (uint32_t bitRate), (override));
    MOCK_METHOD(int32_t, SelectTrack, (int32_t index, PlayerSwitchMode mode), (override));
    MOCK_METHOD(int32_t, DeselectTrack, (int32_t index), (override));
    MOCK_METHOD(int32_t, GetCurrentTrack, (int32_t trackType, int32_t &index), (override));
    MOCK_METHOD(int32_t, GetSubtitleTrackInfo, (std::vector<Format> &subtitleTrack), (override));
    MOCK_METHOD(bool, IsPlaying, (), (override));
    MOCK_METHOD(bool, IsLooping, (), (override));
    MOCK_METHOD(int32_t, SetLooping, (bool loop), (override));
    MOCK_METHOD(int32_t, SetParameter, (const Format &param), (override));
#ifdef SUPPORT_VIDEO
    MOCK_METHOD(int32_t, SetVideoSurface, (sptr<Surface> surface), (override));
#endif

    // Override methods with default impl that player_client_test.cpp calls
    MOCK_METHOD(int32_t, ReleaseSync, (), (override));
    MOCK_METHOD(bool, IsLiveSeek, (), (override));
    MOCK_METHOD(int32_t, SetPlayRange, (int64_t start, int64_t end), (override));
    MOCK_METHOD(int32_t, SetPlayRangeWithMode, (int64_t start, int64_t end, PlayerSeekMode mode), (override));

    // IRemoteBroker
    MOCK_METHOD(sptr<IRemoteObject>, AsObject, (), (override));
};

class PlayerClientTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void) override
    {
        mockService_ = new MockIPlayerService();
        EXPECT_CALL(*mockService_, SetListenerObject(testing::_)).WillOnce(testing::Return(MSERR_OK));
        EXPECT_CALL(*mockService_, DestroyStub()).WillRepeatedly(testing::Return(MSERR_OK));
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
