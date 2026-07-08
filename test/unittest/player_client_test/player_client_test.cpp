/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
5 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "player_client_test.h"

using namespace testing;
using namespace testing::Ext;

namespace OHOS {
namespace Media {

HWTEST_F(PlayerClientTest, SetSource_Url_DelegatesToProxy_001, TestSize.Level0)
{
    EXPECT_CALL(*mockService_, SetSource("http://example.com/test.mp4")).WillOnce(Return(MSERR_OK));
    int32_t ret = playerClient_->SetSource("http://example.com/test.mp4");
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerClientTest, SetSource_Url_ErrorPropagated_001, TestSize.Level0)
{
    EXPECT_CALL(*mockService_, SetSource("http://invalid.com/bad.mp4")).WillOnce(Return(MSERR_INVALID_OPERATION));
    int32_t ret = playerClient_->SetSource("http://invalid.com/bad.mp4");
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

HWTEST_F(PlayerClientTest, SetSource_Fd_DelegatesToProxy_001, TestSize.Level0)
{
    EXPECT_CALL(*mockService_, SetSource(5, 0, 1024)).WillOnce(Return(MSERR_OK));
    int32_t ret = playerClient_->SetSource(5, 0, 1024);
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerClientTest, Prepare_DelegatesToProxy_001, TestSize.Level0)
{
    EXPECT_CALL(*mockService_, Prepare()).WillOnce(Return(MSERR_OK));
    int32_t ret = playerClient_->Prepare();
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerClientTest, PrepareAsync_DelegatesToProxy_001, TestSize.Level0)
{
    EXPECT_CALL(*mockService_, PrepareAsync()).WillOnce(Return(MSERR_OK));
    int32_t ret = playerClient_->PrepareAsync();
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerClientTest, Play_DelegatesToProxy_001, TestSize.Level0)
{
    EXPECT_CALL(*mockService_, Play()).WillOnce(Return(MSERR_OK));
    int32_t ret = playerClient_->Play();
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerClientTest, Pause_DelegatesToProxy_001, TestSize.Level0)
{
    EXPECT_CALL(*mockService_, Pause()).WillOnce(Return(MSERR_OK));
    int32_t ret = playerClient_->Pause();
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerClientTest, Stop_DelegatesToProxy_001, TestSize.Level0)
{
    EXPECT_CALL(*mockService_, Stop()).WillOnce(Return(MSERR_OK));
    int32_t ret = playerClient_->Stop();
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerClientTest, Reset_DelegatesToProxy_001, TestSize.Level0)
{
    EXPECT_CALL(*mockService_, Reset()).WillOnce(Return(MSERR_OK));
    int32_t ret = playerClient_->Reset();
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerClientTest, Release_DelegatesToProxy_001, TestSize.Level0)
{
    EXPECT_CALL(*mockService_, Release()).WillOnce(Return(MSERR_OK));
    int32_t ret = playerClient_->Release();
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerClientTest, ReleaseSync_DelegatesToProxy_001, TestSize.Level0)
{
    EXPECT_CALL(*mockService_, ReleaseSync()).WillOnce(Return(MSERR_OK));
    int32_t ret = playerClient_->ReleaseSync();
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerClientTest, SetVolume_DelegatesToProxy_001, TestSize.Level0)
{
    EXPECT_CALL(*mockService_, SetVolume(0.5f, 0.5f)).WillOnce(Return(MSERR_OK));
    int32_t ret = playerClient_->SetVolume(0.5f, 0.5f);
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerClientTest, Seek_DelegatesToProxy_001, TestSize.Level0)
{
    EXPECT_CALL(*mockService_, Seek(1000, PlayerSeekMode::SEEK_PREVIOUS_SYNC)).WillOnce(Return(MSERR_OK));
    int32_t ret = playerClient_->Seek(1000, PlayerSeekMode::SEEK_PREVIOUS_SYNC);
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerClientTest, SetLooping_True_DelegatesToProxy_001, TestSize.Level0)
{
    EXPECT_CALL(*mockService_, SetLooping(true)).WillOnce(Return(MSERR_OK));
    int32_t ret = playerClient_->SetLooping(true);
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerClientTest, SetLooping_False_DelegatesToProxy_001, TestSize.Level0)
{
    EXPECT_CALL(*mockService_, SetLooping(false)).WillOnce(Return(MSERR_OK));
    int32_t ret = playerClient_->SetLooping(false);
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerClientTest, SetPlaybackSpeed_DelegatesToProxy_001, TestSize.Level0)
{
    EXPECT_CALL(*mockService_, SetPlaybackSpeed(PlaybackRateMode::SPEED_FORWARD_2X)).WillOnce(Return(MSERR_OK));
    int32_t ret = playerClient_->SetPlaybackSpeed(PlaybackRateMode::SPEED_FORWARD_2X);
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerClientTest, SetPlaybackRate_DelegatesToProxy_001, TestSize.Level0)
{
    EXPECT_CALL(*mockService_, SetPlaybackRate(2.0f)).WillOnce(Return(MSERR_OK));
    int32_t ret = playerClient_->SetPlaybackRate(2.0f);
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerClientTest, IsPlaying_True_DelegatesToProxy_001, TestSize.Level0)
{
    EXPECT_CALL(*mockService_, IsPlaying()).WillOnce(Return(true));
    bool ret = playerClient_->IsPlaying();
    EXPECT_TRUE(ret);
}

HWTEST_F(PlayerClientTest, IsPlaying_False_DelegatesToProxy_001, TestSize.Level0)
{
    EXPECT_CALL(*mockService_, IsPlaying()).WillOnce(Return(false));
    bool ret = playerClient_->IsPlaying();
    EXPECT_FALSE(ret);
}

HWTEST_F(PlayerClientTest, IsLooping_True_DelegatesToProxy_001, TestSize.Level0)
{
    EXPECT_CALL(*mockService_, IsLooping()).WillOnce(Return(true));
    bool ret = playerClient_->IsLooping();
    EXPECT_TRUE(ret);
}

HWTEST_F(PlayerClientTest, IsLooping_False_DelegatesToProxy_001, TestSize.Level0)
{
    EXPECT_CALL(*mockService_, IsLooping()).WillOnce(Return(false));
    bool ret = playerClient_->IsLooping();
    EXPECT_FALSE(ret);
}

HWTEST_F(PlayerClientTest, GetCurrentTime_DelegatesToProxy_001, TestSize.Level0)
{
    EXPECT_CALL(*mockService_, GetCurrentTime(_)).WillOnce(DoAll(SetArgReferee<0>(5000), Return(MSERR_OK)));
    int32_t currentTime = 0;
    int32_t ret = playerClient_->GetCurrentTime(currentTime);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(currentTime, 5000);
}

HWTEST_F(PlayerClientTest, GetDuration_DelegatesToProxy_001, TestSize.Level0)
{
    EXPECT_CALL(*mockService_, GetDuration(_)).WillOnce(DoAll(SetArgReferee<0>(120000), Return(MSERR_OK)));
    int32_t duration = 0;
    int32_t ret = playerClient_->GetDuration(duration);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(duration, 120000);
}

HWTEST_F(PlayerClientTest, GetVideoWidth_DelegatesToProxy_001, TestSize.Level0)
{
    EXPECT_CALL(*mockService_, GetVideoWidth()).WillOnce(Return(1920));
    int32_t width = playerClient_->GetVideoWidth();
    EXPECT_EQ(width, 1920);
}

HWTEST_F(PlayerClientTest, GetVideoHeight_DelegatesToProxy_001, TestSize.Level0)
{
    EXPECT_CALL(*mockService_, GetVideoHeight()).WillOnce(Return(1080));
    int32_t height = playerClient_->GetVideoHeight();
    EXPECT_EQ(height, 1080);
}

HWTEST_F(PlayerClientTest, SelectTrack_DelegatesToProxy_001, TestSize.Level0)
{
    EXPECT_CALL(*mockService_, SelectTrack(1, PlayerSwitchMode::SWITCH_SMOOTH)).WillOnce(Return(MSERR_OK));
    int32_t ret = playerClient_->SelectTrack(1, PlayerSwitchMode::SWITCH_SMOOTH);
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerClientTest, DeselectTrack_DelegatesToProxy_001, TestSize.Level0)
{
    EXPECT_CALL(*mockService_, DeselectTrack(1)).WillOnce(Return(MSERR_OK));
    int32_t ret = playerClient_->DeselectTrack(1);
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerClientTest, GetCurrentTrack_DelegatesToProxy_001, TestSize.Level0)
{
    EXPECT_CALL(*mockService_, GetCurrentTrack(0, _)).WillOnce(DoAll(SetArgReferee<1>(1), Return(MSERR_OK)));
    int32_t index = 0;
    int32_t ret = playerClient_->GetCurrentTrack(0, index);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(index, 1);
}

HWTEST_F(PlayerClientTest, SelectBitRate_DelegatesToProxy_001, TestSize.Level0)
{
    EXPECT_CALL(*mockService_, SelectBitRate(1000000)).WillOnce(Return(MSERR_OK));
    int32_t ret = playerClient_->SelectBitRate(1000000);
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerClientTest, IsLiveSeek_DelegatesToProxy_001, TestSize.Level0)
{
    EXPECT_CALL(*mockService_, IsLiveSeek()).WillOnce(Return(false));
    bool ret = playerClient_->IsLiveSeek();
    EXPECT_FALSE(ret);
}

HWTEST_F(PlayerClientTest, SetPlayRange_DelegatesToProxy_001, TestSize.Level0)
{
    EXPECT_CALL(*mockService_, SetPlayRange(0, 60000)).WillOnce(Return(MSERR_OK));
    int32_t ret = playerClient_->SetPlayRange(0, 60000);
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerClientTest, SetPlayRangeWithMode_DelegatesToProxy_001, TestSize.Level0)
{
    EXPECT_CALL(*mockService_,
        SetPlayRangeWithMode(0, 60000, PlayerSeekMode::SEEK_PREVIOUS_SYNC)).WillOnce(Return(MSERR_OK));
    int32_t ret = playerClient_->SetPlayRangeWithMode(0, 60000, PlayerSeekMode::SEEK_PREVIOUS_SYNC);
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerClientTest, DestroyStub_DelegatesToProxy_001, TestSize.Level0)
{
    EXPECT_CALL(*mockService_, DestroyStub()).WillOnce(Return(MSERR_OK));
    int32_t ret = playerClient_->SetPlayerProducer(PlayerProducer::INNER);
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerClientTest, MediaServerDied_ReturnsServiceDied_001, TestSize.Level0)
{
    playerClient_->MediaServerDied();
    EXPECT_CALL(*mockService_, Play()).Times(0);
    int32_t ret = playerClient_->Play();
    EXPECT_EQ(ret, MSERR_SERVICE_DIED);
}

HWTEST_F(PlayerClientTest, MediaServerDied_SeekReturnsServiceDied_001, TestSize.Level0)
{
    playerClient_->MediaServerDied();
    int32_t ret = playerClient_->Seek(1000, PlayerSeekMode::SEEK_PREVIOUS_SYNC);
    EXPECT_EQ(ret, MSERR_SERVICE_DIED);
}

HWTEST_F(PlayerClientTest, MediaServerDied_SetSourceReturnsServiceDied_001, TestSize.Level0)
{
    playerClient_->MediaServerDied();
    int32_t ret = playerClient_->SetSource("http://example.com/test.mp4");
    EXPECT_EQ(ret, MSERR_SERVICE_DIED);
}

HWTEST_F(PlayerClientTest, MediaServerDied_IsPlayingReturnsFalse_001, TestSize.Level0)
{
    playerClient_->MediaServerDied();
    bool ret = playerClient_->IsPlaying();
    EXPECT_FALSE(ret);
}

} // namespace Media
} // namespace OHOS
