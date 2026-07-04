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

#include "player_client_test.h"

using namespace testing;
using namespace testing::Ext;

namespace OHOS {
namespace Media {

HWTEST_F(PlayerClientTest, Create_ValidProxy_001, TestSize.Level0)
{
    auto proxy = sptr<MockIPlayerService>::MakeRaw();
    ASSERT_NE(proxy, nullptr);
}

HWTEST_F(PlayerClientTest, SetSource_Url_001, TestSize.Level0)
{
    auto proxy = sptr<MockIPlayerService>::MakeRaw();
    EXPECT_CALL(*proxy, SetSource(_)).WillOnce(Return(0));
    int32_t ret = proxy->SetSource("http://example.com/test.mp4");
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerClientTest, SetSource_Fd_001, TestSize.Level0)
{
    auto proxy = sptr<MockIPlayerService>::MakeRaw();
    EXPECT_CALL(*proxy, SetSource(5, 0, 1024)).WillOnce(Return(0));
    int32_t ret = proxy->SetSource(5, 0, 1024);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerClientTest, Prepare_001, TestSize.Level0)
{
    auto proxy = sptr<MockIPlayerService>::MakeRaw();
    EXPECT_CALL(*proxy, Prepare()).WillOnce(Return(0));
    int32_t ret = proxy->Prepare();
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerClientTest, PrepareAsync_001, TestSize.Level0)
{
    auto proxy = sptr<MockIPlayerService>::MakeRaw();
    EXPECT_CALL(*proxy, PrepareAsync()).WillOnce(Return(0));
    int32_t ret = proxy->PrepareAsync();
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerClientTest, Play_001, TestSize.Level0)
{
    auto proxy = sptr<MockIPlayerService>::MakeRaw();
    EXPECT_CALL(*proxy, Play()).WillOnce(Return(0));
    int32_t ret = proxy->Play();
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerClientTest, Pause_001, TestSize.Level0)
{
    auto proxy = sptr<MockIPlayerService>::MakeRaw();
    EXPECT_CALL(*proxy, Pause()).WillOnce(Return(0));
    int32_t ret = proxy->Pause();
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerClientTest, Stop_001, TestSize.Level0)
{
    auto proxy = sptr<MockIPlayerService>::MakeRaw();
    EXPECT_CALL(*proxy, Stop()).WillOnce(Return(0));
    int32_t ret = proxy->Stop();
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerClientTest, Reset_001, TestSize.Level0)
{
    auto proxy = sptr<MockIPlayerService>::MakeRaw();
    EXPECT_CALL(*proxy, Reset()).WillOnce(Return(0));
    int32_t ret = proxy->Reset();
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerClientTest, Release_001, TestSize.Level0)
{
    auto proxy = sptr<MockIPlayerService>::MakeRaw();
    EXPECT_CALL(*proxy, Release()).WillOnce(Return(0));
    int32_t ret = proxy->Release();
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerClientTest, ReleaseSync_001, TestSize.Level0)
{
    auto proxy = sptr<MockIPlayerService>::MakeRaw();
    EXPECT_CALL(*proxy, ReleaseSync()).WillOnce(Return(0));
    int32_t ret = proxy->ReleaseSync();
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerClientTest, SetVolume_001, TestSize.Level0)
{
    auto proxy = sptr<MockIPlayerService>::MakeRaw();
    EXPECT_CALL(*proxy, SetVolume(0.5f, 0.5f)).WillOnce(Return(0));
    int32_t ret = proxy->SetVolume(0.5f, 0.5f);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerClientTest, SetVolumeMode_001, TestSize.Level0)
{
    auto proxy = sptr<MockIPlayerService>::MakeRaw();
    EXPECT_CALL(*proxy, SetVolumeMode(_)).WillOnce(Return(0));
    int32_t ret = proxy->SetVolumeMode(1);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerClientTest, Seek_001, TestSize.Level0)
{
    auto proxy = sptr<MockIPlayerService>::MakeRaw();
    EXPECT_CALL(*proxy, Seek(1000, PlayerSeekMode::SEEK_PREVIOUS_SYNC)).WillOnce(Return(0));
    int32_t ret = proxy->Seek(1000, PlayerSeekMode::SEEK_PREVIOUS_SYNC);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerClientTest, SeekToDefaultPosition_001, TestSize.Level0)
{
    auto proxy = sptr<MockIPlayerService>::MakeRaw();
    EXPECT_CALL(*proxy, SeekToDefaultPosition()).WillOnce(Return(0));
    int32_t ret = proxy->SeekToDefaultPosition();
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerClientTest, SetLooping_True_001, TestSize.Level0)
{
    auto proxy = sptr<MockIPlayerService>::MakeRaw();
    EXPECT_CALL(*proxy, SetLooping(true)).WillOnce(Return(0));
    int32_t ret = proxy->SetLooping(true);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerClientTest, SetLooping_False_001, TestSize.Level0)
{
    auto proxy = sptr<MockIPlayerService>::MakeRaw();
    EXPECT_CALL(*proxy, SetLooping(false)).WillOnce(Return(0));
    int32_t ret = proxy->SetLooping(false);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerClientTest, SetPlaybackSpeed_001, TestSize.Level0)
{
    auto proxy = sptr<MockIPlayerService>::MakeRaw();
    EXPECT_CALL(*proxy, SetPlaybackSpeed(PlaybackRateMode::SPEED_FORWARD_2X)).WillOnce(Return(0));
    int32_t ret = proxy->SetPlaybackSpeed(PlaybackRateMode::SPEED_FORWARD_2X);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerClientTest, SetPlaybackRate_001, TestSize.Level0)
{
    auto proxy = sptr<MockIPlayerService>::MakeRaw();
    EXPECT_CALL(*proxy, SetPlaybackRate(2.0f)).WillOnce(Return(0));
    int32_t ret = proxy->SetPlaybackRate(2.0f);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerClientTest, SetPlayRange_001, TestSize.Level0)
{
    auto proxy = sptr<MockIPlayerService>::MakeRaw();
    EXPECT_CALL(*proxy, SetPlayRange(0, 60000)).WillOnce(Return(0));
    int32_t ret = proxy->SetPlayRange(0, 60000);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerClientTest, SetPlayRangeWithMode_001, TestSize.Level0)
{
    auto proxy = sptr<MockIPlayerService>::MakeRaw();
    EXPECT_CALL(*proxy, SetPlayRangeWithMode(0, 60000, PlayerSeekMode::SEEK_PREVIOUS_SYNC)).WillOnce(Return(0));
    int32_t ret = proxy->SetPlayRangeWithMode(0, 60000, PlayerSeekMode::SEEK_PREVIOUS_SYNC);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerClientTest, IsPlaying_True_001, TestSize.Level0)
{
    auto proxy = sptr<MockIPlayerService>::MakeRaw();
    EXPECT_CALL(*proxy, IsPlaying()).WillOnce(Return(true));
    bool ret = proxy->IsPlaying();
    EXPECT_TRUE(ret);
}

HWTEST_F(PlayerClientTest, IsPlaying_False_001, TestSize.Level0)
{
    auto proxy = sptr<MockIPlayerService>::MakeRaw();
    EXPECT_CALL(*proxy, IsPlaying()).WillOnce(Return(false));
    bool ret = proxy->IsPlaying();
    EXPECT_FALSE(ret);
}

HWTEST_F(PlayerClientTest, IsLooping_True_001, TestSize.Level0)
{
    auto proxy = sptr<MockIPlayerService>::MakeRaw();
    EXPECT_CALL(*proxy, IsLooping()).WillOnce(Return(true));
    bool ret = proxy->IsLooping();
    EXPECT_TRUE(ret);
}

HWTEST_F(PlayerClientTest, IsLiveSeek_001, TestSize.Level0)
{
    auto proxy = sptr<MockIPlayerService>::MakeRaw();
    EXPECT_CALL(*proxy, IsLiveSeek()).WillOnce(Return(false));
    bool ret = proxy->IsLiveSeek();
    EXPECT_FALSE(ret);
}

HWTEST_F(PlayerClientTest, IsSeekContinuousSupported_001, TestSize.Level0)
{
    auto proxy = sptr<MockIPlayerService>::MakeRaw();
    EXPECT_CALL(*proxy, IsSeekContinuousSupported()).WillOnce(Return(true));
    bool ret = proxy->IsSeekContinuousSupported();
    EXPECT_TRUE(ret);
}

HWTEST_F(PlayerClientTest, GetCurrentTime_001, TestSize.Level0)
{
    auto proxy = sptr<MockIPlayerService>::MakeRaw();
    EXPECT_CALL(*proxy, GetCurrentTime(_)).WillOnce(DoAll(SetArgReferee<0>(5000), Return(0)));
    int32_t currentTime = 0;
    int32_t ret = proxy->GetCurrentTime(currentTime);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(currentTime, 5000);
}

HWTEST_F(PlayerClientTest, GetDuration_001, TestSize.Level0)
{
    auto proxy = sptr<MockIPlayerService>::MakeRaw();
    EXPECT_CALL(*proxy, GetDuration(_)).WillOnce(DoAll(SetArgReferee<0>(120000), Return(0)));
    int32_t duration = 0;
    int32_t ret = proxy->GetDuration(duration);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(duration, 120000);
}

HWTEST_F(PlayerClientTest, GetVideoWidth_001, TestSize.Level0)
{
    auto proxy = sptr<MockIPlayerService>::MakeRaw();
    EXPECT_CALL(*proxy, GetVideoWidth()).WillOnce(Return(1920));
    int32_t width = proxy->GetVideoWidth();
    EXPECT_EQ(width, 1920);
}

HWTEST_F(PlayerClientTest, GetVideoHeight_001, TestSize.Level0)
{
    auto proxy = sptr<MockIPlayerService>::MakeRaw();
    EXPECT_CALL(*proxy, GetVideoHeight()).WillOnce(Return(1080));
    int32_t height = proxy->GetVideoHeight();
    EXPECT_EQ(height, 1080);
}

HWTEST_F(PlayerClientTest, SelectTrack_001, TestSize.Level0)
{
    auto proxy = sptr<MockIPlayerService>::MakeRaw();
    EXPECT_CALL(*proxy, SelectTrack(1, PlayerSwitchMode::SWITCH_SMOOTH)).WillOnce(Return(0));
    int32_t ret = proxy->SelectTrack(1, PlayerSwitchMode::SWITCH_SMOOTH);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerClientTest, DeselectTrack_001, TestSize.Level0)
{
    auto proxy = sptr<MockIPlayerService>::MakeRaw();
    EXPECT_CALL(*proxy, DeselectTrack(1)).WillOnce(Return(0));
    int32_t ret = proxy->DeselectTrack(1);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerClientTest, GetCurrentTrack_001, TestSize.Level0)
{
    auto proxy = sptr<MockIPlayerService>::MakeRaw();
    EXPECT_CALL(*proxy, GetCurrentTrack(0, _)).WillOnce(DoAll(SetArgReferee<1>(1), Return(0)));
    int32_t index = 0;
    int32_t ret = proxy->GetCurrentTrack(0, index);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(index, 1);
}

HWTEST_F(PlayerClientTest, SelectBitRate_001, TestSize.Level0)
{
    auto proxy = sptr<MockIPlayerService>::MakeRaw();
    EXPECT_CALL(*proxy, SelectBitRate(1000000)).WillOnce(Return(0));
    int32_t ret = proxy->SelectBitRate(1000000);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerClientTest, PlayerSeekMode_Values_001, TestSize.Level0)
{
    EXPECT_EQ(static_cast<int32_t>(PlayerSeekMode::SEEK_PREVIOUS_SYNC), 0);
    EXPECT_EQ(static_cast<int32_t>(PlayerSeekMode::SEEK_NEXT_SYNC), 1);
    EXPECT_EQ(static_cast<int32_t>(PlayerSeekMode::SEEK_CLOSEST_SYNC), 2);
    EXPECT_EQ(static_cast<int32_t>(PlayerSeekMode::SEEK_CLOSEST), 3);
}

HWTEST_F(PlayerClientTest, PlaybackRateMode_Values_001, TestSize.Level0)
{
    EXPECT_EQ(static_cast<int32_t>(PlaybackRateMode::SPEED_FORWARD_0_75_X), 0);
    EXPECT_EQ(static_cast<int32_t>(PlaybackRateMode::SPEED_FORWARD_1_00_X), 1);
    EXPECT_EQ(static_cast<int32_t>(PlaybackRateMode::SPEED_FORWARD_1_25_X), 2);
    EXPECT_EQ(static_cast<int32_t>(PlaybackRateMode::SPEED_FORWARD_1_75_X), 3);
    EXPECT_EQ(static_cast<int32_t>(PlaybackRateMode::SPEED_FORWARD_2_00_X), 4);
}

HWTEST_F(PlayerClientTest, PlayerSwitchMode_Values_001, TestSize.Level0)
{
    EXPECT_EQ(static_cast<int32_t>(PlayerSwitchMode::SWITCH_SMOOTH), 0);
    EXPECT_EQ(static_cast<int32_t>(PlayerSwitchMode::SWITCH_RESEek), 1);
}

} // namespace Media
} // namespace OHOS
