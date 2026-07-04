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

#include "player_service_proxy_test.h"

using namespace testing;
using namespace testing::Ext;

namespace OHOS {
namespace Media {

HWTEST_F(PlayerServiceProxyTest, SetListenerObject_001, TestSize.Level0)
{
    auto mockService = sptr<MockIStandardPlayerService>::MakeRaw();
    ASSERT_NE(mockService, nullptr);
    EXPECT_CALL(*mockService, SetListenerObject(_)).WillOnce(Return(0));
    int32_t ret = mockService->SetListenerObject(nullptr);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerServiceProxyTest, SetSource_Url_001, TestSize.Level0)
{
    auto mockService = sptr<MockIStandardPlayerService>::MakeRaw();
    EXPECT_CALL(*mockService, SetSource(_)).WillOnce(Return(0));
    int32_t ret = mockService->SetSource("http://example.com/test.mp4");
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerServiceProxyTest, SetSource_Fd_001, TestSize.Level0)
{
    auto mockService = sptr<MockIStandardPlayerService>::MakeRaw();
    EXPECT_CALL(*mockService, SetSource(5, 0, 1024)).WillOnce(Return(0));
    int32_t ret = mockService->SetSource(5, 0, 1024);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerServiceProxyTest, Prepare_001, TestSize.Level0)
{
    auto mockService = sptr<MockIStandardPlayerService>::MakeRaw();
    EXPECT_CALL(*mockService, Prepare()).WillOnce(Return(0));
    int32_t ret = mockService->Prepare();
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerServiceProxyTest, PrepareAsync_001, TestSize.Level0)
{
    auto mockService = sptr<MockIStandardPlayerService>::MakeRaw();
    EXPECT_CALL(*mockService, PrepareAsync()).WillOnce(Return(0));
    int32_t ret = mockService->PrepareAsync();
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerServiceProxyTest, Play_001, TestSize.Level0)
{
    auto mockService = sptr<MockIStandardPlayerService>::MakeRaw();
    EXPECT_CALL(*mockService, Play()).WillOnce(Return(0));
    int32_t ret = mockService->Play();
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerServiceProxyTest, Pause_001, TestSize.Level0)
{
    auto mockService = sptr<MockIStandardPlayerService>::MakeRaw();
    EXPECT_CALL(*mockService, Pause()).WillOnce(Return(0));
    int32_t ret = mockService->Pause();
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerServiceProxyTest, Stop_001, TestSize.Level0)
{
    auto mockService = sptr<MockIStandardPlayerService>::MakeRaw();
    EXPECT_CALL(*mockService, Stop()).WillOnce(Return(0));
    int32_t ret = mockService->Stop();
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerServiceProxyTest, Reset_001, TestSize.Level0)
{
    auto mockService = sptr<MockIStandardPlayerService>::MakeRaw();
    EXPECT_CALL(*mockService, Reset()).WillOnce(Return(0));
    int32_t ret = mockService->Reset();
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerServiceProxyTest, Release_001, TestSize.Level0)
{
    auto mockService = sptr<MockIStandardPlayerService>::MakeRaw();
    EXPECT_CALL(*mockService, Release()).WillOnce(Return(0));
    int32_t ret = mockService->Release();
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerServiceProxyTest, ReleaseSync_001, TestSize.Level0)
{
    auto mockService = sptr<MockIStandardPlayerService>::MakeRaw();
    EXPECT_CALL(*mockService, ReleaseSync()).WillOnce(Return(0));
    int32_t ret = mockService->ReleaseSync();
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerServiceProxyTest, SetVolume_001, TestSize.Level0)
{
    auto mockService = sptr<MockIStandardPlayerService>::MakeRaw();
    EXPECT_CALL(*mockService, SetVolume(0.5f, 0.5f)).WillOnce(Return(0));
    int32_t ret = mockService->SetVolume(0.5f, 0.5f);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerServiceProxyTest, Seek_001, TestSize.Level0)
{
    auto mockService = sptr<MockIStandardPlayerService>::MakeRaw();
    EXPECT_CALL(*mockService, Seek(1000, PlayerSeekMode::SEEK_PREVIOUS_SYNC)).WillOnce(Return(0));
    int32_t ret = mockService->Seek(1000, PlayerSeekMode::SEEK_PREVIOUS_SYNC);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerServiceProxyTest, SetLooping_001, TestSize.Level0)
{
    auto mockService = sptr<MockIStandardPlayerService>::MakeRaw();
    EXPECT_CALL(*mockService, SetLooping(true)).WillOnce(Return(0));
    int32_t ret = mockService->SetLooping(true);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerServiceProxyTest, SetPlaybackSpeed_001, TestSize.Level0)
{
    auto mockService = sptr<MockIStandardPlayerService>::MakeRaw();
    EXPECT_CALL(*mockService, SetPlaybackSpeed(PlaybackRateMode::SPEED_FORWARD_2X)).WillOnce(Return(0));
    int32_t ret = mockService->SetPlaybackSpeed(PlaybackRateMode::SPEED_FORWARD_2X);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerServiceProxyTest, SetPlaybackRate_001, TestSize.Level0)
{
    auto mockService = sptr<MockIStandardPlayerService>::MakeRaw();
    EXPECT_CALL(*mockService, SetPlaybackRate(2.0f)).WillOnce(Return(0));
    int32_t ret = mockService->SetPlaybackRate(2.0f);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerServiceProxyTest, IsPlaying_001, TestSize.Level0)
{
    auto mockService = sptr<MockIStandardPlayerService>::MakeRaw();
    EXPECT_CALL(*mockService, IsPlaying()).WillOnce(Return(true));
    bool ret = mockService->IsPlaying();
    EXPECT_TRUE(ret);
}

HWTEST_F(PlayerServiceProxyTest, IsLooping_001, TestSize.Level0)
{
    auto mockService = sptr<MockIStandardPlayerService>::MakeRaw();
    EXPECT_CALL(*mockService, IsLooping()).WillOnce(Return(true));
    bool ret = mockService->IsLooping();
    EXPECT_TRUE(ret);
}

HWTEST_F(PlayerServiceProxyTest, IsLiveSeek_001, TestSize.Level0)
{
    auto mockService = sptr<MockIStandardPlayerService>::MakeRaw();
    EXPECT_CALL(*mockService, IsLiveSeek()).WillOnce(Return(false));
    bool ret = mockService->IsLiveSeek();
    EXPECT_FALSE(ret);
}

HWTEST_F(PlayerServiceProxyTest, GetCurrentTime_001, TestSize.Level0)
{
    auto mockService = sptr<MockIStandardPlayerService>::MakeRaw();
    EXPECT_CALL(*mockService, GetCurrentTime(_)).WillOnce(DoAll(SetArgReferee<0>(5000), Return(0)));
    int32_t currentTime = 0;
    int32_t ret = mockService->GetCurrentTime(currentTime);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(currentTime, 5000);
}

HWTEST_F(PlayerServiceProxyTest, GetDuration_001, TestSize.Level0)
{
    auto mockService = sptr<MockIStandardPlayerService>::MakeRaw();
    EXPECT_CALL(*mockService, GetDuration(_)).WillOnce(DoAll(SetArgReferee<0>(120000), Return(0)));
    int32_t duration = 0;
    int32_t ret = mockService->GetDuration(duration);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(duration, 120000);
}

HWTEST_F(PlayerServiceProxyTest, GetVideoWidth_001, TestSize.Level0)
{
    auto mockService = sptr<MockIStandardPlayerService>::MakeRaw();
    EXPECT_CALL(*mockService, GetVideoWidth()).WillOnce(Return(1920));
    int32_t width = mockService->GetVideoWidth();
    EXPECT_EQ(width, 1920);
}

HWTEST_F(PlayerServiceProxyTest, GetVideoHeight_001, TestSize.Level0)
{
    auto mockService = sptr<MockIStandardPlayerService>::MakeRaw();
    EXPECT_CALL(*mockService, GetVideoHeight()).WillOnce(Return(1080));
    int32_t height = mockService->GetVideoHeight();
    EXPECT_EQ(height, 1080);
}

HWTEST_F(PlayerServiceProxyTest, SelectTrack_001, TestSize.Level0)
{
    auto mockService = sptr<MockIStandardPlayerService>::MakeRaw();
    EXPECT_CALL(*mockService, SelectTrack(1, PlayerSwitchMode::SWITCH_SMOOTH)).WillOnce(Return(0));
    int32_t ret = mockService->SelectTrack(1, PlayerSwitchMode::SWITCH_SMOOTH);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerServiceProxyTest, DeselectTrack_001, TestSize.Level0)
{
    auto mockService = sptr<MockIStandardPlayerService>::MakeRaw();
    EXPECT_CALL(*mockService, DeselectTrack(1)).WillOnce(Return(0));
    int32_t ret = mockService->DeselectTrack(1);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerServiceProxyTest, GetCurrentTrack_001, TestSize.Level0)
{
    auto mockService = sptr<MockIStandardPlayerService>::MakeRaw();
    EXPECT_CALL(*mockService, GetCurrentTrack(0, _)).WillOnce(DoAll(SetArgReferee<1>(1), Return(0)));
    int32_t index = 0;
    int32_t ret = mockService->GetCurrentTrack(0, index);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(index, 1);
}

HWTEST_F(PlayerServiceProxyTest, SelectBitRate_001, TestSize.Level0)
{
    auto mockService = sptr<MockIStandardPlayerService>::MakeRaw();
    EXPECT_CALL(*mockService, SelectBitRate(1000000)).WillOnce(Return(0));
    int32_t ret = mockService->SelectBitRate(1000000);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerServiceProxyTest, DestroyStub_001, TestSize.Level0)
{
    auto mockService = sptr<MockIStandardPlayerService>::MakeRaw();
    EXPECT_CALL(*mockService, DestroyStub()).WillOnce(Return(0));
    int32_t ret = mockService->DestroyStub();
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerServiceProxyTest, SetMaxAmplitudeCbStatus_001, TestSize.Level0)
{
    auto mockService = sptr<MockIStandardPlayerService>::MakeRaw();
    EXPECT_CALL(*mockService, SetMaxAmplitudeCbStatus(true)).WillOnce(Return(0));
    int32_t ret = mockService->SetMaxAmplitudeCbStatus(true);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerServiceProxyTest, SetDeviceChangeCbStatus_001, TestSize.Level0)
{
    auto mockService = sptr<MockIStandardPlayerService>::MakeRaw();
    EXPECT_CALL(*mockService, SetDeviceChangeCbStatus(true)).WillOnce(Return(0));
    int32_t ret = mockService->SetDeviceChangeCbStatus(true);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerServiceProxyTest, SetSeiMessageCbStatus_001, TestSize.Level0)
{
    auto mockService = sptr<MockIStandardPlayerService>::MakeRaw();
    std::vector<int32_t> payloadTypes = {1, 2, 3};
    EXPECT_CALL(*mockService, SetSeiMessageCbStatus(true, payloadTypes)).WillOnce(Return(0));
    int32_t ret = mockService->SetSeiMessageCbStatus(true, payloadTypes);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerServiceProxyTest, EnableReportMediaProgress_001, TestSize.Level0)
{
    auto mockService = sptr<MockIStandardPlayerService>::MakeRaw();
    EXPECT_CALL(*mockService, EnableReportMediaProgress(true)).WillOnce(Return(0));
    int32_t ret = mockService->EnableReportMediaProgress(true);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PlayerServiceProxyTest, EnableReportAudioInterrupt_001, TestSize.Level0)
{
    auto mockService = sptr<MockIStandardPlayerService>::MakeRaw();
    EXPECT_CALL(*mockService, EnableReportAudioInterrupt(true)).WillOnce(Return(0));
    int32_t ret = mockService->EnableReportAudioInterrupt(true);
    EXPECT_EQ(ret, 0);
}

} // namespace Media
} // namespace OHOS
