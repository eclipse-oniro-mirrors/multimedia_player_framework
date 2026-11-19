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
using namespace testing::ext;

namespace OHOS {
namespace Media {

HWTEST_F(PlayerServiceProxyTest, SetSource_Url_001, TestSize.Level0)
{
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardPlayerService::SET_SOURCE, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) -> int {
            reply.WriteInt32(MSERR_OK);
            return 0;
        }));
    int32_t ret = proxy_->SetSource("http://example.com/test.mp4");
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerServiceProxyTest, SetSource_Url_Error_001, TestSize.Level0)
{
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardPlayerService::SET_SOURCE, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) -> int {
            reply.WriteInt32(MSERR_INVALID_OPERATION);
            return 0;
        }));
    int32_t ret = proxy_->SetSource("http://invalid.com/test.mp4");
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

HWTEST_F(PlayerServiceProxyTest, Prepare_001, TestSize.Level0)
{
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardPlayerService::PREPARE, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) -> int {
            reply.WriteInt32(MSERR_OK);
            return 0;
        }));
    int32_t ret = proxy_->Prepare();
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerServiceProxyTest, Play_001, TestSize.Level0)
{
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardPlayerService::PLAY, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) -> int {
            reply.WriteInt32(MSERR_OK);
            return 0;
        }));
    int32_t ret = proxy_->Play();
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerServiceProxyTest, Pause_001, TestSize.Level0)
{
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardPlayerService::PAUSE, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) -> int {
            reply.WriteInt32(MSERR_OK);
            return 0;
        }));
    int32_t ret = proxy_->Pause();
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerServiceProxyTest, Stop_001, TestSize.Level0)
{
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardPlayerService::STOP, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) -> int {
            reply.WriteInt32(MSERR_OK);
            return 0;
        }));
    int32_t ret = proxy_->Stop();
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerServiceProxyTest, Reset_001, TestSize.Level0)
{
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardPlayerService::RESET, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) -> int {
            reply.WriteInt32(MSERR_OK);
            return 0;
        }));
    int32_t ret = proxy_->Reset();
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerServiceProxyTest, Release_001, TestSize.Level0)
{
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardPlayerService::RELEASE, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) -> int {
            reply.WriteInt32(MSERR_OK);
            return 0;
        }));
    int32_t ret = proxy_->Release();
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerServiceProxyTest, IsPlaying_True_001, TestSize.Level0)
{
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardPlayerService::IS_PLAYING, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) -> int {
            reply.WriteBool(true);
            return 0;
        }));
    bool ret = proxy_->IsPlaying();
    EXPECT_TRUE(ret);
}

HWTEST_F(PlayerServiceProxyTest, IsPlaying_False_001, TestSize.Level0)
{
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardPlayerService::IS_PLAYING, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) -> int {
            reply.WriteBool(false);
            return 0;
        }));
    bool ret = proxy_->IsPlaying();
    EXPECT_FALSE(ret);
}

HWTEST_F(PlayerServiceProxyTest, IsLooping_True_001, TestSize.Level0)
{
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardPlayerService::IS_LOOPING, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) -> int {
            reply.WriteBool(true);
            return 0;
        }));
    bool ret = proxy_->IsLooping();
    EXPECT_TRUE(ret);
}

HWTEST_F(PlayerServiceProxyTest, IsLooping_False_001, TestSize.Level0)
{
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardPlayerService::IS_LOOPING, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) -> int {
            reply.WriteBool(false);
            return 0;
        }));
    bool ret = proxy_->IsLooping();
    EXPECT_FALSE(ret);
}

HWTEST_F(PlayerServiceProxyTest, SetVolume_001, TestSize.Level0)
{
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardPlayerService::SET_VOLUME, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) -> int {
            reply.WriteInt32(MSERR_OK);
            return 0;
        }));
    int32_t ret = proxy_->SetVolume(0.5f, 0.5f);
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerServiceProxyTest, Seek_001, TestSize.Level0)
{
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardPlayerService::SEEK, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) -> int {
            reply.WriteInt32(MSERR_OK);
            return 0;
        }));
    int32_t ret = proxy_->Seek(1000, PlayerSeekMode::SEEK_PREVIOUS_SYNC);
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerServiceProxyTest, SetLooping_001, TestSize.Level0)
{
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardPlayerService::SET_LOOPING, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) -> int {
            reply.WriteInt32(MSERR_OK);
            return 0;
        }));
    int32_t ret = proxy_->SetLooping(true);
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerServiceProxyTest, SetPlaybackSpeed_001, TestSize.Level0)
{
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardPlayerService::SET_PLAYERBACK_SPEED, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) -> int {
            reply.WriteInt32(MSERR_OK);
            return 0;
        }));
    int32_t ret = proxy_->SetPlaybackSpeed(PlaybackRateMode::SPEED_FORWARD_2_00_X);
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerServiceProxyTest, GetCurrentTime_001, TestSize.Level0)
{
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardPlayerService::GET_CURRENT_TIME, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) -> int {
            reply.WriteInt32(5000);
            reply.WriteInt32(MSERR_OK);
            return 0;
        }));
    int32_t currentTime = 0;
    int32_t ret = proxy_->GetCurrentTime(currentTime);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(currentTime, 5000);
}

HWTEST_F(PlayerServiceProxyTest, GetDuration_001, TestSize.Level0)
{
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardPlayerService::GET_DURATION, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) -> int {
            reply.WriteInt32(120000);
            reply.WriteInt32(MSERR_OK);
            return 0;
        }));
    int32_t duration = 0;
    int32_t ret = proxy_->GetDuration(duration);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(duration, 120000);
}

HWTEST_F(PlayerServiceProxyTest, GetVideoWidth_001, TestSize.Level0)
{
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardPlayerService::GET_VIDEO_WIDTH, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) -> int {
            reply.WriteInt32(1920);
            return 0;
        }));
    int32_t width = proxy_->GetVideoWidth();
    EXPECT_EQ(width, 1920);
}

HWTEST_F(PlayerServiceProxyTest, GetVideoHeight_001, TestSize.Level0)
{
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardPlayerService::GET_VIDEO_HEIGHT, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) -> int {
            reply.WriteInt32(1080);
            return 0;
        }));
    int32_t height = proxy_->GetVideoHeight();
    EXPECT_EQ(height, 1080);
}

HWTEST_F(PlayerServiceProxyTest, SetSource_Fd_001, TestSize.Level0)
{
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardPlayerService::SET_FD_SOURCE, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) -> int {
            reply.WriteInt32(MSERR_OK);
            return 0;
        }));
    int32_t ret = proxy_->SetSource(5, 0, 1024);
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerServiceProxyTest, PrepareAsync_001, TestSize.Level0)
{
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardPlayerService::PREPAREASYNC, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) -> int {
            reply.WriteInt32(MSERR_OK);
            return 0;
        }));
    int32_t ret = proxy_->PrepareAsync();
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerServiceProxyTest, SelectBitRate_001, TestSize.Level0)
{
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardPlayerService::SELECT_BIT_RATE, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) -> int {
            reply.WriteInt32(MSERR_OK);
            return 0;
        }));
    int32_t ret = proxy_->SelectBitRate(1000000);
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerServiceProxyTest, DestroyStub_001, TestSize.Level0)
{
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardPlayerService::DESTROY, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) -> int {
            reply.WriteInt32(MSERR_OK);
            return 0;
        }));
    int32_t ret = proxy_->DestroyStub();
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerServiceProxyTest, SelectTrack_001, TestSize.Level0)
{
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardPlayerService::SELECT_TRACK, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) -> int {
            reply.WriteInt32(MSERR_OK);
            return 0;
        }));
    int32_t ret = proxy_->SelectTrack(1, PlayerSwitchMode::SWITCH_SMOOTH);
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerServiceProxyTest, DeselectTrack_001, TestSize.Level0)
{
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardPlayerService::DESELECT_TRACK, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) -> int {
            reply.WriteInt32(MSERR_OK);
            return 0;
        }));
    int32_t ret = proxy_->DeselectTrack(1);
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerServiceProxyTest, GetCurrentTrack_001, TestSize.Level0)
{
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardPlayerService::GET_CURRENT_TRACK, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) -> int {
            reply.WriteInt32(1);
            reply.WriteInt32(MSERR_OK);
            return 0;
        }));
    int32_t index = 0;
    int32_t ret = proxy_->GetCurrentTrack(0, index);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(index, 1);
}

HWTEST_F(PlayerServiceProxyTest, SendRequest_Failure_001, TestSize.Level0)
{
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardPlayerService::PLAY, _, _, _))
        .WillOnce(Return(-1));
    int32_t ret = proxy_->Play();
    EXPECT_NE(ret, MSERR_OK);
}

HWTEST_F(PlayerServiceProxyTest, SetListenerObject_001, TestSize.Level0)
{
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardPlayerService::SET_LISTENER_OBJ, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) -> int {
            reply.WriteInt32(MSERR_OK);
            return 0;
        }));
    int32_t ret = proxy_->SetListenerObject(nullptr);
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerServiceProxyTest, ReleaseSync_001, TestSize.Level0)
{
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardPlayerService::RELEASE, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) -> int {
            reply.WriteInt32(MSERR_OK);
            return 0;
        }));
    int32_t ret = proxy_->ReleaseSync();
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerServiceProxyTest, SetMaxAmplitudeCbStatus_001, TestSize.Level0)
{
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardPlayerService::SET_MAX_AMPLITUDE_CB_STATUS, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) -> int {
            reply.WriteInt32(MSERR_OK);
            return 0;
        }));
    int32_t ret = proxy_->SetMaxAmplitudeCbStatus(true);
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerServiceProxyTest, SetDeviceChangeCbStatus_001, TestSize.Level0)
{
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardPlayerService::SET_DEVICE_CHANGE_CB_STATUS, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) -> int {
            reply.WriteInt32(MSERR_OK);
            return 0;
        }));
    int32_t ret = proxy_->SetDeviceChangeCbStatus(true);
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerServiceProxyTest, SetSeiMessageCbStatus_001, TestSize.Level0)
{
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardPlayerService::SET_SEI_MESSAGE_CB_STATUS, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) -> int {
            reply.WriteInt32(MSERR_OK);
            return 0;
        }));
    std::vector<int32_t> payloadTypes = {1, 2, 3};
    int32_t ret = proxy_->SetSeiMessageCbStatus(true, payloadTypes);
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerServiceProxyTest, EnableReportMediaProgress_001, TestSize.Level0)
{
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardPlayerService::ENABLE_REPORT_MEDIA_PROGRESS, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) -> int {
            reply.WriteInt32(MSERR_OK);
            return 0;
        }));
    int32_t ret = proxy_->EnableReportMediaProgress(true);
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerServiceProxyTest, EnableReportAudioInterrupt_001, TestSize.Level0)
{
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardPlayerService::ENABLE_REPORT_AUDIO_INTERRUPT, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) -> int {
            reply.WriteInt32(MSERR_OK);
            return 0;
        }));
    int32_t ret = proxy_->EnableReportAudioInterrupt(true);
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerServiceProxyTest, SetPlaybackRate_001, TestSize.Level0)
{
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardPlayerService::SET_PLAYERBACK_RATE, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) -> int {
            reply.WriteInt32(MSERR_OK);
            return 0;
        }));
    int32_t ret = proxy_->SetPlaybackRate(2.0f);
    EXPECT_EQ(ret, MSERR_OK);
}

HWTEST_F(PlayerServiceProxyTest, IsLiveSeek_True_001, TestSize.Level0)
{
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardPlayerService::IS_LIVE_SEEK, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) -> int {
            reply.WriteBool(true);
            return 0;
        }));
    bool ret = proxy_->IsLiveSeek();
    EXPECT_TRUE(ret);
}

HWTEST_F(PlayerServiceProxyTest, IsLiveSeek_False_001, TestSize.Level0)
{
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardPlayerService::IS_LIVE_SEEK, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) -> int {
            reply.WriteBool(false);
            return 0;
        }));
    bool ret = proxy_->IsLiveSeek();
    EXPECT_FALSE(ret);
}

} // namespace Media
} // namespace OHOS
