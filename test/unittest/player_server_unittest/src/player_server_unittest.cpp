/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "player_server_unittest.h"
#include <unistd.h>
#include <securec.h>
#include "media_errors.h"
#include "audio_effect.h"
#include "av_common.h"
#include "meta/video_types.h"
#include "meta/format.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS::Media::PlayerTestParam;

namespace OHOS {
namespace Media {
void PlayerServerUnitTest::SetUpTestCase(void)
{
}

void PlayerServerUnitTest::TearDownTestCase(void)
{
    std::cout << "sleep one second to protect PlayerEngine safely exit." << endl;
    sleep(1); //let PlayEngine safe exit.
}

void PlayerServerUnitTest::SetUp(void)
{
    callback_ = std::make_shared<PlayerCallbackTest>();
    ASSERT_NE(nullptr, callback_);
    player_ = std::make_shared<PlayerServerMock>(callback_);
    ASSERT_NE(nullptr, player_);
    EXPECT_TRUE(player_->CreatePlayer());
    EXPECT_EQ(MSERR_OK, player_->SetPlayerCallback(callback_));
}

void PlayerServerUnitTest::TearDown(void)
{
    if (player_ != nullptr) {
        player_->Release();
    }
}

/**
 * @tc.name  : Test SetSource API
 * @tc.number: Player_SetSource_008
 * @tc.desc  : Test Player SetSource interface
 */
HWTEST_F(PlayerServerUnitTest, Player_SetSource_008, TestSize.Level1)
{
    auto playerServer = static_pointer_cast<PlayerServer>(player_->player_);
    ASSERT_NE(playerServer, nullptr);
    playerServer->appTokenId_ = 0;
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->SetSource(MEDIA_URL));
}

/**
 * @tc.name  : Test SetSource API
 * @tc.number: Player_SetSource_010
 * @tc.desc  : Test Player SetSource interface
 */
HWTEST_F(PlayerServerUnitTest, Player_SetSource_010, TestSize.Level1)
{
    auto playerServer = static_pointer_cast<PlayerServer>(player_->player_);
    ASSERT_NE(playerServer, nullptr);
    playerServer->lastOpStatus_ = PlayerStates::PLAYER_IDLE;
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->SetSource(MEDIA_URL));
}

/**
 * @tc.name  : Test SetSource API
 * @tc.number: Player_SetSource_011
 * @tc.desc  : Test Player SetSource interface
 */
HWTEST_F(PlayerServerUnitTest, Player_SetSource_011, TestSize.Level1)
{
    auto playerServer = static_pointer_cast<PlayerServer>(player_->player_);
    ASSERT_NE(playerServer, nullptr);
    playerServer->lastOpStatus_ = PlayerStates::PLAYER_STATE_ERROR;
    playerServer->uriHelper_ = std::make_unique<UriHelper>(0, 0, 0);
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->SetSource(0, 0, 0));
    playerServer->uriHelper_.reset();
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->SetSource(0, 0, 0));
}

/**
 * @tc.name  : Test OnPlay
 * @tc.number: Player_OnPlay_001
 * @tc.desc  : Test Player OnPlay interface
 */
HWTEST_F(PlayerServerUnitTest, Player_OnPlay_001, TestSize.Level1)
{
    auto playerServer = static_pointer_cast<PlayerServer>(player_->player_);
    ASSERT_NE(playerServer, nullptr);
    playerServer->lastOpStatus_ = PlayerStates::PLAYER_STATE_ERROR;
    playerServer->dataSrc_ = std::make_shared<PlayerMediaDataSourceMock>(-1);
    ASSERT_NE(playerServer->dataSrc_, nullptr);
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->Play());
}

/**
 * @tc.name  : Test OnPlay
 * @tc.number: Player_OnPlay_002
 * @tc.desc  : Test Player OnPlay interface
 */
HWTEST_F(PlayerServerUnitTest, Player_OnPlay_002, TestSize.Level1)
{
    auto playerServer = static_pointer_cast<PlayerServer>(player_->player_);
    ASSERT_NE(playerServer, nullptr);
    playerServer->lastOpStatus_ = PlayerStates::PLAYER_STATE_ERROR;
    playerServer->dataSrc_ = std::make_shared<PlayerMediaDataSourceMock>(0);
    ASSERT_NE(playerServer->dataSrc_, nullptr);
    playerServer->taskMgr_.isInited_ = false;
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->Play());
}

/**
 * @tc.name  : Test HandleFreeze
 * @tc.number: Player_HandleFreeze_001
 * @tc.desc  : Test Player HandleFreeze interface
 */
HWTEST_F(PlayerServerUnitTest, Player_HandleFreeze_001, TestSize.Level1)
{
    auto playerServer = static_pointer_cast<PlayerServer>(player_->player_);
    ASSERT_NE(playerServer, nullptr);
    playerServer->playerEngine_ = std::make_unique<PlayerEngineMock>();
    ASSERT_NE(playerServer->playerEngine_, nullptr);
    ASSERT_EQ(MSERR_OK, playerServer->HandleFreeze());
}

/**
 * @tc.name  : Test HandleUnFreeze
 * @tc.number: Player_HandleUnFreeze_001
 * @tc.desc  : Test Player HandleUnFreeze interface
 */
HWTEST_F(PlayerServerUnitTest, Player_HandleUnFreeze_001, TestSize.Level1)
{
    auto playerServer = static_pointer_cast<PlayerServer>(player_->player_);
    ASSERT_NE(playerServer, nullptr);
    playerServer->playerEngine_ = std::make_unique<PlayerEngineMock>();
    ASSERT_NE(playerServer->playerEngine_, nullptr);
    ASSERT_EQ(MSERR_OK, playerServer->HandleUnFreeze());
}

/**
 * @tc.name  : Test SetVolumeMode API
 * @tc.number: Player_SetVolumeMode_002
 * @tc.desc  : Test Player SetVolumeMode interface
 */
HWTEST_F(PlayerServerUnitTest, Player_SetVolumeMode_002, TestSize.Level1)
{
    auto playerServer = static_pointer_cast<PlayerServer>(player_->player_);
    ASSERT_NE(playerServer, nullptr);
    playerServer->lastOpStatus_ = PlayerStates::PLAYER_STATE_ERROR;
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->SetVolumeMode(0));
}

/**
 * @tc.name  : Test GetPlaybackPosition API
 * @tc.number: Player_GetPlaybackPosition_001
 * @tc.desc  : Test Player GetPlaybackPosition interface
 */
HWTEST_F(PlayerServerUnitTest, Player_GetPlaybackPosition_001, TestSize.Level1)
{
    auto playerServer = static_pointer_cast<PlayerServer>(player_->player_);
    ASSERT_NE(playerServer, nullptr);
    playerServer->lastOpStatus_ = PlayerStates::PLAYER_IDLE;
    int32_t mockPosition {0};
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->GetPlaybackPosition(mockPosition));
}

/**
 * @tc.name  : Test GetPlaybackPosition API
 * @tc.number: Player_GetPlaybackPosition_002
 * @tc.desc  : Test Player GetPlaybackPosition interface
 */
HWTEST_F(PlayerServerUnitTest, Player_GetPlaybackPosition_002, TestSize.Level1)
{
    auto playerServer = static_pointer_cast<PlayerServer>(player_->player_);
    ASSERT_NE(playerServer, nullptr);
    playerServer->lastOpStatus_ = PlayerStates::PLAYER_STATE_ERROR;
    int32_t mockPosition {0};
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->GetPlaybackPosition(mockPosition));
}

/**
 * @tc.name  : Test GetPlaybackPosition API
 * @tc.number: Player_GetPlaybackPosition_003
 * @tc.desc  : Test Player GetPlaybackPosition interface
 */
HWTEST_F(PlayerServerUnitTest, Player_GetPlaybackPosition_003, TestSize.Level1)
{
    auto playerServer = static_pointer_cast<PlayerServer>(player_->player_);
    ASSERT_NE(playerServer, nullptr);
    playerServer->lastOpStatus_ = PlayerStates::PLAYER_PREPARED;
    int32_t mockPosition {0};
    playerServer->playerEngine_.reset();
    ASSERT_EQ(MSERR_OK, player_->GetPlaybackPosition(mockPosition));
}

/**
 * @tc.name  : Test GetPlaybackPosition API
 * @tc.number: Player_GetPlaybackPosition_004
 * @tc.desc  : Test Player GetPlaybackPosition interface
 */
HWTEST_F(PlayerServerUnitTest, Player_GetPlaybackPosition_004, TestSize.Level1)
{
    auto playerServer = static_pointer_cast<PlayerServer>(player_->player_);
    ASSERT_NE(playerServer, nullptr);
    playerServer->lastOpStatus_ = PlayerStates::PLAYER_STARTED;
    int32_t mockPosition {0};
    playerServer->playerEngine_.reset();
    ASSERT_EQ(MSERR_OK, player_->GetPlaybackPosition(mockPosition));
}

/**
 * @tc.name  : Test GetPlaybackPosition API
 * @tc.number: Player_GetPlaybackPosition_005
 * @tc.desc  : Test Player GetPlaybackPosition interface
 */
HWTEST_F(PlayerServerUnitTest, Player_GetPlaybackPosition_005, TestSize.Level1)
{
    auto playerServer = static_pointer_cast<PlayerServer>(player_->player_);
    ASSERT_NE(playerServer, nullptr);
    playerServer->lastOpStatus_ = PlayerStates::PLAYER_PAUSED;
    int32_t mockPosition {0};
    playerServer->playerEngine_.reset();
    ASSERT_EQ(MSERR_OK, player_->GetPlaybackPosition(mockPosition));
}

/**
 * @tc.name  : Test GetPlaybackPosition API
 * @tc.number: Player_GetPlaybackPosition_006
 * @tc.desc  : Test Player GetPlaybackPosition interface
 */
HWTEST_F(PlayerServerUnitTest, Player_GetPlaybackPosition_006, TestSize.Level1)
{
    auto playerServer = static_pointer_cast<PlayerServer>(player_->player_);
    ASSERT_NE(playerServer, nullptr);
    playerServer->lastOpStatus_ = PlayerStates::PLAYER_PLAYBACK_COMPLETE;
    int32_t mockPosition {0};
    playerServer->playerEngine_.reset();
    ASSERT_EQ(MSERR_OK, player_->GetPlaybackPosition(mockPosition));
}

/**
 * @tc.name  : Test GetPlaybackPosition API
 * @tc.number: Player_GetPlaybackPosition_007
 * @tc.desc  : Test Player GetPlaybackPosition interface
 */
HWTEST_F(PlayerServerUnitTest, Player_GetPlaybackPosition_007, TestSize.Level1)
{
    auto playerServer = static_pointer_cast<PlayerServer>(player_->player_);
    ASSERT_NE(playerServer, nullptr);
    playerServer->lastOpStatus_ = PlayerStates::PLAYER_PREPARING;
    int32_t mockPosition {0};
    playerServer->playerEngine_.reset();
    ASSERT_EQ(MSERR_OK, player_->GetPlaybackPosition(mockPosition));
}

/**
 * @tc.name  : Test SetPlaybackRate API
 * @tc.number: Player_SetPlaybackRate_006
 * @tc.desc  : Test Player SetPlaybackRate interface
 */
HWTEST_F(PlayerServerUnitTest, Player_SetPlaybackRate_006, TestSize.Level1)
{
    auto playerServer = static_pointer_cast<PlayerServer>(player_->player_);
    ASSERT_NE(playerServer, nullptr);
    playerServer->lastOpStatus_ = PlayerStates::PLAYER_STARTED;
    playerServer->isLiveStream_ = true;
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->SetPlaybackRate(0.0));
}

/**
 * @tc.name  : Test SetMediaSource API
 * @tc.number: Player_SetMediaSource_007
 * @tc.desc  : Test Player SetMediaSource interface
 */
HWTEST_F(PlayerServerUnitTest, Player_SetMediaSource_007, TestSize.Level1)
{
    auto playerServer = static_pointer_cast<PlayerServer>(player_->player_);
    ASSERT_NE(playerServer, nullptr);
    std::map<std::string, std::string> header = {};
    struct AVPlayStrategy strategy = {1080, 920, 10000, false};
    std::string mockUrl = "fd://-?offset=";
    std::shared_ptr<AVMediaSource> mediaSource = std::make_shared<AVMediaSource>(mockUrl, header);
    mediaSource->mimeType_ = AVMimeType::APPLICATION_M3U8;
    playerServer->lastOpStatus_ = PlayerStates::PLAYER_STARTED;
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->SetMediaSource(mediaSource, strategy));
}

/**
 * @tc.name  : Test SetMediaSource API
 * @tc.number: Player_SetMediaSource_008
 * @tc.desc  : Test Player SetMediaSource interface
 */
HWTEST_F(PlayerServerUnitTest, Player_SetMediaSource_008, TestSize.Level1)
{
    auto playerServer = static_pointer_cast<PlayerServer>(player_->player_);
    ASSERT_NE(playerServer, nullptr);
    std::map<std::string, std::string> header = {};
    struct AVPlayStrategy strategy = {1080, 920, 10000, false};
    std::string mockUrl = "?fd://offset=&";
    std::shared_ptr<AVMediaSource> mediaSource = std::make_shared<AVMediaSource>(mockUrl, header);
    mediaSource->mimeType_ = AVMimeType::APPLICATION_M3U8;
    ASSERT_EQ(MSERR_INVALID_VAL, player_->SetMediaSource(mediaSource, strategy));
}

/**
 * @tc.name  : Test HandleAudioDeviceChangeEvent
 * @tc.number: Player_HandleAudioDeviceChangeEvent_001
 * @tc.desc  : Test Player HandleAudioDeviceChangeEvent interface
 */
HWTEST_F(PlayerServerUnitTest, Player_HandleAudioDeviceChangeEvent_001, TestSize.Level1)
{
    auto playerServer = static_pointer_cast<PlayerServer>(player_->player_);
    ASSERT_NE(playerServer, nullptr);
    playerServer->audioDeviceChangeState_ = PLAYER_IDLE;
    playerServer->deviceChangeCallbackflag_ = true;
    Format infoBody;
    playerServer->HandleAudioDeviceChangeEvent(infoBody);
    ASSERT_EQ(PLAYER_IDLE, playerServer->audioDeviceChangeState_);
}

/**
 * @tc.name  : Test HandleAudioDeviceChangeEvent
 * @tc.number: Player_HandleAudioDeviceChangeEvent_002
 * @tc.desc  : Test Player HandleAudioDeviceChangeEvent interface
 */
HWTEST_F(PlayerServerUnitTest, Player_HandleAudioDeviceChangeEvent_002, TestSize.Level1)
{
    auto playerServer = static_pointer_cast<PlayerServer>(player_->player_);
    ASSERT_NE(playerServer, nullptr);
    playerServer->audioDeviceChangeState_ = PLAYER_IDLE;
    playerServer->deviceChangeCallbackflag_ = false;
    Format infoBody;
    int32_t mockValue = -1;
    (void)infoBody.PutIntValue(PlayerKeys::AUDIO_DEVICE_CHANGE_REASON, mockValue);
    playerServer->HandleAudioDeviceChangeEvent(infoBody);
    ASSERT_EQ(PLAYER_IDLE, playerServer->audioDeviceChangeState_);
}

/**
 * @tc.name  : Test HandleAudioDeviceChangeEvent
 * @tc.number: Player_HandleAudioDeviceChangeEvent_003
 * @tc.desc  : Test Player HandleAudioDeviceChangeEvent interface
 */
HWTEST_F(PlayerServerUnitTest, Player_HandleAudioDeviceChangeEvent_003, TestSize.Level1)
{
    auto playerServer = static_pointer_cast<PlayerServer>(player_->player_);
    ASSERT_NE(playerServer, nullptr);
    playerServer->audioDeviceChangeState_ = PLAYER_IDLE;
    playerServer->deviceChangeCallbackflag_ = false;
    Format infoBody;
    (void)infoBody.PutIntValue(PlayerKeys::AUDIO_DEVICE_CHANGE_REASON,
        static_cast<int32_t>(OHOS::AudioStandard::AudioStreamDeviceChangeReason::OLD_DEVICE_UNAVALIABLE));
    playerServer->isStreamUsagePauseRequired_ = false;
    playerServer->HandleAudioDeviceChangeEvent(infoBody);
    ASSERT_EQ(PLAYER_IDLE, playerServer->audioDeviceChangeState_);
}

/**
 * @tc.name  : Test HandleAudioDeviceChangeEvent
 * @tc.number: Player_HandleAudioDeviceChangeEvent_004
 * @tc.desc  : Test Player HandleAudioDeviceChangeEvent interface
 */
HWTEST_F(PlayerServerUnitTest, Player_HandleAudioDeviceChangeEvent_004, TestSize.Level1)
{
    auto playerServer = static_pointer_cast<PlayerServer>(player_->player_);
    ASSERT_NE(playerServer, nullptr);
    playerServer->audioDeviceChangeState_ = PLAYER_IDLE;
    playerServer->deviceChangeCallbackflag_ = false;
    Format infoBody;
    (void)infoBody.PutIntValue(PlayerKeys::AUDIO_DEVICE_CHANGE_REASON,
        static_cast<int32_t>(OHOS::AudioStandard::AudioStreamDeviceChangeReason::OLD_DEVICE_UNAVALIABLE));
    playerServer->isStreamUsagePauseRequired_ = true;
    playerServer->lastOpStatus_ = PLAYER_PAUSED;
    playerServer->HandleAudioDeviceChangeEvent(infoBody);
    ASSERT_EQ(PLAYER_PAUSED, playerServer->audioDeviceChangeState_);
}

/**
 * @tc.name  : Test ExitSeekContinousAsync
 * @tc.number: Player_ExitSeekContinousAsync_001
 * @tc.desc  : Test Player ExitSeekContinousAsync interface
 */
HWTEST_F(PlayerServerUnitTest, Player_ExitSeekContinousAsync_001, TestSize.Level1)
{
    auto playerServer = static_pointer_cast<PlayerServer>(player_->player_);
    ASSERT_NE(playerServer, nullptr);
    playerServer->isInSeekContinous_ = false;
    ASSERT_EQ(MSERR_OK, playerServer->ExitSeekContinousAsync(0));
}

/**
 * @tc.name  : Test ExitSeekContinousAsync
 * @tc.number: Player_ExitSeekContinousAsync_002
 * @tc.desc  : Test Player ExitSeekContinousAsync interface
 */
HWTEST_F(PlayerServerUnitTest, Player_ExitSeekContinousAsync_002, TestSize.Level1)
{
    auto playerServer = static_pointer_cast<PlayerServer>(player_->player_);
    ASSERT_NE(playerServer, nullptr);
    playerServer->isInSeekContinous_ = true;
    playerServer->playerEngine_.reset();
    ASSERT_EQ(MSERR_INVALID_OPERATION, playerServer->ExitSeekContinousAsync(0));
}

/**
 * @tc.name  : Test DoCheckLiveDelayTime
 * @tc.number: Player_DoCheckLiveDelayTime_001
 * @tc.desc  : Test Player DoCheckLiveDelayTime interface
 */
HWTEST_F(PlayerServerUnitTest, Player_DoCheckLiveDelayTime_001, TestSize.Level1)
{
    auto playerServer = static_pointer_cast<PlayerServer>(player_->player_);
    ASSERT_NE(playerServer, nullptr);
    playerServer->sumPauseTime_ = -1;
    playerServer->isXSpeedPlay_ = true;
    playerServer->playerEngine_ = std::make_unique<PlayerEngineMock>();
    ASSERT_NE(playerServer->playerEngine_, nullptr);
    playerServer->DoCheckLiveDelayTime();
    ASSERT_EQ(0, playerServer->sumPauseTime_);
}

/**
 * @tc.name  : Test InnerOnInfo
 * @tc.number: Player_InnerOnInfo_004
 * @tc.desc  : Test Player InnerOnInfo interface
 */
HWTEST_F(PlayerServerUnitTest, Player_InnerOnInfo_004, TestSize.Level1)
{
    auto playerServer = static_pointer_cast<PlayerServer>(player_->player_);
    ASSERT_NE(playerServer, nullptr);
    ASSERT_NE(player_->callback_, nullptr);
    Format infoBody;
    playerServer->InnerOnInfo(INFO_TYPE_ERROR_MSG, 0, infoBody, 0);
    ASSERT_EQ(true, player_->callback_->errInfo_);
}

/**
 * @tc.name  : Test OnError Propagation
 * @tc.number: Player_OnError_Propagation_001
 * @tc.desc  : Test that PlayerServer propagates errors from the engine to the callback
 */
HWTEST_F(PlayerServerUnitTest, Player_OnError_Propagation_001, TestSize.Level1)
{
    auto playerServer = static_pointer_cast<PlayerServer>(player_->player_);
    ASSERT_NE(playerServer, nullptr);

    auto mockEngine = std::make_unique<PlayerEngineMock>();
    auto mockEnginePtr = mockEngine.get();
    playerServer->playerEngine_ = std::move(mockEngine);

    mockEnginePtr->SetObs(playerServer);

    int32_t expectedErrorCode = MSERR_UNSUPPORT_AUD_DEC_TYPE;
    mockEnginePtr->TriggerError(PlayerErrorType::PLAYER_ERROR, expectedErrorCode, "Test Error Propagation");

    ASSERT_EQ(expectedErrorCode, callback_->errorCode_.load());
}

/**
 * @tc.name  : Test OnError Coverage for All Scenarios
 * @tc.number: Player_OnError_Coverage_001
 * @tc.desc  : Test that PlayerServer propagates all specific error codes identified in analysis with correct ErrorType
 */
HWTEST_F(PlayerServerUnitTest, Player_OnError_Coverage_001, TestSize.Level1)
{
    using ErrorScenario = std::tuple<PlayerErrorType, int32_t, std::string>;
    std::vector<ErrorScenario> scenarios = {
        {PlayerErrorType::AUD_DEC_ERR, MSERR_UNSUPPORT_AUD_DEC_TYPE, "AUD_DEC_ERR-"},
        {PlayerErrorType::DRM_ERR, MSERR_DRM_VERIFICATION_FAILED, "DRM_ERR-"},
        {PlayerErrorType::AUD_OUTPUT_ERR, MSERR_AUD_RENDER_FAILED, "AUD_OUTPUT_ERR-"},
        {PlayerErrorType::VID_DEC_ERR, MSERR_EXT_API9_IO, "VID_DEC_ERR-"},
        {PlayerErrorType::VID_DEC_ERR, MSERR_UNSUPPORT_VID_DEC_TYPE, "VID_DEC_ERR-"},
        {PlayerErrorType::VID_DEC_ERR, MSERR_VID_DEC_FAILED, "VID_DEC_ERR-"},
        {PlayerErrorType::DEM_FMT_ERR, MSERR_DEMUXER_FAILED, "DEM_FMT_ERR-"},
        {PlayerErrorType::DEM_FMT_ERR, MSERR_UNSUPPORT_CONTAINER_TYPE, "DEM_FMT_ERR-"},
        {PlayerErrorType::DEM_PARSE_ERR, MSERR_DATA_SOURCE_ERROR_UNKNOWN, "DEM_PARSE_ERR-"},
        {PlayerErrorType::DEM_PARSE_ERR, MSERR_DEMUXER_BUFFER_NO_MEMORY, "DEM_PARSE_ERR-"},
        {PlayerErrorType::AUD_OUTPUT_ERR, MSERR_UNSUPPORT_AUD_SAMPLE_RATE, "AUD_OUTPUT_ERR-"},
        {PlayerErrorType::AUD_OUTPUT_ERR, MSERR_UNSUPPORT_AUD_CHANNEL_NUM, "AUD_OUTPUT_ERR-"},
        {PlayerErrorType::AUD_OUTPUT_ERR, MSERR_UNSUPPORT_AUD_PARAMS, "AUD_OUTPUT_ERR-"},
        {PlayerErrorType::PLAY_ERR, MSERR_SEEK_CONTINUOUS_UNSUPPORTED, "PLAY_ERR-"},
        {PlayerErrorType::PLAY_ERR, MSERR_DATA_SOURCE_IO_ERROR, "PLAY_ERR-"},
        {PlayerErrorType::PLAY_ERR, MSERR_INVALID_VAL, "PLAY_ERR-"},
        {PlayerErrorType::CONTAINER_ERR, MSERR_UNSUPPORT_CONTAINER_TYPE, "CONTAINER_ERR-"},
    };
    for (const auto& scenario : scenarios) {
        auto serverAccessor = std::make_shared<PlayerServerTestAccessor>();
        ASSERT_NE(serverAccessor, nullptr);
        serverAccessor->Init();
        serverAccessor->InitTaskMgr();
        std::shared_ptr<PlayerServer> server = serverAccessor;
        auto callback = std::make_shared<PlayerCallbackTest>();
        server->SetPlayerCallback(callback);
        auto mockEngine = std::make_unique<PlayerEngineMock>();
        auto mockEnginePtr = mockEngine.get();
        server->playerEngine_ = std::move(mockEngine);
        mockEnginePtr->SetObs(server);
        std::string msg = "test_msg_" + std::to_string(std::get<1>(scenario));
        mockEnginePtr->TriggerError(std::get<0>(scenario), std::get<1>(scenario), msg);
        int retry = 0;
        while (callback->errorCode_.load() != std::get<1>(scenario) && retry++ < 100) {
            usleep(10000);
        }
        EXPECT_EQ(std::get<1>(scenario), callback->errorCode_.load());
        EXPECT_NE(callback->errorMsg_.find(msg), std::string::npos);
        EXPECT_NE(callback->errorMsg_.find(std::get<2>(scenario)), std::string::npos);
        server->Release();
    }
}
} // namespace Media
} // namespace OHOS
