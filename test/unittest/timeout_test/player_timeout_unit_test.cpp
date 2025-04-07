/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "player_timeout_unit_test.h"

#include "gmock/gmock.h"

using namespace std;
using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace Media {
const std::string MEDIA_ROOT = "file:///data/test/";
const std::string VIDEO_FILE1 = MEDIA_ROOT + "H264_AAC.mp4";

IMediaService& MediaServiceFactory::GetInstance()
{
    static auto mockMediaService = std::make_shared<MockIMediaService>();
    return *mockMediaService;
}

void PlayerTimeoutUnitTest::SetUpTestCase(void)
{
}

void PlayerTimeoutUnitTest::TearDownTestCase(void)
{
}

void PlayerTimeoutUnitTest::SetUp(void)
{
    mockPlayerService_ = std::make_shared<MockIPlayerService>();
    auto& mockMediaService = MediaServiceFactory::GetInstance();

    auto* mockMediaServicePtr = reinterpret_cast<MockIMediaService*>(&mockMediaService);
    ASSERT_NE(mockMediaServicePtr, nullptr);

    EXPECT_CALL(*mockMediaServicePtr, CreatePlayerService())
        .WillOnce(Return(mockPlayerService_));

    playerImpl_ = std::make_shared<PlayerImpl>();
    ASSERT_NE(nullptr, playerImpl_);
    EXPECT_EQ(MSERR_OK, playerImpl_->Init());
}

void PlayerTimeoutUnitTest::TearDown(void)
{
    if (playerImpl_ != nullptr) {
        playerImpl_->Release();
    }
}

/**
 * @tc.name  : Test SetMediaMuted_Timeout
 * @tc.number: Player_SetMediaMuted_Timeout_001
 * @tc.desc  : Test Player SetMediaMuted_Timeout
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_SetMediaMuted_Timeout_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    EXPECT_CALL(*mockPlayerService_, SetMediaMuted(_, _))
        .WillOnce([](MediaType mediaType, bool isMuted) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return MSERR_OK;
        });
    EXPECT_EQ(MSERR_OK, playerImpl_->SetMediaMuted(OHOS::Media::MediaType::MEDIA_TYPE_AUD, true));
}

/**
 * @tc.name  : Test SetSource_dataSrc_Timeout
 * @tc.number: Player_SetSource_dataSrc_Timeout_001
 * @tc.desc  : Test Player SetSource_dataSrc_Timeout
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_SetSource_DataSrc_Timeout_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    
    auto mockDataSource = std::make_shared<MockIMediaDataSource>();
    
    EXPECT_CALL(*mockPlayerService_, SetSource(::testing::An<const std::shared_ptr<IMediaDataSource>&>()))
        .WillOnce([](const std::shared_ptr<IMediaDataSource>&) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return MSERR_OK;
        });
    
    EXPECT_EQ(MSERR_OK, playerImpl_->SetSource(mockDataSource));
}

/**
 * @tc.name  : Test SetSource_Url_Timeout
 * @tc.number: Player_SetSource_Url_Timeout_001
 * @tc.desc  : Test Player SetSource_Url_Timeout
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_SetSource_Url_Timeout_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;

    const std::string testUrl = "http://example.com/video.mp4";

    EXPECT_CALL(*mockPlayerService_, SetSource(::testing::An<const std::string&>()))
        .WillOnce([](const std::string&) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return MSERR_OK;
        });
    EXPECT_EQ(MSERR_OK, playerImpl_->SetSource(testUrl));
}

/**
 * @tc.name  : Test SetSource_Fd_Timeout
 * @tc.number: Player_SetSource_Fd_Timeout_001
 * @tc.desc  : Test Player SetSource_Fd_Timeout
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_SetSource_Fd_Timeout_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    EXPECT_CALL(*mockPlayerService_, SetSource(_, _, _))
        .WillOnce([](int32_t, int64_t, int64_t) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return MSERR_OK;
        });
    EXPECT_EQ(MSERR_OK, playerImpl_->SetSource(1, 0, 100));
}

/**
 * @tc.name  : Test AddSubSource_Url_Timeout
 * @tc.number: Player_AddSubSource_Url_Timeout_001
 * @tc.desc  : Test Player AddSubSource_Url_Timeout
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_AddSubSource_Url_Timeout_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    EXPECT_CALL(*mockPlayerService_, AddSubSource(_))
        .WillOnce([](const std::string&) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return MSERR_OK;
        });
    EXPECT_EQ(MSERR_OK, playerImpl_->AddSubSource("http://example.com/subtitle.srt"));
}

/**
 * @tc.name  : Test AddSubSource_Fd_Timeout
 * @tc.number: Player_AddSubSource_Fd_Timeout_001
 * @tc.desc  : Test Player AddSubSource_Fd_Timeout
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_AddSubSource_Fd_Timeout_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    EXPECT_CALL(*mockPlayerService_, AddSubSource(_, _, _))
        .WillOnce([](int32_t, int64_t, int64_t) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return MSERR_OK;
        });
    EXPECT_EQ(MSERR_OK, playerImpl_->AddSubSource(1, 0, 100));
}

/**
 * @tc.name  : Test Play_Timeout
 * @tc.number: Player_Play_Timeout_001
 * @tc.desc  : Test Player Play_Timeout
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_Play_Timeout_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    EXPECT_CALL(*mockPlayerService_, Play())
        .WillOnce([]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return MSERR_OK;
        });
    EXPECT_EQ(MSERR_OK, playerImpl_->Play());
}

/**
 * @tc.name  : Test SetPlayRange_Timeout
 * @tc.number: Player_SetPlayRange_Timeout_001
 * @tc.desc  : Test Player SetPlayRange_Timeout
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_SetPlayRange_Timeout_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    EXPECT_CALL(*mockPlayerService_, SetPlayRange(_, _))
        .WillOnce([](int64_t, int64_t) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return MSERR_OK;
        });
    EXPECT_EQ(MSERR_OK, playerImpl_->SetPlayRange(0, 1000));
}

/**
 * @tc.name  : Test SetPlayRangeWithMode_Timeout
 * @tc.number: Player_SetPlayRangeWithMode_Timeout_001
 * @tc.desc  : Test Player SetPlayRangeWithMode_Timeout
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_SetPlayRangeWithMode_Timeout_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    EXPECT_CALL(*mockPlayerService_, SetPlayRangeWithMode(_, _, _))
        .WillOnce([](int64_t, int64_t, PlayerSeekMode) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return MSERR_OK;
        });
    EXPECT_EQ(MSERR_OK, playerImpl_->SetPlayRangeWithMode(0, 1000, PlayerSeekMode::SEEK_PREVIOUS_SYNC));
}

/**
 * @tc.name  : Test Prepare_Timeout
 * @tc.number: Player_Prepare_Timeout_001
 * @tc.desc  : Test Player Prepare timeout behavior
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_Prepare_Timeout_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    EXPECT_CALL(*mockPlayerService_, Prepare())
        .WillOnce([]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return MSERR_OK;
        });
    EXPECT_EQ(MSERR_OK, playerImpl_->Prepare());
}

/**
 * @tc.name  : Test SetRenderFirstFrame_Timeout
 * @tc.number: Player_SetRenderFirstFrame_Timeout_001
 * @tc.desc  : Test Player SetRenderFirstFrame timeout behavior
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_SetRenderFirstFrame_Timeout_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    EXPECT_CALL(*mockPlayerService_, SetRenderFirstFrame(_))
        .WillOnce([](bool display) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return MSERR_OK;
        });
    EXPECT_EQ(MSERR_OK, playerImpl_->SetRenderFirstFrame(true));
}

/**
 * @tc.name  : Test PrepareAsync_Timeout
 * @tc.number: Player_PrepareAsync_Timeout_001
 * @tc.desc  : Test Player PrepareAsync timeout behavior
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_PrepareAsync_Timeout_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    EXPECT_CALL(*mockPlayerService_, PrepareAsync())
        .WillOnce([]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return MSERR_OK;
        });
    EXPECT_EQ(MSERR_OK, playerImpl_->PrepareAsync());
}

/**
 * @tc.name  : Test Pause_Timeout
 * @tc.number: Player_Pause_Timeout_001
 * @tc.desc  : Test Player Pause timeout behavior
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_Pause_Timeout_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    EXPECT_CALL(*mockPlayerService_, Pause())
        .WillOnce([]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return MSERR_OK;
        });
    EXPECT_EQ(MSERR_OK, playerImpl_->Pause());
}

/**
 * @tc.name  : Test Stop_Timeout
 * @tc.number: Player_Stop_Timeout_001
 * @tc.desc  : Test Player Stop timeout behavior
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_Stop_Timeout_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    EXPECT_CALL(*mockPlayerService_, Stop())
        .WillOnce([]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return MSERR_OK;
        });
    EXPECT_EQ(MSERR_OK, playerImpl_->Stop());
}

/**
 * @tc.name  : Test Reset_Timeout
 * @tc.number: Player_Reset_Timeout_001
 * @tc.desc  : Test Player Reset timeout behavior
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_Reset_Timeout_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    EXPECT_CALL(*mockPlayerService_, Reset())
        .WillOnce([]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return MSERR_OK;
        });
    EXPECT_EQ(MSERR_OK, playerImpl_->Reset());
}

/**
 * @tc.name  : Test Release_Timeout
 * @tc.number: Player_Release_Timeout_001
 * @tc.desc  : Test Player Release timeout behavior
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_Release_Timeout_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    EXPECT_CALL(*mockPlayerService_, Release())
        .WillOnce([]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
            return MSERR_OK;
        });
    EXPECT_EQ(MSERR_OK, playerImpl_->Release());
}

/**
 * @tc.name  : Test ReleaseSync_Timeout
 * @tc.number: Player_ReleaseSync_Timeout_001
 * @tc.desc  : Test Player ReleaseSync timeout behavior
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_ReleaseSync_Timeout_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    EXPECT_CALL(*mockPlayerService_, ReleaseSync())
        .WillOnce([]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return MSERR_OK;
        });
    EXPECT_EQ(MSERR_OK, playerImpl_->ReleaseSync());
}

/**
 * @tc.name  : Test SetVolumeMode_Timeout
 * @tc.number: Player_SetVolumeMode_Timeout_001
 * @tc.desc  : Test Player SetVolumeMode timeout behavior
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_SetVolumeMode_Timeout_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    EXPECT_CALL(*mockPlayerService_, SetVolumeMode(_))
        .WillOnce([](int32_t mode) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return MSERR_OK;
        });
    EXPECT_EQ(MSERR_OK, playerImpl_->SetVolumeMode(0));
}

/**
 * @tc.name  : Test SetVolume_Timeout
 * @tc.number: Player_SetVolume_Timeout_001
 * @tc.desc  : Test Player SetVolume timeout behavior
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_SetVolume_Timeout_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    EXPECT_CALL(*mockPlayerService_, SetVolume(_, _))
        .WillOnce([](float left, float right) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return MSERR_OK;
        });
    EXPECT_EQ(MSERR_OK, playerImpl_->SetVolume(1.0f, 1.0f));
}

/**
 * @tc.name  : Test Seek_Timeout
 * @tc.number: Player_Seek_Timeout_001
 * @tc.desc  : Test Player Seek timeout behavior in normal mode
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_Seek_Timeout_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    
    EXPECT_CALL(*mockPlayerService_, Seek(_, _))
        .WillOnce([](int32_t mSeconds, PlayerSeekMode mode) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return MSERR_OK;
        });
    
    EXPECT_EQ(MSERR_OK, playerImpl_->Seek(1000, PlayerSeekMode::SEEK_PREVIOUS_SYNC));
}

/**
 * @tc.name  : Test GetCurrentTime_Timeout
 * @tc.number: Player_GetCurrentTime_Timeout_001
 * @tc.desc  : Test Player GetCurrentTime timeout behavior
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_GetCurrentTime_Timeout_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    
    int32_t currentTime = 0;
    EXPECT_CALL(*mockPlayerService_, GetCurrentTime(_))
        .WillOnce([](int32_t &time) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return MSERR_OK;
        });
    
    EXPECT_EQ(MSERR_OK, playerImpl_->GetCurrentTime(currentTime));
}

/**
 * @tc.name  : Test GetPlaybackPosition_Timeout
 * @tc.number: Player_GetPlaybackPosition_Timeout_001
 * @tc.desc  : Test Player GetPlaybackPosition timeout behavior
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_GetPlaybackPosition_Timeout_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    
    int32_t position = 0;
    EXPECT_CALL(*mockPlayerService_, GetPlaybackPosition(_))
        .WillOnce([](int32_t &pos) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return MSERR_OK;
        });
    
    EXPECT_EQ(MSERR_OK, playerImpl_->GetPlaybackPosition(position));
}

/**
 * @tc.name  : Test GetVideoTrackInfo_Timeout
 * @tc.number: Player_GetVideoTrackInfo_Timeout_001
 * @tc.desc  : Test Player GetVideoTrackInfo timeout behavior
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_GetVideoTrackInfo_Timeout_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    
    std::vector<Format> videoTracks;
    EXPECT_CALL(*mockPlayerService_, GetVideoTrackInfo(_))
        .WillOnce([](std::vector<Format> &tracks) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return MSERR_OK;
        });
    
    EXPECT_EQ(MSERR_OK, playerImpl_->GetVideoTrackInfo(videoTracks));
}

/**
 * @tc.name  : Test GetPlaybackInfo_Timeout
 * @tc.number: Player_GetPlaybackInfo_Timeout_001
 * @tc.desc  : Test Player GetPlaybackInfo timeout behavior
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_GetPlaybackInfo_Timeout_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    
    Format playbackInfo;
    EXPECT_CALL(*mockPlayerService_, GetPlaybackInfo(_))
        .WillOnce([](Format &info) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return MSERR_OK;
        });
    
    EXPECT_EQ(MSERR_OK, playerImpl_->GetPlaybackInfo(playbackInfo));
}

/**
 * @tc.name  : Test GetAudioTrackInfo_Timeout
 * @tc.number: Player_GetAudioTrackInfo_Timeout_001
 * @tc.desc  : Test Player GetAudioTrackInfo timeout behavior
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_GetAudioTrackInfo_Timeout_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    
    std::vector<Format> audioTracks;
    EXPECT_CALL(*mockPlayerService_, GetAudioTrackInfo(_))
        .WillOnce([](std::vector<Format> &tracks) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return MSERR_OK;
        });
    
    EXPECT_EQ(MSERR_OK, playerImpl_->GetAudioTrackInfo(audioTracks));
}

/**
 * @tc.name  : Test GetSubtitleTrackInfo_Timeout
 * @tc.number: Player_GetSubtitleTrackInfo_Timeout_001
 * @tc.desc  : Test Player GetSubtitleTrackInfo timeout behavior
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_GetSubtitleTrackInfo_Timeout_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    
    std::vector<Format> subtitleTracks;
    EXPECT_CALL(*mockPlayerService_, GetSubtitleTrackInfo(_))
        .WillOnce([](std::vector<Format> &tracks) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return MSERR_OK;
        });
    
    EXPECT_EQ(MSERR_OK, playerImpl_->GetSubtitleTrackInfo(subtitleTracks));
}

/**
 * @tc.name  : Test GetVideoWidth_Timeout
 * @tc.number: Player_GetVideoWidth_Timeout_001
 * @tc.desc  : Test Player GetVideoWidth timeout behavior
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_GetVideoWidth_Timeout_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    
    EXPECT_CALL(*mockPlayerService_, GetVideoWidth())
        .WillOnce([]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return 1920;
        });
    
    EXPECT_EQ(1920, playerImpl_->GetVideoWidth());
}

/**
 * @tc.name  : Test GetVideoHeight_Timeout
 * @tc.number: Player_GetVideoHeight_Timeout_001
 * @tc.desc  : Test Player GetVideoHeight timeout behavior
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_GetVideoHeight_Timeout_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    
    EXPECT_CALL(*mockPlayerService_, GetVideoHeight())
        .WillOnce([]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return 1080;
        });
    
    EXPECT_EQ(1080, playerImpl_->GetVideoHeight());
}

/**
 * @tc.name  : Test SetPlaybackSpeed_Timeout
 * @tc.number: Player_SetPlaybackSpeed_Timeout_001
 * @tc.desc  : Test Player SetPlaybackSpeed timeout behavior
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_SetPlaybackSpeed_Timeout_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    
    EXPECT_CALL(*mockPlayerService_, SetPlaybackSpeed(_))
        .WillOnce([](PlaybackRateMode mode) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return MSERR_OK;
        });
    
    EXPECT_EQ(MSERR_OK, 
        playerImpl_->SetPlaybackSpeed(PlaybackRateMode::SPEED_FORWARD_2_00_X));
}

/**
 * @tc.name  : Test GetPlaybackSpeed_Timeout
 * @tc.number: Player_GetPlaybackSpeed_Timeout_001
 * @tc.desc  : Test Player GetPlaybackSpeed timeout behavior
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_GetPlaybackSpeed_Timeout_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    
    PlaybackRateMode mode = PlaybackRateMode::SPEED_FORWARD_1_00_X;
    EXPECT_CALL(*mockPlayerService_, GetPlaybackSpeed(_))
        .WillOnce([](PlaybackRateMode &outMode) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            outMode = PlaybackRateMode::SPEED_FORWARD_2_00_X;
            return MSERR_OK;
        });
    
    EXPECT_EQ(MSERR_OK, playerImpl_->GetPlaybackSpeed(mode));
    EXPECT_EQ(PlaybackRateMode::SPEED_FORWARD_2_00_X, mode);
}

/**
 * @tc.name  : Test SelectBitRate_Timeout
 * @tc.number: Player_SelectBitRate_Timeout_001
 * @tc.desc  : Test Player SelectBitRate timeout behavior
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_SelectBitRate_Timeout_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    
    const uint32_t testBitRate = 1024000;
    EXPECT_CALL(*mockPlayerService_, SelectBitRate(_))
        .WillOnce([](uint32_t bitRate) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return MSERR_OK;
        });
    
    EXPECT_EQ(MSERR_OK, playerImpl_->SelectBitRate(testBitRate));
}

/**
 * @tc.name  : Test GetDuration_Timeout
 * @tc.number: Player_GetDuration_Timeout_001
 * @tc.desc  : Test Player GetDuration timeout behavior
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_GetDuration_Timeout_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    
    int32_t duration = 0;
    EXPECT_CALL(*mockPlayerService_, GetDuration(_))
        .WillOnce([](int32_t &outDuration) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return MSERR_OK;
        });
    
    EXPECT_EQ(MSERR_OK, playerImpl_->GetDuration(duration));
}

/**
 * @tc.name  : Test GetApiVersion_Timeout
 * @tc.number: Player_GetApiVersion_Timeout_001
 * @tc.desc  : Test Player GetApiVersion timeout behavior
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_GetApiVersion_Timeout_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    
    int32_t apiVersion = 0;
    EXPECT_CALL(*mockPlayerService_, GetApiVersion(_))
        .WillOnce([](int32_t &outVersion) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return MSERR_OK;
        });
    
    EXPECT_EQ(MSERR_OK, playerImpl_->GetApiVersion(apiVersion));
}

/**
 * @tc.name  : Test SetLooping_Timeout
 * @tc.number: Player_SetLooping_Timeout_001
 * @tc.desc  : Test Player SetLooping timeout behavior
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_SetLooping_Timeout_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    
    EXPECT_CALL(*mockPlayerService_, SetLooping(_))
        .WillOnce([](bool loop) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return MSERR_OK;
        });
    
    EXPECT_EQ(MSERR_OK, playerImpl_->SetLooping(true));
}

/**
 * @tc.name  : Test SetParameter_Timeout
 * @tc.number: Player_SetParameter_Timeout_001
 * @tc.desc  : Test Player SetParameter timeout behavior
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_SetParameter_Timeout_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    
    Format format;
    format.PutIntValue(PlayerKeys::VIDEO_SCALE_TYPE,
        static_cast<int32_t>(Plugins::VideoScaleType::VIDEO_SCALE_TYPE_FIT));
    EXPECT_CALL(*mockPlayerService_, SetParameter(_))
        .WillOnce([](const Format&) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return MSERR_OK;
        });
    
    EXPECT_EQ(MSERR_OK, playerImpl_->SetParameter(format));
}

/**
 * @tc.name  : Test SelectTrack_Timeout
 * @tc.number: Player_SelectTrack_Timeout_001
 * @tc.desc  : Test Player SelectTrack timeout behavior
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_SelectTrack_Timeout_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    
    const int32_t testIndex = 1;
    EXPECT_CALL(*mockPlayerService_, SelectTrack(_, _))
        .WillOnce([](int32_t index, PlayerSwitchMode mode) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return MSERR_OK;
        });
    
    EXPECT_EQ(MSERR_OK, 
        playerImpl_->SelectTrack(testIndex, PlayerSwitchMode::SWITCH_SMOOTH));
}

/**
 * @tc.name  : Test DeselectTrack_Timeout
 * @tc.number: Player_DeselectTrack_Timeout_001
 * @tc.desc  : Test Player DeselectTrack timeout behavior
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_DeselectTrack_Timeout_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    
    const int32_t testIndex = 2;
    EXPECT_CALL(*mockPlayerService_, DeselectTrack(_))
        .WillOnce([](int32_t index) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return MSERR_OK;
        });
    
    EXPECT_EQ(MSERR_OK, playerImpl_->DeselectTrack(testIndex));
}

/**
 * @tc.name  : Test GetCurrentTrack_Timeout
 * @tc.number: Player_GetCurrentTrack_Timeout_001
 * @tc.desc  : Test Player GetCurrentTrack timeout behavior
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_GetCurrentTrack_Timeout_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    
    int32_t trackIndex = 1;
    EXPECT_CALL(*mockPlayerService_, GetCurrentTrack(_, _))
        .WillOnce([](int32_t trackType, int32_t &index) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return MSERR_OK;
        });
    
    EXPECT_EQ(MSERR_OK, 
        playerImpl_->GetCurrentTrack(MediaType::MEDIA_TYPE_AUD, trackIndex));
}

/**
 * @tc.name  : Test SetPlaybackStrategy_Timeout
 * @tc.number: Player_SetPlaybackStrategy_Timeout_001
 * @tc.desc  : Test Player SetPlaybackStrategy timeout behavior
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_SetPlaybackStrategy_Timeout_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    
    AVPlayStrategy playbackStrategy = {
        .mutedMediaType = OHOS::Media::MediaType::MEDIA_TYPE_AUD
    };
    EXPECT_CALL(*mockPlayerService_, SetPlaybackStrategy(_))
        .WillOnce([](AVPlayStrategy strategy) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return MSERR_OK;
        });
    
    EXPECT_EQ(MSERR_OK, playerImpl_->SetPlaybackStrategy(playbackStrategy));
}

/**
 * @tc.name  : Test SetSuperResolution_Timeout
 * @tc.number: Player_SetSuperResolution_Timeout_001
 * @tc.desc  : Test Player SetSuperResolution timeout behavior
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_SetSuperResolution_Timeout_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    
    EXPECT_CALL(*mockPlayerService_, SetSuperResolution(_))
        .WillOnce([](bool enabled) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return MSERR_OK;
        });
    
    EXPECT_EQ(MSERR_OK, playerImpl_->SetSuperResolution(true));
}

/**
 * @tc.name  : Test SetVideoWindowSize_Timeout
 * @tc.number: Player_SetVideoWindowSize_Timeout_001
 * @tc.desc  : Test Player SetVideoWindowSize timeout behavior
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_SetVideoWindowSize_Timeout_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    
    const int32_t width = 1920, height = 1080;
    EXPECT_CALL(*mockPlayerService_, SetVideoWindowSize(_, _))
        .WillOnce([](int32_t w, int32_t h) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return MSERR_OK;
        });
    
    EXPECT_EQ(MSERR_OK, playerImpl_->SetVideoWindowSize(width, height));
}

/**
 * @tc.name  : Test SetMaxAmplitudeCbStatus_Timeout
 * @tc.number: Player_SetMaxAmplitudeCbStatus_Timeout_001
 * @tc.desc  : Test Player SetMaxAmplitudeCbStatus timeout behavior
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_SetMaxAmplitudeCbStatus_Timeout_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    
    EXPECT_CALL(*mockPlayerService_, SetMaxAmplitudeCbStatus(_))
        .WillOnce([](bool status) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return MSERR_OK;
        });
    
    EXPECT_EQ(MSERR_OK, playerImpl_->SetMaxAmplitudeCbStatus(true));
}

/**
 * @tc.name  : Test SetSeiMessageCbStatus_Timeout
 * @tc.number: Player_SetSeiMessageCbStatus_Timeout_001
 * @tc.desc  : Test Player SetSeiMessageCbStatus timeout behavior
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_SetSeiMessageCbStatus_Timeout_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;

    bool testStatus = true;
    std::vector<int32_t> testPayloadTypes = {1, 5, 6};

    EXPECT_CALL(*mockPlayerService_, SetSeiMessageCbStatus(_, _))
        .WillOnce([](bool status, const std::vector<int32_t>& payloadTypes) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return MSERR_OK;
        });

    EXPECT_EQ(MSERR_OK, playerImpl_->SetSeiMessageCbStatus(testStatus, testPayloadTypes));
}

/**
 * @tc.name  : Test Play_Timeout
 * @tc.number: Player_Play_Timeout_002
 * @tc.desc  : Test Player Play_Timeout
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_Play_Timeout_002, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    EXPECT_CALL(*mockPlayerService_, Play())
        .WillOnce([]() {
            std::this_thread::sleep_for(std::chrono::seconds(7));
            return MSERR_OK;
        });
    EXPECT_EQ(MSERR_OK, playerImpl_->Play());
}

/**
 * @tc.name  : Test PrepareAsync_Timeout
 * @tc.number: Player_PrepareAsync_Timeout_002
 * @tc.desc  : Test Player PrepareAsync timeout behavior
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_PrepareAsync_Timeout_002, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    EXPECT_CALL(*mockPlayerService_, PrepareAsync())
        .WillOnce([]() {
            std::this_thread::sleep_for(std::chrono::seconds(7));
            return MSERR_OK;
        });
    EXPECT_EQ(MSERR_OK, playerImpl_->PrepareAsync());
}

/**
 * @tc.name  : Test Pause_Timeout
 * @tc.number: Player_Pause_Timeout_002
 * @tc.desc  : Test Player Pause timeout behavior
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_Pause_Timeout_002, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    EXPECT_CALL(*mockPlayerService_, Pause())
        .WillOnce([]() {
            std::this_thread::sleep_for(std::chrono::seconds(7));
            return MSERR_OK;
        });
    EXPECT_EQ(MSERR_OK, playerImpl_->Pause());
}

/**
 * @tc.name  : Test Reset_Timeout
 * @tc.number: Player_Reset_Timeout_002
 * @tc.desc  : Test Player Reset timeout behavior
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_Reset_Timeout_002, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    EXPECT_CALL(*mockPlayerService_, Reset())
        .WillOnce([]() {
            std::this_thread::sleep_for(std::chrono::seconds(7));
            return MSERR_OK;
        });
    EXPECT_EQ(MSERR_OK, playerImpl_->Reset());
}

/**
 * @tc.name  : Test Seek_Timeout
 * @tc.number: Player_Seek_Timeout_002
 * @tc.desc  : Test Player Seek timeout behavior in normal mode
 */
HWTEST_F(PlayerTimeoutUnitTest, Player_Seek_Timeout_002, TestSize.Level0)
{
    ASSERT_NE(nullptr, mockPlayerService_);
    playerImpl_->playerService_ = mockPlayerService_;
    
    EXPECT_CALL(*mockPlayerService_, Seek(_, _))
        .WillOnce([](int32_t mSeconds, PlayerSeekMode mode) {
            std::this_thread::sleep_for(std::chrono::seconds(7));
            return MSERR_OK;
        });
    
    EXPECT_EQ(MSERR_OK, playerImpl_->Seek(1000, PlayerSeekMode::SEEK_PREVIOUS_SYNC));
}
}
}