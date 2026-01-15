/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "player_unit_test.h"
#include <unistd.h>
#include <securec.h>
#include "media_errors.h"
#include "media_errors.cpp"
#include "audio_effect.h"
#include "av_common.h"
#include "meta/video_types.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS::Media::PlayerTestParam;

namespace OHOS {
namespace Media {

void PlayerUnitTest::SetUpTestCase(void)
{
}

void PlayerUnitTest::TearDownTestCase(void)
{
}

void PlayerUnitTest::SetUp(void)
{
    callback_ = std::make_shared<PlayerCallbackTest>();
    ASSERT_NE(nullptr, callback_);
    player_ = std::make_shared<PlayerMock>(callback_);
    ASSERT_NE(nullptr, player_);
    EXPECT_TRUE(player_->CreatePlayer());
    EXPECT_EQ(MSERR_OK, player_->SetPlayerCallback(callback_));
}

void PlayerUnitTest::TearDown(void)
{
    if (player_ != nullptr) {
        player_->Release();
    }
}

void PlayerUnitTest::PlayFunTest(const std::string &protocol)
{
    int32_t duration = 0;
    float playbackRate = 2.5f;
    if (player_ != nullptr) {
        EXPECT_EQ(MSERR_OK, player_->GetDuration(duration));
        EXPECT_EQ(MSERR_OK, player_->Play());
        EXPECT_TRUE(player_->IsPlaying());
        EXPECT_EQ(MSERR_OK, player_->GetDuration(duration));
        EXPECT_EQ(MSERR_OK, player_->Pause());
        int32_t time;
        EXPECT_EQ(MSERR_OK, player_->GetCurrentTime(time));
        std::vector<Format> videoTrack;
        std::vector<Format> audioTrack;
        EXPECT_EQ(MSERR_OK, player_->GetVideoTrackInfo(videoTrack));
        EXPECT_EQ(MSERR_OK, player_->GetAudioTrackInfo(audioTrack));
        PlaybackRateMode mode;
        player_->SetPlaybackSpeed(SPEED_FORWARD_2_00_X);
        player_->SetPlaybackRate(playbackRate);
        player_->GetPlaybackSpeed(mode);
        EXPECT_EQ(MSERR_OK, player_->SetLooping(true));
        EXPECT_EQ(true, player_->IsLooping());
        EXPECT_EQ(MSERR_OK, player_->Seek(duration, SEEK_NEXT_SYNC));
        EXPECT_EQ(MSERR_OK, player_->Play());
        sleep(PLAYING_TIME_2_SEC);
        if (protocol == PlayerTestParam::HLS_PLAY) {
            EXPECT_EQ(MSERR_OK, player_->SelectBitRate(200000));  // 200000:bitrate
            sleep(PLAYING_TIME_2_SEC);
        }
        EXPECT_EQ(MSERR_OK, player_->SetLooping(false));
        EXPECT_EQ(false, player_->IsLooping());
        EXPECT_EQ(MSERR_OK, player_->SetVolume(1, 1));
        EXPECT_EQ(MSERR_OK, player_->Seek(SEEK_TIME_2_SEC, SEEK_NEXT_SYNC));
        EXPECT_EQ(MSERR_OK, player_->Stop());
        EXPECT_EQ(MSERR_OK, player_->Reset());
    }
}

void PlayerUnitTest::NoRunPlayFunTest(const std::string &protocol)
{
    int32_t duration = 0;
    float playbackRate = 2.5f;
    if (player_ != nullptr) {
        EXPECT_NE(MSERR_OK, player_->GetDuration(duration));
        EXPECT_NE(MSERR_OK, player_->Play());
        EXPECT_FALSE(player_->IsPlaying());
        EXPECT_NE(MSERR_OK, player_->GetDuration(duration));
        EXPECT_NE(MSERR_OK, player_->Pause());
        int32_t time;
        EXPECT_NE(MSERR_OK, player_->GetCurrentTime(time));
        std::vector<Format> videoTrack;
        std::vector<Format> audioTrack;
        EXPECT_NE(MSERR_OK, player_->GetVideoTrackInfo(videoTrack));
        EXPECT_NE(MSERR_OK, player_->GetAudioTrackInfo(audioTrack));
        PlaybackRateMode mode;
        player_->SetPlaybackSpeed(SPEED_FORWARD_2_00_X);
        player_->SetPlaybackRate(playbackRate);
        player_->GetPlaybackSpeed(mode);
        EXPECT_NE(MSERR_OK, player_->SetLooping(true));
        EXPECT_NE(true, player_->IsLooping());
        EXPECT_NE(MSERR_OK, player_->Seek(duration, SEEK_NEXT_SYNC));
        EXPECT_NE(MSERR_OK, player_->Play());
        sleep(PLAYING_TIME_2_SEC);
        if (protocol == PlayerTestParam::HLS_PLAY) {
            EXPECT_NE(MSERR_OK, player_->SelectBitRate(200000));  // 200000:bitrate
            sleep(PLAYING_TIME_2_SEC);
        }
        EXPECT_NE(MSERR_OK, player_->SetLooping(false));
        EXPECT_EQ(false, player_->IsLooping());
        EXPECT_NE(MSERR_OK, player_->SetVolume(1, 1));
        EXPECT_NE(MSERR_OK, player_->Seek(SEEK_TIME_2_SEC, SEEK_NEXT_SYNC));
        EXPECT_NE(MSERR_OK, player_->Stop());
        EXPECT_NE(MSERR_OK, player_->Reset());
    }
}


void PlayerUnitTest::GetSetParaFunTest()
{
    if (player_ != nullptr) {
        int32_t duration = 0;
        int32_t time = 0;
        float playbackRate = 2.5f;
        PlaybackRateMode mode;
        std::vector<Format> videoTrack;
        std::vector<Format> audioTrack;
        player_->GetVideoTrackInfo(videoTrack);
        player_->GetAudioTrackInfo(audioTrack);
        player_->GetCurrentTime(time);
        player_->GetDuration(duration);
        player_->SetPlaybackSpeed(SPEED_FORWARD_2_00_X);
        player_->SetPlaybackRate(playbackRate);
        player_->GetPlaybackSpeed(mode);
        player_->SetLooping(true);
        player_->IsLooping();
        player_->SetVolume(1, 1);
    }
}

void PlayerUnitTest::MediaServiceErrCodeTest(MediaServiceErrCode code)
{
    if (MSERRCODE_INFOS.count(code) != 0) {
        EXPECT_EQ(MSERRCODE_INFOS.at(code), MSErrorToString(code));
    } else if (code > MSERR_EXTEND_START) {
        EXPECT_EQ("extend error:" + std::to_string(static_cast<int32_t>(code - MSERR_EXTEND_START)),
            MSErrorToString(code));
    } else {
        EXPECT_EQ("invalid error code:" + std::to_string(static_cast<int32_t>(code)), MSErrorToString(code));
    }

    if (MSERRCODE_INFOS.count(code) != 0 && MSERRCODE_TO_EXTERRORCODE.count(code) != 0 &&
        MSEXTERRCODE_INFOS.count(MSERRCODE_TO_EXTERRORCODE.at(code)) != 0) {
        EXPECT_EQ(MSEXTERRCODE_INFOS.at(MSERRCODE_TO_EXTERRORCODE.at(code)), MSErrorToExtErrorString(code));
    } else {
        EXPECT_EQ("unkown error", MSErrorToExtErrorString(code));
    }

    if (MSERRCODE_INFOS.count(code) != 0 && MSERRCODE_TO_EXTERRORCODE.count(code) != 0) {
        EXPECT_EQ(MSERRCODE_TO_EXTERRORCODE.at(code), MSErrorToExtError(code));
    } else {
        EXPECT_EQ(MSERR_EXT_UNKNOWN, MSErrorToExtError(code));
    }

    if (MSERRCODE_INFOS.count(code) != 0 && MSERRCODE_TO_EXTERRORCODEAPI9.count(code) != 0 &&
        MSEXTERRAPI9CODE_FUNCS.count(MSERRCODE_TO_EXTERRORCODEAPI9.at(code)) != 0) {
        EXPECT_EQ(MSEXTERRAPI9CODE_FUNCS.at(MSERRCODE_TO_EXTERRORCODEAPI9.at(code))("test1", "test2"),
            MSErrorToExtErrorAPI9String(code, "test1", "test2"));
    } else {
        EXPECT_EQ("unkown error", MSErrorToExtErrorAPI9String(code, "test1", "test2"));
    }

    if (MSERRCODE_INFOS.count(code) != 0 && MSERRCODE_TO_EXTERRORCODEAPI9.count(code) != 0) {
        EXPECT_EQ(MSERRCODE_TO_EXTERRORCODEAPI9.at(code), MSErrorToExtErrorAPI9(code));
    } else {
        EXPECT_EQ(MSERR_EXT_API9_IO, MSErrorToExtErrorAPI9(code));
    }
}

void PlayerUnitTest::MediaServiceExtErrCodeAPI9Test(MediaServiceExtErrCodeAPI9 code)
{
    if (MSEXTERRAPI9CODE_FUNCS.count(code) != 0) {
        EXPECT_EQ(MSEXTERRAPI9CODE_FUNCS.at(code)("test1", "test2"),
            MSExtErrorAPI9ToString(code, "test1", "test2"));
    } else {
        EXPECT_EQ("invalid error code:" + std::to_string(code), MSExtErrorAPI9ToString(code, "test1", "test2"));
    }

    if (MSEXTERRCODE_API9_INFOS.count(code) != 0) {
        EXPECT_EQ(MSEXTERRCODE_API9_INFOS.at(code), MSExtAVErrorToString(code));
    } else {
        EXPECT_EQ("invalid error code:", MSExtAVErrorToString(code));
    }
}

/**
 * @tc.name  : Test Player SetMediaSource API
 * @tc.number: Player_SetMediaSource_001
 * @tc.desc  : Test Player SetMediaSource interface
 */
HWTEST_F(PlayerUnitTest, Player_SetMediaSource_001, TestSize.Level0)
{
    std::map<std::string, std::string> header = {
        {"key1", "value1"},
        {"key2", "value2"},
    };
    struct AVPlayStrategy strategy = {1080, 920, 10000, false};
    std::shared_ptr<AVMediaSource> mediaSource = std::make_shared<AVMediaSource>(VIDEO_FILE1, header);
    int32_t ret = player_->SetMediaSource(mediaSource, strategy);
    EXPECT_EQ(MSERR_OK, ret);
}

/**
 * @tc.name  : Test Player SetMediaSource API
 * @tc.number: Player_SetMediaSource_002
 * @tc.desc  : Test Player SetMediaSource interface
 */
HWTEST_F(PlayerUnitTest, Player_SetMediaSource_002, TestSize.Level0)
{
    struct AVPlayStrategy strategy = {1080, 920, 10000, false};
    int32_t ret = player_->SetMediaSource(nullptr, strategy);
    EXPECT_NE(MSERR_OK, ret);
}

/**
 * @tc.name  : Test Player SetMediaSource API
 * @tc.number: Player_SetMediaSource_003
 * @tc.desc  : Test Player SetMediaSource interface
 */
HWTEST_F(PlayerUnitTest, Player_SetMediaSource_003, TestSize.Level1)
{
    std::map<std::string, std::string> header = {
        {"key1", "value1"},
        {"key2", "value2"},
    };
    struct AVPlayStrategy strategy = {1080, 920, 10000, false};
    std::shared_ptr<AVMediaSource> mediaSource = std::make_shared<AVMediaSource>(MEDIA_ROOT + "error.mp4", header);
    int32_t ret = player_->SetMediaSource(mediaSource, strategy);
    EXPECT_EQ(MSERR_OK, ret);
    EXPECT_NE(MSERR_OK, player_->PrepareAsync());
}

/**
 * @tc.name  : Test Player SetMediaSource API
 * @tc.number: Player_SetMediaSource_004
 * @tc.desc  : Test Player SetMediaSource interface
 */
HWTEST_F(PlayerUnitTest, Player_SetMediaSource_004, TestSize.Level0)
{
    std::map<std::string, std::string> header = {
        {"key1", "value1"},
        {"key2", "value2"},
    };
    struct AVPlayStrategy strategy = {1080, 920, 10000, false};
    std::shared_ptr<AVMediaSource> mediaSource = std::make_shared<AVMediaSource>(MEDIA_ROOT + "error.mp4", header);
    int32_t ret = player_->SetMediaSource(mediaSource, strategy);
    EXPECT_EQ(MSERR_OK, ret);
    EXPECT_NE(MSERR_OK, player_->PrepareAsync());
    EXPECT_NE(MSERR_OK, player_->Prepare());
}

/**
 * @tc.name  : Test Player SetMediaSource API
 * @tc.number: Player_SetMediaSource_005
 * @tc.desc  : Test Player SetMediaSource interface
 */
HWTEST_F(PlayerUnitTest, Player_SetMediaSource_005, TestSize.Level0)
{
    std::map<std::string, std::string> header = {
        {"key1", "value1"},
        {"key2", "value2"},
    };
    struct AVPlayStrategy strategy = {1080, 920, 10000, false};
    std::shared_ptr<AVMediaSource> mediaSource = std::make_shared<AVMediaSource>(MEDIA_ROOT + "error.mp4", header);
    int32_t ret = player_->SetMediaSource(mediaSource, strategy);
    EXPECT_EQ(MSERR_OK, ret);
    EXPECT_NE(MSERR_OK, player_->Play());
    EXPECT_EQ(false, player_->IsPlaying());
}

/**
 * @tc.name  : Test Player SetMediaSource API
 * @tc.number: Player_SetMediaSource_006
 * @tc.desc  : Test Player SetMediaSource interface
 */
HWTEST_F(PlayerUnitTest, Player_SetMediaSource_006, TestSize.Level0)
{
    std::map<std::string, std::string> header = {
    };
    struct AVPlayStrategy strategy = {1080, 920, 10000, false};
    std::shared_ptr<AVMediaSource> mediaSource = std::make_shared<AVMediaSource>(MEDIA_ROOT + "error.mp4", header);
    int32_t ret = player_->SetMediaSource(mediaSource, strategy);
    EXPECT_EQ(MSERR_OK, ret);
    EXPECT_NE(MSERR_OK, player_->Play());
    EXPECT_EQ(false, player_->IsPlaying());
}

/**
 * @tc.name  : Test Player SetMediaSource API
 * @tc.number: Player_SetMediaSource_007
 * @tc.desc  : Test Player SetMediaSource interface pre_download
 */
HWTEST_F(PlayerUnitTest, Player_SetMediaSource_007, TestSize.Level0)
{
    std::map<std::string, std::string> header = {
        {"key1", "value1"},
        {"key2", "value2"},
    };
    struct AVPlayStrategy strategy = {1080, 920, 0, false};
    std::shared_ptr<LoaderCallback> mediaSourceLoaderCb = std::make_shared<MockLoaderCallback>();
    std::shared_ptr<AVMediaSource> mediaSource = std::make_shared<AVMediaSource>(VIDEO_URL, header);
    mediaSource->mediaSourceLoaderCb_ = mediaSourceLoaderCb;
    EXPECT_EQ(MSERR_OK, player_->SetMediaSource(mediaSource, strategy));

    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    int32_t ret = player_->PrepareAsync();
    if (ret == MSERR_OK) {
        PlayFunTest(PRE_DOWNLOAD);
    }
}

/**
 * @tc.name  : Test Player SetMediaSource API
 * @tc.number: Player_SetMediaSource_008
 * @tc.desc  : Test Player SetMediaSource with MediaStream
 */
HWTEST_F(PlayerUnitTest, Player_SetMediaSource_008, TestSize.Level0)
{
    std::map<std::string, std::string> header = {
    };
    struct AVPlayStrategy strategy = {720, 1280, 0, false};
    std::shared_ptr<AVMediaSource> mediaSource = std::make_shared<AVMediaSource>("", header);
    AVPlayMediaStream mediaStream;
    mediaStream.url = "http://media.iyuns.top:1003/live/SEI-H264.flv";
    mediaStream.width = 720;
    mediaStream.height = 1280;
    mediaStream.bitrate = 1024*1024;
    mediaSource->AddMediaStream(mediaStream);
    int32_t ret = player_->SetMediaSource(mediaSource, strategy);
    EXPECT_EQ(MSERR_OK, ret);
}

/**
 * @tc.name  : Test Player SetSource API
 * @tc.number: Player_SetSource_001
 * @tc.desc  : Test Player SetSource interface
 */
HWTEST_F(PlayerUnitTest, Player_SetSource_001, TestSize.Level0)
{
    int32_t ret = player_->SetSource(VIDEO_FILE1);
    EXPECT_EQ(MSERR_OK, ret);
}

/**
 * @tc.name  : Test Player SetSource API
 * @tc.number: Player_SetSource_002
 * @tc.desc  : Test Player SetSource interface with invalid path
 */
HWTEST_F(PlayerUnitTest, Player_SetSource_002, TestSize.Level1)
{
    int32_t ret = player_->SetSource(MEDIA_ROOT + "kong.mp4");
    EXPECT_NE(MSERR_OK, ret);
}

/**
 * @tc.name  : Test Player SetSource API
 * @tc.number: Player_SetSource_003
 * @tc.desc  : Test Player SetSource interface with wrong mp3
 */
HWTEST_F(PlayerUnitTest, Player_SetSource_003, TestSize.Level2)
{
    system("param set sys.media.player.buffering.enable TRUE");
    PlaybackRateMode mode;
    int32_t time = 0;
    int32_t duration = 0;
    float playbackRate = 2.5f;
    std::vector<Format> videoTrack;
    std::vector<Format> audioTrack;
    int32_t ret = player_->SetSource(MEDIA_ROOT + "1kb.mp3");
    EXPECT_EQ(MSERR_OK, ret);
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_NE(MSERR_OK, player_->PrepareAsync());
    EXPECT_NE(MSERR_OK, player_->Prepare());
    Format format;
    format.PutIntValue(PlayerKeys::VIDEO_SCALE_TYPE,
        static_cast<int32_t>(Plugins::VideoScaleType::VIDEO_SCALE_TYPE_FIT));
    EXPECT_NE(MSERR_OK, player_->SetParameter(format));
    EXPECT_NE(MSERR_OK, player_->SetVolume(1, 1));
    EXPECT_NE(MSERR_OK, player_->Play());
    EXPECT_EQ(false, player_->IsPlaying());
    EXPECT_NE(MSERR_OK, player_->Pause());
    EXPECT_NE(MSERR_OK, player_->Seek(0, SEEK_CLOSEST));
    EXPECT_NE(MSERR_OK, player_->SetLooping(true));
    EXPECT_EQ(false, player_->IsLooping());
    EXPECT_NE(MSERR_OK, player_->SetVolume(1, 1));
    EXPECT_NE(MSERR_OK, player_->SetPlaybackSpeed(SPEED_FORWARD_2_00_X));
    EXPECT_NE(MSERR_OK, player_->SetPlaybackRate(playbackRate));
    EXPECT_NE(MSERR_OK, player_->GetPlaybackSpeed(mode));
    EXPECT_NE(MSERR_OK, player_->GetCurrentTime(time));
    EXPECT_NE(MSERR_OK, player_->GetDuration(duration));
    EXPECT_NE(MSERR_OK, player_->GetVideoTrackInfo(videoTrack));
    EXPECT_NE(MSERR_OK, player_->GetAudioTrackInfo(audioTrack));
    EXPECT_NE(480, player_->GetVideoHeight());
    EXPECT_NE(720, player_->GetVideoWidth());
    EXPECT_NE(MSERR_OK, player_->Stop());
    EXPECT_EQ(MSERR_OK, player_->Reset());
    system("param set sys.media.player.buffering.enable FALSE");
}

/**
 * @tc.name  : Test Player SetSource API
 * @tc.number: Player_SetSource_004
 * @tc.desc  : Test Player SetSource interface with txt
 */
HWTEST_F(PlayerUnitTest, Player_SetSource_004, TestSize.Level2)
{
    int32_t ret = player_->SetSource(MEDIA_ROOT + "error.mp4");
    EXPECT_EQ(MSERR_OK, ret);
    EXPECT_NE(MSERR_OK, player_->PrepareAsync());
}
} // namespace Media
} // namespace OHOS
