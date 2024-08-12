/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "media_errors.h"
#include "hiplayer_impl_unit_test.h"
#include "pipeline/pipeline.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing::ext;
void HiplayerImplUnitTest::SetUpTestCase(void)
{
}

void HiplayerImplUnitTest::TearDownTestCase(void)
{
}

void HiplayerImplUnitTest::SetUp(void)
{
    hiplayer_ = std::make_unique<HiPlayerImpl>(0, 0, 0, 0);
}

void HiplayerImplUnitTest::TearDown(void)
{
    hiplayer_ = nullptr;
}

/**
* @tc.name    : Test GetRealPath API
* @tc.number  : GetRealPath_001
* @tc.desc    : Test GetRealPath interface, set url to "file://".
* @tc.require : issueI5NZAQ
*/
HWTEST_F(HiplayerImplUnitTest, GetRealPath_001, TestSize.Level0)
{
    // 1. Set up the test environment
    std::string url = "file://";
    std::string realUrlPath;

    // 2. Call the function to be tested
    int32_t ret = hiplayer_->GetRealPath(url, realUrlPath);

    // 3. Verify the result
    EXPECT_EQ(ret, MSERR_OPEN_FILE_FAILED);
}

/**
* @tc.name    : Test GetRealPath API
* @tc.number  : GetRealPath_002
* @tc.desc    : Test GetRealPath interface, set url to "file".
* @tc.require : issueI5NZAQ
*/
HWTEST_F(HiplayerImplUnitTest, GetRealPath_002, TestSize.Level0)
{
    // 1. Set up the test environment
    std::string url = "file";
    std::string realUrlPath;

    // 2. Call the function to be tested
    int32_t ret = hiplayer_->GetRealPath(url, realUrlPath);

    // 3. Verify the result
    EXPECT_EQ(ret, MSERR_OPEN_FILE_FAILED);
}

/**
* @tc.name    : Test GetRealPath API
* @tc.number  : GetRealPath_003
* @tc.desc    : Test GetRealPath interface, set url to "file:///storage/../test.mp3".
* @tc.require : issueI5NZAQ
*/
HWTEST_F(HiplayerImplUnitTest, GetRealPath_003, TestSize.Level0)
{
    // 1. Set up the test environment
    std::string url = "file:///storage/../test.mp3";
    std::string realUrlPath;

    // 2. Call the function to be tested
    int32_t ret = hiplayer_->GetRealPath(url, realUrlPath);

    // 3. Verify the result
    EXPECT_EQ(ret, MSERR_FILE_ACCESS_FAILED);
}

/**
* @tc.name    : Test SetSource API
* @tc.number  : SetSource_001
* @tc.desc    : Test SetSource interface, set uri to "".
* @tc.require : issueI5NZAQ
*/
HWTEST_F(HiplayerImplUnitTest, SetSource_001, TestSize.Level0)
{
    // 1. Set up the test environment
    std::string uri = "";

    // 2. Call the function to be tested
    int32_t result = hiplayer_->SetSource(uri);

    // 3. Verify the result
    EXPECT_EQ(result, MSERR_OPEN_FILE_FAILED);
}

/**
* @tc.name    : Test SetSource API
* @tc.number  : SetSource_002
* @tc.desc    : Test SetSource interface, set uri to "file://".
* @tc.require : issueI5NZAQ
*/
HWTEST_F(HiplayerImplUnitTest, SetSource_002, TestSize.Level0)
{
    // 1. Set up the test environment
    std::string uri = "file://";

    // 2. Call the function to be tested
    int32_t result = hiplayer_->SetSource(uri);

    // 3. Verify the result
    EXPECT_EQ(result, MSERR_OPEN_FILE_FAILED);
}

/**
* @tc.name    : Test SetSource API
* @tc.number  : SetSource_003
* @tc.desc    : Test SetSource interface, set uri to "http://".
* @tc.require : issueI5NZAQ
*/
HWTEST_F(HiplayerImplUnitTest, SetSource_003, TestSize.Level0)
{
    // 1. Set up the test environment
    std::string uri = "http://";

    // 2. Call the function to be tested
    int32_t result = hiplayer_->SetSource(uri);

    // 3. Verify the result
    EXPECT_EQ(result, MSERR_OK);
}

/**
* @tc.name    : Test SetSource API
* @tc.number  : SetSource_004
* @tc.desc    : Test SetSource interface, set uri to "https://".
* @tc.require : issueI5NZAQ
*/
HWTEST_F(HiplayerImplUnitTest, SetSource_004, TestSize.Level0)
{
    // 1. Set up the test environment
    std::string uri = "https://";

    // 2. Call the function to be tested
    int32_t result = hiplayer_->SetSource(uri);

    // 3. Verify the result
    EXPECT_EQ(result, MSERR_OK);
}

/**
* @tc.name    : Test SetSource API
* @tc.number  : SetSource_005
* @tc.desc    : Test SetSource interface, set uri to "invalid".
* @tc.require : issueI5NZAQ
*/
HWTEST_F(HiplayerImplUnitTest, SetSource_005, TestSize.Level0)
{
    // 1. Set up the test environment
    std::string uri = "invalid";

    // 2. Call the function to be tested
    int32_t result = hiplayer_->SetSource(uri);

    // 3. Verify the result
    EXPECT_EQ(result, MSERR_OPEN_FILE_FAILED);
}

/**
* @tc.name    : Test SetMediaSource API
* @tc.number  : SetMediaSource_001
* @tc.desc    : Test SetMediaSource interface, set mediaSource to nullptr.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(HiplayerImplUnitTest, SetMediaSource_001, TestSize.Level0)
{
    // 1. Set up the test environment
    std::shared_ptr<AVMediaSource> mediaSource = nullptr;
    AVPlayStrategy strategy;

    // 2. Call the function to be tested
    int32_t ret = hiplayer_->SetMediaSource(mediaSource, strategy);

    // 3. Verify the result
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
* @tc.name    : Test SetMediaSource API
* @tc.number  : SetMediaSource_002
* @tc.desc    : Test SetMediaSource interface, set url to file url.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(HiplayerImplUnitTest, SetMediaSource_002, TestSize.Level0)
{
    // 1. Set up the test environment
    std::map<std::string, std::string> sourceHeader;
    std::shared_ptr<AVMediaSource> mediaSource = std::make_shared<AVMediaSource>("/storage/test.mp3", sourceHeader);
    AVPlayStrategy strategy;

    // 2. Call the function to be tested
    int32_t ret = hiplayer_->SetMediaSource(mediaSource, strategy);

    // 3. Verify the result
    EXPECT_EQ(ret, MSERR_OPEN_FILE_FAILED);
}

/**
* @tc.name    : Test SetMediaSource API
* @tc.number  : SetMediaSource_003
* @tc.desc    : Test SetMediaSource interface, set url to http url.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(HiplayerImplUnitTest, SetMediaSource_003, TestSize.Level0)
{
    // 1. Set up the test environment
    std::map<std::string, std::string> sourceHeader;
    std::shared_ptr<AVMediaSource> mediaSource = std::make_shared<AVMediaSource>("http://test.mp3", sourceHeader);
    AVPlayStrategy strategy;

    // 2. Call the function to be tested
    int32_t ret = hiplayer_->SetMediaSource(mediaSource, strategy);

    // 3. Verify the result
    EXPECT_EQ(ret, MSERR_OK);
}

/**
* @tc.name    : Test SetMediaSource API
* @tc.number  : SetMediaSource_004
* @tc.desc    : Test SetMediaSource interface, set mimeType to AVMimeTypes::APPLICATION_M3U8.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(HiplayerImplUnitTest, SetMediaSource_004, TestSize.Level0)
{
    // 1. Set up the test environment
    std::map<std::string, std::string> sourceHeader;
    std::shared_ptr<AVMediaSource> mediaSource = std::make_shared<AVMediaSource>("http://test.mp3", sourceHeader);
    mediaSource->mimeType_ = AVMimeTypes::APPLICATION_M3U8;
    AVPlayStrategy strategy;

    // 2. Call the function to be tested
    int32_t ret = hiplayer_->SetMediaSource(mediaSource, strategy);

    // 3. Verify the result
    EXPECT_EQ(ret, MSERR_OK);
}

/**
* @tc.name    : Test ResetIfSourceExisted API
* @tc.number  : ResetIfSourceExisted_001
* @tc.desc    : Test ResetIfSourceExisted interface, pipeline is not nullptr.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(HiplayerImplUnitTest, ResetIfSourceExisted_001, TestSize.Level0)
{
    // 1. Set up the test environment
    hiplayer_->demuxer_ = FilterFactory::Instance().CreateFilter<DemuxerFilter>("builtin.player.demuxer",
        FilterType::FILTERTYPE_DEMUXER);

    // 2. Call the function to be tested
    hiplayer_->ResetIfSourceExisted();

    // 3. Verify the result
    EXPECT_NE(hiplayer_->pipeline_, nullptr);
    EXPECT_EQ(hiplayer_->audioDecoder_, nullptr);
}

/**
* @tc.name    : Test ResetIfSourceExisted API
* @tc.number  : ResetIfSourceExisted_002
* @tc.desc    : Test ResetIfSourceExisted interface, audioDecoder is not nullptr.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(HiplayerImplUnitTest, ResetIfSourceExisted_002, TestSize.Level0)
{
    // 1. Set up the test environment
    hiplayer_->demuxer_ = FilterFactory::Instance().CreateFilter<DemuxerFilter>("builtin.player.demuxer",
        FilterType::FILTERTYPE_DEMUXER);
    hiplayer_->audioDecoder_ = FilterFactory::Instance().CreateFilter<AudioDecoderFilter>("player.audiodecoder",
        FilterType::FILTERTYPE_ADEC);

    hiplayer_->audioDecoder_->mediaCodec_ = std::make_shared<MediaCodec>();
    // 2. Call the function to be tested
    hiplayer_->ResetIfSourceExisted();

    // 3. Verify the result
    EXPECT_NE(hiplayer_->pipeline_, nullptr);
    EXPECT_EQ(hiplayer_->audioDecoder_, nullptr);
}


/**
* @tc.name    : Test DoInitializeForHttp API
* @tc.number  : DoInitializeForHttp_001
* @tc.desc    : Test DoInitializeForHttp interface, isNetWorkPlay_ is false.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(HiplayerImplUnitTest, DoInitializeForHttp_001, TestSize.Level0)
{
    // 1. Set up the test environment
    hiplayer_->isNetWorkPlay_ = false;

    // 2. Call the function to be tested
    hiplayer_->DoInitializeForHttp();

    // 3. Verify the result
    EXPECT_EQ(hiplayer_->isNetWorkPlay_, false);
}

/**
* @tc.name    : Test DoInitializeForHttp API
* @tc.number  : DoInitializeForHttp_002
* @tc.desc    : Test DoInitializeForHttp interface, GetBitRates return OK and vBitRates is not empty.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(HiplayerImplUnitTest, DoInitializeForHttp_002, TestSize.Level0)
{
    // 1. Set up the test environment
    hiplayer_->isNetWorkPlay_ = true;
    std::string name = "builtin.player.demuxer";
    std::shared_ptr<DemuxerFilterMock> demuxerMock =
        std::make_shared<DemuxerFilterMock>(name, FilterType::FILTERTYPE_DEMUXER);
    hiplayer_->demuxer_ = demuxerMock;
    demuxerMock->pushData_ = true;

    // 2. Call the function to be tested
    hiplayer_->DoInitializeForHttp();

    // 3. Verify the result
    EXPECT_EQ(hiplayer_->isNetWorkPlay_, true);
}

/**
* @tc.name    : Test DoInitializeForHttp API
* @tc.number  : DoInitializeForHttp_003
* @tc.desc    : Test DoInitializeForHttp interface, GetBitRates return not OK   or vBitRates is empty.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(HiplayerImplUnitTest, DoInitializeForHttp_003, TestSize.Level0)
{
    // 1. Set up the test environment
    hiplayer_->isNetWorkPlay_ = true;
    std::string name = "builtin.player.demuxer";
    std::shared_ptr<DemuxerFilterMock> demuxerMock =
        std::make_shared<DemuxerFilterMock>(name, FilterType::FILTERTYPE_DEMUXER);
    hiplayer_->demuxer_ = demuxerMock;
    demuxerMock->getBitRatesStatus_ = Status::ERROR_UNKNOWN;

    // 2. Call the function to be tested
    hiplayer_->DoInitializeForHttp();

    // 3. Verify the result
    EXPECT_EQ(hiplayer_->isNetWorkPlay_, true);
}

/**
* @tc.name    : Test DoInitializeForHttp API
* @tc.number  : DoInitializeForHttp_004
* @tc.desc    : Test DoInitializeForHttp interface, vBitRates is empty.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(HiplayerImplUnitTest, DoInitializeForHttp_004, TestSize.Level0)
{
    // 1. Set up the test environment
    hiplayer_->isNetWorkPlay_ = true;
    std::string name = "builtin.player.demuxer";
    std::shared_ptr<DemuxerFilterMock> demuxerMock =
        std::make_shared<DemuxerFilterMock>(name, FilterType::FILTERTYPE_DEMUXER);
    hiplayer_->demuxer_ = demuxerMock;
    demuxerMock->pushData_ = false;

    // 2. Call the function to be tested
    hiplayer_->DoInitializeForHttp();

    // 3. Verify the result
    EXPECT_EQ(hiplayer_->isNetWorkPlay_, true);
}

/**
* @tc.name    : Test Play API
* @tc.number  : Play_001
* @tc.desc    : Test Play interface, pipelineStates_ is PLAYER_PLAYBACK_COMPLETE.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(HiplayerImplUnitTest, Play_001, TestSize.Level0)
{
    // 1. Set up the test environment
    hiplayer_->pipelineStates_ = PlayerStates::PLAYER_PLAYBACK_COMPLETE;
    hiplayer_->isStreaming_ = false;
    hiplayer_->playRangeStartTime_ = 100;
    hiplayer_->playRangeEndTime_ = 200;

    // 2. Call the function to be tested
    int32_t ret = hiplayer_->Play();

    // 3. Verify the result
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
    EXPECT_EQ(hiplayer_->isStreaming_, false);
}

/**
* @tc.name    : Test Play API
* @tc.number  : Play_002
* @tc.desc    : Test Play interface, pipelineStates_ is PLAYER_PAUSED.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(HiplayerImplUnitTest, Play_002, TestSize.Level0)
{
    // 1. Set up the test environment
    hiplayer_->pipelineStates_ = PlayerStates::PLAYER_PAUSED;
    hiplayer_->isStreaming_ = false;
    hiplayer_->playRangeStartTime_ = 100;
    hiplayer_->playRangeEndTime_ = 200;

    // 2. Call the function to be tested
    int32_t ret = hiplayer_->Play();

    // 3. Verify the result
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
    EXPECT_EQ(hiplayer_->isStreaming_, false);
}

/**
* @tc.name    : Test Play API
* @tc.number  : Play_003
* @tc.desc    : Test Play interface, pipelineStates_ is other states.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(HiplayerImplUnitTest, Play_003, TestSize.Level0)
{
    // 1. Set up the test environment
    hiplayer_->pipelineStates_ = PlayerStates::PLAYER_PREPARING;
    hiplayer_->isStreaming_ = false;
    hiplayer_->playRangeStartTime_ = 100;
    hiplayer_->playRangeEndTime_ = 200;

    // 2. Call the function to be tested
    int32_t ret = hiplayer_->Play();

    // 3. Verify the result
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
    EXPECT_EQ(hiplayer_->isStreaming_, false);
}

/**
* @tc.name    : Test Play API
* @tc.number  : Play_004
* @tc.desc    : Test Play interface, playRangeStartTime_ and playRangeEndTime_ is invalid.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(HiplayerImplUnitTest, Play_004, TestSize.Level0)
{
    // 1. Set up the test environment
    hiplayer_->pipelineStates_ = PlayerStates::PLAYER_PLAYBACK_COMPLETE;
    hiplayer_->isStreaming_ = false;
    hiplayer_->playRangeStartTime_ = 200;
    hiplayer_->playRangeEndTime_ = 100;

    // 2. Call the function to be tested
    int32_t ret = hiplayer_->Play();

    // 3. Verify the result
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
    EXPECT_EQ(hiplayer_->isStreaming_, false);
}

} // namespace Media
} // namespace OHOS