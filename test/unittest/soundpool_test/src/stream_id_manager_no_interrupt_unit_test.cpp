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

#include "stream_id_manager_no_interrupt_unit_test.h"
#include "media_errors.h"
#include "meta/format.h"

using namespace OHOS;
using namespace OHOS::Media;
using namespace testing::ext;
using namespace std;

const int32_t MAX_STREAMS = 3;
const int32_t BEGIN_NUM = 0;
const int32_t STREAM_ID_BEGIN = 1;
const int32_t SOUND_ID_BEGIN = 1;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SOUNDPOOL, "StreamIdManagerNoInterruptUnitTest"};
}

namespace OHOS {
namespace Media {
void StreamIDManagerNoInterruptUnitTest::SetUpTestCase(void)
{}

void StreamIDManagerNoInterruptUnitTest::TearDownTestCase(void)
{
    std::cout << "sleep one second to protect PlayerEngine safely exit." << endl;
    sleep(1);  // let PlayEngine safe exit.
}

void StreamIDManagerNoInterruptUnitTest::SetUp(void)
{
    AudioStandard::AudioRendererInfo audioRenderInfo;
    audioRenderInfo.contentType = AudioStandard::CONTENT_TYPE_MUSIC;
    audioRenderInfo.streamUsage = AudioStandard::STREAM_USAGE_MUSIC;
    audioRenderInfo.rendererFlags = 0;
    streamIDManager_ = std::make_shared<StreamIDManagerWithNoInterrupt>(MAX_STREAMS, audioRenderInfo);
}

void StreamIDManagerNoInterruptUnitTest::TearDown(void)
{
    if (streamIDManager_ != nullptr) {
        streamIDManager_.reset();
    }
}

/**
 * @tc.name: streamIdNoInterrupt_function_001
 * @tc.desc: function test MulInitThreadPool
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerNoInterruptUnitTest, streamIdNoInterrupt_function_001, TestSize.Level2)
{
    MEDIA_LOGI("streamIdNoInterrupt_function_001 before");
    streamIDManager_->isStreamThreadPoolStarted_.store(true);
    EXPECT_EQ(MSERR_OK, streamIDManager_->InitThreadPool());
    MEDIA_LOGI("streamIdNoInterrupt_function_001 after");
}

/**
 * @tc.name: streamIdNoInterrupt_function_002
 * @tc.desc: function test InitThreadPool with maxStreams_ below min
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerNoInterruptUnitTest, streamIdNoInterrupt_function_002, TestSize.Level2)
{
    MEDIA_LOGI("streamIdNoInterrupt_function_002 before");
    streamIDManager_->isStreamThreadPoolStarted_.store(false);
    streamIDManager_->maxStreams_ = 0;
    EXPECT_EQ(MSERR_OK, streamIDManager_->InitThreadPool());
    EXPECT_EQ(IStreamIDManager::MIN_PLAY_STREAMS_NUMBER, streamIDManager_->maxStreams_);
    MEDIA_LOGI("streamIdNoInterrupt_function_002 after");
}

/**
 * @tc.name: streamIdNoInterrupt_function_003
 * @tc.desc: function test InitThreadPool with maxStreams_ above max
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerNoInterruptUnitTest, streamIdNoInterrupt_function_003, TestSize.Level2)
{
    MEDIA_LOGI("streamIdNoInterrupt_function_003 before");
    streamIDManager_->isStreamThreadPoolStarted_.store(false);
    streamIDManager_->maxStreams_ = 100; // 瓒呰繃MAX_PLAY_STREAMS_NUMBER
    EXPECT_EQ(MSERR_OK, streamIDManager_->InitThreadPool());
    EXPECT_EQ(IStreamIDManager::MAX_PLAY_STREAMS_NUMBER, streamIDManager_->maxStreams_);
    MEDIA_LOGI("streamIdNoInterrupt_function_003 after");
}

/**
 * @tc.name: streamIdNoInterrupt_function_004
 * @tc.desc: function test SetPlay before Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerNoInterruptUnitTest, streamIdNoInterrupt_function_004, TestSize.Level2)
{
    MEDIA_LOGI("streamIdNoInterrupt_function_004 before");
    streamIDManager_->isStreamThreadPoolStarted_.store(false);
    PlayParams playParams;
    EXPECT_EQ(MSERR_INVALID_VAL, streamIDManager_->SetPlay(0, 0, playParams));
    MEDIA_LOGI("streamIdNoInterrupt_function_004 after");
}

/**
 * @tc.name: streamIdNoInterrupt_function_005
 * @tc.desc: function test SetPlay with null stream
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerNoInterruptUnitTest, streamIdNoInterrupt_function_005, TestSize.Level2)
{
    MEDIA_LOGI("streamIdNoInterrupt_function_005 before");
    streamIDManager_->InitThreadPool();
    PlayParams playParams;
    playParams.priority = 1;
    // streamID涓嶅瓨鍦?+    EXPECT_EQ(MSERR_INVALID_VAL, streamIDManager_->SetPlay(1, 999, playParams));
    MEDIA_LOGI("streamIdNoInterrupt_function_005 after");
}

/**
 * @tc.name: streamIdNoInterrupt_function_006
 * @tc.desc: function test SetPlay with available slot
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerNoInterruptUnitTest, streamIdNoInterrupt_function_006, TestSize.Level2)
{
    MEDIA_LOGI("streamIdNoInterrupt_function_006 before");
    streamIDManager_->InitThreadPool();
    Format format;
    int32_t soundID = 1;
    int32_t streamID = 1;
    auto audioStream = std::make_shared<AudioStream>(format, soundID, streamID, nullptr);
    streamIDManager_->soundID2MultiStreams_[soundID].push_back(audioStream);
    PlayParams playParams;
    playParams.priority = 1;
    EXPECT_EQ(MSERR_OK, streamIDManager_->SetPlay(soundID, streamID, playParams));
    EXPECT_EQ(1, streamIDManager_->playingStreamIDs_.size());
    MEDIA_LOGI("streamIdNoInterrupt_function_006 after");
    sleep(2);
}

/**
 * @tc.name: streamIdNoInterrupt_function_007
 * @tc.desc: function test SetPlay when full and new stream priority is lower
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerNoInterruptUnitTest, streamIdNoInterrupt_function_007, TestSize.Level2)
{
    MEDIA_LOGI("streamIdNoInterrupt_function_007 before");
    streamIDManager_->InitThreadPool();
    Format format;
    int32_t soundID = 1;
    int32_t streamID = 1;
    auto audioStream = std::make_shared<AudioStream>(format, soundID, streamID, nullptr);
    streamIDManager_->soundID2MultiStreams_[soundID].push_back(audioStream);
    // fill playingStreamIDs_ with 5 streams and add them to the map so that the
    // last stream can be found to exercise the priority comparison branch
    for (int32_t i = 1; i <= 5; ++i) {
        streamIDManager_->playingStreamIDs_.push_back(i);
        auto playingStream = std::make_shared<AudioStream>(format, soundID, i, nullptr);
        playingStream->SetPriority(10); // higher priority than the new stream
        streamIDManager_->soundID2MultiStreams_[soundID].push_back(playingStream);
    }
    PlayParams playParams;
    playParams.priority = 0;
    // last playing stream has higher priority, so the new stream is rejected
    EXPECT_EQ(MSERR_INVALID_VAL, streamIDManager_->SetPlay(soundID, streamID, playParams));
    MEDIA_LOGI("streamIdNoInterrupt_function_007 after");
}

/**
 * @tc.name: streamIdNoInterrupt_function_008
 * @tc.desc: function test SetPlay when full and new stream priority is higher
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerNoInterruptUnitTest, streamIdNoInterrupt_function_008, TestSize.Level2)
{
    MEDIA_LOGI("streamIdNoInterrupt_function_008 before");
    streamIDManager_->InitThreadPool();
    Format format;
    int32_t soundID = 1;
    int32_t streamID = 1;
    auto audioStream = std::make_shared<AudioStream>(format, soundID, streamID, nullptr);
    streamIDManager_->soundID2MultiStreams_[soundID].push_back(audioStream);
    // last stream in playingStreamIDs_ has low priority
    for (int32_t i = 1; i <= 5; ++i) {
        streamIDManager_->playingStreamIDs_.push_back(i);
        auto lastStream = std::make_shared<AudioStream>(format, soundID, i, nullptr);
        streamIDManager_->soundID2MultiStreams_[soundID].push_back(lastStream);
    }
    PlayParams playParams;
    playParams.priority = 10;
    EXPECT_EQ(MSERR_OK, streamIDManager_->SetPlay(soundID, streamID, playParams));
    MEDIA_LOGI("streamIdNoInterrupt_function_008 after");
    sleep(2);
}

/**
 * @tc.name: streamIdNoInterrupt_function_009
 * @tc.desc: function test GetAvailableStreamIDBySoundID with non-existent soundID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerNoInterruptUnitTest, streamIdNoInterrupt_function_009, TestSize.Level2)
{
    MEDIA_LOGI("streamIdNoInterrupt_function_009 before");
    EXPECT_EQ(0, streamIDManager_->GetAvailableStreamIDBySoundID(999));
    MEDIA_LOGI("streamIdNoInterrupt_function_009 after");
}

/**
 * @tc.name: streamIdNoInterrupt_function_010
 * @tc.desc: function test GetAvailableStreamIDBySoundID with null stream
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerNoInterruptUnitTest, streamIdNoInterrupt_function_010, TestSize.Level2)
{
    MEDIA_LOGI("streamIdNoInterrupt_function_010 before");
    int32_t soundID = 1;
    streamIDManager_->soundID2MultiStreams_[soundID].push_back(nullptr);
    EXPECT_EQ(0, streamIDManager_->GetAvailableStreamIDBySoundID(soundID));
    MEDIA_LOGI("streamIdNoInterrupt_function_010 after");
}

/**
 * @tc.name: streamIdNoInterrupt_function_011
 * @tc.desc: function test GetAvailableStreamIDBySoundID with STOPPED state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerNoInterruptUnitTest, streamIdNoInterrupt_function_011, TestSize.Level2)
{
    MEDIA_LOGI("streamIdNoInterrupt_function_011 before");
    Format format;
    int32_t soundID = 1;
    int32_t streamID = 1;
    auto audioStream = std::make_shared<AudioStream>(format, soundID, streamID, nullptr);
    audioStream->SetStreamState(StreamState::STOPPED);
    streamIDManager_->soundID2MultiStreams_[soundID].push_back(audioStream);
    // STOPPED stream should be reused, state converted to PREPARED
    EXPECT_EQ(streamID, streamIDManager_->GetAvailableStreamIDBySoundID(soundID));
    EXPECT_EQ(StreamState::PREPARED, audioStream->GetStreamState());
    MEDIA_LOGI("streamIdNoInterrupt_function_011 after");
}

/**
 * @tc.name: streamIdNoInterrupt_function_012
 * @tc.desc: function test GetAvailableStreamIDBySoundID with PLAYING state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerNoInterruptUnitTest, streamIdNoInterrupt_function_012, TestSize.Level2)
{
    MEDIA_LOGI("streamIdNoInterrupt_function_012 before");
    Format format;
    int32_t soundID = 1;
    int32_t streamID = 1;
    auto audioStream = std::make_shared<AudioStream>(format, soundID, streamID, nullptr);
    audioStream->SetStreamState(StreamState::PLAYING);
    streamIDManager_->soundID2MultiStreams_[soundID].push_back(audioStream);
    // PLAYING stream is not reusable
    EXPECT_EQ(0, streamIDManager_->GetAvailableStreamIDBySoundID(soundID));
    MEDIA_LOGI("streamIdNoInterrupt_function_012 after");
}

/**
 * @tc.name: streamIdNoInterrupt_function_013
 * @tc.desc: function test RemoveInvalidStreams with RELEASED state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerNoInterruptUnitTest, streamIdNoInterrupt_function_013, TestSize.Level2)
{
    MEDIA_LOGI("streamIdNoInterrupt_function_013 before");
    streamIDManager_->InitThreadPool();
    Format format;
    int32_t soundID = 1;
    int32_t streamID = 1;
    auto audioStream = std::make_shared<AudioStream>(format, soundID, streamID, nullptr);
    audioStream->SetStreamState(StreamState::RELEASED);
    streamIDManager_->soundID2MultiStreams_[soundID].push_back(audioStream);
    streamIDManager_->currentStreamsNum_.store(10);
    streamIDManager_->RemoveInvalidStreams();
    EXPECT_EQ(0, streamIDManager_->soundID2MultiStreams_[soundID].size());
    MEDIA_LOGI("streamIdNoInterrupt_function_013 after");
}

/**
 * @tc.name: streamIdNoInterrupt_function_014
 * @tc.desc: function test RemoveInvalidStreams with STOPPED state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerNoInterruptUnitTest, streamIdNoInterrupt_function_014, TestSize.Level2)
{
    MEDIA_LOGI("streamIdNoInterrupt_function_014 before");
    streamIDManager_->InitThreadPool();
    Format format;
    int32_t soundID = 1;
    int32_t streamID = 1;
    auto audioStream = std::make_shared<AudioStream>(format, soundID, streamID, nullptr);
    audioStream->SetStreamState(StreamState::STOPPED);
    streamIDManager_->soundID2MultiStreams_[soundID].push_back(audioStream);
    streamIDManager_->currentStreamsNum_.store(10);
    streamIDManager_->RemoveInvalidStreams();
    EXPECT_EQ(0, streamIDManager_->soundID2MultiStreams_[soundID].size());
    MEDIA_LOGI("streamIdNoInterrupt_function_014 after");
}

/**
 * @tc.name: streamIdNoInterrupt_function_015
 * @tc.desc: function test RemoveInvalidStreams with PLAYING state should not be removed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerNoInterruptUnitTest, streamIdNoInterrupt_function_015, TestSize.Level2)
{
    MEDIA_LOGI("streamIdNoInterrupt_function_015 before");
    streamIDManager_->InitThreadPool();
    Format format;
    int32_t soundID = 1;
    int32_t streamID = 1;
    auto audioStream = std::make_shared<AudioStream>(format, soundID, streamID, nullptr);
    audioStream->SetStreamState(StreamState::PLAYING);
    streamIDManager_->soundID2MultiStreams_[soundID].push_back(audioStream);
    streamIDManager_->currentStreamsNum_.store(10);
    streamIDManager_->RemoveInvalidStreams();
    EXPECT_EQ(1, streamIDManager_->soundID2MultiStreams_[soundID].size());
    MEDIA_LOGI("streamIdNoInterrupt_function_015 after");
}

/**
 * @tc.name: streamIdNoInterrupt_function_016
 * @tc.desc: function test RemoveInvalidStreams does not remove when under held limit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerNoInterruptUnitTest, streamIdNoInterrupt_function_016, TestSize.Level2)
{
    MEDIA_LOGI("streamIdNoInterrupt_function_016 before");
    streamIDManager_->InitThreadPool();
    Format format;
    int32_t soundID = 1;
    int32_t streamID = 1;
    auto audioStream = std::make_shared<AudioStream>(format, soundID, streamID, nullptr);
    audioStream->SetStreamState(StreamState::RELEASED);
    streamIDManager_->soundID2MultiStreams_[soundID].push_back(audioStream);
    streamIDManager_->currentStreamsNum_.store(3); // 浣庝簬MAX_NUMBER_OF_HELD_STREAMS (6)
    // currentStreamsNum_ <= MAX_NUMBER_OF_HELD_STREAMS, so InnerProcessOfRemoveInvalidStreams
    // returns true directly without removing any stream
    streamIDManager_->RemoveInvalidStreams();
    EXPECT_EQ(1, streamIDManager_->soundID2MultiStreams_[soundID].size());
    MEDIA_LOGI("streamIdNoInterrupt_function_016 after");
}

/**
 * @tc.name: streamIdNoInterrupt_function_017
 * @tc.desc: function test RemoveStreamBySoundIDAndStreamID with valid params
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerNoInterruptUnitTest, streamIdNoInterrupt_function_017, TestSize.Level2)
{
    MEDIA_LOGI("streamIdNoInterrupt_function_017 before");
    Format format;
    int32_t soundID = 1;
    int32_t streamID = 1;
    auto audioStream = std::make_shared<AudioStream>(format, soundID, streamID, nullptr);
    streamIDManager_->soundID2MultiStreams_[soundID].push_back(audioStream);
    streamIDManager_->currentStreamsNum_.store(1);
    streamIDManager_->RemoveStreamBySoundIDAndStreamID(soundID, streamID);
    EXPECT_EQ(0, streamIDManager_->soundID2MultiStreams_[soundID].size());
    EXPECT_EQ(0, streamIDManager_->currentStreamsNum_.load());
    MEDIA_LOGI("streamIdNoInterrupt_function_017 after");
}

/**
 * @tc.name: streamIdNoInterrupt_function_018
 * @tc.desc: function test ClearStreamIDInDeque
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerNoInterruptUnitTest, streamIdNoInterrupt_function_018, TestSize.Level2)
{
    MEDIA_LOGI("streamIdNoInterrupt_function_018 before");
    Format format;
    int32_t soundID = 1;
    int32_t streamID = 1;
    auto audioStream = std::make_shared<AudioStream>(format, soundID, streamID, nullptr);
    streamIDManager_->soundID2MultiStreams_[soundID].push_back(audioStream);
    streamIDManager_->playingStreamIDs_.emplace_back(streamID);
    streamIDManager_->playingStreamIDs_.emplace_back(STREAM_ID_BEGIN + 1);
    EXPECT_EQ(MSERR_OK, streamIDManager_->ClearStreamIDInDeque(soundID, streamID));
    EXPECT_EQ(1, streamIDManager_->playingStreamIDs_.size());
    MEDIA_LOGI("streamIdNoInterrupt_function_018 after");
}

/**
 * @tc.name: streamIdNoInterrupt_function_019
 * @tc.desc: function test OnPlayFinished
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerNoInterruptUnitTest, streamIdNoInterrupt_function_019, TestSize.Level2)
{
    MEDIA_LOGI("streamIdNoInterrupt_function_019 before");
    Format format;
    int32_t soundID = 1;
    int32_t streamID = 1;
    auto audioStream = std::make_shared<AudioStream>(format, soundID, streamID, nullptr);
    audioStream->SetStreamState(StreamState::PLAYING);
    streamIDManager_->soundID2MultiStreams_[soundID].push_back(audioStream);
    streamIDManager_->playingStreamIDs_.emplace_back(streamID);
    streamIDManager_->OnPlayFinished(streamID);
    EXPECT_TRUE(streamIDManager_->playingStreamIDs_.empty());
    EXPECT_EQ(StreamState::STOPPED, audioStream->GetStreamState());
    MEDIA_LOGI("streamIdNoInterrupt_function_019 after");
}

/**
 * @tc.name: streamIdNoInterrupt_function_020
 * @tc.desc: function test GetStreamIDBySoundID with empty map
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerNoInterruptUnitTest, streamIdNoInterrupt_function_020, TestSize.Level2)
{
    MEDIA_LOGI("streamIdNoInterrupt_function_020 before");
    std::vector<int32_t> result = streamIDManager_->GetStreamIDBySoundID(1);
    EXPECT_TRUE(result.empty());
    MEDIA_LOGI("streamIdNoInterrupt_function_020 after");
}

/**
 * @tc.name: streamIdNoInterrupt_function_021
 * @tc.desc: function test GetStreamIDBySoundID with non-existent soundID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerNoInterruptUnitTest, streamIdNoInterrupt_function_021, TestSize.Level2)
{
    MEDIA_LOGI("streamIdNoInterrupt_function_021 before");
    Format format;
    int32_t soundID = 1;
    int32_t streamID = 1;
    auto audioStream = std::make_shared<AudioStream>(format, soundID, streamID, nullptr);
    streamIDManager_->soundID2MultiStreams_[soundID].push_back(audioStream);
    std::vector<int32_t> result = streamIDManager_->GetStreamIDBySoundID(999);
    EXPECT_TRUE(result.empty());
    MEDIA_LOGI("streamIdNoInterrupt_function_021 after");
}

/**
 * @tc.name: streamIdNoInterrupt_function_022
 * @tc.desc: function test GetStreamIDBySoundID with valid soundID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerNoInterruptUnitTest, streamIdNoInterrupt_function_022, TestSize.Level2)
{
    MEDIA_LOGI("streamIdNoInterrupt_function_022 before");
    Format format;
    int32_t soundID = 1;
    int32_t streamID = 1;
    auto audioStream = std::make_shared<AudioStream>(format, soundID, streamID, nullptr);
    streamIDManager_->soundID2MultiStreams_[soundID].push_back(audioStream);
    std::vector<int32_t> result = streamIDManager_->GetStreamIDBySoundID(soundID);
    EXPECT_EQ(1, result.size());
    EXPECT_EQ(streamID, result[0]);
    MEDIA_LOGI("streamIdNoInterrupt_function_022 after");
}

/**
 * @tc.name: streamIdNoInterrupt_function_023
 * @tc.desc: function test GetStreamByStreamID with invalid streamID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerNoInterruptUnitTest, streamIdNoInterrupt_function_023, TestSize.Level2)
{
    MEDIA_LOGI("streamIdNoInterrupt_function_023 before");
    EXPECT_EQ(nullptr, streamIDManager_->GetStreamByStreamID(-1));
    MEDIA_LOGI("streamIdNoInterrupt_function_023 after");
}

/**
 * @tc.name: streamIdNoInterrupt_function_024
 * @tc.desc: function test GetStreamByStreamID with non-existent streamID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerNoInterruptUnitTest, streamIdNoInterrupt_function_024, TestSize.Level2)
{
    MEDIA_LOGI("streamIdNoInterrupt_function_024 before");
    EXPECT_EQ(nullptr, streamIDManager_->GetStreamByStreamID(999));
    MEDIA_LOGI("streamIdNoInterrupt_function_024 after");
}

/**
 * @tc.name: streamIdNoInterrupt_function_025
 * @tc.desc: function test GetStreamByStreamID with valid streamID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerNoInterruptUnitTest, streamIdNoInterrupt_function_025, TestSize.Level2)
{
    MEDIA_LOGI("streamIdNoInterrupt_function_025 before");
    Format format;
    int32_t soundID = 1;
    int32_t streamID = 1;
    auto audioStream = std::make_shared<AudioStream>(format, soundID, streamID, nullptr);
    streamIDManager_->soundID2MultiStreams_[soundID].push_back(audioStream);
    auto result = streamIDManager_->GetStreamByStreamID(streamID);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(streamID, result->GetStreamID());
    MEDIA_LOGI("streamIdNoInterrupt_function_025 after");
}

/**
 * @tc.name: streamIdNoInterrupt_function_026
 * @tc.desc: function test DoPlay with non-existent streamID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerNoInterruptUnitTest, streamIdNoInterrupt_function_026, TestSize.Level2)
{
    MEDIA_LOGI("streamIdNoInterrupt_function_026 before");
    EXPECT_EQ(MSERR_INVALID_VAL, streamIDManager_->DoPlay(999));
    MEDIA_LOGI("streamIdNoInterrupt_function_026 after");
}

/**
 * @tc.name: streamIdNoInterrupt_function_027
 * @tc.desc: function test DoPlay with PREPARED stream without renderer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerNoInterruptUnitTest, streamIdNoInterrupt_function_027, TestSize.Level2)
{
    MEDIA_LOGI("streamIdNoInterrupt_function_027 before");
    Format format;
    int32_t soundID = 1;
    int32_t streamID = 1;
    auto audioStream = std::make_shared<AudioStream>(format, soundID, streamID, nullptr);
    streamIDManager_->soundID2MultiStreams_[soundID].push_back(audioStream);
    streamIDManager_->playingStreamIDs_.emplace_back(streamID);
    // PREPARED stream without pcmBuffer leads to DoPlayWithNoInterrupt failure
    EXPECT_EQ(MSERR_INVALID_VAL, streamIDManager_->DoPlay(streamID));
    MEDIA_LOGI("streamIdNoInterrupt_function_027 after");
}

/**
 * @tc.name: streamIdNoInterrupt_function_028
 * @tc.desc: function test PostProcessingOfStreamDoPlayFailed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerNoInterruptUnitTest, streamIdNoInterrupt_function_028, TestSize.Level2)
{
    MEDIA_LOGI("streamIdNoInterrupt_function_028 before");
    Format format;
    int32_t soundID = 1;
    int32_t streamID = 1;
    auto audioStream = std::make_shared<AudioStream>(format, soundID, streamID, nullptr);
    audioStream->SetStreamState(StreamState::PLAYING);
    streamIDManager_->soundID2MultiStreams_[soundID].push_back(audioStream);
    streamIDManager_->playingStreamIDs_.emplace_back(streamID);
    streamIDManager_->PostProcessingOfStreamDoPlayFailed(streamID);
    EXPECT_TRUE(streamIDManager_->playingStreamIDs_.empty());
    EXPECT_EQ(StreamState::RELEASED, audioStream->GetStreamState());
    MEDIA_LOGI("streamIdNoInterrupt_function_028 after");
}

/**
 * @tc.name: streamIdNoInterrupt_function_029
 * @tc.desc: function test QueueAndSortPlayingStreamID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerNoInterruptUnitTest, streamIdNoInterrupt_function_029, TestSize.Level2)
{
    MEDIA_LOGI("streamIdNoInterrupt_function_029 before");
    Format format;
    int32_t soundID = 1;
    // playingStreamIDs_ empty, freshStreamID is directly appended
    streamIDManager_->QueueAndSortPlayingStreamID(BEGIN_NUM);
    EXPECT_EQ(1, streamIDManager_->playingStreamIDs_.size());
    EXPECT_EQ(BEGIN_NUM, streamIDManager_->playingStreamIDs_.front());
    // non-existent playingStreamID is erased and freshStreamID re-queued
    streamIDManager_->playingStreamIDs_.emplace_back(999);
    int32_t streamID = 1;
    auto audioStream = std::make_shared<AudioStream>(format, soundID, streamID, nullptr);
    streamIDManager_->soundID2MultiStreams_[soundID].push_back(audioStream);
    streamIDManager_->QueueAndSortPlayingStreamID(streamID);
    // 999 is erased, then BEGIN_NUM(0) is also erased (not in map), only streamID(1) remains
    EXPECT_EQ(1, streamIDManager_->playingStreamIDs_.size());
    EXPECT_EQ(streamID, streamIDManager_->playingStreamIDs_.front());
    MEDIA_LOGI("streamIdNoInterrupt_function_029 after");
}

}  // namespace Media
}  // namespace OHOS