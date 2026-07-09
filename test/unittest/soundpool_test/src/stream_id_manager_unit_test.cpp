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

#include "stream_id_manager_unit_test.h"
#include "media_errors.h"
#include "stream_id_manager.h"
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
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SOUNDPOOL, "StreamIdManagerUnitTest"};
}

namespace OHOS {
namespace Media {
void StreamIDManagerUnitTest::SetUpTestCase(void)
{}

void StreamIDManagerUnitTest::TearDownTestCase(void)
{
    std::cout << "sleep one second to protect PlayerEngine safely exit." << endl;
    sleep(1);  // let PlayEngine safe exit.
}

void StreamIDManagerUnitTest::SetUp(void)
{
    AudioStandard::AudioRendererInfo audioRenderInfo;
    audioRenderInfo.contentType = AudioStandard::CONTENT_TYPE_MUSIC;
    audioRenderInfo.streamUsage = AudioStandard::STREAM_USAGE_MUSIC;
    audioRenderInfo.rendererFlags = 0;
    streamIDManager_ = std::make_shared<StreamIDManagerWithSameSoundInterrupt>(MAX_STREAMS, audioRenderInfo);
}

void StreamIDManagerUnitTest::TearDown(void)
{
    if (streamIDManager_ != nullptr) {
        streamIDManager_.reset();
    }
}

/**
 * @tc.name: streamId_function_001
 * @tc.desc: function test MulInitThreadPool
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerUnitTest, streamId_function_001, TestSize.Level2)
{
    MEDIA_LOGI("streamId_function_001 before");
    streamIDManager_->isStreamThreadPoolStarted_.store(true);
    EXPECT_EQ(MSERR_OK, streamIDManager_->InitThreadPool());
    MEDIA_LOGI("streamId_function_001 after");
}

/**
 * @tc.name: streamId_function_002
 * @tc.desc: function test streamNum not enough
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerUnitTest, streamId_function_002, TestSize.Level2)
{
    MEDIA_LOGI("streamId_function_002 before");
    streamIDManager_->isStreamThreadPoolStarted_.store(false);
    streamIDManager_->maxStreams_ = 0;
    EXPECT_EQ(MSERR_OK, streamIDManager_->InitThreadPool());
    MEDIA_LOGI("streamId_function_002 after");
}

/**
 * @tc.name: streamId_function_003
 * @tc.desc: function test play brefore Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerUnitTest, streamId_function_003, TestSize.Level2)
{
    MEDIA_LOGI("streamId_function_003 before");
    streamIDManager_->isStreamThreadPoolStarted_.store(false);
    PlayParams playParams;
    EXPECT_EQ(MSERR_INVALID_VAL, streamIDManager_->SetPlay(0, 0, playParams));
    MEDIA_LOGI("streamId_function_003 after");
}

/**
 * @tc.name: streamId_function_004
 * @tc.desc: function test QueueAndSortPlayingStreamID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerUnitTest, streamId_function_004, TestSize.Level2)
{
    MEDIA_LOGI("streamId_function_004 before");
    streamIDManager_->isStreamThreadPoolStarted_.store(false);
    streamIDManager_->playingStreamIDs_.emplace_back(BEGIN_NUM);
    streamIDManager_->QueueAndSortPlayingStreamID(BEGIN_NUM);
    EXPECT_EQ(1, streamIDManager_->playingStreamIDs_.size());
    Format format;
    std::deque<std::shared_ptr<AudioBufferEntry>> cacheData;
    int32_t soundID = 0;
    int32_t streamID = 0;
    auto audioStream = std::make_shared<AudioStream>(format, soundID, streamID, nullptr);
    streamIDManager_->playingStreamIDs_.emplace_back(BEGIN_NUM);
    streamIDManager_->soundID2Stream_.emplace(BEGIN_NUM, audioStream);
    streamIDManager_->QueueAndSortPlayingStreamID(BEGIN_NUM + 1);
    EXPECT_EQ(2, streamIDManager_->playingStreamIDs_.size());
    MEDIA_LOGI("streamId_function_004 after");
}

/**
 * @tc.name: streamId_function_005
 * @tc.desc: function test QueueAndSortWillPlayStreamID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerUnitTest, streamId_function_005, TestSize.Level2)
{
    MEDIA_LOGI("streamId_function_005 before");
    IStreamIDManager::StreamIDAndPlayParamsInfo freshStreamIDAndPlayParamsInfo;
    freshStreamIDAndPlayParamsInfo.streamID = BEGIN_NUM;
    streamIDManager_->QueueAndSortWillPlayStreamID(freshStreamIDAndPlayParamsInfo);
    EXPECT_EQ(1, streamIDManager_->willPlayStreamInfos_.size());

    Format format;
    std::deque<std::shared_ptr<AudioBufferEntry>> cacheData;
    int32_t soundID = 0;
    int32_t streamID = 0;
    auto audioStream = std::make_shared<AudioStream>(format, soundID, streamID, nullptr);
    streamIDManager_->soundID2Stream_.emplace(BEGIN_NUM, audioStream);
    IStreamIDManager::StreamIDAndPlayParamsInfo freshStreamIDAndPlayParamsInfo1;
    freshStreamIDAndPlayParamsInfo.streamID = BEGIN_NUM + 1;
    streamIDManager_->QueueAndSortWillPlayStreamID(freshStreamIDAndPlayParamsInfo1);
    EXPECT_EQ(2, streamIDManager_->willPlayStreamInfos_.size());

    audioStream->priority_ = 0;
    streamIDManager_->QueueAndSortWillPlayStreamID(freshStreamIDAndPlayParamsInfo);
    EXPECT_EQ(2, streamIDManager_->willPlayStreamInfos_.size());
    MEDIA_LOGI("streamId_function_005 after");
}

/**
 * @tc.name: streamId_function_006
 * @tc.desc: function test DoPlay
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerUnitTest, streamId_function_006, TestSize.Level2)
{
    MEDIA_LOGI("streamId_function_006 before");
    Format format;
    std::deque<std::shared_ptr<AudioBufferEntry>> cacheData;
    int32_t soundID = 0;
    int32_t streamID = 0;
    auto audioStream = std::make_shared<AudioStream>(format, soundID, streamID, nullptr);
    streamIDManager_->soundID2Stream_.emplace(BEGIN_NUM, audioStream);
    streamIDManager_->playingStreamIDs_.emplace_back(BEGIN_NUM + 1);
    EXPECT_EQ(MSERR_INVALID_VAL, streamIDManager_->DoPlay(BEGIN_NUM + 1));
    streamIDManager_->playingStreamIDs_.emplace_back(BEGIN_NUM);
    EXPECT_EQ(MSERR_INVALID_VAL, streamIDManager_->DoPlay(BEGIN_NUM + 1));
    MEDIA_LOGI("streamId_function_006 after");
}

/**
 * @tc.name: streamId_function_007
 * @tc.desc: function test ClearStreamIDInDeque
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerUnitTest, streamId_function_007, TestSize.Level2)
{
    MEDIA_LOGI("streamId_function_007 before");
    streamIDManager_->playingStreamIDs_.emplace_back(BEGIN_NUM);
    streamIDManager_->playingStreamIDs_.emplace_back(STREAM_ID_BEGIN);
    streamIDManager_->ClearStreamIDInDeque(SOUND_ID_BEGIN, STREAM_ID_BEGIN);
    EXPECT_EQ(MSERR_OK, streamIDManager_->ClearStreamIDInDeque(SOUND_ID_BEGIN, STREAM_ID_BEGIN));

    IStreamIDManager::StreamIDAndPlayParamsInfo streamIDAndPlayParamsInfo;
    streamIDManager_->willPlayStreamInfos_.emplace_back(streamIDAndPlayParamsInfo);
    IStreamIDManager::StreamIDAndPlayParamsInfo streamIDAndPlayParamsInfo1;
    streamIDManager_->willPlayStreamInfos_.emplace_back(streamIDAndPlayParamsInfo1);
    EXPECT_EQ(MSERR_OK, streamIDManager_->ClearStreamIDInDeque(SOUND_ID_BEGIN, STREAM_ID_BEGIN));
    MEDIA_LOGI("streamId_function_007 after");
}

/**
 * @tc.name: streamId_function_008
 * @tc.desc: function test InitThreadPool with maxStreams > MAX_PLAY_STREAMS_NUMBER
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerUnitTest, streamId_function_008, TestSize.Level2)
{
    MEDIA_LOGI("streamId_function_008 before");
    streamIDManager_->isStreamThreadPoolStarted_.store(false);
    streamIDManager_->maxStreams_ = 100; // 超过MAX_PLAY_STREAMS_NUMBER
    EXPECT_EQ(MSERR_OK, streamIDManager_->InitThreadPool());
    EXPECT_EQ(IStreamIDManager::MAX_PLAY_STREAMS_NUMBER, streamIDManager_->maxStreams_);
    MEDIA_LOGI("streamId_function_008 after");
}

/**
 * @tc.name: streamId_function_009
 * @tc.desc: function test InitThreadPool with maxStreams < MIN_PLAY_STREAMS_NUMBER
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerUnitTest, streamId_function_009, TestSize.Level2)
{
    MEDIA_LOGI("streamId_function_009 before");
    streamIDManager_->isStreamThreadPoolStarted_.store(false);
    streamIDManager_->maxStreams_ = 0; // 低于MIN_PLAY_STREAMS_NUMBER
    EXPECT_EQ(MSERR_OK, streamIDManager_->InitThreadPool());
    EXPECT_EQ(IStreamIDManager::MIN_PLAY_STREAMS_NUMBER, streamIDManager_->maxStreams_);
    MEDIA_LOGI("streamId_function_009 after");
}

/**
 * @tc.name: streamId_function_010
 * @tc.desc: function test ReorderStream with playing streams
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerUnitTest, streamId_function_010, TestSize.Level2)
{
    MEDIA_LOGI("streamId_function_010 before");
    Format format;
    int32_t soundID = 1;
    int32_t streamID1 = 1;
    int32_t streamID2 = 2;
    
    auto audioStream1 = std::make_shared<AudioStream>(format, soundID, streamID1, nullptr);
    auto audioStream2 = std::make_shared<AudioStream>(format, soundID, streamID2, nullptr);
    
    audioStream1->priority_ = 1;
    audioStream2->priority_ = 2;
    
    streamIDManager_->soundID2Stream_.emplace(soundID, audioStream1);
    streamIDManager_->playingStreamIDs_.emplace_back(streamID1);
    streamIDManager_->playingStreamIDs_.emplace_back(streamID2);
    
    EXPECT_EQ(MSERR_OK, streamIDManager_->ReorderStream(streamID1, 1));
    MEDIA_LOGI("streamId_function_010 after");
}

/**
 * @tc.name: streamId_function_011
 * @tc.desc: function test InnerProcessOfOnPlayFinished with stream not in playing list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerUnitTest, streamId_function_011, TestSize.Level2)
{
    MEDIA_LOGI("streamId_function_011 before");
    Format format;
    int32_t soundID = 1;
    int32_t streamID = 1;
    
    auto audioStream = std::make_shared<AudioStream>(format, soundID, streamID, nullptr);
    audioStream->SetStreamState(StreamState::PLAYING);
    
    streamIDManager_->soundID2Stream_.emplace(soundID, audioStream);
    // streamID不在playingStreamIDs_中
    EXPECT_TRUE(streamIDManager_->InnerProcessOfOnPlayFinished(streamID));
    EXPECT_EQ(StreamState::STOPPED, audioStream->GetStreamState());
    MEDIA_LOGI("streamId_function_011 after");
}

/**
 * @tc.name: streamId_function_012
 * @tc.desc: function test InnerProcessOfOnPlayFinished with null stream
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerUnitTest, streamId_function_012, TestSize.Level2)
{
    MEDIA_LOGI("streamId_function_012 before");
    // streamID不存在，GetStreamByStreamID返回nullptr
    EXPECT_FALSE(streamIDManager_->InnerProcessOfOnPlayFinished(999));
    MEDIA_LOGI("streamId_function_012 after");
}

/**
 * @tc.name: streamId_function_013
 * @tc.desc: function test StopAudioStream with null stream
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerUnitTest, streamId_function_013, TestSize.Level2)
{
    MEDIA_LOGI("streamId_function_013 before");
    streamIDManager_->InitThreadPool();
    // streamID不存在
    EXPECT_EQ(MSERR_INVALID_VAL, streamIDManager_->StopAudioStream(999));
    MEDIA_LOGI("streamId_function_013 after");
}

/**
 * @tc.name: streamId_function_014
 * @tc.desc: function test AddPlayTask
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerUnitTest, streamId_function_014, TestSize.Level2)
{
    MEDIA_LOGI("streamId_function_014 before");
    streamIDManager_->InitThreadPool();
    Format format;
    int32_t soundID = 1;
    int32_t streamID = 1;
    
    auto audioStream = std::make_shared<AudioStream>(format, soundID, streamID, nullptr);
    streamIDManager_->soundID2Stream_.emplace(soundID, audioStream);
    
    EXPECT_EQ(MSERR_OK, streamIDManager_->AddPlayTask(streamID));
    EXPECT_EQ(1, streamIDManager_->playingStreamIDs_.size());
    MEDIA_LOGI("streamId_function_014 after");
    sleep(2);
}

/**
 * @tc.name: streamId_function_015
 * @tc.desc: function test AddStopTask
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerUnitTest, streamId_function_015, TestSize.Level2)
{
    MEDIA_LOGI("streamId_function_015 before");
    streamIDManager_->InitThreadPool();
    Format format;
    int32_t soundID = 1;
    int32_t streamID = 1;
    
    auto audioStream = std::make_shared<AudioStream>(format, soundID, streamID, nullptr);
    
    EXPECT_EQ(MSERR_OK, streamIDManager_->AddStopTask(audioStream));
    MEDIA_LOGI("streamId_function_015 after");
}

/**
 * @tc.name: streamId_function_016
 * @tc.desc: function test AddReleaseTask
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerUnitTest, streamId_function_016, TestSize.Level2)
{
    MEDIA_LOGI("streamId_function_016 before");
    streamIDManager_->InitThreadPool();
    Format format;
    int32_t soundID = 1;
    int32_t streamID = 1;
    
    auto audioStream = std::make_shared<AudioStream>(format, soundID, streamID, nullptr);
    std::vector<std::shared_ptr<AudioStream>> streamsToBeReleased;
    streamsToBeReleased.push_back(audioStream);
    
    EXPECT_EQ(MSERR_OK, streamIDManager_->AddReleaseTask(streamsToBeReleased));
    MEDIA_LOGI("streamId_function_016 after");
}

/**
 * @tc.name: streamId_function_017
 * @tc.desc: function test AddReleaseTask with empty vector
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerUnitTest, streamId_function_017, TestSize.Level2)
{
    MEDIA_LOGI("streamId_function_017 before");
    std::vector<std::shared_ptr<AudioStream>> streamsToBeReleased;
    EXPECT_EQ(MSERR_INVALID_VAL, streamIDManager_->AddReleaseTask(streamsToBeReleased));
    MEDIA_LOGI("streamId_function_017 after");
}

/**
 * @tc.name: streamId_function_018
 * @tc.desc: function test GetAvailableStreamIDBySoundID with non-existent soundID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerUnitTest, streamId_function_018, TestSize.Level2)
{
    MEDIA_LOGI("streamId_function_018 before");
    EXPECT_EQ(0, streamIDManager_->GetAvailableStreamIDBySoundID(999));
    MEDIA_LOGI("streamId_function_018 after");
}

/**
 * @tc.name: streamId_function_019
 * @tc.desc: function test GetAvailableStreamIDBySoundID with null stream
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerUnitTest, streamId_function_019, TestSize.Level2)
{
    MEDIA_LOGI("streamId_function_019 before");
    int32_t soundID = 1;
    streamIDManager_->soundID2Stream_[soundID] = nullptr;
    EXPECT_EQ(0, streamIDManager_->GetAvailableStreamIDBySoundID(soundID));
    MEDIA_LOGI("streamId_function_019 after");
}

/**
 * @tc.name: streamId_function_020
 * @tc.desc: function test GetAvailableStreamIDBySoundID with RELEASED state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerUnitTest, streamId_function_020, TestSize.Level2)
{
    MEDIA_LOGI("streamId_function_020 before");
    Format format;
    int32_t soundID = 1;
    int32_t streamID = 1;
    
    auto audioStream = std::make_shared<AudioStream>(format, soundID, streamID, nullptr);
    audioStream->SetStreamState(StreamState::RELEASED);
    streamIDManager_->soundID2Stream_.emplace(soundID, audioStream);
    
    EXPECT_EQ(0, streamIDManager_->GetAvailableStreamIDBySoundID(soundID));
    MEDIA_LOGI("streamId_function_020 after");
}

/**
 * @tc.name: streamId_function_021
 * @tc.desc: function test GetAvailableStreamIDBySoundID with available stream
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerUnitTest, streamId_function_021, TestSize.Level2)
{
    MEDIA_LOGI("streamId_function_021 before");
    Format format;
    int32_t soundID = 1;
    int32_t streamID = 1;
    
    auto audioStream = std::make_shared<AudioStream>(format, soundID, streamID, nullptr);
    audioStream->SetStreamState(StreamState::PREPARED);
    streamIDManager_->soundID2Stream_.emplace(soundID, audioStream);
    
    EXPECT_EQ(streamID, streamIDManager_->GetAvailableStreamIDBySoundID(soundID));
    MEDIA_LOGI("streamId_function_021 after");
}

/**
 * @tc.name: streamId_function_022
 * @tc.desc: function test RemoveInvalidStreams with RELEASED state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerUnitTest, streamId_function_022, TestSize.Level2)
{
    MEDIA_LOGI("streamId_function_022 before");
    streamIDManager_->InitThreadPool();
    Format format;
    int32_t soundID = 1;
    int32_t streamID = 1;
    
    auto audioStream = std::make_shared<AudioStream>(format, soundID, streamID, nullptr);
    audioStream->SetStreamState(StreamState::RELEASED);
    streamIDManager_->soundID2Stream_.emplace(soundID, audioStream);
    streamIDManager_->currentStreamsNum_.store(10);
    
    streamIDManager_->RemoveInvalidStreams();
    EXPECT_EQ(0, streamIDManager_->soundID2Stream_.size());
    MEDIA_LOGI("streamId_function_022 after");
}

/**
 * @tc.name: streamId_function_023
 * @tc.desc: function test RemoveInvalidStreams with STOPPED state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerUnitTest, streamId_function_023, TestSize.Level2)
{
    MEDIA_LOGI("streamId_function_023 before");
    streamIDManager_->InitThreadPool();
    Format format;
    int32_t soundID = 1;
    int32_t streamID = 1;
    
    auto audioStream = std::make_shared<AudioStream>(format, soundID, streamID, nullptr);
    audioStream->SetStreamState(StreamState::STOPPED);
    streamIDManager_->soundID2Stream_.emplace(soundID, audioStream);
    streamIDManager_->currentStreamsNum_.store(10);
    
    streamIDManager_->RemoveInvalidStreams();
    EXPECT_EQ(0, streamIDManager_->soundID2Stream_.size());
    MEDIA_LOGI("streamId_function_023 after");
}

/**
 * @tc.name: streamId_function_025
 * @tc.desc: function test RemoveInvalidStreams with streams under limit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerUnitTest, streamId_function_025, TestSize.Level2)
{
    MEDIA_LOGI("streamId_function_025 before");
    streamIDManager_->InitThreadPool();
    Format format;
    int32_t soundID = 1;
    int32_t streamID = 1;
    
    auto audioStream = std::make_shared<AudioStream>(format, soundID, streamID, nullptr);
    audioStream->SetStreamState(StreamState::RELEASED);
    streamIDManager_->soundID2Stream_.emplace(soundID, audioStream);
    streamIDManager_->currentStreamsNum_.store(3); // 低于MAX_NUMBER_OF_HELD_STREAMS (6)
    
    streamIDManager_->RemoveInvalidStreams();
    // 低于限制时应该保留
    EXPECT_EQ(1, streamIDManager_->soundID2Stream_.size());
    MEDIA_LOGI("streamId_function_025 after");
}

/**
 * @tc.name: streamId_function_027
 * @tc.desc: function test SetPlay with null stream
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerUnitTest, streamId_function_027, TestSize.Level2)
{
    MEDIA_LOGI("streamId_function_027 before");
    streamIDManager_->InitThreadPool();
    
    PlayParams playParams;
    playParams.priority = 1;
    
    // streamID不存在
    EXPECT_EQ(MSERR_INVALID_VAL, streamIDManager_->SetPlay(1, 999, playParams));
    MEDIA_LOGI("streamId_function_027 after");
}

/**
 * @tc.name: streamId_function_028
 * @tc.desc: function test GetStreamIDBySoundID with empty soundID2Stream_
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerUnitTest, streamId_function_028, TestSize.Level2)
{
    MEDIA_LOGI("streamId_function_028 before");
    std::vector<int32_t> result = streamIDManager_->GetStreamIDBySoundID(1);
    EXPECT_TRUE(result.empty());
    MEDIA_LOGI("streamId_function_028 after");
}

/**
 * @tc.name: streamId_function_029
 * @tc.desc: function test GetStreamIDBySoundID with non-existent soundID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerUnitTest, streamId_function_029, TestSize.Level2)
{
    MEDIA_LOGI("streamId_function_029 before");
    Format format;
    int32_t soundID = 1;
    int32_t streamID = 1;
    
    auto audioStream = std::make_shared<AudioStream>(format, soundID, streamID, nullptr);
    streamIDManager_->soundID2Stream_.emplace(soundID, audioStream);
    
    std::vector<int32_t> result = streamIDManager_->GetStreamIDBySoundID(999);
    EXPECT_TRUE(result.empty());
    MEDIA_LOGI("streamId_function_029 after");
}

/**
 * @tc.name: streamId_function_030
 * @tc.desc: function test GetStreamIDBySoundID with null stream
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerUnitTest, streamId_function_030, TestSize.Level2)
{
    MEDIA_LOGI("streamId_function_030 before");
    int32_t soundID = 1;
    streamIDManager_->soundID2Stream_[soundID] = nullptr;
    
    std::vector<int32_t> result = streamIDManager_->GetStreamIDBySoundID(soundID);
    EXPECT_TRUE(result.empty());
    MEDIA_LOGI("streamId_function_030 after");
}

/**
 * @tc.name: streamId_function_031
 * @tc.desc: function test GetStreamIDBySoundID with valid stream
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerUnitTest, streamId_function_031, TestSize.Level2)
{
    MEDIA_LOGI("streamId_function_031 before");
    Format format;
    int32_t soundID = 1;
    int32_t streamID = 1;
    
    auto audioStream = std::make_shared<AudioStream>(format, soundID, streamID, nullptr);
    streamIDManager_->soundID2Stream_.emplace(soundID, audioStream);
    
    std::vector<int32_t> result = streamIDManager_->GetStreamIDBySoundID(soundID);
    EXPECT_EQ(1, result.size());
    EXPECT_EQ(streamID, result[0]);
    MEDIA_LOGI("streamId_function_031 after");
}

/**
 * @tc.name: streamId_function_032
 * @tc.desc: function test GetStreamByStreamID with invalid streamID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerUnitTest, streamId_function_032, TestSize.Level2)
{
    MEDIA_LOGI("streamId_function_032 before");
    EXPECT_EQ(nullptr, streamIDManager_->GetStreamByStreamID(-1));
    MEDIA_LOGI("streamId_function_032 after");
}

/**
 * @tc.name: streamId_function_033
 * @tc.desc: function test GetStreamByStreamID with non-existent streamID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerUnitTest, streamId_function_033, TestSize.Level2)
{
    MEDIA_LOGI("streamId_function_033 before");
    EXPECT_EQ(nullptr, streamIDManager_->GetStreamByStreamID(999));
    MEDIA_LOGI("streamId_function_033 after");
}

/**
 * @tc.name: streamId_function_034
 * @tc.desc: function test GetStreamByStreamID with valid streamID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerUnitTest, streamId_function_034, TestSize.Level2)
{
    MEDIA_LOGI("streamId_function_034 before");
    Format format;
    int32_t soundID = 1;
    int32_t streamID = 1;
    
    auto audioStream = std::make_shared<AudioStream>(format, soundID, streamID, nullptr);
    streamIDManager_->soundID2Stream_.emplace(soundID, audioStream);
    
    auto result = streamIDManager_->GetStreamByStreamID(streamID);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(streamID, result->GetStreamID());
    MEDIA_LOGI("streamId_function_034 after");
}

/**
 * @tc.name: streamId_function_036
 * @tc.desc: function test PostProcessingOfStreamDoPlayFailed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerUnitTest, streamId_function_036, TestSize.Level2)
{
    MEDIA_LOGI("streamId_function_036 before");
    Format format;
    int32_t soundID = 1;
    int32_t streamID = 1;
    
    auto audioStream = std::make_shared<AudioStream>(format, soundID, streamID, nullptr);
    audioStream->SetStreamState(StreamState::PLAYING);
    
    streamIDManager_->soundID2Stream_.emplace(soundID, audioStream);
    streamIDManager_->playingStreamIDs_.emplace_back(streamID);
    
    streamIDManager_->PostProcessingOfStreamDoPlayFailed(streamID);
    
    // 验证streamID从playingStreamIDs_中移除
    EXPECT_TRUE(streamIDManager_->playingStreamIDs_.empty());
    EXPECT_EQ(StreamState::RELEASED, audioStream->GetStreamState());
    MEDIA_LOGI("streamId_function_036 after");
}

/**
 * @tc.name: streamId_function_038
 * @tc.desc: function test RemoveStreamBySoundIDAndStreamID with mismatched streamID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerUnitTest, streamId_function_038, TestSize.Level2)
{
    MEDIA_LOGI("streamId_function_038 before");
    Format format;
    int32_t soundID = 1;
    int32_t streamID = 1;
    
    auto audioStream = std::make_shared<AudioStream>(format, soundID, streamID, nullptr);
    streamIDManager_->soundID2Stream_.emplace(soundID, audioStream);
    
    // streamID不匹配，不应该删除
    streamIDManager_->RemoveStreamBySoundIDAndStreamID(soundID, 999);
    EXPECT_EQ(1, streamIDManager_->soundID2Stream_.size());
    MEDIA_LOGI("streamId_function_038 after");
}

/**
 * @tc.name: streamId_function_039
 * @tc.desc: function test RemoveStreamBySoundIDAndStreamID with valid params
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamIDManagerUnitTest, streamId_function_039, TestSize.Level2)
{
    MEDIA_LOGI("streamId_function_039 before");
    Format format;
    int32_t soundID = 1;
    int32_t streamID = 1;
    
    auto audioStream = std::make_shared<AudioStream>(format, soundID, streamID, nullptr);
    streamIDManager_->soundID2Stream_.emplace(soundID, audioStream);
    streamIDManager_->currentStreamsNum_.store(1);
    
    streamIDManager_->RemoveStreamBySoundIDAndStreamID(soundID, streamID);
    EXPECT_EQ(0, streamIDManager_->soundID2Stream_.size());
    EXPECT_EQ(0, streamIDManager_->currentStreamsNum_.load());
    MEDIA_LOGI("streamId_function_039 after");
}
}  // namespace Media
}  // namespace OHOS
