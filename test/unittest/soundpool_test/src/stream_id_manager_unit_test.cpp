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
    streamIDManager_ = std::make_shared<StreamIDManager>(MAX_STREAMS, audioRenderInfo);
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
    streamIDManager_->isStreamPlayingThreadPoolStarted_.store(true);
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
    streamIDManager_->isStreamPlayingThreadPoolStarted_.store(false);
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
    streamIDManager_->isStreamPlayingThreadPoolStarted_.store(false);
    PlayParams playParams;
    EXPECT_EQ(MSERR_INVALID_VAL, streamIDManager_->SetPlayWithSameSoundInterrupt(0, 0, playParams));
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
    streamIDManager_->isStreamPlayingThreadPoolStarted_.store(false);
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
    StreamIDManager::StreamIDAndPlayParamsInfo freshStreamIDAndPlayParamsInfo;
    freshStreamIDAndPlayParamsInfo.streamID = BEGIN_NUM;
    streamIDManager_->QueueAndSortWillPlayStreamID(freshStreamIDAndPlayParamsInfo);
    EXPECT_EQ(1, streamIDManager_->willPlayStreamInfos_.size());

    Format format;
    std::deque<std::shared_ptr<AudioBufferEntry>> cacheData;
    int32_t soundID = 0;
    int32_t streamID = 0;
    auto audioStream = std::make_shared<AudioStream>(format, soundID, streamID, nullptr);
    streamIDManager_->soundID2Stream_.emplace(BEGIN_NUM, audioStream);
    StreamIDManager::StreamIDAndPlayParamsInfo freshStreamIDAndPlayParamsInfo1;
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
    audioStream->isRunning_.store(true);
    EXPECT_EQ(MSERR_INVALID_VAL, streamIDManager_->DoPlay(BEGIN_NUM + 1));
    audioStream->isRunning_.store(false);
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
    EXPECT_EQ(MSERR_INVALID_VAL, streamIDManager_->ClearStreamIDInDeque(SOUND_ID_BEGIN, STREAM_ID_BEGIN));

    StreamIDManager::StreamIDAndPlayParamsInfo streamIDAndPlayParamsInfo;
    streamIDManager_->willPlayStreamInfos_.emplace_back(streamIDAndPlayParamsInfo);
    StreamIDManager::StreamIDAndPlayParamsInfo streamIDAndPlayParamsInfo1;
    streamIDManager_->willPlayStreamInfos_.emplace_back(streamIDAndPlayParamsInfo1);
    EXPECT_EQ(MSERR_INVALID_VAL, streamIDManager_->ClearStreamIDInDeque(SOUND_ID_BEGIN, STREAM_ID_BEGIN));
    MEDIA_LOGI("streamId_function_007 after");
}

}  // namespace Media
}  // namespace OHOS