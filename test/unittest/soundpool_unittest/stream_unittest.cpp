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

#include "media_errors.h"
#include "stream_unittest.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing;
using namespace testing::ext;
static const int32_t DEFAULT_NUM = 10;
static const int32_t MSERR_INVALID = -1;

void SoundPoolStreamUnitTest::SetUpTestCase(void)
{
}

void SoundPoolStreamUnitTest::TearDownTestCase(void)
{
}

void SoundPoolStreamUnitTest::SetUp(void)
{
    Format trackFormat;
    int32_t soundID = 1;
    int32_t streamID = DEFAULT_NUM;
    std::shared_ptr<ThreadPool> streamStopThreadPool;
    stream_ = std::make_shared<Stream>(trackFormat, soundID, streamID, streamStopThreadPool);
}

void SoundPoolStreamUnitTest::TearDown(void)
{
    stream_ = nullptr;
}

// @tc.name     Test GetGlobalId API
// @tc.number   StreamGetGlobalIdUnittest_001
// @tc.desc     Test return ERROE_GLOBAL_ID
HWTEST_F(SoundPoolStreamUnitTest, StreamGetGlobalIdUnittest_001, TestSize.Level0)
{
    ASSERT_NE(stream_, nullptr);
    int32_t soundID = DEFAULT_NUM;
    int32_t ret = stream_->GetGlobalId(soundID);
    EXPECT_EQ(ret, MSERR_INVALID);
}

// @tc.name     Test IsAudioRendererCanMix API
// @tc.number   StreamIsAudioRendererCanMixUnittest_001
// @tc.desc     Test return true
//              Test return false
HWTEST_F(SoundPoolStreamUnitTest, StreamIsAudioRendererCanMixUnittest_001, TestSize.Level0)
{
    ASSERT_NE(stream_, nullptr);
    AudioStandard::AudioRendererInfo audioRendererInfo;
    audioRendererInfo.contentType = AudioStandard::ContentType::CONTENT_TYPE_PROMPT;
    bool ret = false;
    ret = stream_->IsAudioRendererCanMix(audioRendererInfo);
    EXPECT_EQ(ret, true);
    audioRendererInfo.streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_SYSTEM;
    ret = stream_->IsAudioRendererCanMix(audioRendererInfo);
    EXPECT_EQ(ret, false);
}

// @tc.name     Test OnInterrupt API
// @tc.number   StreamOnInterruptUnittest_001
// @tc.desc     Test all
HWTEST_F(SoundPoolStreamUnitTest, StreamOnInterruptUnittest_001, TestSize.Level0)
{
    ASSERT_NE(stream_, nullptr);
    AudioStandard::InterruptEvent interruptEvent;
    interruptEvent.hintType = AudioStandard::InterruptHint::INTERRUPT_HINT_PAUSE;
    stream_->OnInterrupt(interruptEvent);
    EXPECT_EQ(stream_->startStopFlag_.load(), true);
}

// @tc.name     Test CheckAndAlignRendererRate API
// @tc.number   StreamCheckAndAlignRendererRateUnittest_001
// @tc.desc     Test  default
HWTEST_F(SoundPoolStreamUnitTest, StreamCheckAndAlignRendererRateUnittest_001, TestSize.Level0)
{
    ASSERT_NE(stream_, nullptr);
    int32_t rate = DEFAULT_NUM;
    AudioStandard::AudioRendererRate ret = stream_->CheckAndAlignRendererRate(rate);
    EXPECT_EQ(ret, AudioStandard::AudioRendererRate::RENDER_RATE_NORMAL);
}

// @tc.name     Test CreateAudioRenderer API
// @tc.number   StreamCreateAudioRendererUnittest_001
// @tc.desc     Test playParams.cacheDir != ""
HWTEST_F(SoundPoolStreamUnitTest, StreamCreateAudioRendererUnittest_001, TestSize.Level0)
{
    ASSERT_NE(stream_, nullptr);
    AudioStandard::AudioRendererInfo audioRendererInfo;
    PlayParams playParams;
    playParams.cacheDir = "/data/test/cache/dir";
    auto ret = stream_->CreateAudioRenderer(audioRendererInfo, playParams);
    EXPECT_EQ(ret, nullptr);
}

// @tc.name     Test DoPlay API
// @tc.number   StreamDoPlayUnittest_001
// @tc.desc     Test fullCacheData_ == nullptr
//              Test callback_ != nullptr, streamCallback_ != nullptr
HWTEST_F(SoundPoolStreamUnitTest, StreamDoPlayUnittest_001, TestSize.Level0)
{
    ASSERT_NE(stream_, nullptr);
    auto audioRenderer = std::make_unique<MockAudioRender>();
    EXPECT_CALL(*(audioRenderer), GetBufferSize(_)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*(audioRenderer), SetRenderMode(_)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*(audioRenderer), SetRenderRate(_)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*(audioRenderer), SetVolume(_)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*(audioRenderer), SetOffloadAllowed(_)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*(audioRenderer), SetRendererCallback(_)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*(audioRenderer), SetRendererWriteCallback(_)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*(audioRenderer), SetRendererFirstFrameWritingCallback(_)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*(audioRenderer), SetParallelPlayFlag(_)).WillRepeatedly(testing::Return(0));
    stream_->audioRenderer_ = std::move(audioRenderer);
    auto callback = std::make_shared<MockISoundPoolCallback>();
    EXPECT_CALL(*callback, OnError(_)).WillRepeatedly(testing::Return());
    stream_->callback_ = callback;
    auto streamCallback = std::make_shared<MockISoundPoolCallback>();
    EXPECT_CALL(*streamCallback, OnError(_)).WillRepeatedly(testing::Return());
    stream_->streamCallback_ = streamCallback;
    auto ret = stream_->DoPlay();
    stream_->audioRenderer_ = nullptr;
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

// @tc.name     Test DoPlay API
// @tc.number   StreamDoPlayUnittest_002
// @tc.desc     Test audioRenderer_->Start() == false
//              Test callback_ != nullptr, streamCallback_ != nullptr
HWTEST_F(SoundPoolStreamUnitTest, StreamDoPlayUnittest_002, TestSize.Level0)
{
    ASSERT_NE(stream_, nullptr);
    auto audioRenderer = std::make_unique<MockAudioRender>();
    EXPECT_CALL(*(audioRenderer), GetBufferSize(_)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*(audioRenderer), SetRenderMode(_)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*(audioRenderer), SetRenderRate(_)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*(audioRenderer), SetVolume(_)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*(audioRenderer), SetOffloadAllowed(_)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*(audioRenderer), SetRendererCallback(_)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*(audioRenderer), SetRendererWriteCallback(_)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*(audioRenderer), SetRendererFirstFrameWritingCallback(_)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*(audioRenderer), SetParallelPlayFlag(_)).WillRepeatedly(testing::Return(0));
    stream_->audioRenderer_ = std::move(audioRenderer);
    auto callback = std::make_shared<MockISoundPoolCallback>();
    EXPECT_CALL(*callback, OnError(_)).WillRepeatedly(testing::Return());
    stream_->callback_ = callback;
    auto streamCallback = std::make_shared<MockISoundPoolCallback>();
    EXPECT_CALL(*streamCallback, OnError(_)).WillRepeatedly(testing::Return());
    EXPECT_CALL(*streamCallback, OnPlayFinished(_)).WillRepeatedly(testing::Return());
    stream_->streamCallback_ = streamCallback;
    auto ret = stream_->DoPlay();
    stream_->audioRenderer_ = nullptr;
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

// @tc.name     Test Stop API
// @tc.number   StreamStopUnittest_001
// @tc.desc     Test (audioRenderer_->IsFastRenderer()) == true
HWTEST_F(SoundPoolStreamUnitTest, StreamStopUnittest_001, TestSize.Level0)
{
    ASSERT_NE(stream_, nullptr);
    stream_->isRunning_.store(true);
    stream_->audioRenderer_ = std::make_unique<MockAudioRender>();
    auto callBack = std::make_shared<MockISoundPoolCallback>();
    EXPECT_CALL(*callBack, OnPlayFinished(_)).WillRepeatedly(testing::Return());
    stream_->callback_ = callBack;
    auto audioRenderer = std::make_unique<MockAudioRender>();
    EXPECT_CALL(*audioRenderer, IsFastRenderer()).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(*audioRenderer, Pause(_)).WillRepeatedly(testing::Return(false));
    EXPECT_CALL(*audioRenderer, Flush()).WillRepeatedly(testing::Return(false));
    stream_->audioRenderer_ = std::move(audioRenderer);
    auto ret = stream_->Stop();
    EXPECT_EQ(ret, MSERR_OK);
}

// @tc.name     Test AddStopTask API
// @tc.number   StreamAddStopTaskUnittest_001
// @tc.desc     Test streamStopThreadPool_ = nullptr
HWTEST_F(SoundPoolStreamUnitTest, StreamAddStopTaskUnittest_001, TestSize.Level0)
{
    ASSERT_NE(stream_, nullptr);
    stream_->streamCallback_ = nullptr;
    auto audioRenderer = std::make_unique<MockAudioRender>();
    EXPECT_CALL(*audioRenderer, IsFastRenderer()).WillRepeatedly(testing::Return(true));
    stream_->audioRenderer_ = std::move(audioRenderer);
    stream_->AddStopTask();
    EXPECT_EQ(stream_->startStopFlag_.load(), true);
}

// @tc.name     Test DealPlayParamsBeforePlay API
// @tc.number   StreamDealPlayParamsBeforePlayUnittest_001
HWTEST_F(SoundPoolStreamUnitTest, StreamDealPlayParamsBeforePlayUnittest_001, TestSize.Level2)
{
    ASSERT_NE(stream_, nullptr);
    auto audioRenderer = std::make_unique<MockAudioRender>();
    EXPECT_CALL(*(audioRenderer), SetRenderRate(_)).Times(1).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*(audioRenderer), SetVolume(_)).Times(1).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*(audioRenderer), SetOffloadAllowed(_)).Times(1).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*(audioRenderer), SetParallelPlayFlag(_)).Times(1).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*(audioRenderer), SetAudioHapticsSyncId(_)).Times(1).WillRepeatedly(testing::Return());
    stream_->audioRenderer_ = std::move(audioRenderer);
    int32_t audioHapticsSyncId = 1;
    struct PlayParams playParameters;
    playParameters.loop = -1;
    playParameters.rate = 0;
    playParameters.leftVolume = 0.5;
    playParameters.rightVolume = 0.3;
    playParameters.priority = 1;
    playParameters.parallelPlayFlag = true;
    playParameters.audioHapticsSyncId = audioHapticsSyncId;
    stream_->DealPlayParamsBeforePlay(playParameters);
    ASSERT_EQ(stream_->loop_, playParameters.loop);
    ASSERT_EQ(stream_->priority_, playParameters.priority);
}
} // namespace Media
} // namespace OHOS
