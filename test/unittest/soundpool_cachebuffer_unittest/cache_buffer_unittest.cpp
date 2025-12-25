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

#include "cache_buffer_unittest.h"
#include "media_errors.h"
#include "media_log.h"

using namespace OHOS;
using namespace OHOS::Media;
using namespace testing;
using namespace testing::ext;

const static int32_t DEFAULT_GLOBAL_ID = 1;
const static int32_t ERROR_GLOBAL_ID = -1;
const static int32_t TEST_SOUND_ID = 1;
const static int32_t TEST_STREAM_ID = 1;
const static int32_t TEST_FULL_CACHE_DATA = 1000;
const static size_t TEST_CURRENT_LENGTH = 10;
const static float TEST_LEFT_VOLUMN = 1.0f;
const static float TEST_RIGHT_VOLUMN = 1.0f;
const static int32_t TEST_LOOP = 1;
const static int32_t TEST_PRIORITY = 1;

const static int32_t TIMES_ONE = 1;
const static int32_t TIMES_THREE = 3;

namespace OHOS {
namespace Media {

void CacheBufferUnitTest::SetUpTestCase(void) {}

void CacheBufferUnitTest::TearDownTestCase(void) {}

void CacheBufferUnitTest::SetUp(void)
{
    cacheBuffer_ = std::make_shared<AudioStream>(trackFormat, soundID, streamID, cacheBufferStopThreadPool);
    streamIDManager_ = std::make_shared<StreamIDManagerWithSameSoundInterrupt>(TEST_FULL_CACHE_DATA,
        AudioStandard::AudioRendererInfo());
    mockAudioRenderer_ = std::make_unique<MockAudioRenderer>();
}

void CacheBufferUnitTest::TearDown(void)
{
    cacheBuffer_ = nullptr;
    streamIDManager_ = nullptr;
    mockAudioRenderer_ = nullptr;
}

/**
 * @tc.name  : Test DealAudioRendererParams
 * @tc.number: DealAudioRendererParams_001
 * @tc.desc  : Test DealAudioRendererParams IsAudioRendererCanMix(audioRendererInfo) == false
 */
HWTEST_F(CacheBufferUnitTest, DealAudioRendererParams_001, TestSize.Level1)
{
    AudioStandard::AudioRendererOptions rendererOptions;
    rendererOptions.strategy.concurrencyMode = AudioStandard::AudioConcurrencyMode::DEFAULT;
    AudioStandard::AudioRendererInfo audioRendererInfo;
    audioRendererInfo.contentType = AudioStandard::ContentType::CONTENT_TYPE_UNKNOWN;
    audioRendererInfo.streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_VOICE_RINGTONE;
    cacheBuffer_->DealAudioRendererParams(rendererOptions, audioRendererInfo);
    EXPECT_EQ(rendererOptions.strategy.concurrencyMode, AudioStandard::AudioConcurrencyMode::DEFAULT);
}

/**
 * @tc.name  : Test GetAvailableAudioRenderer
 * @tc.number: GetAvailableAudioRenderer_001
 * @tc.desc  : Test GetAvailableAudioRenderer CreateAudioRenderer(audioRendererInfo, playParams) == nullptr
 */
HWTEST_F(CacheBufferUnitTest, GetAvailableAudioRenderer_001, TestSize.Level1)
{
    cacheBuffer_->manager_ = streamIDManager_;
    AudioStandard::AudioRendererInfo audioRendererInfo;
    audioRendererInfo.contentType = AudioStandard::ContentType::CONTENT_TYPE_ULTRASONIC;
    audioRendererInfo.streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_SYSTEM;
    PlayParams playParams;
    cacheBuffer_->GetAvailableAudioRenderer(audioRendererInfo, playParams);
    EXPECT_EQ(cacheBuffer_->audioRenderer_, nullptr);
}

/**
 * @tc.name  : Test HandleRendererNotStart
 * @tc.number: HandleRendererNotStart_001
 * @tc.desc  : Test HandleRendererNotStart audioRenderer_->GetStatus() !=
 *             OHOS::AudioStandard::RendererState::RENDERER_RUNNING
 *             Test HandleRendererNotStart callback_ == nullptr
 *             Test HandleRendererNotStart cacheBufferCallback_ == nullptr
 */
HWTEST_F(CacheBufferUnitTest, HandleRendererNotStart_001, TestSize.Level1)
{
    EXPECT_CALL(*mockAudioRenderer_, GetStatus())
        .WillOnce(Return(OHOS::AudioStandard::RendererState::RENDERER_INVALID));
    EXPECT_CALL(*mockAudioRenderer_, Stop()).WillOnce(Return(true));
    EXPECT_CALL(*mockAudioRenderer_, Release()).WillOnce(Return(true));
    cacheBuffer_->audioRenderer_ = std::move(mockAudioRenderer_);
    int32_t ret = cacheBuffer_->HandleRendererNotStart();
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name  : Test HandleRendererNotStart
 * @tc.number: HandleRendererNotStart_002
 * @tc.desc  : Test HandleRendererNotStart callback_ != nullptr
 *             Test HandleRendererNotStart cacheBufferCallback_ != nullptr
 */
HWTEST_F(CacheBufferUnitTest, HandleRendererNotStart_002, TestSize.Level1)
{
    EXPECT_CALL(*mockAudioRenderer_, GetStatus())
        .WillOnce(Return(OHOS::AudioStandard::RendererState::RENDERER_INVALID));
    EXPECT_CALL(*mockAudioRenderer_, Stop()).WillOnce(Return(true));
    EXPECT_CALL(*mockAudioRenderer_, Release()).WillOnce(Return(true));
    cacheBuffer_->audioRenderer_ = std::move(mockAudioRenderer_);

    auto callback = std::make_shared<MockSoundPoolCallback>();
    EXPECT_CALL(*callback, OnError(_)).Times(TIMES_ONE);
    EXPECT_CALL(*callback, OnErrorOccurred(_)).Times(TIMES_ONE);
    cacheBuffer_->callback_ = callback;

    auto cacheBufferCallback = std::make_shared<MockSoundPoolCallback>();
    EXPECT_CALL(*cacheBufferCallback, OnError(_)).Times(TIMES_ONE);
    cacheBuffer_->streamCallback_ = cacheBufferCallback;
    cacheBuffer_->HandleRendererNotStart();
}

/**
 * @tc.name  : Test HandleRendererNotStart
 * @tc.number: HandleRendererNotStart_003
 * @tc.desc  : Test HandleRendererNotStart callback_ == nullptr
 */
HWTEST_F(CacheBufferUnitTest, HandleRendererNotStart_003, TestSize.Level1)
{
    EXPECT_CALL(*mockAudioRenderer_, GetStatus())
        .WillOnce(Return(OHOS::AudioStandard::RendererState::RENDERER_RUNNING));
    EXPECT_CALL(*mockAudioRenderer_, Stop()).WillOnce(Return(true));
    EXPECT_CALL(*mockAudioRenderer_, Release()).WillOnce(Return(true));
    cacheBuffer_->audioRenderer_ = std::move(mockAudioRenderer_);
    int32_t ret = cacheBuffer_->HandleRendererNotStart();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test OnInterrupt
 * @tc.number: OnInterrupt_001
 * @tc.desc  : Test OnInterrupt (auto ptr = cacheBufferStopThreadPool_.lock()) == nullptr
 */
HWTEST_F(CacheBufferUnitTest, OnInterrupt_001, TestSize.Level1)
{
    AudioStandard::InterruptEvent interruptEvent;
    interruptEvent.hintType = AudioStandard::InterruptHint::INTERRUPT_HINT_PAUSE;
    cacheBuffer_->OnInterrupt(interruptEvent);
    EXPECT_EQ(cacheBuffer_->streamStopThreadPool_.lock(), nullptr);
}

/**
 * @tc.name  : Test SetVolume
 * @tc.number: SetVolume_001
 * @tc.desc  : Test SetVolume streamID != streamID_
 */
HWTEST_F(CacheBufferUnitTest, SetVolume_001, TestSize.Level1)
{
    float leftVolume = TEST_LEFT_VOLUMN;
    float rightVolume = TEST_RIGHT_VOLUMN;
    int32_t ret = cacheBuffer_->SetVolume(leftVolume, rightVolume);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test SetVolume
 * @tc.number: SetVolume_002
 * @tc.desc  : Test SetVolume audioRenderer_ == nullptr
 */
HWTEST_F(CacheBufferUnitTest, SetVolume_002, TestSize.Level1)
{
    float leftVolume = TEST_LEFT_VOLUMN;
    float rightVolume = TEST_RIGHT_VOLUMN;
    cacheBuffer_->streamID_ = TEST_STREAM_ID;
    cacheBuffer_->audioRenderer_ = nullptr;
    int32_t ret = cacheBuffer_->SetVolume(leftVolume, rightVolume);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test SetRate
 * @tc.number: SetRate_001
 * @tc.desc  : Test SetRate streamID != streamID_
 */
HWTEST_F(CacheBufferUnitTest, SetRate_001, TestSize.Level1)
{
    AudioStandard::AudioRendererRate renderRate = AudioStandard::AudioRendererRate::RENDER_RATE_NORMAL;
    int32_t ret = cacheBuffer_->SetRate(renderRate);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test SetRate
 * @tc.number: SetRate_002
 * @tc.desc  : Test SetRate_002 audioRenderer_ == nullptr
 */
HWTEST_F(CacheBufferUnitTest, SetRate_002, TestSize.Level1)
{
    int32_t streamId = TEST_STREAM_ID;
    cacheBuffer_->streamID_ = TEST_STREAM_ID;
    AudioStandard::AudioRendererRate renderRate = AudioStandard::AudioRendererRate::RENDER_RATE_NORMAL;
    cacheBuffer_->audioRenderer_ = nullptr;
    int32_t ret = cacheBuffer_->SetRate(renderRate);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test SetPriority
 * @tc.number: SetPriority_001
 * @tc.desc  : Test SetPriority streamID != streamID_
 */
HWTEST_F(CacheBufferUnitTest, SetPriority_001, TestSize.Level1)
{
    int32_t priority = TEST_PRIORITY;
    cacheBuffer_->SetPriority(priority);
    EXPECT_EQ(cacheBuffer_->priority_, 0);
}

/**
 * @tc.name  : Test SetLoop
 * @tc.number: SetLoop_001
 * @tc.desc  : Test SetLoop streamID != streamID_
 */
HWTEST_F(CacheBufferUnitTest, SetLoop_001, TestSize.Level1)
{
    int32_t loop = TEST_LOOP;
    cacheBuffer_->SetLoop(loop);
    EXPECT_EQ(cacheBuffer_->loop_, 0);
}
} // namespace Media
} // namespace OHOS