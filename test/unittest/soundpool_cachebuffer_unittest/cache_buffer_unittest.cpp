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
    cacheBuffer_ = std::make_shared<CacheBuffer>(trackFormat, soundID, streamID, cacheBufferStopThreadPool);
    streamIDManager_ = std::make_shared<StreamIDManager>(TEST_FULL_CACHE_DATA, AudioStandard::AudioRendererInfo());
    mockAudioRenderer_ = std::make_unique<MockAudioRenderer>();
}

void CacheBufferUnitTest::TearDown(void)
{
    cacheBuffer_ = nullptr;
    streamIDManager_ = nullptr;
    mockAudioRenderer_ = nullptr;
}

/**
 * @tc.name  : Test GetGlobalId
 * @tc.number: GetGlobalId_001
 * @tc.desc  : Test GetGlobalId (auto sharedManager = manager_.lock()) == false
 */
HWTEST_F(CacheBufferUnitTest, GetGlobalId_001, TestSize.Level1)
{
    int32_t soundId = TEST_SOUND_ID;
    int32_t ret = cacheBuffer_->GetGlobalId(soundId);
    EXPECT_EQ(ret, ERROR_GLOBAL_ID);
}

/**
 * @tc.name  : Test DelGlobalId
 * @tc.number: DelGlobalId_001
 * @tc.desc  : Test DelGlobalId (auto sharedManager = manager_.lock()) == true
 *             Test DelGlobalId (auto sharedManager = manager_.lock()) == false
 */
HWTEST_F(CacheBufferUnitTest, DelGlobalId_001, TestSize.Level1)
{
    // Test DelGlobalId (auto sharedManager = manager_.lock()) == false
    int32_t soundId = TEST_SOUND_ID;
    cacheBuffer_->DelGlobalId(soundId);
    EXPECT_TRUE(!cacheBuffer_->manager_.lock());

    // Test DelGlobalId (auto sharedManager = manager_.lock()) == true
    cacheBuffer_->manager_ = streamIDManager_;
    cacheBuffer_->DelGlobalId(soundId);
    EXPECT_TRUE(cacheBuffer_->manager_.lock());
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
 * @tc.desc  : Test GetAvailableAudioRenderer AudioRendererManager::GetInstance()
 *             .GetAudioRendererInstance(globalId) == nullptr
 */
HWTEST_F(CacheBufferUnitTest, GetAvailableAudioRenderer_001, TestSize.Level1)
{
    streamIDManager_->globalIdVector_.push_back(std::make_pair(TEST_SOUND_ID, DEFAULT_GLOBAL_ID));
    cacheBuffer_->soundID_ = TEST_SOUND_ID;
    cacheBuffer_->manager_ = streamIDManager_;
    cacheBuffer_->audioRenderer_ = std::move(mockAudioRenderer_);
    AudioStandard::AudioRendererInfo audioRendererInfo;
    PlayParams playParams;
    cacheBuffer_->GetAvailableAudioRenderer(audioRendererInfo, playParams);
    EXPECT_EQ(cacheBuffer_->GetGlobalId(TEST_SOUND_ID), ERROR_GLOBAL_ID);
}

/**
 * @tc.name  : Test GetAvailableAudioRenderer
 * @tc.number: GetAvailableAudioRenderer_002
 * @tc.desc  : Test GetAvailableAudioRenderer CreateAudioRenderer(audioRendererInfo, playParams) == nullptr
 */
HWTEST_F(CacheBufferUnitTest, GetAvailableAudioRenderer_002, TestSize.Level1)
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
    int32_t streamId = TEST_STREAM_ID;
    int32_t ret = cacheBuffer_->HandleRendererNotStart(streamId);
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
    cacheBuffer_->cacheBufferCallback_ = cacheBufferCallback;

    int32_t streamId = TEST_STREAM_ID;
    cacheBuffer_->HandleRendererNotStart(streamId);
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
    int32_t streamId = TEST_STREAM_ID;
    int32_t ret = cacheBuffer_->HandleRendererNotStart(streamId);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test OnWriteData
 * @tc.number: OnWriteData_001
 * @tc.desc  : Test OnWriteData (auto ptr = cacheBufferStopThreadPool_.lock()) == nullptr
 */
HWTEST_F(CacheBufferUnitTest, OnWriteData_001, TestSize.Level1)
{
    EXPECT_CALL(*mockAudioRenderer_, Stop()).WillOnce(Return(true));
    EXPECT_CALL(*mockAudioRenderer_, Release()).WillOnce(Return(true));
    EXPECT_CALL(*mockAudioRenderer_, GetBufferDesc(_)).WillOnce(Return(AudioStandard::SUCCESS));
    cacheBuffer_->audioRenderer_ = std::move(mockAudioRenderer_);
    cacheBuffer_->isRunning_.store(true);
    cacheBuffer_->isReadyToStopAudioRenderer_.store(false);
    uint8_t* data = new uint8_t[1024];
    cacheBuffer_->fullCacheData_ = std::make_shared<AudioBufferEntry>(data, TEST_FULL_CACHE_DATA);
    cacheBuffer_->cacheDataFrameIndex_ = TEST_FULL_CACHE_DATA;
    size_t length = TEST_CURRENT_LENGTH;
    cacheBuffer_->OnWriteData(length);
    EXPECT_TRUE(!cacheBuffer_->cacheBufferStopThreadPool_.lock());
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
    EXPECT_EQ(cacheBuffer_->cacheBufferStopThreadPool_.lock(), nullptr);
}

/**
 * @tc.name  : Test Stop
 * @tc.number: Stop_001
 * @tc.desc  : Test Stop audioRenderer_->IsFastRenderer() == true
 *             Test Stop callback_ == nullptr
 *             Test Stop cacheBufferCallback_ == nullptr
 */
HWTEST_F(CacheBufferUnitTest, Stop_001, TestSize.Level1)
{
    // Test Stop audioRenderer_->IsFastRenderer() == true
    EXPECT_CALL(*mockAudioRenderer_, IsFastRenderer()).WillOnce(Return(true));
    EXPECT_CALL(*mockAudioRenderer_, Pause(_)).Times(TIMES_ONE);
    EXPECT_CALL(*mockAudioRenderer_, Flush()).Times(TIMES_ONE);
    cacheBuffer_->audioRenderer_ = std::move(mockAudioRenderer_);
    cacheBuffer_->isRunning_.store(true);

    // Test Stop callback_ == nullptr
    cacheBuffer_->callback_ = nullptr;

    // Test Stop cacheBufferCallback_ == nullptr
    cacheBuffer_->cacheBufferCallback_ = nullptr;

    int32_t streamId = TEST_STREAM_ID;
    cacheBuffer_->streamID_ = TEST_STREAM_ID;
    cacheBuffer_->Stop(streamId);
}

/**
 * @tc.name  : Test SetVolume
 * @tc.number: SetVolume_001
 * @tc.desc  : Test SetVolume streamID != streamID_
 */
HWTEST_F(CacheBufferUnitTest, SetVolume_001, TestSize.Level1)
{
    int32_t streamId = TEST_STREAM_ID;
    float leftVolume = TEST_LEFT_VOLUMN;
    float rightVolume = TEST_RIGHT_VOLUMN;
    int32_t ret = cacheBuffer_->SetVolume(streamId, leftVolume, rightVolume);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test SetVolume
 * @tc.number: SetVolume_002
 * @tc.desc  : Test SetVolume audioRenderer_ == nullptr
 */
HWTEST_F(CacheBufferUnitTest, SetVolume_002, TestSize.Level1)
{
    int32_t streamId = TEST_STREAM_ID;
    float leftVolume = TEST_LEFT_VOLUMN;
    float rightVolume = TEST_RIGHT_VOLUMN;
    cacheBuffer_->streamID_ = TEST_STREAM_ID;
    cacheBuffer_->audioRenderer_ = nullptr;
    int32_t ret = cacheBuffer_->SetVolume(streamId, leftVolume, rightVolume);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test SetRate
 * @tc.number: SetRate_001
 * @tc.desc  : Test SetRate streamID != streamID_
 */
HWTEST_F(CacheBufferUnitTest, SetRate_001, TestSize.Level1)
{
    int32_t streamId = TEST_STREAM_ID;
    AudioStandard::AudioRendererRate renderRate = AudioStandard::AudioRendererRate::RENDER_RATE_NORMAL;
    int32_t ret = cacheBuffer_->SetRate(streamId, renderRate);
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
    int32_t ret = cacheBuffer_->SetRate(streamId, renderRate);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test SetPriority
 * @tc.number: SetPriority_001
 * @tc.desc  : Test SetPriority streamID != streamID_
 */
HWTEST_F(CacheBufferUnitTest, SetPriority_001, TestSize.Level1)
{
    int32_t streamId = TEST_STREAM_ID;
    int32_t priority = TEST_PRIORITY;
    cacheBuffer_->SetPriority(streamId, priority);
    EXPECT_EQ(cacheBuffer_->priority_, 0);
}

/**
 * @tc.name  : Test SetLoop
 * @tc.number: SetLoop_001
 * @tc.desc  : Test SetLoop streamID != streamID_
 */
HWTEST_F(CacheBufferUnitTest, SetLoop_001, TestSize.Level1)
{
    int32_t streamId = TEST_STREAM_ID;
    int32_t loop = TEST_LOOP;
    cacheBuffer_->SetLoop(streamId, loop);
    EXPECT_EQ(cacheBuffer_->loop_, 0);
}

/**
 * @tc.name  : Test SetParallelPlayFlag
 * @tc.number: SetParallelPlayFlag_001
 * @tc.desc  : Test SetParallelPlayFlag streamID != streamID_
 */
HWTEST_F(CacheBufferUnitTest, SetParallelPlayFlag_001, TestSize.Level1)
{
    int32_t streamId = TEST_STREAM_ID;
    bool parallelPlayFlag = false;
    int32_t ret = cacheBuffer_->SetParallelPlayFlag(streamId, parallelPlayFlag);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test SetParallelPlayFlag
 * @tc.number: SetParallelPlayFlag_002
 * @tc.desc  : Test SetParallelPlayFlag audioRenderer_ != nullptr
 */
HWTEST_F(CacheBufferUnitTest, SetParallelPlayFlag_002, TestSize.Level1)
{
    EXPECT_CALL(*mockAudioRenderer_, SetParallelPlayFlag(_))
        .WillOnce(Return(MSERR_OK));
    EXPECT_CALL(*mockAudioRenderer_, Stop()).WillOnce(Return(true));
    EXPECT_CALL(*mockAudioRenderer_, Release()).WillOnce(Return(true));
    cacheBuffer_->audioRenderer_ = std::move(mockAudioRenderer_);

    int32_t streamId = TEST_STREAM_ID;
    bool parallelPlayFlag = false;
    cacheBuffer_->streamID_ = TEST_STREAM_ID;
    cacheBuffer_->SetParallelPlayFlag(streamId, parallelPlayFlag);
}

/**
 * @tc.name  : Test Release
 * @tc.number: Release_001
 * @tc.desc  : Test FadeInAudioBuffer ret != AudioStandard::SUCCESS
 *             Test Release cacheData_.empty() == true
 *             Test Release frameWriteCallback_ == nullptr
 */
HWTEST_F(CacheBufferUnitTest, Release_001, TestSize.Level1)
{
    // Test FadeInAudioBuffer ret != AudioStandard::SUCCESS
    cacheBuffer_->isNeedFadeIn_ = true;
    AudioStandard::BufferDesc bufDesc;
    bufDesc.bufLength = 0;
    cacheBuffer_->FadeInAudioBuffer(bufDesc);

    // Test Release cacheData_.empty() == true
    cacheBuffer_->cacheData_.clear();

    // Test Release frameWriteCallback_ == nullptr
    cacheBuffer_->frameWriteCallback_ == nullptr;

    int32_t ret = cacheBuffer_->Release();
    EXPECT_EQ(ret, MSERR_OK);
}
} // namespace Media
} // namespace OHOS