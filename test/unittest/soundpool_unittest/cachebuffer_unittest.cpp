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

#include "cachebuffer_unittest.h"
#include "media_errors.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing;
using namespace testing::ext;

void SoundPoolCacheBufferUnitTest::SetUpTestCase(void)
{
}

void SoundPoolCacheBufferUnitTest::TearDownTestCase(void)
{
}

void SoundPoolCacheBufferUnitTest::SetUp(void)
{
    Format trackFormat;
    int32_t soundID = 1;
    int32_t streamID = 10;
    std::shared_ptr<ThreadPool> cacheBufferStopThreadPool;
    cacheBuffer_ = std::make_shared<AudioStream>(trackFormat, soundID, streamID, cacheBufferStopThreadPool);
}

void SoundPoolCacheBufferUnitTest::TearDown(void)
{
    cacheBuffer_ = nullptr;
}


// @tc.name     Test DealPlayParamsBeforePlay API
// @tc.number   CacheBuferDealPlayParamsBeforePlayUnittest_001
HWTEST_F(SoundPoolCacheBufferUnitTest, CacheBuferDealPlayParamsBeforePlayUnittest_001, TestSize.Level0)
{
    ASSERT_NE(cacheBuffer_, nullptr);
    auto audioRenderer = std::make_unique<MockAudioRender>();
    EXPECT_CALL(*(audioRenderer), SetRenderRate(_)).Times(1).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*(audioRenderer), SetVolume(_)).Times(1).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*(audioRenderer), SetOffloadAllowed(_)).Times(1).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*(audioRenderer), SetParallelPlayFlag(_)).Times(1).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*(audioRenderer), SetAudioHapticsSyncId(_)).Times(1).WillRepeatedly(testing::Return());
    cacheBuffer_->audioRenderer_ = std::move(audioRenderer);
    int32_t audioHapticsSyncId = 1;
    struct PlayParams playParameters;
    playParameters.loop = -1;
    playParameters.rate = 0;
    playParameters.leftVolume = 0.5;
    playParameters.rightVolume = 0.3;
    playParameters.priority = 1;
    playParameters.parallelPlayFlag = true;
    playParameters.audioHapticsSyncId = audioHapticsSyncId;
    cacheBuffer_->DealPlayParamsBeforePlay(playParameters);
    ASSERT_EQ(cacheBuffer_->loop_, playParameters.loop);
    ASSERT_EQ(cacheBuffer_->priority_, playParameters.priority);
}

/**
 * @tc.name  : Test CreateAudioRenderer
 * @tc.number: CreateAudioRenderer_001
 * @tc.desc  : Test returns NORMAL_PLAY_RENDERER_FLAGS
 */
HWTEST_F(SoundPoolCacheBufferUnitTest, CreateAudioRenderer_001, TestSize.Level0)
{
    ASSERT_NE(cacheBuffer_, nullptr);
    AudioStandard::AudioRendererInfo info;
    PlayParams playParams;

    cacheBuffer_->CreateAudioRenderer(info, playParams);

    EXPECT_EQ(cacheBuffer_->rendererFlags_, 0);
}
} // namespace Media
} // namespace OHOS
