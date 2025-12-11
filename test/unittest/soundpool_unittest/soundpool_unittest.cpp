/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "soundpool_unittest.h"
#include "media_errors.h"
#include "soundpool_manager_multi.h"

using namespace OHOS;
using namespace OHOS::Media;
using namespace testing;
using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace Media {
static const int32_t ID_TEST = 0;
static const int32_t NUM_TEST = 1;
static const int32_t MSERR_INVALID = -1;
static const int32_t SOUNDPOOL_INSTANCE_MAX_NUM = 128;
void SoundPoolUnittest::SetUpTestCase(void)
{}

void SoundPoolUnittest::TearDownTestCase(void)
{}

void SoundPoolUnittest::SetUp(void)
{
    soundPool_ = std::make_shared<SoundPool>();
}

void SoundPoolUnittest::TearDown(void)
{
    soundPool_ = nullptr;
}

/**
 * @tc.name  : Test CheckInitParam
 * @tc.number: CheckInitParam_001
 * @tc.desc  : Test Return false
 */
HWTEST_F(SoundPoolUnittest, CheckInitParam_001, TestSize.Level0)
{
    ASSERT_NE(soundPool_, nullptr);
    int maxStreams = NUM_TEST;
    AudioStandard::AudioRendererInfo audioRenderInfo;
    audioRenderInfo.rendererFlags = -1;
    auto ret = SoundPool::CheckInitParam(maxStreams, audioRenderInfo);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name  : Test CheckInitParam
 * @tc.number: CheckInitParam_002
 * @tc.desc  : Test Return false
 */
HWTEST_F(SoundPoolUnittest, CheckInitParam_002, TestSize.Level1)
{
    ASSERT_NE(soundPool_, nullptr);
    int maxStreams = NUM_TEST;
    AudioStandard::AudioRendererInfo audioRenderInfo;
    audioRenderInfo.rendererFlags = 1024;
    auto ret = SoundPool::CheckInitParam(maxStreams, audioRenderInfo);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name  : Test CheckInitParam
 * @tc.number: CheckInitParam_003
 * @tc.desc  : Test Return false
 */
HWTEST_F(SoundPoolUnittest, CheckInitParam_003, TestSize.Level1)
{
    ASSERT_NE(soundPool_, nullptr);
    int maxStreams = NUM_TEST;
    AudioStandard::AudioRendererInfo audioRenderInfo;
    audioRenderInfo.rendererFlags = 1025;
    auto ret = SoundPool::CheckInitParam(maxStreams, audioRenderInfo);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name  : Test Play
 * @tc.number: Play_001
 * @tc.desc  : Test return -1
 */
HWTEST_F(SoundPoolUnittest, Play_001, TestSize.Level0)
{
    ASSERT_NE(soundPool_, nullptr);
    std::shared_ptr<SoundParser> testPtr = std::make_shared<SoundParser>(1, "testurl");
    soundPool_->soundIDManager_ = std::make_shared<SoundIDManager>();
    int32_t soundID = ID_TEST;
    PlayParams playParameters;
    auto ret = soundPool_->Play(soundID, playParameters);
    EXPECT_EQ(ret, MSERR_INVALID);
}

/**
 * @tc.name  : Test Play
 * @tc.number: Play_002
 * @tc.desc  : Test return -1
 */
HWTEST_F(SoundPoolUnittest, Play_002, TestSize.Level0)
{
    ASSERT_NE(soundPool_, nullptr);
    std::shared_ptr<SoundParser> testPtr = std::make_shared<SoundParser>(1, "testurl");
    soundPool_->soundIDManager_ = std::make_shared<SoundIDManager>();
    int32_t soundID = ID_TEST;
    PlayParams playParameters;
    soundPool_->SetInterruptMode(InterruptMode::NO_INTERRUPT);
    auto ret = soundPool_->Play(soundID, playParameters);
    EXPECT_EQ(ret, MSERR_INVALID);
}

/**
 * @tc.name  : Test SetPriority
 * @tc.number: SetPriority_001
 * @tc.desc  : Test return MSERR_INVALID_OPERATION
 */
HWTEST_F(SoundPoolUnittest, SetPriority_001, TestSize.Level0)
{
    ASSERT_NE(soundPool_, nullptr);
    int32_t streamID = ID_TEST;
    int32_t priority = NUM_TEST;
    soundPool_->parallelStreamFlag_ = true;
    int32_t maxStreams = NUM_TEST;
    AudioStandard::AudioRendererInfo audioRenderInfo;
    soundPool_->parallelStreamManager_ = std::make_shared<ParallelStreamManager>(maxStreams, audioRenderInfo);
    auto ret = soundPool_->SetPriority(streamID, priority);
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/**
 * @tc.name  : Test SetRate
 * @tc.number: SetRate_001
 * @tc.desc  : Test return MSERR_INVALID_OPERATION
 */
HWTEST_F(SoundPoolUnittest, SetRate_001, TestSize.Level0)
{
    ASSERT_NE(soundPool_, nullptr);
    int32_t streamID = ID_TEST;
    soundPool_->parallelStreamFlag_ = true;
    int32_t maxStreams = NUM_TEST;
    AudioStandard::AudioRendererInfo audioRenderInfo;
    AudioStandard::AudioRendererRate renderRate = AudioStandard::AudioRendererRate::RENDER_RATE_NORMAL;
    soundPool_->parallelStreamManager_ = std::make_shared<ParallelStreamManager>(maxStreams, audioRenderInfo);
    auto ret = soundPool_->SetRate(streamID, renderRate);
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/**
 * @tc.name  : Test ReleaseInner
 * @tc.number: ReleaseInner_001
 * @tc.desc  : Test return MSERR_OK
 */
HWTEST_F(SoundPoolUnittest, ReleaseInner_001, TestSize.Level0)
{
    ASSERT_NE(soundPool_, nullptr);
    soundPool_->apiVersion_ = NUM_TEST;
    soundPool_->parallelStreamFlag_ = false;
    auto ret = soundPool_->ReleaseInner();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test SetSoundPoolFrameWriteCallback
 * @tc.number: SetSoundPoolFrameWriteCallback_001
 * @tc.desc  : Test return MSERR_OK
 */
HWTEST_F(SoundPoolUnittest, SetSoundPoolFrameWriteCallback_001, TestSize.Level0)
{
    ASSERT_NE(soundPool_, nullptr);
    AudioStandard::AudioRendererInfo audioRenderInfo;
    std::shared_ptr<ISoundPoolFrameWriteCallback> frameWriteCallback;
    soundPool_->parallelStreamManager_ = std::make_shared<ParallelStreamManager>(1, audioRenderInfo);
    auto ret = soundPool_->SetSoundPoolFrameWriteCallback(frameWriteCallback);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test GetSoundPoolInstance
 * @tc.number: GetSoundPoolInstance_001
 * @tc.desc  : Test return MSERR_INVALID_OPERATION
 */
HWTEST_F(SoundPoolUnittest, GetSoundPoolInstance_001, TestSize.Level0)
{
    auto soundPoolManagerMulti = std::make_shared<SoundPoolManagerMulti>();
    ASSERT_NE(soundPoolManagerMulti, nullptr);
    std::shared_ptr<SoundPool> soundPool;
    for (int i = 0; i < (SOUNDPOOL_INSTANCE_MAX_NUM + 1); ++i)
    {
        soundPoolManagerMulti->soundPools_.push_back(soundPool);
    }
    auto ret = soundPoolManagerMulti->GetSoundPoolInstance(soundPool);
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/**
 * @tc.name  : Test CheckRendererFlagsValid
 * @tc.number: CheckRendererFlagsValid_001
 * @tc.desc  : Test CheckRendererFlagsValid returns true when rendererFlags is 0
 */
HWTEST_F(SoundPoolUnittest, CheckRendererFlagsValid_001, TestSize.Level0)
{
    ASSERT_NE(soundPool_, nullptr);
    AudioStandard::AudioRendererInfo audioRenderInfo;
    audioRenderInfo.rendererFlags = 0;
    auto ret = soundPool_->CheckRendererFlagsValid(audioRenderInfo);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name  : Test CheckRendererFlagsValid
 * @tc.number: CheckRendererFlagsValid_002
 * @tc.desc  : Test CheckRendererFlagsValid returns true when rendererFlags is 1
 */
HWTEST_F(SoundPoolUnittest, CheckRendererFlagsValid_002, TestSize.Level0)
{
    ASSERT_NE(soundPool_, nullptr);
    AudioStandard::AudioRendererInfo audioRenderInfo;
    audioRenderInfo.rendererFlags = 1;
    auto ret = soundPool_->CheckRendererFlagsValid(audioRenderInfo);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name  : Test CheckRendererFlagsValid
 * @tc.number: CheckRendererFlagsValid_003
 * @tc.desc  : Test CheckRendererFlagsValid returns false when rendererFlags is AUDIO_FLAG_VKB_NORMAL
               but the isBundleNameValid flag is false
 */
HWTEST_F(SoundPoolUnittest, CheckRendererFlagsValid_003, TestSize.Level0)
{
    ASSERT_NE(soundPool_, nullptr);
    AudioStandard::AudioRendererInfo audioRenderInfo;
    audioRenderInfo.rendererFlags = AudioStandard::AUDIO_FLAG_VKB_NORMAL;
    auto ret = soundPool_->CheckRendererFlagsValid(audioRenderInfo);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name  : Test CheckRendererFlagsValid
 * @tc.number: CheckRendererFlagsValid_004
 * @tc.desc  : Test CheckRendererFlagsValid returns false when rendererFlags is AUDIO_FLAG_VKB_FAST
               but the isBundleNameValid flag is false
 */
HWTEST_F(SoundPoolUnittest, CheckRendererFlagsValid_004, TestSize.Level0)
{
    ASSERT_NE(soundPool_, nullptr);
    AudioStandard::AudioRendererInfo audioRenderInfo;
    audioRenderInfo.rendererFlags = AudioStandard::AUDIO_FLAG_VKB_FAST;
    auto ret = soundPool_->CheckRendererFlagsValid(audioRenderInfo);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name  : Test CheckRendererFlagsValid
 * @tc.number: CheckRendererFlagsValid_005
 * @tc.desc  : Test CheckRendererFlagsValid returns true when rendererFlags is AUDIO_FLAG_VKB_FAST
 */
HWTEST_F(SoundPoolUnittest, CheckRendererFlagsValid_005, TestSize.Level0)
{
    ASSERT_NE(soundPool_, nullptr);
    AudioStandard::AudioRendererInfo audioRenderInfo;
    audioRenderInfo.rendererFlags = -100;
    auto ret = soundPool_->CheckRendererFlagsValid(audioRenderInfo);
    EXPECT_EQ(ret, false);
}
}  // namespace Media
}  // namespace OHOS
