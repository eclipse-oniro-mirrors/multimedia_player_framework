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

#include "soundpool_impl_unit_test.h"
#include "media_errors.h"

using namespace OHOS;
using namespace OHOS::Media;
using namespace testing::ext;
using namespace std;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SOUNDPOOL, "SoundPoolImplUnitTest"};
}

namespace OHOS {
namespace Media {
void SoundPoolImplUnitTest::SetUpTestCase(void)
{}

void SoundPoolImplUnitTest::TearDownTestCase(void)
{}

void SoundPoolImplUnitTest::SetUp(void)
{
    soundPool_ = std::make_shared<SoundPool>();
    ASSERT_NE(nullptr, soundPool_);
}

void SoundPoolImplUnitTest::TearDown(void)
{
    if (soundPool_ != nullptr) {
        soundPool_.reset();
    }
}

/**
 * @tc.name: soundpoolImpl_function_001
 * @tc.desc: function test CheckInitParam with valid params
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolImplUnitTest, soundpoolImpl_function_001, TestSize.Level2)
{
    MEDIA_LOGI("soundpoolImpl_function_001 before");
    AudioStandard::AudioRendererInfo audioRenderInfo;
    audioRenderInfo.contentType = AudioStandard::CONTENT_TYPE_MUSIC;
    audioRenderInfo.streamUsage = AudioStandard::STREAM_USAGE_MUSIC;
    audioRenderInfo.rendererFlags = 0;
    EXPECT_TRUE(SoundPool::CheckInitParam(3, audioRenderInfo));
    MEDIA_LOGI("soundpoolImpl_function_001 after");
}

/**
 * @tc.name: soundpoolImpl_function_002
 * @tc.desc: function test CheckInitParam with maxStreams <= 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolImplUnitTest, soundpoolImpl_function_002, TestSize.Level2)
{
    MEDIA_LOGI("soundpoolImpl_function_002 before");
    AudioStandard::AudioRendererInfo audioRenderInfo;
    audioRenderInfo.contentType = AudioStandard::CONTENT_TYPE_MUSIC;
    audioRenderInfo.streamUsage = AudioStandard::STREAM_USAGE_MUSIC;
    audioRenderInfo.rendererFlags = 0;
    EXPECT_FALSE(SoundPool::CheckInitParam(0, audioRenderInfo));
    EXPECT_FALSE(SoundPool::CheckInitParam(-1, audioRenderInfo));
    MEDIA_LOGI("soundpoolImpl_function_002 after");
}

/**
 * @tc.name: soundpoolImpl_function_003
 * @tc.desc: function test CheckInitParam with invalid contentType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolImplUnitTest, soundpoolImpl_function_003, TestSize.Level2)
{
    MEDIA_LOGI("soundpoolImpl_function_003 before");
    AudioStandard::AudioRendererInfo audioRenderInfo;
    audioRenderInfo.contentType = static_cast<AudioStandard::ContentType>(-1); // 闈炴硶contentType
    audioRenderInfo.streamUsage = AudioStandard::STREAM_USAGE_MUSIC;
    audioRenderInfo.rendererFlags = 0;
    EXPECT_FALSE(SoundPool::CheckInitParam(3, audioRenderInfo));

    audioRenderInfo.contentType = static_cast<AudioStandard::ContentType>(100); // 瓒呭嚭鑼冨洿contentType
    EXPECT_FALSE(SoundPool::CheckInitParam(3, audioRenderInfo));
    MEDIA_LOGI("soundpoolImpl_function_003 after");
}

/**
 * @tc.name: soundpoolImpl_function_004
 * @tc.desc: function test CheckInitParam with invalid streamUsage
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolImplUnitTest, soundpoolImpl_function_004, TestSize.Level2)
{
    MEDIA_LOGI("soundpoolImpl_function_004 before");
    AudioStandard::AudioRendererInfo audioRenderInfo;
    audioRenderInfo.contentType = AudioStandard::CONTENT_TYPE_MUSIC;
    audioRenderInfo.streamUsage = static_cast<AudioStandard::StreamUsage>(-1); // 闈炴硶streamUsage
    audioRenderInfo.rendererFlags = 0;
    EXPECT_FALSE(SoundPool::CheckInitParam(3, audioRenderInfo));

    audioRenderInfo.streamUsage = static_cast<AudioStandard::StreamUsage>(1000); // 瓒呭嚭鑼冨洿streamUsage
    EXPECT_FALSE(SoundPool::CheckInitParam(3, audioRenderInfo));
    MEDIA_LOGI("soundpoolImpl_function_004 after");
}

/**
 * @tc.name: soundpoolImpl_function_005
 * @tc.desc: function test CheckInitParam with invalid rendererFlags
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolImplUnitTest, soundpoolImpl_function_005, TestSize.Level2)
{
    MEDIA_LOGI("soundpoolImpl_function_005 before");
    AudioStandard::AudioRendererInfo audioRenderInfo;
    audioRenderInfo.contentType = AudioStandard::CONTENT_TYPE_MUSIC;
    audioRenderInfo.streamUsage = AudioStandard::STREAM_USAGE_MUSIC;
    audioRenderInfo.rendererFlags = 2; // 闈炴硶rendererFlags
    EXPECT_FALSE(SoundPool::CheckInitParam(3, audioRenderInfo));
    MEDIA_LOGI("soundpoolImpl_function_005 after");
}

/**
 * @tc.name: soundpoolImpl_function_006
 * @tc.desc: function test Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolImplUnitTest, soundpoolImpl_function_006, TestSize.Level2)
{
    MEDIA_LOGI("soundpoolImpl_function_006 before");
    AudioStandard::AudioRendererInfo audioRenderInfo;
    audioRenderInfo.contentType = AudioStandard::CONTENT_TYPE_MUSIC;
    audioRenderInfo.streamUsage = AudioStandard::STREAM_USAGE_MUSIC;
    audioRenderInfo.rendererFlags = 0;
    EXPECT_EQ(MSERR_OK, soundPool_->Init(3, audioRenderInfo));
    EXPECT_NE(nullptr, soundPool_->soundIDManager_);
    EXPECT_NE(nullptr, soundPool_->streamIDManagerWithSameSoundInterrupt_);
    EXPECT_NE(nullptr, soundPool_->streamIDManagerWithNoInterrupt_);
    MEDIA_LOGI("soundpoolImpl_function_006 after");
}

/**
 * @tc.name: soundpoolImpl_function_007
 * @tc.desc: function test InitParallel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolImplUnitTest, soundpoolImpl_function_007, TestSize.Level2)
{
    MEDIA_LOGI("soundpoolImpl_function_007 before");
    AudioStandard::AudioRendererInfo audioRenderInfo;
    audioRenderInfo.contentType = AudioStandard::CONTENT_TYPE_MUSIC;
    audioRenderInfo.streamUsage = AudioStandard::STREAM_USAGE_MUSIC;
    audioRenderInfo.rendererFlags = 0;
    EXPECT_EQ(MSERR_OK, soundPool_->InitParallel(3, audioRenderInfo));
    EXPECT_TRUE(soundPool_->parallelStreamFlag_);
    MEDIA_LOGI("soundpoolImpl_function_007 after");
}

/**
 * @tc.name: soundpoolImpl_function_008
 * @tc.desc: function test SetInterruptMode with valid mode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolImplUnitTest, soundpoolImpl_function_008, TestSize.Level2)
{
    MEDIA_LOGI("soundpoolImpl_function_008 before");
    soundPool_->SetInterruptMode(InterruptMode::NO_INTERRUPT);
    EXPECT_FALSE(soundPool_->isSetInterruptMode_);
    EXPECT_EQ(InterruptMode::NO_INTERRUPT, soundPool_->interruptMode_);
    MEDIA_LOGI("soundpoolImpl_function_008 after");
}

/**
 * @tc.name: soundpoolImpl_function_009
 * @tc.desc: function test SetInterruptMode with invalid mode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolImplUnitTest, soundpoolImpl_function_009, TestSize.Level2)
{
    MEDIA_LOGI("soundpoolImpl_function_009 before");
    soundPool_->SetInterruptMode(static_cast<InterruptMode>(100)); // 闈炴硶interruptMode
    EXPECT_EQ(InterruptMode::SAME_SOUND_INTERRUPT, soundPool_->interruptMode_);
    MEDIA_LOGI("soundpoolImpl_function_009 after");
}

/**
 * @tc.name: soundpoolImpl_function_010
 * @tc.desc: function test SetInterruptMode after it has been set
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolImplUnitTest, soundpoolImpl_function_010, TestSize.Level2)
{
    MEDIA_LOGI("soundpoolImpl_function_010 before");
    soundPool_->isSetInterruptMode_ = true;
    soundPool_->SetInterruptMode(InterruptMode::NO_INTERRUPT);
    // already set, should not be modified
    EXPECT_EQ(InterruptMode::SAME_SOUND_INTERRUPT, soundPool_->interruptMode_);
    MEDIA_LOGI("soundpoolImpl_function_010 after");
}

/**
 * @tc.name: soundpoolImpl_function_011
 * @tc.desc: function test CheckVolumeValid with in-range volumes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolImplUnitTest, soundpoolImpl_function_011, TestSize.Level2)
{
    MEDIA_LOGI("soundpoolImpl_function_011 before");
    float left = 0.5f;
    float right = 0.5f;
    EXPECT_TRUE(soundPool_->CheckVolumeValid(&left, &right));
    EXPECT_EQ(0.5f, left);
    EXPECT_EQ(0.5f, right);
    MEDIA_LOGI("soundpoolImpl_function_011 after");
}

/**
 * @tc.name: soundpoolImpl_function_012
 * @tc.desc: function test CheckVolumeValid with out-of-range volumes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolImplUnitTest, soundpoolImpl_function_012, TestSize.Level2)
{
    MEDIA_LOGI("soundpoolImpl_function_012 before");
    float left = 1.5f;
    float right = -1.0f;
    EXPECT_TRUE(soundPool_->CheckVolumeValid(&left, &right));
    // out of range volumes are set to 1.f
    EXPECT_EQ(1.0f, left);
    EXPECT_EQ(1.0f, right);
    MEDIA_LOGI("soundpoolImpl_function_012 after");
}

/**
 * @tc.name: soundpoolImpl_function_013
 * @tc.desc: function test CheckVolumeValid with unequal left/right volumes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolImplUnitTest, soundpoolImpl_function_013, TestSize.Level2)
{
    MEDIA_LOGI("soundpoolImpl_function_013 before");
    float left = 0.3f;
    float right = 0.8f;
    EXPECT_TRUE(soundPool_->CheckVolumeValid(&left, &right));
    // left and right are not equal, use left volume
    EXPECT_EQ(0.3f, left);
    EXPECT_EQ(0.3f, right);
    MEDIA_LOGI("soundpoolImpl_function_013 after");
}

/**
 * @tc.name: soundpoolImpl_function_014
 * @tc.desc: function test SetApiVersion
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolImplUnitTest, soundpoolImpl_function_014, TestSize.Level2)
{
    MEDIA_LOGI("soundpoolImpl_function_014 before");
    AudioStandard::AudioRendererInfo audioRenderInfo;
    audioRenderInfo.contentType = AudioStandard::CONTENT_TYPE_MUSIC;
    audioRenderInfo.streamUsage = AudioStandard::STREAM_USAGE_MUSIC;
    audioRenderInfo.rendererFlags = 0;
    soundPool_->Init(3, audioRenderInfo);
    soundPool_->SetApiVersion(18);
    EXPECT_EQ(18, soundPool_->apiVersion_);
    EXPECT_EQ(18, soundPool_->soundIDManager_->apiVersion_);
    MEDIA_LOGI("soundpoolImpl_function_014 after");
}

/**
 * @tc.name: soundpoolImpl_function_015
 * @tc.desc: function test SetSoundPoolCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolImplUnitTest, soundpoolImpl_function_015, TestSize.Level2)
{
    MEDIA_LOGI("soundpoolImpl_function_015 before");
    AudioStandard::AudioRendererInfo audioRenderInfo;
    audioRenderInfo.contentType = AudioStandard::CONTENT_TYPE_MUSIC;
    audioRenderInfo.streamUsage = AudioStandard::STREAM_USAGE_MUSIC;
    audioRenderInfo.rendererFlags = 0;
    soundPool_->Init(3, audioRenderInfo);
    std::shared_ptr<ISoundPoolCallback> callback;
    EXPECT_EQ(MSERR_OK, soundPool_->SetSoundPoolCallback(callback));
    EXPECT_EQ(MSERR_OK, soundPool_->SetSoundPoolFrameWriteCallback(nullptr));
    MEDIA_LOGI("soundpoolImpl_function_015 after");
}

/**
 * @tc.name: soundpoolImpl_function_016
 * @tc.desc: function test Release without Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolImplUnitTest, soundpoolImpl_function_016, TestSize.Level2)
{
    MEDIA_LOGI("soundpoolImpl_function_016 before");
    // apiVersion_ = 0, so no manager release branch is triggered
    EXPECT_EQ(MSERR_OK, soundPool_->Release());
    MEDIA_LOGI("soundpoolImpl_function_016 after");
}

/**
 * @tc.name: soundpoolImpl_function_017
 * @tc.desc: function test Release with Init and SetApiVersion 18
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolImplUnitTest, soundpoolImpl_function_017, TestSize.Level2)
{
    MEDIA_LOGI("soundpoolImpl_function_017 before");
    AudioStandard::AudioRendererInfo audioRenderInfo;
    audioRenderInfo.contentType = AudioStandard::CONTENT_TYPE_MUSIC;
    audioRenderInfo.streamUsage = AudioStandard::STREAM_USAGE_MUSIC;
    audioRenderInfo.rendererFlags = 0;
    EXPECT_EQ(MSERR_OK, soundPool_->Init(3, audioRenderInfo));
    soundPool_->SetApiVersion(18);
    EXPECT_EQ(MSERR_OK, soundPool_->Release());
    EXPECT_EQ(nullptr, soundPool_->soundIDManager_);
    MEDIA_LOGI("soundpoolImpl_function_017 after");
}

/**
 * @tc.name: soundpoolImpl_function_018
 * @tc.desc: function test Stop without Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolImplUnitTest, soundpoolImpl_function_018, TestSize.Level2)
{
    MEDIA_LOGI("soundpoolImpl_function_018 before");
    EXPECT_EQ(MSERR_INVALID_OPERATION, soundPool_->Stop(1));
    MEDIA_LOGI("soundpoolImpl_function_018 after");
}

/**
 * @tc.name: soundpoolImpl_function_019
 * @tc.desc: function test SetLoop without Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolImplUnitTest, soundpoolImpl_function_019, TestSize.Level2)
{
    MEDIA_LOGI("soundpoolImpl_function_019 before");
    EXPECT_EQ(MSERR_INVALID_VAL, soundPool_->SetLoop(1, 0));
    MEDIA_LOGI("soundpoolImpl_function_019 after");
}

/**
 * @tc.name: soundpoolImpl_function_020
 * @tc.desc: function test SetPriority without Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolImplUnitTest, soundpoolImpl_function_020, TestSize.Level2)
{
    MEDIA_LOGI("soundpoolImpl_function_020 before");
    EXPECT_EQ(MSERR_INVALID_VAL, soundPool_->SetPriority(1, 5));
    MEDIA_LOGI("soundpoolImpl_function_020 after");
}

/**
 * @tc.name: soundpoolImpl_function_021
 * @tc.desc: function test SetRate without Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolImplUnitTest, soundpoolImpl_function_021, TestSize.Level2)
{
    MEDIA_LOGI("soundpoolImpl_function_021 before");
    EXPECT_EQ(MSERR_INVALID_VAL, soundPool_->SetRate(1, AudioStandard::RENDER_RATE_NORMAL));
    MEDIA_LOGI("soundpoolImpl_function_021 after");
}

/**
 * @tc.name: soundpoolImpl_function_022
 * @tc.desc: function test SetVolume with out-of-range volume
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolImplUnitTest, soundpoolImpl_function_022, TestSize.Level2)
{
    MEDIA_LOGI("soundpoolImpl_function_022 before");
    // out-of-range volume is not rejected by CheckVolumeValid (it clamps), so it proceeds.
    // streamIdManager_ is nullptr (not initialized), so SetVolume returns MSERR_INVALID_VAL.
    EXPECT_EQ(MSERR_INVALID_VAL, soundPool_->SetVolume(1, 2.0f, 2.0f));
    MEDIA_LOGI("soundpoolImpl_function_022 after");
}

/**
 * @tc.name: soundpoolImpl_function_023
 * @tc.desc: function test Load with empty url
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolImplUnitTest, soundpoolImpl_function_023, TestSize.Level2)
{
    MEDIA_LOGI("soundpoolImpl_function_023 before");
    EXPECT_EQ(-1, soundPool_->Load(""));
    MEDIA_LOGI("soundpoolImpl_function_023 after");
}

/**
 * @tc.name: soundpoolImpl_function_024
 * @tc.desc: function test Load fd with invalid params
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolImplUnitTest, soundpoolImpl_function_024, TestSize.Level2)
{
    MEDIA_LOGI("soundpoolImpl_function_024 before");
    EXPECT_EQ(-1, soundPool_->Load(-1, 0, 0));
    EXPECT_EQ(-1, soundPool_->Load(1, 0, 0));
    EXPECT_EQ(-1, soundPool_->Load(1, 0, -1));
    MEDIA_LOGI("soundpoolImpl_function_024 after");
}

/**
 * @tc.name: soundpoolImpl_function_025
 * @tc.desc: function test Unload without Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundPoolImplUnitTest, soundpoolImpl_function_025, TestSize.Level2)
{
    MEDIA_LOGI("soundpoolImpl_function_025 before");
    EXPECT_EQ(-1, soundPool_->Unload(1));
    MEDIA_LOGI("soundpoolImpl_function_025 after");
}

}  // namespace Media
}  // namespace OHOS
