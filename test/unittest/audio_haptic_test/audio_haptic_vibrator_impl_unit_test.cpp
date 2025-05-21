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

#include "audio_haptic_vibrator_impl_unit_test.h"

namespace OHOS {
namespace Media {
using namespace testing::ext;

const int32_t NUM123 = 123;
const int32_t NUM5 = 5;
const int32_t MSERR_OK = 0;
const int ERROR = -1;

void AudioHapticVibratorImplUnitTest::SetUpTestCase(void) {}
void AudioHapticVibratorImplUnitTest::TearDownTestCase(void) {}
void AudioHapticVibratorImplUnitTest::SetUp(void) {}
void AudioHapticVibratorImplUnitTest::TearDown(void) {}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: AudioHapticVibratorImpl_001
 * @tc.desc  : Test AudioHapticVibratorImpl::AudioHapticVibratorImpl()
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, AudioHapticVibratorImpl_001, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    audioHapticPlayerImpl.muteHaptic_ = true;

    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    EXPECT_EQ(audioHapticVibratorImpl->audioHapticPlayer_.IsMuted(AUDIO_HAPTIC_TYPE_HAPTIC), true);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: AudioHapticVibratorImpl_002
 * @tc.desc  : Test AudioHapticVibratorImpl::AudioHapticVibratorImpl()
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, AudioHapticVibratorImpl_002, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    audioHapticPlayerImpl.muteHaptic_ = false;

    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    EXPECT_EQ(audioHapticVibratorImpl->audioHapticPlayer_.IsMuted(AUDIO_HAPTIC_TYPE_HAPTIC), false);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: AudioHapticVibratorImpl_003
 * @tc.desc  : Test AudioHapticVibratorImpl::ExtractFd()
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, AudioHapticVibratorImpl_003, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    std::string hapticsUri = "1";

    auto ret = audioHapticVibratorImpl->ExtractFd(hapticsUri);
    EXPECT_EQ(ret, ERROR);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: AudioHapticVibratorImpl_004
 * @tc.desc  : Test AudioHapticVibratorImpl::ExtractFd()
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, AudioHapticVibratorImpl_004, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    std::string hapticsUri = "1fd://";

    auto ret = audioHapticVibratorImpl->ExtractFd(hapticsUri);
    EXPECT_EQ(ret, ERROR);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: AudioHapticVibratorImpl_005
 * @tc.desc  : Test AudioHapticVibratorImpl::ExtractFd()
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, AudioHapticVibratorImpl_005, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    std::string hapticsUri = "fd://abc";

    auto ret = audioHapticVibratorImpl->ExtractFd(hapticsUri);
    EXPECT_EQ(ret, ERROR);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: AudioHapticVibratorImpl_006
 * @tc.desc  : Test AudioHapticVibratorImpl::ExtractFd()
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, AudioHapticVibratorImpl_006, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    std::string hapticsUri = "fd://0";

    auto ret = audioHapticVibratorImpl->ExtractFd(hapticsUri);
    EXPECT_EQ(ret, ERROR);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: AudioHapticVibratorImpl_007
 * @tc.desc  : Test AudioHapticVibratorImpl::ExtractFd()
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, AudioHapticVibratorImpl_007, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    std::string hapticsUri = "fd://123";

    auto ret = audioHapticVibratorImpl->ExtractFd(hapticsUri);
    EXPECT_EQ(ret, NUM123);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: AudioHapticVibratorImpl_008
 * @tc.desc  : Test AudioHapticVibratorImpl::OpenHapticFile()
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, AudioHapticVibratorImpl_008, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    std::string hapticsUri = "fd://123";

    auto ret = audioHapticVibratorImpl->OpenHapticFile(hapticsUri);
    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: AudioHapticVibratorImpl_009
 * @tc.desc  : Test AudioHapticVibratorImpl::PreLoad()
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, AudioHapticVibratorImpl_009, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    HapticSource hapticSource;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_MUSIC;
    HapticsMode hapticsMode = HapticsMode::HAPTICS_MODE_NONE;
    audioHapticVibratorImpl->audioHapticPlayer_.SetHapticsMode(hapticsMode);
    EXPECT_EQ(audioHapticVibratorImpl->audioHapticPlayer_.GetHapticsMode(), HapticsMode::HAPTICS_MODE_NONE);

    auto ret = audioHapticVibratorImpl->PreLoad(hapticSource, streamUsage);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: AudioHapticVibratorImpl_010
 * @tc.desc  : Test AudioHapticVibratorImpl::PreLoad()
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, AudioHapticVibratorImpl_010, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    HapticSource hapticSource;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_MUSIC;
    HapticsMode hapticsMode = HapticsMode::HAPTICS_MODE_SYNC;
    audioHapticVibratorImpl->audioHapticPlayer_.SetHapticsMode(hapticsMode);
    EXPECT_EQ(audioHapticVibratorImpl->audioHapticPlayer_.GetHapticsMode(), HapticsMode::HAPTICS_MODE_SYNC);

    auto ret = audioHapticVibratorImpl->PreLoad(hapticSource, streamUsage);
    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: AudioHapticVibratorImpl_011
 * @tc.desc  : Test AudioHapticVibratorImpl::PreLoad()
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, AudioHapticVibratorImpl_011, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    HapticSource hapticSource;
    hapticSource.hapticUri = "123";
    AudioStandard::StreamUsage streamUsage = static_cast<AudioStandard::StreamUsage>(NUM123);
    HapticsMode hapticsMode = HapticsMode::HAPTICS_MODE_SYNC;
    audioHapticVibratorImpl->audioHapticPlayer_.SetHapticsMode(hapticsMode);
    EXPECT_EQ(audioHapticVibratorImpl->audioHapticPlayer_.GetHapticsMode(), HapticsMode::HAPTICS_MODE_SYNC);

    auto ret = audioHapticVibratorImpl->PreLoad(hapticSource, streamUsage);
    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: AudioHapticVibratorImpl_012
 * @tc.desc  : Test AudioHapticVibratorImpl::Release()
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, AudioHapticVibratorImpl_012, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    audioHapticVibratorImpl->vibratorPkg_ = std::make_shared<VibratorPackage>();
    EXPECT_NE(audioHapticVibratorImpl->vibratorPkg_, nullptr);

    auto ret = audioHapticVibratorImpl->Release();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: AudioHapticVibratorImpl_013
 * @tc.desc  : Test AudioHapticVibratorImpl::Release()
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, AudioHapticVibratorImpl_013, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    audioHapticVibratorImpl->vibratorPkg_ = nullptr;
    auto ret = audioHapticVibratorImpl->Release();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: AudioHapticVibratorImpl_014
 * @tc.desc  : Test AudioHapticVibratorImpl::StartVibrate()
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, AudioHapticVibratorImpl_014, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    AudioLatencyMode latencyMode = AUDIO_LATENCY_MODE_NORMAL;
    HapticsMode hapticsMode = HapticsMode::HAPTICS_MODE_NONE;
    audioHapticVibratorImpl->audioHapticPlayer_.SetHapticsMode(hapticsMode);
    auto ret = audioHapticVibratorImpl->StartVibrate(latencyMode);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: AudioHapticVibratorImpl_015
 * @tc.desc  : Test AudioHapticVibratorImpl::StartVibrate()
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, AudioHapticVibratorImpl_015, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    AudioLatencyMode latencyMode = AUDIO_LATENCY_MODE_NORMAL;
    HapticsMode hapticsMode = HapticsMode::HAPTICS_MODE_NON_SYNC;
    audioHapticVibratorImpl->audioHapticPlayer_.SetHapticsMode(hapticsMode);
    auto ret = audioHapticVibratorImpl->StartVibrate(latencyMode);
    EXPECT_NE(ret, MSERR_OK);
}


/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: AudioHapticVibratorImpl_016
 * @tc.desc  : Test AudioHapticVibratorImpl::StartVibrate()
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, AudioHapticVibratorImpl_016, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    AudioLatencyMode latencyMode = AUDIO_LATENCY_MODE_NORMAL;
    HapticsMode hapticsMode = HapticsMode::HAPTICS_MODE_SYNC;
    audioHapticVibratorImpl->audioHapticPlayer_.SetHapticsMode(hapticsMode);
    auto ret = audioHapticVibratorImpl->StartVibrate(latencyMode);
    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: AudioHapticVibratorImpl_017
 * @tc.desc  : Test AudioHapticVibratorImpl::StartVibrate()
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, AudioHapticVibratorImpl_017, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    AudioLatencyMode latencyMode = AUDIO_LATENCY_MODE_FAST;
    audioHapticVibratorImpl->isSupportEffectId_ = true;
    HapticsMode hapticsMode = HapticsMode::HAPTICS_MODE_SYNC;
    audioHapticVibratorImpl->audioHapticPlayer_.SetHapticsMode(hapticsMode);
    auto ret = audioHapticVibratorImpl->StartVibrate(latencyMode);
    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: AudioHapticVibratorImpl_018
 * @tc.desc  : Test AudioHapticVibratorImpl::StartVibrate()
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, AudioHapticVibratorImpl_018, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    AudioLatencyMode latencyMode = AUDIO_LATENCY_MODE_FAST;
    audioHapticVibratorImpl->isSupportEffectId_ = false;
    HapticsMode hapticsMode = HapticsMode::HAPTICS_MODE_SYNC;
    audioHapticVibratorImpl->audioHapticPlayer_.SetHapticsMode(hapticsMode);
    auto ret = audioHapticVibratorImpl->StartVibrate(latencyMode);
    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: AudioHapticVibratorImpl_019
 * @tc.desc  : Test AudioHapticVibratorImpl::StartVibrate()
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, AudioHapticVibratorImpl_019, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    AudioLatencyMode latencyMode = static_cast<AudioLatencyMode>(NUM5);
    HapticsMode hapticsMode = HapticsMode::HAPTICS_MODE_SYNC;
    audioHapticVibratorImpl->audioHapticPlayer_.SetHapticsMode(hapticsMode);
    auto ret = audioHapticVibratorImpl->StartVibrate(latencyMode);
    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: AudioHapticVibratorImpl_020
 * @tc.desc  : Test AudioHapticVibratorImpl::StartVibrateWithEffect()
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, AudioHapticVibratorImpl_20, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    auto ret = audioHapticVibratorImpl->StartVibrateWithEffect();
    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: AudioHapticVibratorImpl_021
 * @tc.desc  : Test AudioHapticVibratorImpl::StartVibrateForSoundPool()
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, AudioHapticVibratorImpl_21, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    audioHapticVibratorImpl->isStopped_ = true;
    auto ret = audioHapticVibratorImpl->StartVibrateForSoundPool();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: AudioHapticVibratorImpl_022
 * @tc.desc  : Test AudioHapticVibratorImpl::StartVibrateForSoundPool()
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, AudioHapticVibratorImpl_22, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    audioHapticVibratorImpl->isStopped_ = false;

    audioHapticVibratorImpl->vibratorPkg_ = std::make_shared<VibratorPackage>();
    EXPECT_NE(audioHapticVibratorImpl->vibratorPkg_, nullptr);

    audioHapticVibratorImpl->vibratorFD_ = std::make_shared<VibratorFileDescription>();
    EXPECT_NE(audioHapticVibratorImpl->vibratorFD_, nullptr);

    auto ret = audioHapticVibratorImpl->StartVibrateForSoundPool();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: AudioHapticVibratorImpl_023
 * @tc.desc  : Test AudioHapticVibratorImpl::StartVibrateForSoundPool()
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, AudioHapticVibratorImpl_23, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    audioHapticVibratorImpl->isStopped_ = false;

    audioHapticVibratorImpl->vibratorPkg_ = std::make_shared<VibratorPackage>();
    EXPECT_NE(audioHapticVibratorImpl->vibratorPkg_, nullptr);

    audioHapticVibratorImpl->vibratorFD_ = nullptr;

    auto ret = audioHapticVibratorImpl->StartVibrateForSoundPool();
    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: AudioHapticVibratorImpl_024
 * @tc.desc  : Test AudioHapticVibratorImpl::StartVibrateForSoundPool()
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, AudioHapticVibratorImpl_24, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    audioHapticVibratorImpl->isStopped_ = false;

    audioHapticVibratorImpl->vibratorPkg_ = nullptr;
    audioHapticVibratorImpl->vibratorFD_ = nullptr;

    auto ret = audioHapticVibratorImpl->StartVibrateForSoundPool();
    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: AudioHapticVibratorImpl_025
 * @tc.desc  : Test AudioHapticVibratorImpl::StartNonSyncVibration()
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, AudioHapticVibratorImpl_25, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    audioHapticVibratorImpl->isStopped_ = true;

    auto ret = audioHapticVibratorImpl->StartNonSyncVibration();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: AudioHapticVibratorImpl_027
 * @tc.desc  : Test AudioHapticVibratorImpl::StartNonSyncVibration()
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, AudioHapticVibratorImpl_27, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    audioHapticVibratorImpl->isStopped_ = false;

    audioHapticVibratorImpl->vibratorPkg_ = std::make_shared<VibratorPackage>();
    EXPECT_NE(audioHapticVibratorImpl->vibratorPkg_, nullptr);

    audioHapticVibratorImpl->vibratorFD_ = nullptr;

    auto ret = audioHapticVibratorImpl->StartNonSyncVibration();
    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: AudioHapticVibratorImpl_028
 * @tc.desc  : Test AudioHapticVibratorImpl::StartNonSyncVibration()
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, AudioHapticVibratorImpl_28, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    audioHapticVibratorImpl->isStopped_ = false;

    audioHapticVibratorImpl->vibratorPkg_ = nullptr;
    audioHapticVibratorImpl->vibratorFD_ = nullptr;

    auto ret = audioHapticVibratorImpl->StartNonSyncVibration();
    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: AudioHapticVibratorImpl_029
 * @tc.desc  : Test AudioHapticVibratorImpl::StartVibrateForAVPlayer()
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, AudioHapticVibratorImpl_29, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    audioHapticVibratorImpl->isStopped_ = true;

    auto ret = audioHapticVibratorImpl->StartVibrateForAVPlayer();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: AudioHapticVibratorImpl_030
 * @tc.desc  : Test AudioHapticVibratorImpl::StartVibrateForAVPlayer()
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, AudioHapticVibratorImpl_30, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    audioHapticVibratorImpl->isStopped_ = false;

    audioHapticVibratorImpl->vibratorPkg_ = std::make_shared<VibratorPackage>();
    EXPECT_NE(audioHapticVibratorImpl->vibratorPkg_, nullptr);

    audioHapticVibratorImpl->vibratorFD_ = std::make_shared<VibratorFileDescription>();
    EXPECT_NE(audioHapticVibratorImpl->vibratorFD_, nullptr);

    auto ret = audioHapticVibratorImpl->StartVibrateForAVPlayer();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: AudioHapticVibratorImpl_031
 * @tc.desc  : Test AudioHapticVibratorImpl::StartVibrateForAVPlayer()
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, AudioHapticVibratorImpl_31, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    audioHapticVibratorImpl->isStopped_ = false;

    audioHapticVibratorImpl->vibratorPkg_ = std::make_shared<VibratorPackage>();
    EXPECT_NE(audioHapticVibratorImpl->vibratorPkg_, nullptr);

    audioHapticVibratorImpl->vibratorFD_ = nullptr;

    auto ret = audioHapticVibratorImpl->StartVibrateForAVPlayer();
    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: AudioHapticVibratorImpl_032
 * @tc.desc  : Test AudioHapticVibratorImpl::StartVibrateForAVPlayer()
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, AudioHapticVibratorImpl_32, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    audioHapticVibratorImpl->isStopped_ = false;

    audioHapticVibratorImpl->vibratorPkg_ = nullptr;
    audioHapticVibratorImpl->vibratorFD_ = nullptr;

    auto ret = audioHapticVibratorImpl->StartVibrateForAVPlayer();
    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: AudioHapticVibratorImpl_033
 * @tc.desc  : Test AudioHapticVibratorImpl::StartNonSyncOnceVibration()
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, AudioHapticVibratorImpl_33, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    audioHapticVibratorImpl->isStopped_ = true;

    auto ret = audioHapticVibratorImpl->StartNonSyncOnceVibration();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: AudioHapticVibratorImpl_034
 * @tc.desc  : Test AudioHapticVibratorImpl::StartNonSyncOnceVibration()
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, AudioHapticVibratorImpl_34, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    audioHapticVibratorImpl->isStopped_ = false;

    audioHapticVibratorImpl->vibratorPkg_ = std::make_shared<VibratorPackage>();
    EXPECT_NE(audioHapticVibratorImpl->vibratorPkg_, nullptr);

    audioHapticVibratorImpl->vibratorFD_ = nullptr;

    auto ret = audioHapticVibratorImpl->StartNonSyncOnceVibration();
    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: AudioHapticVibratorImpl_035
 * @tc.desc  : Test AudioHapticVibratorImpl::StartNonSyncOnceVibration()
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, AudioHapticVibratorImpl_35, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    audioHapticVibratorImpl->isStopped_ = false;

    audioHapticVibratorImpl->vibratorPkg_ = nullptr;
    audioHapticVibratorImpl->vibratorFD_ = nullptr;

    auto ret = audioHapticVibratorImpl->StartNonSyncOnceVibration();
    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: AudioHapticVibratorImpl_036
 * @tc.desc  : Test AudioHapticVibratorImpl::StartVibrate()
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, AudioHapticVibratorImpl_036, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    AudioLatencyMode latencyMode = AUDIO_LATENCY_MODE_NORMAL;
    HapticsMode hapticsMode = HapticsMode::HAPTICS_MODE_NON_SYNC_ONCE;
    audioHapticVibratorImpl->audioHapticPlayer_.SetHapticsMode(hapticsMode);
    auto ret = audioHapticVibratorImpl->StartVibrate(latencyMode);
    EXPECT_NE(ret, MSERR_OK);
}
} // namespace Media
} // namespace OHOS