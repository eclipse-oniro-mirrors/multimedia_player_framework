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

#include "audio_haptic_test_common.h"
#include "media_errors.h"

namespace OHOS {
namespace Media {
using namespace testing::ext;

const int32_t NUM123 = 123;
const int32_t NUM5 = 5;
const int ERROR = -1;
const int32_t ZERO_INDEX = 0;
const int32_t ONE_INDEX = 1;
const int32_t TWO_INDEX = 2;
const int32_t INTENSITY_FIFTY = 50;
const int32_t INTENSITY_SEVENTY = 70;
const int32_t FREQUENCY = 150;
const int32_t PKG_DURATION_MS = 30000;
const int32_t PATTERN1_DURATION_MS = 20000;
const int32_t PATTERN2_DURATION_MS = 9000;
const int32_t EVENT_DURATION_MS = 9000;
const int32_t PATTERN2_TIME_MS = 21000;

std::shared_ptr<VibratorPackage> CreatePackage()
{
    auto g_vibrationPackage = std::make_shared<VibratorPackage>();
    g_vibrationPackage->patternNum = TWO_INDEX;
    g_vibrationPackage->packageDuration = PKG_DURATION_MS;

    g_vibrationPackage->patterns = new VibratorPattern[g_vibrationPackage->patternNum];

    VibratorPattern &pattern1 = g_vibrationPackage->patterns[0];
    pattern1.time = ZERO_INDEX;
    pattern1.eventNum = ONE_INDEX;
    pattern1.patternDuration = PATTERN1_DURATION_MS;

    pattern1.events = new VibratorEvent[pattern1.eventNum];

    VibratorEvent &event1 = pattern1.events[0];
    event1.type = EVENT_TYPE_UNKNOWN;
    event1.time = ZERO_INDEX;
    event1.duration = EVENT_DURATION_MS;
    event1.intensity = INTENSITY_FIFTY;
    event1.frequency = FREQUENCY;
    event1.index = ZERO_INDEX;
    event1.pointNum = ZERO_INDEX;
    event1.points = nullptr;

    VibratorPattern &pattern2 = g_vibrationPackage->patterns[1];
    pattern2.time = PATTERN2_TIME_MS;
    pattern2.eventNum = ONE_INDEX;
    pattern2.patternDuration = PATTERN2_DURATION_MS;

    pattern2.events = new VibratorEvent[pattern2.eventNum];

    VibratorEvent &event2 = pattern2.events[0];
    event2.type = EVENT_TYPE_UNKNOWN;
    event2.time = ZERO_INDEX;
    event2.duration = EVENT_DURATION_MS;
    event2.intensity = INTENSITY_SEVENTY;
    event2.frequency = FREQUENCY;
    event2.index = ONE_INDEX;
    event2.pointNum = ZERO_INDEX;
    event2.points = nullptr;

    return g_vibrationPackage;
}

std::mutex vibrateMutex_;

static std::shared_ptr<VibratorPackage> g_vibrationPackage = nullptr;
static std::shared_ptr<VibratorPackage> g_vibrationPackage2 = nullptr;

void AudioHapticVibratorImplUnitTest::SetUpTestCase(void)
{
    g_vibrationPackage = CreatePackage();
    g_vibrationPackage2 = CreatePackage();
}
void AudioHapticVibratorImplUnitTest::TearDownTestCase(void) {}
void AudioHapticVibratorImplUnitTest::SetUp(void) {}
void AudioHapticVibratorImplUnitTest::TearDown(void) {}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: PlayVibrateForSoundPool_001
 * @tc.desc  : Test PlayVibrateForSoundPool interface.
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, PlayVibrateForSoundPool_001, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    auto vibratorPkg = std::make_shared<VibratorPackage>();
    EXPECT_NE(vibratorPkg, nullptr);
    std::unique_lock<std::mutex> lock(vibrateMutex_);

    audioHapticVibratorImpl->isStopped_ = false;
    audioHapticVibratorImpl->isNeedRestart_ = false;
    audioHapticVibratorImpl->seekVibratorPkg_ = nullptr;
    int32_t result = audioHapticVibratorImpl->PlayVibrateForSoundPool(vibratorPkg, lock);
    EXPECT_EQ(result, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: PlayVibrateForSoundPool_002
 * @tc.desc  : Test PlayVibrateForSoundPool interface.
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, PlayVibrateForSoundPool_002, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    auto vibratorPkg = std::make_shared<VibratorPackage>();
    EXPECT_NE(vibratorPkg, nullptr);
    std::unique_lock<std::mutex> lock(vibrateMutex_);

    audioHapticVibratorImpl->isStopped_ = true;
    audioHapticVibratorImpl->isNeedRestart_ = false;
    audioHapticVibratorImpl->seekVibratorPkg_ = nullptr;
    int32_t result = audioHapticVibratorImpl->PlayVibrateForSoundPool(vibratorPkg, lock);
    EXPECT_EQ(result, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: PlayVibrateForSoundPool_003
 * @tc.desc  : Test PlayVibrateForSoundPool interface.
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, PlayVibrateForSoundPool_003, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    auto vibratorPkg = std::make_shared<VibratorPackage>();
    EXPECT_NE(vibratorPkg, nullptr);
    std::unique_lock<std::mutex> lock(vibrateMutex_);

    audioHapticVibratorImpl->isStopped_ = false;
    audioHapticVibratorImpl->isNeedRestart_ = true;
    audioHapticVibratorImpl->seekVibratorPkg_ = std::make_shared<VibratorPackage>();
    EXPECT_NE(audioHapticVibratorImpl->seekVibratorPkg_, nullptr);
    int32_t result = audioHapticVibratorImpl->PlayVibrateForSoundPool(vibratorPkg, lock);
    EXPECT_EQ(result, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: PlayVibrateForSoundPool_004
 * @tc.desc  : Test PlayVibrateForSoundPool interface.
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, PlayVibrateForSoundPool_004, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    auto vibratorPkg = std::make_shared<VibratorPackage>();
    EXPECT_NE(vibratorPkg, nullptr);
    std::unique_lock<std::mutex> lock(vibrateMutex_);

    audioHapticVibratorImpl->isStopped_ = false;
    audioHapticVibratorImpl->isNeedRestart_ = false;
    audioHapticVibratorImpl->seekVibratorPkg_ = std::make_shared<VibratorPackage>();
    EXPECT_NE(audioHapticVibratorImpl->seekVibratorPkg_, nullptr);
    int32_t result = audioHapticVibratorImpl->PlayVibrateForSoundPool(vibratorPkg, lock);
    EXPECT_EQ(result, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: PlayVibrateForSoundPool_005
 * @tc.desc  : Test PlayVibrateForSoundPool interface.
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, PlayVibrateForSoundPool_005, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    auto vibratorPkg = std::make_shared<VibratorPackage>();
    EXPECT_NE(vibratorPkg, nullptr);
    std::unique_lock<std::mutex> lock(vibrateMutex_);

    audioHapticVibratorImpl->isStopped_ = false;
    audioHapticVibratorImpl->isNeedRestart_ = true;
    audioHapticVibratorImpl->seekVibratorPkg_ = nullptr;
    int32_t result = audioHapticVibratorImpl->PlayVibrateForSoundPool(vibratorPkg, lock);
    EXPECT_EQ(result, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: RunVibrationPatterns_001
 * @tc.desc  : Test RunVibrationPatterns interface.
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, RunVibrationPatterns_001, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    auto vibratorPkg = std::make_shared<VibratorPackage>();
    EXPECT_NE(vibratorPkg, nullptr);
    std::unique_lock<std::mutex> lock(vibrateMutex_);

    audioHapticVibratorImpl->isStopped_ = false;
    audioHapticVibratorImpl->isNeedRestart_ = false;
    audioHapticVibratorImpl->seekVibratorPkg_ = nullptr;
    int32_t result = audioHapticVibratorImpl->RunVibrationPatterns(vibratorPkg, lock);
    EXPECT_EQ(result, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: RunVibrationPatterns_002
 * @tc.desc  : Test RunVibrationPatterns interface.
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, RunVibrationPatterns_002, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    auto vibratorPkg = std::make_shared<VibratorPackage>();
    EXPECT_NE(vibratorPkg, nullptr);
    std::unique_lock<std::mutex> lock(vibrateMutex_);

    audioHapticVibratorImpl->isStopped_ = true;
    audioHapticVibratorImpl->isNeedRestart_ = false;
    audioHapticVibratorImpl->seekVibratorPkg_ = nullptr;
    int32_t result = audioHapticVibratorImpl->RunVibrationPatterns(vibratorPkg, lock);
    EXPECT_EQ(result, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: RunVibrationPatterns_003
 * @tc.desc  : Test RunVibrationPatterns interface.
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, RunVibrationPatterns_003, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    auto vibratorPkg = std::make_shared<VibratorPackage>();
    EXPECT_NE(vibratorPkg, nullptr);
    std::unique_lock<std::mutex> lock(vibrateMutex_);

    audioHapticVibratorImpl->isStopped_ = false;
    audioHapticVibratorImpl->isNeedRestart_ = true;
    audioHapticVibratorImpl->seekVibratorPkg_ = std::make_shared<VibratorPackage>();
    EXPECT_NE(audioHapticVibratorImpl->seekVibratorPkg_, nullptr);
    int32_t result = audioHapticVibratorImpl->RunVibrationPatterns(vibratorPkg, lock);
    EXPECT_EQ(result, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: RunVibrationPatterns_004
 * @tc.desc  : Test RunVibrationPatterns interface.
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, RunVibrationPatterns_004, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    auto vibratorPkg = std::make_shared<VibratorPackage>();
    EXPECT_NE(vibratorPkg, nullptr);
    std::unique_lock<std::mutex> lock(vibrateMutex_);

    audioHapticVibratorImpl->isStopped_ = false;
    audioHapticVibratorImpl->isNeedRestart_ = false;
    audioHapticVibratorImpl->seekVibratorPkg_ = std::make_shared<VibratorPackage>();
    EXPECT_NE(audioHapticVibratorImpl->seekVibratorPkg_, nullptr);
    int32_t result = audioHapticVibratorImpl->RunVibrationPatterns(vibratorPkg, lock);
    EXPECT_EQ(result, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: RunVibrationPatterns_005
 * @tc.desc  : Test RunVibrationPatterns interface.
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, RunVibrationPatterns_005, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    auto vibratorPkg = std::make_shared<VibratorPackage>();
    EXPECT_NE(vibratorPkg, nullptr);
    std::unique_lock<std::mutex> lock(vibrateMutex_);

    audioHapticVibratorImpl->isStopped_ = false;
    audioHapticVibratorImpl->isNeedRestart_ = true;
    audioHapticVibratorImpl->seekVibratorPkg_ = nullptr;
    int32_t result = audioHapticVibratorImpl->RunVibrationPatterns(vibratorPkg, lock);
    EXPECT_EQ(result, MSERR_OK);
}

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
    EXPECT_EQ(ret, MSERR_OK);
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

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: AudioHapticVibratorImpl_038
 * @tc.desc  : Test AudioHapticVibratorImpl::SetHapticIntensity()
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, AudioHapticVibratorImpl_038, TestSize.Level0)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    // effectId intensity
    int32_t result = audioHapticVibratorImpl->SetHapticIntensity(50.0f);
    EXPECT_EQ(result, MSERR_OK);

    audioHapticVibratorImpl->hapticSource_.fd = TWO_INDEX;
    audioHapticVibratorImpl->isRunning_ = false;
    result = audioHapticVibratorImpl->SetHapticIntensity(50.0f);
    EXPECT_EQ(result, MSERR_OK);

    audioHapticVibratorImpl->isRunning_ = true;
    result = audioHapticVibratorImpl->SetHapticIntensity(50.0f);
    EXPECT_EQ(result, MSERR_OK);

    audioHapticVibratorImpl->isIntensityChanged_ = true;
    result = audioHapticVibratorImpl->SetHapticIntensity(50.0f);
    EXPECT_EQ(result, ERR_OPERATE_NOT_ALLOWED);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: AudioHapticVibratorImpl_039
 * @tc.desc  : Test AudioHapticVibratorImpl::SeekAndRestart()
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, AudioHapticVibratorImpl_039, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);

    audioHapticVibratorImpl->patternStartTime_ = 0;
    auto ret = audioHapticVibratorImpl->SeekAndRestart();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: AudioHapticVibratorImpl_040
 * @tc.desc  : Test AudioHapticVibratorImpl::PlayVibrateForAVPlayer()
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, AudioHapticVibratorImpl_040, TestSize.Level1)
{
    uint64_t tokenID;
    ASSERT_TRUE(GetPermission({"ohos.permission.VIBRATE"}, tokenID, false));

    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);
    EXPECT_NE(g_vibrationPackage, nullptr);
    std::unique_lock<std::mutex> lock(vibrateMutex_);
    int32_t result = audioHapticVibratorImpl->PlayVibrateForAVPlayer(g_vibrationPackage, lock);
    EXPECT_EQ(result, MSERR_INVALID_OPERATION);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: AudioHapticVibratorImpl_041
 * @tc.desc  : Test AudioHapticVibratorImpl::PlayVibrationPattern()
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, AudioHapticVibratorImpl_041, TestSize.Level1)
{
    uint64_t tokenID;
    ASSERT_TRUE(GetPermission({"ohos.permission.VIBRATE"}, tokenID, false));
 
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);
    EXPECT_NE(g_vibrationPackage, nullptr);
    std::unique_lock<std::mutex> lock(vibrateMutex_);

    int32_t vibrateTime = 0;
    audioHapticPlayerImpl.hapticsMode_ = HapticsMode::HAPTICS_MODE_NON_SYNC;
    int32_t result = audioHapticVibratorImpl->PlayVibrationPattern(g_vibrationPackage, TWO_INDEX, vibrateTime, lock);
    EXPECT_EQ(result, MSERR_OK);

    vibrateTime = PATTERN2_TIME_MS;
    audioHapticVibratorImpl->audioHapticSyncId_ = 1;
    audioHapticPlayerImpl.hapticsMode_ = HapticsMode::HAPTICS_MODE_SYNC;
    result =
        audioHapticVibratorImpl->PlayVibrationPattern(g_vibrationPackage, ONE_INDEX, vibrateTime, lock);
    EXPECT_EQ(result, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: AudioHapticVibratorImpl_042
 * @tc.desc  : Test AudioHapticVibratorImpl::SetHapticsRamp()
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, AudioHapticVibratorImpl_042, TestSize.Level1)
{
    uint64_t tokenID;
    ASSERT_TRUE(GetPermission({"ohos.permission.VIBRATE"}, tokenID, false));

    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);
    EXPECT_NE(g_vibrationPackage, nullptr);

    // vibratorPkg_ is null
    EXPECT_EQ(ERR_OPERATE_NOT_ALLOWED, audioHapticVibratorImpl->SetHapticsRamp(50, 1.0f, 50.0f));

    audioHapticVibratorImpl->vibratorPkg_ = g_vibrationPackage;
    audioHapticVibratorImpl->isRunning_.store(true);
    // vibratorPkg_ is running
    EXPECT_EQ(ERR_OPERATE_NOT_ALLOWED, audioHapticVibratorImpl->SetHapticsRamp(50, 1.0f, 50.0f));
    
    audioHapticVibratorImpl->isRunning_.store(false);
    // duration less than 100ms
    EXPECT_EQ(MSERR_INVALID_VAL, audioHapticVibratorImpl->SetHapticsRamp(50, 1.0f, 50.0f));

    // start intensity less than 1.0f
    EXPECT_EQ(MSERR_INVALID_VAL, audioHapticVibratorImpl->SetHapticsRamp(50000, 0.0f, 50.0f));
    // start intensity larger than 100.0f
    EXPECT_EQ(MSERR_INVALID_VAL, audioHapticVibratorImpl->SetHapticsRamp(5000, 101.0f, 50.0f));

    // end intensity less than 1.0f
    EXPECT_EQ(MSERR_INVALID_VAL, audioHapticVibratorImpl->SetHapticsRamp(5000, 20.0f, 0.0f));
    // end intensity larger than 100.0f
    EXPECT_EQ(MSERR_INVALID_VAL, audioHapticVibratorImpl->SetHapticsRamp(5000, 20.0f, 101.0f));

    // duration 24000ms, start intensity 20.0f, end intensity 70.0f
    EXPECT_EQ(MSERR_OK, audioHapticVibratorImpl->SetHapticsRamp(24000, 20.0f, 70.0f));

    // 恢复
    audioHapticVibratorImpl->ResumeModulePackge();
    EXPECT_EQ(70.0f, audioHapticVibratorImpl->vibratorParameter_.intensity);
    EXPECT_EQ(nullptr, audioHapticVibratorImpl->modulatePkg_);
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: AudioHapticVibratorImpl_044
 * @tc.desc  : Test AudioHapticVibratorImpl::IsNonSync()
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, AudioHapticVibratorImpl_044, TestSize.Level1)
{
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);
    EXPECT_NE(g_vibrationPackage, nullptr);

    audioHapticPlayerImpl.hapticsMode_ = HapticsMode::HAPTICS_MODE_NON_SYNC;
    EXPECT_EQ(true, audioHapticVibratorImpl->IsNonSync());

    audioHapticPlayerImpl.hapticsMode_ = HapticsMode::HAPTICS_MODE_NON_SYNC_ONCE;
    EXPECT_EQ(true, audioHapticVibratorImpl->IsNonSync());

    audioHapticPlayerImpl.hapticsMode_ = HapticsMode::HAPTICS_MODE_SYNC;
    EXPECT_EQ(false, audioHapticVibratorImpl->IsNonSync());
}

/**
 * @tc.name  : Test AudioHapticVibratorImpl API
 * @tc.number: AudioHapticVibratorImpl_045
 * @tc.desc  : Test AudioHapticVibratorImpl::PlayVibrateForAVPlayer()
 */
HWTEST_F(AudioHapticVibratorImplUnitTest, AudioHapticVibratorImpl_045, TestSize.Level1)
{
    uint64_t tokenID;
    ASSERT_TRUE(GetPermission({"ohos.permission.VIBRATE"}, tokenID, false));
 
    AudioHapticPlayerImpl audioHapticPlayerImpl;
    auto audioHapticVibratorImpl = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticVibratorImpl, nullptr);
    std::unique_lock<std::mutex> lock(vibrateMutex_);

    std::shared_ptr<VibratorPackage> vibrationPackage = CreatePackage();
    audioHapticVibratorImpl->vibratorPkg_ = vibrationPackage;
    audioHapticVibratorImpl->audioHapticSyncId_ = 1;

    int32_t result = audioHapticVibratorImpl->PlayVibrateForAVPlayer(vibrationPackage, lock);
    EXPECT_EQ(result, MSERR_OK);
}
} // namespace Media
} // namespace OHOS