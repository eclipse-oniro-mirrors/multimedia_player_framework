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

#include "audio_haptic_player_impl_unit_test.h"

namespace OHOS {
namespace Media {
using namespace testing::ext;

const int32_t NUM2 = 2;
const float NUM_1 = -1.0f;
const float NUM_2 = 2.0f;
const float NUM_3 = 0.5f;

void AudioHapticPlayerImplUnitTest::SetUpTestCase(void) {}
void AudioHapticPlayerImplUnitTest::TearDownTestCase(void) {}
void AudioHapticPlayerImplUnitTest::SetUp(void) {}
void AudioHapticPlayerImplUnitTest::TearDown(void) {}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_001
 * @tc.desc  : Test AudioHapticSound::CreateAudioHapticSound()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_001, TestSize.Level1)
{
    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSound = std::make_shared<AudioHapticSoundNormalImpl>(audioSource, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSound, nullptr);

    AudioLatencyMode latencyMode = static_cast<AudioLatencyMode>(NUM2);
    bool parallelPlayFlag = true;

    auto ret = audioHapticSound->CreateAudioHapticSound(latencyMode, audioSource, muteAudio,
        streamUsage, parallelPlayFlag);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_002
 * @tc.desc  : Test AudioHapticSound::CreateAudioHapticSound()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_002, TestSize.Level1)
{
    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSound = std::make_shared<AudioHapticSoundNormalImpl>(audioSource, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSound, nullptr);

    AudioLatencyMode latencyMode = AudioLatencyMode::AUDIO_LATENCY_MODE_NORMAL;
    bool parallelPlayFlag = true;

    auto ret = audioHapticSound->CreateAudioHapticSound(latencyMode, audioSource, muteAudio,
        streamUsage, parallelPlayFlag);
    EXPECT_NE(ret, nullptr);
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_003
 * @tc.desc  : Test AudioHapticSound::CreateAudioHapticSound()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_003, TestSize.Level1)
{
    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSound = std::make_shared<AudioHapticSoundNormalImpl>(audioSource, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSound, nullptr);

    AudioLatencyMode latencyMode = AudioLatencyMode::AUDIO_LATENCY_MODE_FAST;
    bool parallelPlayFlag = true;

    auto ret = audioHapticSound->CreateAudioHapticSound(latencyMode, audioSource, muteAudio,
        streamUsage, parallelPlayFlag);
    EXPECT_NE(ret, nullptr);
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_004
 * @tc.desc  : Test AudioHapticPlayerImpl::~AudioHapticPlayerImpl()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_004, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);
    audioHapticPlayerImpl->playerState_ = AudioHapticPlayerState::STATE_RELEASED;
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_005
 * @tc.desc  : Test AudioHapticPlayerImpl::~AudioHapticPlayerImpl()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_005, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);
    audioHapticPlayerImpl->playerState_ = AudioHapticPlayerState::STATE_NEW;
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_006
 * @tc.desc  : Test AudioHapticPlayerImpl::IsMuted()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_006, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    AudioHapticType audioHapticType = AudioHapticType::AUDIO_HAPTIC_TYPE_AUDIO;
    audioHapticPlayerImpl->muteAudio_ = true;

    auto ret = audioHapticPlayerImpl->IsMuted(audioHapticType);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_007
 * @tc.desc  : Test AudioHapticPlayerImpl::IsMuted()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_007, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    AudioHapticType audioHapticType = AudioHapticType::AUDIO_HAPTIC_TYPE_HAPTIC;
    audioHapticPlayerImpl->muteHaptic_ = true;

    auto ret = audioHapticPlayerImpl->IsMuted(audioHapticType);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_008
 * @tc.desc  : Test AudioHapticPlayerImpl::IsMuted()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_008, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    AudioHapticType audioHapticType = static_cast<AudioHapticType>(NUM2);
    audioHapticPlayerImpl->muteHaptic_ = true;

    auto ret = audioHapticPlayerImpl->IsMuted(audioHapticType);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_009
 * @tc.desc  : Test AudioHapticPlayerImpl::Start()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_009, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    audioHapticPlayerImpl->vibrateThread_ = std::make_shared<std::thread>();
    EXPECT_NE(audioHapticPlayerImpl->vibrateThread_, nullptr);

    auto ret = audioHapticPlayerImpl->Start();
    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_010
 * @tc.desc  : Test AudioHapticPlayerImpl::Start()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_010, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    audioHapticPlayerImpl->vibrateThread_ = nullptr;

    auto ret = audioHapticPlayerImpl->Start();
    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_011
 * @tc.desc  : Test AudioHapticPlayerImpl::ReleaseVibrator()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_011, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    AudioHapticPlayerImpl audioHapticPlayerImpl2;
    audioHapticPlayerImpl->audioHapticVibrator_ = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl2);
    EXPECT_NE(audioHapticPlayerImpl->audioHapticVibrator_, nullptr);

    audioHapticPlayerImpl->vibrateThread_ = std::make_shared<std::thread>();
    EXPECT_NE(audioHapticPlayerImpl->vibrateThread_, nullptr);

    audioHapticPlayerImpl->ReleaseVibrator();
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_012
 * @tc.desc  : Test AudioHapticPlayerImpl::ReleaseVibrator()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_012, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    audioHapticPlayerImpl->audioHapticVibrator_ = nullptr;
    audioHapticPlayerImpl->vibrateThread_ = nullptr;

    audioHapticPlayerImpl->ReleaseVibrator();
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_013
 * @tc.desc  : Test AudioHapticPlayerImpl::ReleaseSound()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_013, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl =
        std::make_shared<AudioHapticSoundNormalImpl>(audioSource, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    audioHapticPlayerImpl->audioHapticSound_ = audioHapticSoundNormalImpl;
    audioHapticPlayerImpl->ReleaseSound();
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_014
 * @tc.desc  : Test AudioHapticPlayerImpl::ReleaseSound()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_014, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    audioHapticPlayerImpl->audioHapticSound_ = nullptr;
    audioHapticPlayerImpl->ReleaseSound();
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_015
 * @tc.desc  : Test AudioHapticPlayerImpl::SetVolume()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_015, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    float volume = NUM_1;
    auto ret = audioHapticPlayerImpl->SetVolume(volume);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_016
 * @tc.desc  : Test AudioHapticPlayerImpl::SetVolume()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_016, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    float volume = NUM_2;
    auto ret = audioHapticPlayerImpl->SetVolume(volume);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_017
 * @tc.desc  : Test AudioHapticPlayerImpl::SetVolume()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_017, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    float volume = NUM_3;
    audioHapticPlayerImpl->audioHapticSound_ = nullptr;

    auto ret = audioHapticPlayerImpl->SetVolume(volume);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_018
 * @tc.desc  : Test AudioHapticPlayerImpl::SetVolume()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_018, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    float volume = 0.0f;

    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl =
        std::make_shared<AudioHapticSoundNormalImpl>(audioSource, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    audioHapticPlayerImpl->audioHapticSound_ = audioHapticSoundNormalImpl;

    audioHapticPlayerImpl->latencyMode_ = AudioLatencyMode::AUDIO_LATENCY_MODE_NORMAL;
    audioHapticPlayerImpl->streamUsage_ = AudioStandard::StreamUsage::STREAM_USAGE_VOICE_RINGTONE;
    audioHapticPlayerImpl->playerState_ = AudioHapticPlayerState::STATE_RUNNING;

    auto ret = audioHapticPlayerImpl->SetVolume(volume);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_019
 * @tc.desc  : Test AudioHapticPlayerImpl::SetVolume()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_019, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    float volume = NUM_3;

    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl =
        std::make_shared<AudioHapticSoundNormalImpl>(audioSource, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    audioHapticPlayerImpl->audioHapticSound_ = audioHapticSoundNormalImpl;

    audioHapticPlayerImpl->latencyMode_ = AudioLatencyMode::AUDIO_LATENCY_MODE_NORMAL;
    audioHapticPlayerImpl->streamUsage_ = AudioStandard::StreamUsage::STREAM_USAGE_VOICE_RINGTONE;
    audioHapticPlayerImpl->playerState_ = AudioHapticPlayerState::STATE_RUNNING;

    auto ret = audioHapticPlayerImpl->SetVolume(volume);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_020
 * @tc.desc  : Test AudioHapticPlayerImpl::SetVolume()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_020, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    float volume = NUM_3;

    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl =
        std::make_shared<AudioHapticSoundNormalImpl>(audioSource, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    audioHapticPlayerImpl->audioHapticSound_ = audioHapticSoundNormalImpl;

    audioHapticPlayerImpl->latencyMode_ = AudioLatencyMode::AUDIO_LATENCY_MODE_NORMAL;
    audioHapticPlayerImpl->streamUsage_ = AudioStandard::StreamUsage::STREAM_USAGE_VOICE_RINGTONE;
    audioHapticPlayerImpl->playerState_ = AudioHapticPlayerState::STATE_NEW;

    auto ret = audioHapticPlayerImpl->SetVolume(volume);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_021
 * @tc.desc  : Test AudioHapticPlayerImpl::SetVolume()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_021, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    float volume = NUM_3;

    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl =
        std::make_shared<AudioHapticSoundNormalImpl>(audioSource, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    audioHapticPlayerImpl->audioHapticSound_ = audioHapticSoundNormalImpl;

    audioHapticPlayerImpl->latencyMode_ = AudioLatencyMode::AUDIO_LATENCY_MODE_NORMAL;
    audioHapticPlayerImpl->streamUsage_ = AudioStandard::StreamUsage::STREAM_USAGE_RINGTONE;
    audioHapticPlayerImpl->playerState_ = AudioHapticPlayerState::STATE_NEW;

    auto ret = audioHapticPlayerImpl->SetVolume(volume);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_022
 * @tc.desc  : Test AudioHapticPlayerImpl::SetVolume()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_022, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    float volume = NUM_3;

    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl =
        std::make_shared<AudioHapticSoundNormalImpl>(audioSource, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    audioHapticPlayerImpl->audioHapticSound_ = audioHapticSoundNormalImpl;

    audioHapticPlayerImpl->latencyMode_ = AudioLatencyMode::AUDIO_LATENCY_MODE_NORMAL;
    audioHapticPlayerImpl->streamUsage_ = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    audioHapticPlayerImpl->playerState_ = AudioHapticPlayerState::STATE_NEW;

    auto ret = audioHapticPlayerImpl->SetVolume(volume);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_023
 * @tc.desc  : Test AudioHapticPlayerImpl::SetVolume()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_023, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    float volume = NUM_3;

    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl =
        std::make_shared<AudioHapticSoundNormalImpl>(audioSource, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    audioHapticPlayerImpl->audioHapticSound_ = audioHapticSoundNormalImpl;

    audioHapticPlayerImpl->latencyMode_ = AudioLatencyMode::AUDIO_LATENCY_MODE_FAST;
    audioHapticPlayerImpl->streamUsage_ = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    audioHapticPlayerImpl->playerState_ = AudioHapticPlayerState::STATE_NEW;

    auto ret = audioHapticPlayerImpl->SetVolume(volume);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_024
 * @tc.desc  : Test AudioHapticPlayerImpl::SetHapticIntensity()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_024, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    float intensity = NUM_1;
    auto ret = audioHapticPlayerImpl->SetHapticIntensity(intensity);
    EXPECT_EQ(ret, NOT_SUPPORTED_CODE);
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_027
 * @tc.desc  : Test AudioHapticPlayerImpl::SetLoop()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_027, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    bool loop = true;

    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl =
        std::make_shared<AudioHapticSoundNormalImpl>(audioSource, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    audioHapticPlayerImpl->audioHapticSound_ = audioHapticSoundNormalImpl;

    auto ret = audioHapticPlayerImpl->SetLoop(loop);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_028
 * @tc.desc  : Test AudioHapticPlayerImpl::SetLoop()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_028, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    bool loop = true;

    audioHapticPlayerImpl->audioHapticSound_ = nullptr;

    auto ret = audioHapticPlayerImpl->SetLoop(loop);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_029
 * @tc.desc  : Test AudioHapticPlayerImpl::SetAudioHapticPlayerCallback()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_029, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    std::shared_ptr<AudioHapticPlayerCallback> playerCallback = std::make_shared<AudioHapticPlayerCallbackTest>();
    EXPECT_NE(playerCallback, nullptr);

    auto ret = audioHapticPlayerImpl->SetAudioHapticPlayerCallback(playerCallback);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_030
 * @tc.desc  : Test AudioHapticPlayerImpl::SetAudioHapticPlayerCallback()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_030, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    std::shared_ptr<AudioHapticPlayerCallback> playerCallback = nullptr;

    auto ret = audioHapticPlayerImpl->SetAudioHapticPlayerCallback(playerCallback);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_031
 * @tc.desc  : Test AudioHapticPlayerImpl::StartVibrate()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_031, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    audioHapticPlayerImpl->muteHaptic_ = true;

    auto ret = audioHapticPlayerImpl->StartVibrate();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_032
 * @tc.desc  : Test AudioHapticPlayerImpl::StartVibrate()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_032, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    audioHapticPlayerImpl->muteHaptic_ = false;
    audioHapticPlayerImpl->isVibrationStopped_ = true;
    audioHapticPlayerImpl->loop_ = true;

    auto ret = audioHapticPlayerImpl->StartVibrate();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_033
 * @tc.desc  : Test AudioHapticPlayerImpl::StartVibrate()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_033, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    audioHapticPlayerImpl->muteHaptic_ = false;
    audioHapticPlayerImpl->isVibrationStopped_ = false;
    audioHapticPlayerImpl->loop_ = true;

    auto ret = audioHapticPlayerImpl->StartVibrate();
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_034
 * @tc.desc  : Test AudioHapticPlayerImpl::StartVibrate()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_034, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    audioHapticPlayerImpl->muteHaptic_ = false;
    audioHapticPlayerImpl->isVibrationStopped_ = false;
    audioHapticPlayerImpl->loop_ = false;

    auto ret = audioHapticPlayerImpl->StartVibrate();
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_035
 * @tc.desc  : Test AudioHapticPlayerImpl::StopVibrate()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_035, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    AudioHapticPlayerImpl audioHapticPlayerImpl2;
    audioHapticPlayerImpl->audioHapticVibrator_ = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl2);
    EXPECT_NE(audioHapticPlayerImpl->audioHapticVibrator_, nullptr);

    audioHapticPlayerImpl->vibrateThread_ = std::make_shared<std::thread>();
    EXPECT_NE(audioHapticPlayerImpl->vibrateThread_, nullptr);

    audioHapticPlayerImpl->StopVibrate();
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_036
 * @tc.desc  : Test AudioHapticPlayerImpl::StopVibrate()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_036, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    audioHapticPlayerImpl->audioHapticVibrator_ = nullptr;
    audioHapticPlayerImpl->vibrateThread_ = nullptr;

    audioHapticPlayerImpl->StopVibrate();
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_037
 * @tc.desc  : Test AudioHapticPlayerImpl::ResetVibrateState()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_037, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    AudioHapticPlayerImpl audioHapticPlayerImpl2;
    audioHapticPlayerImpl->audioHapticVibrator_ = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl2);
    EXPECT_NE(audioHapticPlayerImpl->audioHapticVibrator_, nullptr);

    audioHapticPlayerImpl->ResetVibrateState();
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_038
 * @tc.desc  : Test AudioHapticPlayerImpl::ResetVibrateState()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_038, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    audioHapticPlayerImpl->audioHapticVibrator_ = nullptr;

    audioHapticPlayerImpl->ResetVibrateState();
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_039
 * @tc.desc  : Test AudioHapticPlayerImpl::NotifyInterruptEvent()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_039, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    AudioStandard::InterruptEvent interruptEvent;
    std::shared_ptr<AudioHapticPlayerCallback> playerCallback = std::make_shared<AudioHapticPlayerCallbackTest>();
    audioHapticPlayerImpl->audioHapticPlayerCallback_ = playerCallback;
    EXPECT_NE(audioHapticPlayerImpl->audioHapticPlayerCallback_.lock(), nullptr);

    audioHapticPlayerImpl->NotifyInterruptEvent(interruptEvent);
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_040
 * @tc.desc  : Test AudioHapticPlayerImpl::NotifyInterruptEvent()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_040, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    AudioStandard::InterruptEvent interruptEvent;
    audioHapticPlayerImpl->audioHapticPlayerCallback_.reset();

    audioHapticPlayerImpl->NotifyInterruptEvent(interruptEvent);
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_041
 * @tc.desc  : Test AudioHapticPlayerImpl::NotifyEndOfStreamEvent()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_041, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    std::shared_ptr<AudioHapticPlayerCallback> playerCallback = std::make_shared<AudioHapticPlayerCallbackTest>();
    audioHapticPlayerImpl->audioHapticPlayerCallback_ = playerCallback;
    EXPECT_NE(audioHapticPlayerImpl->audioHapticPlayerCallback_.lock(), nullptr);

    audioHapticPlayerImpl->NotifyEndOfStreamEvent();
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_042
 * @tc.desc  : Test AudioHapticPlayerImpl::NotifyEndOfStreamEvent()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_042, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    audioHapticPlayerImpl->audioHapticPlayerCallback_.reset();

    audioHapticPlayerImpl->NotifyEndOfStreamEvent();
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_043
 * @tc.desc  : Test AudioHapticPlayerImpl::HandleEndOfStreamEventThreadFunc()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_043, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    std::weak_ptr<AudioHapticPlayerImpl> player = audioHapticPlayerImpl;
    EXPECT_NE(player.lock(), nullptr);

    audioHapticPlayerImpl->HandleEndOfStreamEventThreadFunc(player);
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_044
 * @tc.desc  : Test AudioHapticPlayerImpl::HandleEndOfStreamEventThreadFunc()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_044, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    std::weak_ptr<AudioHapticPlayerImpl> player;

    audioHapticPlayerImpl->HandleEndOfStreamEventThreadFunc(player);
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_045
 * @tc.desc  : Test AudioHapticPlayerImpl::HandleEndOfStreamEvent()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_045, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    audioHapticPlayerImpl->playerState_ = AudioHapticPlayerState::STATE_RELEASED;

    audioHapticPlayerImpl->HandleEndOfStreamEvent();
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_046
 * @tc.desc  : Test AudioHapticPlayerImpl::HandleEndOfStreamEvent()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_046, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    audioHapticPlayerImpl->playerState_ = AudioHapticPlayerState::STATE_STOPPED;
    audioHapticPlayerImpl->HandleEndOfStreamEvent();
    EXPECT_EQ(audioHapticPlayerImpl->playerState_, AudioHapticPlayerState::STATE_STOPPED);

    audioHapticPlayerImpl->playerState_ = AudioHapticPlayerState::STATE_NEW;
    audioHapticPlayerImpl->HandleEndOfStreamEvent();
    EXPECT_EQ(audioHapticPlayerImpl->playerState_, AudioHapticPlayerState::STATE_STOPPED);

    int32_t syncId = 1;
    audioHapticPlayerImpl->audioHapticSyncId_ = syncId;
    audioHapticPlayerImpl->playerState_ = AudioHapticPlayerState::STATE_NEW;
    audioHapticPlayerImpl->HandleEndOfStreamEvent();
    EXPECT_EQ(audioHapticPlayerImpl->playerState_, AudioHapticPlayerState::STATE_STOPPED);
    EXPECT_EQ(audioHapticPlayerImpl->audioHapticSyncId_, syncId);

    audioHapticPlayerImpl->playerState_ = AudioHapticPlayerState::STATE_NEW;
    audioHapticPlayerImpl->isSupportDSPSync_ = false;
    audioHapticPlayerImpl->loop_ = true;
    audioHapticPlayerImpl->HandleEndOfStreamEvent();
    EXPECT_EQ(audioHapticPlayerImpl->playerState_, AudioHapticPlayerState::STATE_NEW);
    EXPECT_EQ(audioHapticPlayerImpl->audioHapticSyncId_, syncId);

    audioHapticPlayerImpl->isSupportDSPSync_ = true;
    audioHapticPlayerImpl->HandleEndOfStreamEvent();
    EXPECT_EQ(audioHapticPlayerImpl->playerState_, AudioHapticPlayerState::STATE_NEW);
    EXPECT_EQ(audioHapticPlayerImpl->audioHapticSyncId_, ++syncId);
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_047
 * @tc.desc  : Test AudioHapticPlayerImpl::NotifyErrorEvent()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_047, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    int32_t errCode = 0;
    std::shared_ptr<AudioHapticPlayerCallback> playerCallback = std::make_shared<AudioHapticPlayerCallbackTest>();
    audioHapticPlayerImpl->audioHapticPlayerCallback_ = playerCallback;
    EXPECT_NE(audioHapticPlayerImpl->audioHapticPlayerCallback_.lock(), nullptr);

    audioHapticPlayerImpl->NotifyErrorEvent(errCode);
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_048
 * @tc.desc  : Test AudioHapticPlayerImpl::NotifyErrorEvent()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_048, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    int32_t errCode = 0;
    audioHapticPlayerImpl->audioHapticPlayerCallback_.reset();

    audioHapticPlayerImpl->NotifyErrorEvent(errCode);
}

/**
 * @tc.name  : Test AudioHapticSoundCallbackImpl API
 * @tc.number: AudioHapticPlayerImpl_049
 * @tc.desc  : Test AudioHapticSoundCallbackImpl::OnEndOfStream()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_049, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();
    EXPECT_NE(audioHapticPlayerImpl, nullptr);
    auto audioHapticSoundCallbackImpl = std::make_shared<AudioHapticSoundCallbackImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticSoundCallbackImpl, nullptr);

    audioHapticSoundCallbackImpl->audioHapticPlayerImpl_ = audioHapticPlayerImpl;
    EXPECT_NE(audioHapticSoundCallbackImpl->audioHapticPlayerImpl_.lock(), nullptr);

    audioHapticSoundCallbackImpl->OnEndOfStream();
}

/**
 * @tc.name  : Test AudioHapticSoundCallbackImpl API
 * @tc.number: AudioHapticPlayerImpl_050
 * @tc.desc  : Test AudioHapticSoundCallbackImpl::OnEndOfStream()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_050, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();
    EXPECT_NE(audioHapticPlayerImpl, nullptr);
    auto audioHapticSoundCallbackImpl = std::make_shared<AudioHapticSoundCallbackImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticSoundCallbackImpl, nullptr);

    audioHapticSoundCallbackImpl->audioHapticPlayerImpl_.reset();

    audioHapticSoundCallbackImpl->OnEndOfStream();
}

/**
 * @tc.name  : Test AudioHapticSoundCallbackImpl API
 * @tc.number: AudioHapticPlayerImpl_051
 * @tc.desc  : Test AudioHapticSoundCallbackImpl::OnError()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_051, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();
    EXPECT_NE(audioHapticPlayerImpl, nullptr);
    auto audioHapticSoundCallbackImpl = std::make_shared<AudioHapticSoundCallbackImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticSoundCallbackImpl, nullptr);

    int32_t errorCode = 0;
    audioHapticSoundCallbackImpl->audioHapticPlayerImpl_ = audioHapticPlayerImpl;
    EXPECT_NE(audioHapticSoundCallbackImpl->audioHapticPlayerImpl_.lock(), nullptr);

    audioHapticSoundCallbackImpl->OnError(errorCode);
}

/**
 * @tc.name  : Test AudioHapticSoundCallbackImpl API
 * @tc.number: AudioHapticPlayerImpl_052
 * @tc.desc  : Test AudioHapticSoundCallbackImpl::OnError()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_052, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();
    EXPECT_NE(audioHapticPlayerImpl, nullptr);
    auto audioHapticSoundCallbackImpl = std::make_shared<AudioHapticSoundCallbackImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticSoundCallbackImpl, nullptr);

    int32_t errorCode = 0;
    audioHapticSoundCallbackImpl->audioHapticPlayerImpl_.reset();

    audioHapticSoundCallbackImpl->OnError(errorCode);
}

/**
 * @tc.name  : Test AudioHapticSoundCallbackImpl API
 * @tc.number: AudioHapticPlayerImpl_053
 * @tc.desc  : Test AudioHapticSoundCallbackImpl::interruptEvent()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_053, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();
    EXPECT_NE(audioHapticPlayerImpl, nullptr);
    auto audioHapticSoundCallbackImpl = std::make_shared<AudioHapticSoundCallbackImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticSoundCallbackImpl, nullptr);

    AudioStandard::InterruptEvent interruptEvent;
    audioHapticSoundCallbackImpl->audioHapticPlayerImpl_ = audioHapticPlayerImpl;
    EXPECT_NE(audioHapticSoundCallbackImpl->audioHapticPlayerImpl_.lock(), nullptr);

    audioHapticSoundCallbackImpl->OnInterrupt(interruptEvent);
}

/**
 * @tc.name  : Test AudioHapticSoundCallbackImpl API
 * @tc.number: AudioHapticPlayerImpl_054
 * @tc.desc  : Test AudioHapticSoundCallbackImpl::interruptEvent()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_054, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();
    EXPECT_NE(audioHapticPlayerImpl, nullptr);
    auto audioHapticSoundCallbackImpl = std::make_shared<AudioHapticSoundCallbackImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticSoundCallbackImpl, nullptr);

    AudioStandard::InterruptEvent interruptEvent;
    audioHapticSoundCallbackImpl->audioHapticPlayerImpl_.reset();

    audioHapticSoundCallbackImpl->OnInterrupt(interruptEvent);
}

/**
 * @tc.name  : Test AudioHapticSoundCallbackImpl API
 * @tc.number: AudioHapticPlayerImpl_055
 * @tc.desc  : Test AudioHapticSoundCallbackImpl::OnFirstFrameWriting()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_055, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();
    EXPECT_NE(audioHapticPlayerImpl, nullptr);
    auto audioHapticSoundCallbackImpl = std::make_shared<AudioHapticSoundCallbackImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticSoundCallbackImpl, nullptr);

    uint64_t latency = 0;
    audioHapticSoundCallbackImpl->audioHapticPlayerImpl_ = audioHapticPlayerImpl;
    EXPECT_NE(audioHapticSoundCallbackImpl->audioHapticPlayerImpl_.lock(), nullptr);

    audioHapticSoundCallbackImpl->OnFirstFrameWriting(latency);
}

/**
 * @tc.name  : Test AudioHapticSoundCallbackImpl API
 * @tc.number: AudioHapticPlayerImpl_056
 * @tc.desc  : Test AudioHapticSoundCallbackImpl::OnFirstFrameWriting()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_056, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();
    EXPECT_NE(audioHapticPlayerImpl, nullptr);
    auto audioHapticSoundCallbackImpl = std::make_shared<AudioHapticSoundCallbackImpl>(audioHapticPlayerImpl);
    EXPECT_NE(audioHapticSoundCallbackImpl, nullptr);

    uint64_t latency = 0;
    audioHapticSoundCallbackImpl->audioHapticPlayerImpl_.reset();

    audioHapticSoundCallbackImpl->OnFirstFrameWriting(latency);
}

/**
 * @tc.name  : Test EnableHapticsInSilentMode API
 * @tc.number: AudioHapticPlayerImpl_057
 * @tc.desc  : Test AudioHapticPlayerImpl::EnableHapticsInSilentMode()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_057, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();
    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    EXPECT_EQ(ERR_OPERATE_NOT_ALLOWED, audioHapticPlayerImpl->EnableHapticsInSilentMode(true));

    AudioHapticPlayerImpl audioHapticPlayerImpl2;
    auto audioHapticVibrator_ = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl2);
    audioHapticPlayerImpl->audioHapticVibrator_ = audioHapticVibrator_;
    EXPECT_NE(audioHapticPlayerImpl->audioHapticVibrator_, nullptr);
    
    audioHapticPlayerImpl->EnableHapticsInSilentMode(true);
    EXPECT_EQ(true, audioHapticVibrator_->enableInSilentMode_);

    audioHapticPlayerImpl->playerState_ = AudioHapticPlayerState::STATE_RUNNING;
    EXPECT_EQ(ERR_OPERATE_NOT_ALLOWED, audioHapticPlayerImpl->EnableHapticsInSilentMode(true));

    audioHapticPlayerImpl->playerState_ = AudioHapticPlayerState::STATE_RELEASED;
    EXPECT_EQ(ERR_OPERATE_NOT_ALLOWED, audioHapticPlayerImpl->EnableHapticsInSilentMode(true));
}

/**
 * @tc.name  : Test IsHapticsIntensityAdjustmentSupported API
 * @tc.number: AudioHapticPlayerImpl_058
 * @tc.desc  : Test AudioHapticPlayerImpl::IsHapticsIntensityAdjustmentSupported()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_058, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();
    EXPECT_NE(audioHapticPlayerImpl, nullptr);
    
    EXPECT_EQ(false, audioHapticPlayerImpl->IsHapticsIntensityAdjustmentSupported());

    AudioHapticPlayerImpl audioHapticPlayerImpl2;
    auto audioHapticVibrator_ = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl2);
    audioHapticPlayerImpl->audioHapticVibrator_ = audioHapticVibrator_;
    EXPECT_NE(audioHapticPlayerImpl->audioHapticVibrator_, nullptr);
    
    EXPECT_EQ(audioHapticPlayerImpl->IsHapticsIntensityAdjustmentSupported(),
        audioHapticVibrator_->IsHapticsCustomSupported());
}

/**
 * @tc.name  : Test SetHapticsFeature API
 * @tc.number: AudioHapticPlayerImpl_060
 * @tc.desc  : Test AudioHapticPlayerImpl::SetHapticsFeature()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_060, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();
    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    audioHapticPlayerImpl->playerState_ = AudioHapticPlayerState::STATE_RELEASED;
    EXPECT_EQ(ERR_OPERATE_NOT_ALLOWED, audioHapticPlayerImpl->SetHapticsFeature(HapticsFeature::GENTLE_HAPTICS));

    audioHapticPlayerImpl->playerState_ = AudioHapticPlayerState::STATE_STOPPED;
    EXPECT_EQ(ERR_OPERATE_NOT_ALLOWED, audioHapticPlayerImpl->SetHapticsFeature(HapticsFeature::GENTLE_HAPTICS));

    AudioHapticPlayerImpl audioHapticPlayerImpl2;
    auto audioHapticVibrator_ = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl2);
    audioHapticPlayerImpl->audioHapticVibrator_ = audioHapticVibrator_;
    EXPECT_NE(audioHapticPlayerImpl->audioHapticVibrator_, nullptr);

    audioHapticPlayerImpl->isGentle_.store(true);
    EXPECT_EQ(ERR_OPERATE_NOT_ALLOWED, audioHapticPlayerImpl->SetHapticsFeature(HapticsFeature::GENTLE_HAPTICS));
    
    audioHapticPlayerImpl->isGentle_.store(false);
    EXPECT_EQ(ERR_OPERATE_NOT_ALLOWED, audioHapticPlayerImpl->SetHapticsFeature(HapticsFeature::GENTLE_HAPTICS));
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_061
 * @tc.desc  : Test AudioHapticPlayerImpl::Start()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_061, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();
    EXPECT_NE(audioHapticPlayerImpl, nullptr);
    EXPECT_EQ(audioHapticPlayerImpl->audioHapticSyncId_, MSERR_OK);

    AudioHapticPlayerImpl audioHapticPlayerImpl2;
    audioHapticPlayerImpl->audioHapticVibrator_ = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl2);
    EXPECT_NE(audioHapticPlayerImpl->audioHapticVibrator_, nullptr);
    
    AudioSource audioSource;
    audioHapticPlayerImpl->audioHapticSound_ =
        std::make_shared<AudioHapticSoundNormalImpl>(audioSource, false, AudioStandard::STREAM_USAGE_UNKNOWN);
    EXPECT_NE(audioHapticPlayerImpl->audioHapticSound_, nullptr);

    audioHapticPlayerImpl->vibrateThread_ = nullptr;
    audioHapticPlayerImpl->isSupportDSPSync_ = true;
    auto ret = audioHapticPlayerImpl->Start();
    EXPECT_NE(ret, MSERR_OK);
    EXPECT_NE(audioHapticPlayerImpl->audioHapticSyncId_, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_063
 * @tc.desc  : Test AudioHapticPlayerImpl::ReleaseVibratorInternal()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_063, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    AudioHapticPlayerImpl audioHapticPlayerImpl2;
    audioHapticPlayerImpl->audioHapticVibrator_ = std::make_shared<AudioHapticVibratorImpl>(audioHapticPlayerImpl2);
    EXPECT_NE(audioHapticPlayerImpl->audioHapticVibrator_, nullptr);

    audioHapticPlayerImpl->vibrateThread_ = std::make_shared<std::thread>();
    EXPECT_NE(audioHapticPlayerImpl->vibrateThread_, nullptr);

    audioHapticPlayerImpl->ReleaseVibratorInternal();
}

/**
 * @tc.name  : Test AudioHapticPlayerImpl API
 * @tc.number: AudioHapticPlayerImpl_064
 * @tc.desc  : Test AudioHapticPlayerImpl::ReleaseVibratorInternal()
 */
HWTEST_F(AudioHapticPlayerImplUnitTest, AudioHapticPlayerImpl_064, TestSize.Level1)
{
    auto audioHapticPlayerImpl = std::make_shared<AudioHapticPlayerImpl>();

    EXPECT_NE(audioHapticPlayerImpl, nullptr);

    audioHapticPlayerImpl->audioHapticVibrator_ = nullptr;
    audioHapticPlayerImpl->vibrateThread_ = nullptr;

    audioHapticPlayerImpl->ReleaseVibratorInternal();
}
} // namespace Media
} // namespace OHOS