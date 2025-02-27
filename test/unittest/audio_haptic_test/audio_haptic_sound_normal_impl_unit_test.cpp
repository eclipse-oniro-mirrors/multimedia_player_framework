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

#include "audio_haptic_sound_normal_impl_unit_test.h"

namespace OHOS {
namespace Media {
using namespace testing::ext;
static float g_nuM1 = -1.0f;
static float g_nuM2 = 2.0f;
static float g_nuM3 = 0.5f;
static int32_t g_nuM4 = -1;

void AudioHapticSoundNormalImplUnitTest::SetUpTestCase(void) {}

void AudioHapticSoundNormalImplUnitTest::TearDownTestCase(void) {}

void AudioHapticSoundNormalImplUnitTest::SetUp(void) {}

void AudioHapticSoundNormalImplUnitTest::TearDown(void) {}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AudioHapticSoundNormalImpl_001
 * @tc.desc  : Test AudioHapticSoundNormalImpl::~AudioHapticSoundNormalImpl()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AudioHapticSoundNormalImpl_001, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    audioHapticSoundNormalImpl->avPlayer_ = PlayerFactory::CreatePlayer();
    EXPECT_NE(audioHapticSoundNormalImpl->avPlayer_, nullptr);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AudioHapticSoundNormalImpl_002
 * @tc.desc  : Test AudioHapticSoundNormalImpl::~AudioHapticSoundNormalImpl()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AudioHapticSoundNormalImpl_002, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    audioHapticSoundNormalImpl->avPlayer_ = nullptr;
    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AudioHapticSoundNormalImpl_003
 * @tc.desc  : Test AudioHapticSoundNormalImpl::PrepareSound()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AudioHapticSoundNormalImpl_003, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    audioHapticSoundNormalImpl->avPlayer_ = PlayerFactory::CreatePlayer();
    EXPECT_NE(audioHapticSoundNormalImpl->avPlayer_, nullptr);

    audioHapticSoundNormalImpl->audioUri_ = "abc";
    audioHapticSoundNormalImpl->configuredAudioUri_ = "abc";
    auto ret = audioHapticSoundNormalImpl->PrepareSound();

    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AudioHapticSoundNormalImpl_004
 * @tc.desc  : Test AudioHapticSoundNormalImpl::StartSound()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AudioHapticSoundNormalImpl_004, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    audioHapticSoundNormalImpl->avPlayer_ = PlayerFactory::CreatePlayer();
    EXPECT_NE(audioHapticSoundNormalImpl->avPlayer_, nullptr);

    audioHapticSoundNormalImpl->playerState_ = AudioHapticPlayerState::STATE_RUNNING;
    audioHapticSoundNormalImpl->audioUri_ = "abc";
    auto ret = audioHapticSoundNormalImpl->StartSound();

    EXPECT_EQ(ret, MSERR_START_FAILED);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AudioHapticSoundNormalImpl_005
 * @tc.desc  : Test AudioHapticSoundNormalImpl::StartSound()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AudioHapticSoundNormalImpl_005, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    audioHapticSoundNormalImpl->avPlayer_ = PlayerFactory::CreatePlayer();
    EXPECT_NE(audioHapticSoundNormalImpl->avPlayer_, nullptr);

    audioHapticSoundNormalImpl->playerState_ = AudioHapticPlayerState::STATE_STOPPED;
    audioHapticSoundNormalImpl->audioUri_ = "abc";
    auto ret = audioHapticSoundNormalImpl->StartSound();

    EXPECT_EQ(ret, MSERR_START_FAILED);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AudioHapticSoundNormalImpl_006
 * @tc.desc  : Test AudioHapticSoundNormalImpl::StartSound()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AudioHapticSoundNormalImpl_006, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    audioHapticSoundNormalImpl->avPlayer_ = PlayerFactory::CreatePlayer();
    EXPECT_NE(audioHapticSoundNormalImpl->avPlayer_, nullptr);

    audioHapticSoundNormalImpl->playerState_ = AudioHapticPlayerState::STATE_NEW;
    audioHapticSoundNormalImpl->audioUri_ = "abc";
    audioHapticSoundNormalImpl->configuredAudioUri_ = "abcd";
    auto ret = audioHapticSoundNormalImpl->StartSound();

    EXPECT_EQ(ret, MSERR_START_FAILED);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AudioHapticSoundNormalImpl_007
 * @tc.desc  : Test AudioHapticSoundNormalImpl::StartSound()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AudioHapticSoundNormalImpl_007, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    audioHapticSoundNormalImpl->avPlayer_ = PlayerFactory::CreatePlayer();
    EXPECT_NE(audioHapticSoundNormalImpl->avPlayer_, nullptr);

    audioHapticSoundNormalImpl->playerState_ = AudioHapticPlayerState::STATE_NEW;
    audioHapticSoundNormalImpl->audioUri_ = "abc";
    audioHapticSoundNormalImpl->configuredAudioUri_ = "abc";
    auto ret = audioHapticSoundNormalImpl->StartSound();

    EXPECT_EQ(ret, MSERR_START_FAILED);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AudioHapticSoundNormalImpl_008
 * @tc.desc  : Test AudioHapticSoundNormalImpl::StopSound()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AudioHapticSoundNormalImpl_008, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    audioHapticSoundNormalImpl->avPlayer_ = PlayerFactory::CreatePlayer();
    EXPECT_NE(audioHapticSoundNormalImpl->avPlayer_, nullptr);

    audioHapticSoundNormalImpl->playerState_ = AudioHapticPlayerState::STATE_NEW;
    auto ret = audioHapticSoundNormalImpl->StopSound();

    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AudioHapticSoundNormalImpl_009
 * @tc.desc  : Test AudioHapticSoundNormalImpl::StopSound()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AudioHapticSoundNormalImpl_009, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    audioHapticSoundNormalImpl->avPlayer_ = PlayerFactory::CreatePlayer();
    EXPECT_NE(audioHapticSoundNormalImpl->avPlayer_, nullptr);

    audioHapticSoundNormalImpl->playerState_ = AudioHapticPlayerState::STATE_STOPPED;
    auto ret = audioHapticSoundNormalImpl->StopSound();

    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AudioHapticSoundNormalImpl_010
 * @tc.desc  : Test AudioHapticSoundNormalImpl::ReleaseAVPlayer()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AudioHapticSoundNormalImpl_010, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    audioHapticSoundNormalImpl->avPlayer_ = PlayerFactory::CreatePlayer();
    EXPECT_NE(audioHapticSoundNormalImpl->avPlayer_, nullptr);
    audioHapticSoundNormalImpl->fileDes_ = 0;

    audioHapticSoundNormalImpl->ReleaseAVPlayer();
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AudioHapticSoundNormalImpl_011
 * @tc.desc  : Test AudioHapticSoundNormalImpl::ReleaseAVPlayer()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AudioHapticSoundNormalImpl_011, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    audioHapticSoundNormalImpl->avPlayer_ = nullptr;
    audioHapticSoundNormalImpl->fileDes_ = -1;

    audioHapticSoundNormalImpl->ReleaseAVPlayer();
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AudioHapticSoundNormalImpl_012
 * @tc.desc  : Test AudioHapticSoundNormalImpl::SetVolume()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AudioHapticSoundNormalImpl_012, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    float volume = g_nuM1;

    auto ret = audioHapticSoundNormalImpl->SetVolume(volume);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AudioHapticSoundNormalImpl_013
 * @tc.desc  : Test AudioHapticSoundNormalImpl::SetVolume()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AudioHapticSoundNormalImpl_013, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    float volume = g_nuM2;

    auto ret = audioHapticSoundNormalImpl->SetVolume(volume);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AudioHapticSoundNormalImpl_014
 * @tc.desc  : Test AudioHapticSoundNormalImpl::SetVolume()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AudioHapticSoundNormalImpl_014, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    float volume = g_nuM3;
    audioHapticSoundNormalImpl->playerState_ = AudioHapticPlayerState::STATE_NEW;
    audioHapticSoundNormalImpl->avPlayer_ = PlayerFactory::CreatePlayer();
    EXPECT_NE(audioHapticSoundNormalImpl->avPlayer_, nullptr);

    auto ret = audioHapticSoundNormalImpl->SetVolume(volume);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AudioHapticSoundNormalImpl_015
 * @tc.desc  : Test AudioHapticSoundNormalImpl::SetVolume()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AudioHapticSoundNormalImpl_015, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    float volume = g_nuM3;
    audioHapticSoundNormalImpl->playerState_ = AudioHapticPlayerState::STATE_RUNNING;
    audioHapticSoundNormalImpl->avPlayer_ = PlayerFactory::CreatePlayer();
    EXPECT_NE(audioHapticSoundNormalImpl->avPlayer_, nullptr);

    auto ret = audioHapticSoundNormalImpl->SetVolume(volume);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AudioHapticSoundNormalImpl_016
 * @tc.desc  : Test AudioHapticSoundNormalImpl::SetVolume()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AudioHapticSoundNormalImpl_016, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    float volume = g_nuM3;
    audioHapticSoundNormalImpl->playerState_ = AudioHapticPlayerState::STATE_PREPARED;
    audioHapticSoundNormalImpl->avPlayer_ = PlayerFactory::CreatePlayer();
    EXPECT_NE(audioHapticSoundNormalImpl->avPlayer_, nullptr);

    auto ret = audioHapticSoundNormalImpl->SetVolume(volume);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AudioHapticSoundNormalImpl_017
 * @tc.desc  : Test AudioHapticSoundNormalImpl::SetLoop()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AudioHapticSoundNormalImpl_017, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    bool loop = true;
    audioHapticSoundNormalImpl->playerState_ = AudioHapticPlayerState::STATE_NEW;
    audioHapticSoundNormalImpl->avPlayer_ = PlayerFactory::CreatePlayer();
    EXPECT_NE(audioHapticSoundNormalImpl->avPlayer_, nullptr);

    auto ret = audioHapticSoundNormalImpl->SetLoop(loop);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AudioHapticSoundNormalImpl_018
 * @tc.desc  : Test AudioHapticSoundNormalImpl::SetLoop()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AudioHapticSoundNormalImpl_018, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    bool loop = true;
    audioHapticSoundNormalImpl->playerState_ = AudioHapticPlayerState::STATE_RUNNING;
    audioHapticSoundNormalImpl->avPlayer_ = PlayerFactory::CreatePlayer();
    EXPECT_NE(audioHapticSoundNormalImpl->avPlayer_, nullptr);

    auto ret = audioHapticSoundNormalImpl->SetLoop(loop);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AudioHapticSoundNormalImpl_019
 * @tc.desc  : Test AudioHapticSoundNormalImpl::SetLoop()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AudioHapticSoundNormalImpl_019, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    bool loop = true;
    audioHapticSoundNormalImpl->playerState_ = AudioHapticPlayerState::STATE_PREPARED;
    audioHapticSoundNormalImpl->avPlayer_ = PlayerFactory::CreatePlayer();
    EXPECT_NE(audioHapticSoundNormalImpl->avPlayer_, nullptr);

    auto ret = audioHapticSoundNormalImpl->SetLoop(loop);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AudioHapticSoundNormalImpl_020
 * @tc.desc  : Test AudioHapticSoundNormalImpl::GetAudioCurrentTime()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AudioHapticSoundNormalImpl_020, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    audioHapticSoundNormalImpl->avPlayer_ = PlayerFactory::CreatePlayer();
    EXPECT_NE(audioHapticSoundNormalImpl->avPlayer_, nullptr);

    auto ret = audioHapticSoundNormalImpl->GetAudioCurrentTime();
    EXPECT_EQ(ret, g_nuM4);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AudioHapticSoundNormalImpl_021
 * @tc.desc  : Test AudioHapticSoundNormalImpl::GetAudioCurrentTime()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AudioHapticSoundNormalImpl_021, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    audioHapticSoundNormalImpl->avPlayer_ = nullptr;
    auto ret = audioHapticSoundNormalImpl->GetAudioCurrentTime();
    EXPECT_EQ(ret, g_nuM4);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AudioHapticSoundNormalImpl_022
 * @tc.desc  : Test AudioHapticSoundNormalImpl::SetAudioHapticSoundCallback()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AudioHapticSoundNormalImpl_022, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    auto callback = std::make_shared<AudioHapticSoundCallbackImpl>(std::make_shared<AudioHapticPlayerImpl>());
    EXPECT_NE(callback, nullptr);

    auto ret = audioHapticSoundNormalImpl->SetAudioHapticSoundCallback(callback);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AudioHapticSoundNormalImpl_023
 * @tc.desc  : Test AudioHapticSoundNormalImpl::SetAudioHapticSoundCallback()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AudioHapticSoundNormalImpl_023, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    std::shared_ptr<AudioHapticSoundCallback> callback = nullptr;
    auto ret = audioHapticSoundNormalImpl->SetAudioHapticSoundCallback(callback);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AudioHapticSoundNormalImpl_024
 * @tc.desc  : Test AudioHapticSoundNormalImpl::NotifyErrorEvent()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AudioHapticSoundNormalImpl_024, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    int32_t errorCode = MediaServiceErrCode::MSERR_UNSUPPORT_FILE;
    audioHapticSoundNormalImpl->audioHapticPlayerCallback_.reset();
    audioHapticSoundNormalImpl->NotifyErrorEvent(errorCode);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AudioHapticSoundNormalImpl_025
 * @tc.desc  : Test AudioHapticSoundNormalImpl::NotifyErrorEvent()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AudioHapticSoundNormalImpl_025, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    int32_t errorCode = MediaServiceErrCode::MSERR_OK;

    std::shared_ptr<AudioHapticSoundCallback> sharedcb =
        std::make_shared<AudioHapticSoundCallbackImpl>(std::make_shared<AudioHapticPlayerImpl>());
    audioHapticSoundNormalImpl->audioHapticPlayerCallback_ = sharedcb;
    EXPECT_NE(audioHapticSoundNormalImpl->audioHapticPlayerCallback_.lock(), nullptr);

    audioHapticSoundNormalImpl->NotifyErrorEvent(errorCode);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AudioHapticSoundNormalImpl_026
 * @tc.desc  : Test AudioHapticSoundNormalImpl::NotifyFirstFrameEvent()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AudioHapticSoundNormalImpl_026, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    uint64_t latency = 0;

    std::shared_ptr<AudioHapticSoundCallback> sharedcb =
        std::make_shared<AudioHapticSoundCallbackImpl>(std::make_shared<AudioHapticPlayerImpl>());
    audioHapticSoundNormalImpl->audioHapticPlayerCallback_ = sharedcb;
    EXPECT_NE(audioHapticSoundNormalImpl->audioHapticPlayerCallback_.lock(), nullptr);

    audioHapticSoundNormalImpl->NotifyFirstFrameEvent(latency);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AudioHapticSoundNormalImpl_027
 * @tc.desc  : Test AudioHapticSoundNormalImpl::NotifyFirstFrameEvent()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AudioHapticSoundNormalImpl_027, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    uint64_t latency = 0;

    audioHapticSoundNormalImpl->audioHapticPlayerCallback_.reset();
    audioHapticSoundNormalImpl->NotifyFirstFrameEvent(latency);
    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AudioHapticSoundNormalImpl_028
 * @tc.desc  : Test AudioHapticSoundNormalImpl::NotifyInterruptEvent()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AudioHapticSoundNormalImpl_028, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    AudioStandard::InterruptEvent interruptEvent;

    std::shared_ptr<AudioHapticSoundCallback> sharedcb =
        std::make_shared<AudioHapticSoundCallbackImpl>(std::make_shared<AudioHapticPlayerImpl>());
    audioHapticSoundNormalImpl->audioHapticPlayerCallback_ = sharedcb;
    EXPECT_NE(audioHapticSoundNormalImpl->audioHapticPlayerCallback_.lock(), nullptr);

    audioHapticSoundNormalImpl->NotifyInterruptEvent(interruptEvent);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AudioHapticSoundNormalImpl_029
 * @tc.desc  : Test AudioHapticSoundNormalImpl::NotifyInterruptEvent()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AudioHapticSoundNormalImpl_029, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    AudioStandard::InterruptEvent interruptEvent;

    audioHapticSoundNormalImpl->audioHapticPlayerCallback_.reset();
    audioHapticSoundNormalImpl->NotifyInterruptEvent(interruptEvent);
    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AudioHapticSoundNormalImpl_030
 * @tc.desc  : Test AudioHapticSoundNormalImpl::NotifyEndOfStreamEvent()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AudioHapticSoundNormalImpl_030, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    std::shared_ptr<AudioHapticSoundCallback> sharedcb =
        std::make_shared<AudioHapticSoundCallbackImpl>(std::make_shared<AudioHapticPlayerImpl>());
    audioHapticSoundNormalImpl->audioHapticPlayerCallback_ = sharedcb;
    EXPECT_NE(audioHapticSoundNormalImpl->audioHapticPlayerCallback_.lock(), nullptr);

    audioHapticSoundNormalImpl->NotifyEndOfStreamEvent();
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AudioHapticSoundNormalImpl_031
 * @tc.desc  : Test AudioHapticSoundNormalImpl::NotifyEndOfStreamEvent()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AudioHapticSoundNormalImpl_031, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    audioHapticSoundNormalImpl->audioHapticPlayerCallback_.reset();
    audioHapticSoundNormalImpl->NotifyEndOfStreamEvent();
    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AHSoundNormalCallback_032
 * @tc.desc  : Test AHSoundNormalCallback::OnError()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AHSoundNormalCallback_032, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    auto aHSoundNormalCallback = std::make_shared<AHSoundNormalCallback>(audioHapticSoundNormalImpl);
    EXPECT_NE(aHSoundNormalCallback, nullptr);

    std::shared_ptr<AudioHapticSoundNormalImpl> sharedcb =
        std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);
    aHSoundNormalCallback->soundNormalImpl_ = sharedcb;
    EXPECT_NE(aHSoundNormalCallback->soundNormalImpl_.lock(), nullptr);

    int32_t errorCode = 0;
    std::string errorMsg = "abc";
    aHSoundNormalCallback->OnError(errorCode, errorMsg);
    EXPECT_NE(aHSoundNormalCallback, nullptr);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AHSoundNormalCallback_033
 * @tc.desc  : Test AHSoundNormalCallback::OnError()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AHSoundNormalCallback_033, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    auto aHSoundNormalCallback = std::make_shared<AHSoundNormalCallback>(audioHapticSoundNormalImpl);
    EXPECT_NE(aHSoundNormalCallback, nullptr);

    aHSoundNormalCallback->soundNormalImpl_.reset();

    int32_t errorCode = 0;
    std::string errorMsg = "abc";
    aHSoundNormalCallback->OnError(errorCode, errorMsg);
    EXPECT_NE(aHSoundNormalCallback, nullptr);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AHSoundNormalCallback_034
 * @tc.desc  : Test AHSoundNormalCallback::OnInfo()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AHSoundNormalCallback_034, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    auto aHSoundNormalCallback = std::make_shared<AHSoundNormalCallback>(audioHapticSoundNormalImpl);
    EXPECT_NE(aHSoundNormalCallback, nullptr);

    aHSoundNormalCallback->soundNormalImpl_.reset();

    Media::PlayerOnInfoType type = PlayerOnInfoType::INFO_TYPE_STATE_CHANGE;
    int32_t extra = 0;
    Media::Format infoBody;
    aHSoundNormalCallback->OnInfo(type, extra, infoBody);
    EXPECT_NE(aHSoundNormalCallback, nullptr);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AHSoundNormalCallback_035
 * @tc.desc  : Test AHSoundNormalCallback::OnInfo()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AHSoundNormalCallback_035, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    auto aHSoundNormalCallback = std::make_shared<AHSoundNormalCallback>(audioHapticSoundNormalImpl);
    EXPECT_NE(aHSoundNormalCallback, nullptr);

    aHSoundNormalCallback->soundNormalImpl_.reset();

    Media::PlayerOnInfoType type = PlayerOnInfoType::INFO_TYPE_INTERRUPT_EVENT;
    int32_t extra = 0;
    Media::Format infoBody;
    aHSoundNormalCallback->OnInfo(type, extra, infoBody);
    EXPECT_NE(aHSoundNormalCallback, nullptr);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AHSoundNormalCallback_036
 * @tc.desc  : Test AHSoundNormalCallback::OnInfo()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AHSoundNormalCallback_036, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    auto aHSoundNormalCallback = std::make_shared<AHSoundNormalCallback>(audioHapticSoundNormalImpl);
    EXPECT_NE(aHSoundNormalCallback, nullptr);

    aHSoundNormalCallback->soundNormalImpl_.reset();

    Media::PlayerOnInfoType type = PlayerOnInfoType::INFO_TYPE_AUDIO_FIRST_FRAME;
    int32_t extra = 0;
    Media::Format infoBody;
    aHSoundNormalCallback->OnInfo(type, extra, infoBody);
    EXPECT_NE(aHSoundNormalCallback, nullptr);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AHSoundNormalCallback_037
 * @tc.desc  : Test AHSoundNormalCallback::OnInfo()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AHSoundNormalCallback_037, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    auto aHSoundNormalCallback = std::make_shared<AHSoundNormalCallback>(audioHapticSoundNormalImpl);
    EXPECT_NE(aHSoundNormalCallback, nullptr);

    aHSoundNormalCallback->soundNormalImpl_.reset();

    Media::PlayerOnInfoType type = PlayerOnInfoType::INFO_TYPE_AUDIO_DEVICE_CHANGE;
    int32_t extra = 0;
    Media::Format infoBody;
    aHSoundNormalCallback->OnInfo(type, extra, infoBody);
    EXPECT_NE(aHSoundNormalCallback, nullptr);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AHSoundNormalCallback_038
 * @tc.desc  : Test AHSoundNormalCallback::HandleStateChangeEvent()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AHSoundNormalCallback_038, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    auto aHSoundNormalCallback = std::make_shared<AHSoundNormalCallback>(audioHapticSoundNormalImpl);
    EXPECT_NE(aHSoundNormalCallback, nullptr);

    aHSoundNormalCallback->soundNormalImpl_.reset();

    int32_t extra = PlayerStates::PLAYER_STATE_ERROR;
    Format infoBody;
    aHSoundNormalCallback->HandleStateChangeEvent(extra, infoBody);
    EXPECT_EQ(aHSoundNormalCallback->playerState_, AudioHapticPlayerState::STATE_INVALID);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AHSoundNormalCallback_039
 * @tc.desc  : Test AHSoundNormalCallback::HandleStateChangeEvent()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AHSoundNormalCallback_039, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    auto aHSoundNormalCallback = std::make_shared<AHSoundNormalCallback>(audioHapticSoundNormalImpl);
    EXPECT_NE(aHSoundNormalCallback, nullptr);

    aHSoundNormalCallback->soundNormalImpl_.reset();

    int32_t extra = PlayerStates::PLAYER_IDLE;
    Format infoBody;
    aHSoundNormalCallback->HandleStateChangeEvent(extra, infoBody);
    EXPECT_EQ(aHSoundNormalCallback->playerState_, AudioHapticPlayerState::STATE_NEW);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AHSoundNormalCallback_040
 * @tc.desc  : Test AHSoundNormalCallback::HandleStateChangeEvent()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AHSoundNormalCallback_040, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    auto aHSoundNormalCallback = std::make_shared<AHSoundNormalCallback>(audioHapticSoundNormalImpl);
    EXPECT_NE(aHSoundNormalCallback, nullptr);

    std::shared_ptr<AudioHapticSoundNormalImpl> sharedcb =
        std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);
    aHSoundNormalCallback->soundNormalImpl_ = sharedcb;
    EXPECT_NE(aHSoundNormalCallback->soundNormalImpl_.lock(), nullptr);


    int32_t extra = PlayerStates::PLAYER_PREPARED;
    Format infoBody;
    aHSoundNormalCallback->HandleStateChangeEvent(extra, infoBody);
    EXPECT_EQ(aHSoundNormalCallback->playerState_, AudioHapticPlayerState::STATE_PREPARED);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AHSoundNormalCallback_041
 * @tc.desc  : Test AHSoundNormalCallback::HandleStateChangeEvent()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AHSoundNormalCallback_041, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    auto aHSoundNormalCallback = std::make_shared<AHSoundNormalCallback>(audioHapticSoundNormalImpl);
    EXPECT_NE(aHSoundNormalCallback, nullptr);

    aHSoundNormalCallback->soundNormalImpl_.reset();

    int32_t extra = PlayerStates::PLAYER_STARTED;
    Format infoBody;
    aHSoundNormalCallback->HandleStateChangeEvent(extra, infoBody);
    EXPECT_EQ(aHSoundNormalCallback->playerState_, AudioHapticPlayerState::STATE_RUNNING);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AHSoundNormalCallback_042
 * @tc.desc  : Test AHSoundNormalCallback::HandleStateChangeEvent()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AHSoundNormalCallback_042, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    auto aHSoundNormalCallback = std::make_shared<AHSoundNormalCallback>(audioHapticSoundNormalImpl);
    EXPECT_NE(aHSoundNormalCallback, nullptr);

    aHSoundNormalCallback->soundNormalImpl_.reset();

    int32_t extra = PlayerStates::PLAYER_PAUSED;
    Format infoBody;
    aHSoundNormalCallback->HandleStateChangeEvent(extra, infoBody);
    EXPECT_EQ(aHSoundNormalCallback->playerState_, AudioHapticPlayerState::STATE_PAUSED);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AHSoundNormalCallback_043
 * @tc.desc  : Test AHSoundNormalCallback::HandleStateChangeEvent()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AHSoundNormalCallback_043, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    auto aHSoundNormalCallback = std::make_shared<AHSoundNormalCallback>(audioHapticSoundNormalImpl);
    EXPECT_NE(aHSoundNormalCallback, nullptr);

    std::shared_ptr<AudioHapticSoundNormalImpl> sharedcb =
        std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);
    aHSoundNormalCallback->soundNormalImpl_ = sharedcb;
    EXPECT_NE(aHSoundNormalCallback->soundNormalImpl_.lock(), nullptr);


    int32_t extra = PlayerStates::PLAYER_PLAYBACK_COMPLETE;
    Format infoBody;
    aHSoundNormalCallback->HandleStateChangeEvent(extra, infoBody);
    EXPECT_EQ(aHSoundNormalCallback->playerState_, AudioHapticPlayerState::STATE_STOPPED);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AHSoundNormalCallback_044
 * @tc.desc  : Test AHSoundNormalCallback::HandleStateChangeEvent()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AHSoundNormalCallback_044, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    auto aHSoundNormalCallback = std::make_shared<AHSoundNormalCallback>(audioHapticSoundNormalImpl);
    EXPECT_NE(aHSoundNormalCallback, nullptr);

    aHSoundNormalCallback->soundNormalImpl_.reset();

    int32_t extra = PlayerStates::PLAYER_RELEASED;
    Format infoBody;
    aHSoundNormalCallback->HandleStateChangeEvent(extra, infoBody);
    EXPECT_EQ(aHSoundNormalCallback->playerState_, AudioHapticPlayerState::STATE_NEW);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AHSoundNormalCallback_045
 * @tc.desc  : Test AHSoundNormalCallback::HandleAudioInterruptEvent()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AHSoundNormalCallback_045, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    auto aHSoundNormalCallback = std::make_shared<AHSoundNormalCallback>(audioHapticSoundNormalImpl);
    EXPECT_NE(aHSoundNormalCallback, nullptr);

    aHSoundNormalCallback->soundNormalImpl_.reset();

    int32_t extra = PlayerStates::PLAYER_INITIALIZED;
    Format infoBody;
    aHSoundNormalCallback->HandleAudioInterruptEvent(extra, infoBody);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AHSoundNormalCallback_046
 * @tc.desc  : Test AHSoundNormalCallback::HandleAudioInterruptEvent()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AHSoundNormalCallback_046, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    auto aHSoundNormalCallback = std::make_shared<AHSoundNormalCallback>(audioHapticSoundNormalImpl);
    EXPECT_NE(aHSoundNormalCallback, nullptr);

    std::shared_ptr<AudioHapticSoundNormalImpl> sharedcb =
        std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);
    aHSoundNormalCallback->soundNormalImpl_ = sharedcb;
    EXPECT_NE(aHSoundNormalCallback->soundNormalImpl_.lock(), nullptr);

    int32_t extra = PlayerStates::PLAYER_INITIALIZED;
    Format infoBody;
    aHSoundNormalCallback->HandleAudioInterruptEvent(extra, infoBody);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AHSoundNormalCallback_047
 * @tc.desc  : Test AHSoundNormalCallback::HandleAudioFirstFrameEvent()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AHSoundNormalCallback_047, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    auto aHSoundNormalCallback = std::make_shared<AHSoundNormalCallback>(audioHapticSoundNormalImpl);
    EXPECT_NE(aHSoundNormalCallback, nullptr);

    std::shared_ptr<AudioHapticSoundNormalImpl> sharedcb =
        std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);
    aHSoundNormalCallback->soundNormalImpl_ = sharedcb;
    EXPECT_NE(aHSoundNormalCallback->soundNormalImpl_.lock(), nullptr);

    int32_t extra = PlayerStates::PLAYER_INITIALIZED;
    Format infoBody;
    aHSoundNormalCallback->HandleAudioFirstFrameEvent(extra, infoBody);
}

/**
 * @tc.name  : Test AudioHapticSoundNormalImpl API
 * @tc.number: AHSoundNormalCallback_048
 * @tc.desc  : Test AHSoundNormalCallback::HandleAudioInterruptEvent()
 */
HWTEST_F(AudioHapticSoundNormalImplUnitTest, AHSoundNormalCallback_048, TestSize.Level1)
{
    std::string audioUri = "123";
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    auto audioHapticSoundNormalImpl = std::make_shared<AudioHapticSoundNormalImpl>(audioUri, muteAudio, streamUsage);

    EXPECT_NE(audioHapticSoundNormalImpl, nullptr);

    auto aHSoundNormalCallback = std::make_shared<AHSoundNormalCallback>(audioHapticSoundNormalImpl);
    EXPECT_NE(aHSoundNormalCallback, nullptr);

    aHSoundNormalCallback->soundNormalImpl_.reset();

    int32_t extra = PlayerStates::PLAYER_INITIALIZED;
    Format infoBody;
    aHSoundNormalCallback->HandleAudioInterruptEvent(extra, infoBody);
}
} // namespace Media
} // namespace OHOS