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

#include "audio_haptic_sound_low_latency_impl_unit_test.h"

namespace OHOS {
namespace Media {

using namespace testing::ext;

const int32_t MAX_SOUND_POOL_STREAMS = 1;
const float NUM1 = -1.0f;
const float NUM2 = 2.0f;
const float NUM3 = 0.5f;

void AudioHapticSoundLowLatencyImplUnitTest::SetUpTestCase(void) {}

void AudioHapticSoundLowLatencyImplUnitTest::TearDownTestCase(void) {}

void AudioHapticSoundLowLatencyImplUnitTest::SetUp(void) {}

void AudioHapticSoundLowLatencyImplUnitTest::TearDown(void) {}

/**
 * @tc.name  : Test AudioHapticSoundLowLatencyImpl API
 * @tc.number: AudioHapticSoundLowLatencyImpl_001
 * @tc.desc  : Test AudioHapticSoundLowLatencyImpl::~AudioHapticSoundLowLatencyImpl()
 */
HWTEST_F(AudioHapticSoundLowLatencyImplUnitTest, AudioHapticSoundLowLatencyImpl_001, TestSize.Level1)
{
    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    bool parallelPlayFlag = true;
    auto audioHapticSoundLowLatencyImpl =
        std::make_shared<AudioHapticSoundLowLatencyImpl>(audioSource, muteAudio, streamUsage, parallelPlayFlag);

    EXPECT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    AudioStandard::AudioRendererInfo audioRendererInfo;
    audioRendererInfo.contentType = AudioStandard::ContentType::CONTENT_TYPE_UNKNOWN;
    audioRendererInfo.streamUsage = AudioStandard::STREAM_USAGE_UNKNOWN;
    audioRendererInfo.rendererFlags = 1;

    audioHapticSoundLowLatencyImpl->soundPoolPlayer_ =
        SoundPoolFactory::CreateSoundPool(MAX_SOUND_POOL_STREAMS, audioRendererInfo);

    EXPECT_NE(audioHapticSoundLowLatencyImpl->soundPoolPlayer_, nullptr);
}

/**
 * @tc.name  : Test AudioHapticSoundLowLatencyImpl API
 * @tc.number: AudioHapticSoundLowLatencyImpl_002
 * @tc.desc  : Test AudioHapticSoundLowLatencyImpl::~AudioHapticSoundLowLatencyImpl()
 */
HWTEST_F(AudioHapticSoundLowLatencyImplUnitTest, AudioHapticSoundLowLatencyImpl_002, TestSize.Level1)
{
    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    bool parallelPlayFlag = true;
    auto audioHapticSoundLowLatencyImpl =
        std::make_shared<AudioHapticSoundLowLatencyImpl>(audioSource, muteAudio, streamUsage, parallelPlayFlag);

    EXPECT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    audioHapticSoundLowLatencyImpl->soundPoolPlayer_ = nullptr;

    EXPECT_NE(audioHapticSoundLowLatencyImpl, nullptr);
}

/**
 * @tc.name  : Test AudioHapticSoundLowLatencyImpl API
 * @tc.number: AudioHapticSoundLowLatencyImpl_003
 * @tc.desc  : Test AudioHapticSoundLowLatencyImpl::OpenAudioSource()
 */
HWTEST_F(AudioHapticSoundLowLatencyImplUnitTest, AudioHapticSoundLowLatencyImpl_003, TestSize.Level1)
{
    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    bool parallelPlayFlag = true;
    auto audioHapticSoundLowLatencyImpl =
        std::make_shared<AudioHapticSoundLowLatencyImpl>(audioSource, muteAudio, streamUsage, parallelPlayFlag);

    EXPECT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    audioHapticSoundLowLatencyImpl->fileDes_ = 0;
    audioHapticSoundLowLatencyImpl->audioSource_ = {.audioUri = "123"};

    auto ret = audioHapticSoundLowLatencyImpl->OpenAudioSource();
    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticSoundLowLatencyImpl API
 * @tc.number: AudioHapticSoundLowLatencyImpl_004
 * @tc.desc  : Test AudioHapticSoundLowLatencyImpl::OpenAudioSource()
 */
HWTEST_F(AudioHapticSoundLowLatencyImplUnitTest, AudioHapticSoundLowLatencyImpl_004, TestSize.Level1)
{
    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    bool parallelPlayFlag = true;
    auto audioHapticSoundLowLatencyImpl =
        std::make_shared<AudioHapticSoundLowLatencyImpl>(audioSource, muteAudio, streamUsage, parallelPlayFlag);

    EXPECT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    audioHapticSoundLowLatencyImpl->fileDes_ = -1;
    audioHapticSoundLowLatencyImpl->audioSource_ = {.audioUri = "123"};

    auto ret = audioHapticSoundLowLatencyImpl->OpenAudioSource();
    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticSoundLowLatencyImpl API
 * @tc.number: AudioHapticSoundLowLatencyImpl_005
 * @tc.desc  : Test AudioHapticSoundLowLatencyImpl::StartSound()
 */
HWTEST_F(AudioHapticSoundLowLatencyImplUnitTest, AudioHapticSoundLowLatencyImpl_005, TestSize.Level1)
{
    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    bool parallelPlayFlag = true;
    auto audioHapticSoundLowLatencyImpl =
        std::make_shared<AudioHapticSoundLowLatencyImpl>(audioSource, muteAudio, streamUsage, parallelPlayFlag);

    EXPECT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    audioHapticSoundLowLatencyImpl->playerState_ = AudioHapticPlayerState::STATE_NEW;

    auto ret = audioHapticSoundLowLatencyImpl->StartSound();
    EXPECT_EQ(ret, MSERR_START_FAILED);
}

/**
 * @tc.name  : Test AudioHapticSoundLowLatencyImpl API
 * @tc.number: AudioHapticSoundLowLatencyImpl_006
 * @tc.desc  : Test AudioHapticSoundLowLatencyImpl::StartSound()
 */
HWTEST_F(AudioHapticSoundLowLatencyImplUnitTest, AudioHapticSoundLowLatencyImpl_006, TestSize.Level1)
{
    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    bool parallelPlayFlag = true;
    auto audioHapticSoundLowLatencyImpl =
        std::make_shared<AudioHapticSoundLowLatencyImpl>(audioSource, muteAudio, streamUsage, parallelPlayFlag);

    EXPECT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    AudioStandard::AudioRendererInfo audioRendererInfo;
    audioRendererInfo.contentType = AudioStandard::ContentType::CONTENT_TYPE_UNKNOWN;
    audioRendererInfo.streamUsage = AudioStandard::STREAM_USAGE_UNKNOWN;
    audioRendererInfo.rendererFlags = 1;

    audioHapticSoundLowLatencyImpl->soundPoolPlayer_ =
        SoundPoolFactory::CreateSoundPool(MAX_SOUND_POOL_STREAMS, audioRendererInfo);
    EXPECT_NE(audioHapticSoundLowLatencyImpl->soundPoolPlayer_, nullptr);

    audioHapticSoundLowLatencyImpl->playerState_ = AudioHapticPlayerState::STATE_STOPPED;

    auto ret = audioHapticSoundLowLatencyImpl->StartSound();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticSoundLowLatencyImpl API
 * @tc.number: AudioHapticSoundLowLatencyImpl_007
 * @tc.desc  : Test AudioHapticSoundLowLatencyImpl::StartSound()
 */
HWTEST_F(AudioHapticSoundLowLatencyImplUnitTest, AudioHapticSoundLowLatencyImpl_007, TestSize.Level1)
{
    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    bool parallelPlayFlag = true;
    auto audioHapticSoundLowLatencyImpl =
        std::make_shared<AudioHapticSoundLowLatencyImpl>(audioSource, muteAudio, streamUsage, parallelPlayFlag);

    EXPECT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    AudioStandard::AudioRendererInfo audioRendererInfo;
    audioRendererInfo.contentType = AudioStandard::ContentType::CONTENT_TYPE_UNKNOWN;
    audioRendererInfo.streamUsage = AudioStandard::STREAM_USAGE_UNKNOWN;
    audioRendererInfo.rendererFlags = 1;

    audioHapticSoundLowLatencyImpl->soundPoolPlayer_ =
        SoundPoolFactory::CreateSoundPool(MAX_SOUND_POOL_STREAMS, audioRendererInfo);

    audioHapticSoundLowLatencyImpl->playerState_ = AudioHapticPlayerState::STATE_RUNNING;
    EXPECT_NE(audioHapticSoundLowLatencyImpl->soundPoolPlayer_, nullptr);

    auto ret = audioHapticSoundLowLatencyImpl->StartSound();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticSoundLowLatencyImpl API
 * @tc.number: AudioHapticSoundLowLatencyImpl_008
 * @tc.desc  : Test AudioHapticSoundLowLatencyImpl::StartSound()
 */
HWTEST_F(AudioHapticSoundLowLatencyImplUnitTest, AudioHapticSoundLowLatencyImpl_008, TestSize.Level1)
{
    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    bool parallelPlayFlag = true;
    auto audioHapticSoundLowLatencyImpl =
        std::make_shared<AudioHapticSoundLowLatencyImpl>(audioSource, muteAudio, streamUsage, parallelPlayFlag);

    EXPECT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    AudioStandard::AudioRendererInfo audioRendererInfo;
    audioRendererInfo.contentType = AudioStandard::ContentType::CONTENT_TYPE_UNKNOWN;
    audioRendererInfo.streamUsage = AudioStandard::STREAM_USAGE_UNKNOWN;
    audioRendererInfo.rendererFlags = 1;

    audioHapticSoundLowLatencyImpl->soundPoolPlayer_ =
        SoundPoolFactory::CreateSoundPool(MAX_SOUND_POOL_STREAMS, audioRendererInfo);

    audioHapticSoundLowLatencyImpl->playerState_ = AudioHapticPlayerState::STATE_PREPARED;
    EXPECT_NE(audioHapticSoundLowLatencyImpl->soundPoolPlayer_, nullptr);

    auto ret = audioHapticSoundLowLatencyImpl->StartSound();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticSoundLowLatencyImpl API
 * @tc.number: AudioHapticSoundLowLatencyImpl_009
 * @tc.desc  : Test AudioHapticSoundLowLatencyImpl::ReleaseSoundPoolPlayer()
 */
HWTEST_F(AudioHapticSoundLowLatencyImplUnitTest, AudioHapticSoundLowLatencyImpl_009, TestSize.Level1)
{
    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    bool parallelPlayFlag = true;
    auto audioHapticSoundLowLatencyImpl =
        std::make_shared<AudioHapticSoundLowLatencyImpl>(audioSource, muteAudio, streamUsage, parallelPlayFlag);

    EXPECT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    AudioStandard::AudioRendererInfo audioRendererInfo;
    audioRendererInfo.contentType = AudioStandard::ContentType::CONTENT_TYPE_UNKNOWN;
    audioRendererInfo.streamUsage = AudioStandard::STREAM_USAGE_UNKNOWN;
    audioRendererInfo.rendererFlags = 1;

    audioHapticSoundLowLatencyImpl->soundPoolPlayer_ =
        SoundPoolFactory::CreateSoundPool(MAX_SOUND_POOL_STREAMS, audioRendererInfo);

    EXPECT_NE(audioHapticSoundLowLatencyImpl->soundPoolPlayer_, nullptr);

    audioHapticSoundLowLatencyImpl->fileDes_ = 0;

    audioHapticSoundLowLatencyImpl->ReleaseSoundPoolPlayer();
}

/**
 * @tc.name  : Test AudioHapticSoundLowLatencyImpl API
 * @tc.number: AudioHapticSoundLowLatencyImpl_010
 * @tc.desc  : Test AudioHapticSoundLowLatencyImpl::ReleaseSoundPoolPlayer()
 */
HWTEST_F(AudioHapticSoundLowLatencyImplUnitTest, AudioHapticSoundLowLatencyImpl_010, TestSize.Level1)
{
    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    bool parallelPlayFlag = true;
    auto audioHapticSoundLowLatencyImpl =
        std::make_shared<AudioHapticSoundLowLatencyImpl>(audioSource, muteAudio, streamUsage, parallelPlayFlag);

    EXPECT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    audioHapticSoundLowLatencyImpl->soundPoolPlayer_ = nullptr;
    audioHapticSoundLowLatencyImpl->fileDes_ = -1;

    audioHapticSoundLowLatencyImpl->ReleaseSoundPoolPlayer();
}

/**
 * @tc.name  : Test AudioHapticSoundLowLatencyImpl API
 * @tc.number: AudioHapticSoundLowLatencyImpl_011
 * @tc.desc  : Test AudioHapticSoundLowLatencyImpl::SetVolume()
 */
HWTEST_F(AudioHapticSoundLowLatencyImplUnitTest, AudioHapticSoundLowLatencyImpl_011, TestSize.Level1)
{
    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    bool parallelPlayFlag = true;
    auto audioHapticSoundLowLatencyImpl =
        std::make_shared<AudioHapticSoundLowLatencyImpl>(audioSource, muteAudio, streamUsage, parallelPlayFlag);

    EXPECT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    float volume = NUM1;

    auto ret = audioHapticSoundLowLatencyImpl->SetVolume(volume);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name  : Test AudioHapticSoundLowLatencyImpl API
 * @tc.number: AudioHapticSoundLowLatencyImpl_012
 * @tc.desc  : Test AudioHapticSoundLowLatencyImpl::SetVolume()
 */
HWTEST_F(AudioHapticSoundLowLatencyImplUnitTest, AudioHapticSoundLowLatencyImpl_012, TestSize.Level1)
{
    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    bool parallelPlayFlag = true;
    auto audioHapticSoundLowLatencyImpl =
        std::make_shared<AudioHapticSoundLowLatencyImpl>(audioSource, muteAudio, streamUsage, parallelPlayFlag);

    EXPECT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    float volume = NUM2;

    auto ret = audioHapticSoundLowLatencyImpl->SetVolume(volume);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name  : Test AudioHapticSoundLowLatencyImpl API
 * @tc.number: AudioHapticSoundLowLatencyImpl_013
 * @tc.desc  : Test AudioHapticSoundLowLatencyImpl::SetVolume()
 */
HWTEST_F(AudioHapticSoundLowLatencyImplUnitTest, AudioHapticSoundLowLatencyImpl_013, TestSize.Level1)
{
    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    bool parallelPlayFlag = true;
    auto audioHapticSoundLowLatencyImpl =
        std::make_shared<AudioHapticSoundLowLatencyImpl>(audioSource, muteAudio, streamUsage, parallelPlayFlag);

    EXPECT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    float volume = NUM3;
    audioHapticSoundLowLatencyImpl->playerState_ = AudioHapticPlayerState::STATE_NEW;

    auto ret = audioHapticSoundLowLatencyImpl->SetVolume(volume);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticSoundLowLatencyImpl API
 * @tc.number: AudioHapticSoundLowLatencyImpl_014
 * @tc.desc  : Test AudioHapticSoundLowLatencyImpl::SetVolume()
 */
HWTEST_F(AudioHapticSoundLowLatencyImplUnitTest, AudioHapticSoundLowLatencyImpl_014, TestSize.Level1)
{
    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    bool parallelPlayFlag = true;
    auto audioHapticSoundLowLatencyImpl =
        std::make_shared<AudioHapticSoundLowLatencyImpl>(audioSource, muteAudio, streamUsage, parallelPlayFlag);

    EXPECT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    float volume = NUM3;
    audioHapticSoundLowLatencyImpl->playerState_ = AudioHapticPlayerState::STATE_RUNNING;

    AudioStandard::AudioRendererInfo audioRendererInfo;
    audioRendererInfo.contentType = AudioStandard::ContentType::CONTENT_TYPE_UNKNOWN;
    audioRendererInfo.streamUsage = AudioStandard::STREAM_USAGE_UNKNOWN;
    audioRendererInfo.rendererFlags = 1;

    audioHapticSoundLowLatencyImpl->soundPoolPlayer_ =
        SoundPoolFactory::CreateSoundPool(MAX_SOUND_POOL_STREAMS, audioRendererInfo);

    audioHapticSoundLowLatencyImpl->streamID_ = 0;
    EXPECT_NE(audioHapticSoundLowLatencyImpl->soundPoolPlayer_, nullptr);

    auto ret = audioHapticSoundLowLatencyImpl->SetVolume(volume);
    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticSoundLowLatencyImpl API
 * @tc.number: AudioHapticSoundLowLatencyImpl_015
 * @tc.desc  : Test AudioHapticSoundLowLatencyImpl::SetVolume()
 */
HWTEST_F(AudioHapticSoundLowLatencyImplUnitTest, AudioHapticSoundLowLatencyImpl_015, TestSize.Level1)
{
    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    bool parallelPlayFlag = true;
    auto audioHapticSoundLowLatencyImpl =
        std::make_shared<AudioHapticSoundLowLatencyImpl>(audioSource, muteAudio, streamUsage, parallelPlayFlag);

    EXPECT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    float volume = NUM3;
    audioHapticSoundLowLatencyImpl->playerState_ = AudioHapticPlayerState::STATE_PREPARED;
    audioHapticSoundLowLatencyImpl->streamID_ = -1;

    auto ret = audioHapticSoundLowLatencyImpl->SetVolume(volume);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticSoundLowLatencyImpl API
 * @tc.number: AudioHapticSoundLowLatencyImpl_016
 * @tc.desc  : Test AudioHapticSoundLowLatencyImpl::SetLoop()
 */
HWTEST_F(AudioHapticSoundLowLatencyImplUnitTest, AudioHapticSoundLowLatencyImpl_016, TestSize.Level1)
{
    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    bool parallelPlayFlag = true;
    auto audioHapticSoundLowLatencyImpl =
        std::make_shared<AudioHapticSoundLowLatencyImpl>(audioSource, muteAudio, streamUsage, parallelPlayFlag);

    EXPECT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    bool loop = true;
    audioHapticSoundLowLatencyImpl->playerState_ = AudioHapticPlayerState::STATE_NEW;

    auto ret = audioHapticSoundLowLatencyImpl->SetLoop(loop);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticSoundLowLatencyImpl API
 * @tc.number: AudioHapticSoundLowLatencyImpl_017
 * @tc.desc  : Test AudioHapticSoundLowLatencyImpl::SetLoop()
 */
HWTEST_F(AudioHapticSoundLowLatencyImplUnitTest, AudioHapticSoundLowLatencyImpl_017, TestSize.Level1)
{
    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    bool parallelPlayFlag = true;
    auto audioHapticSoundLowLatencyImpl =
        std::make_shared<AudioHapticSoundLowLatencyImpl>(audioSource, muteAudio, streamUsage, parallelPlayFlag);

    EXPECT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    bool loop = true;
    audioHapticSoundLowLatencyImpl->playerState_ = AudioHapticPlayerState::STATE_RUNNING;
    audioHapticSoundLowLatencyImpl->streamID_ = 0;

    AudioStandard::AudioRendererInfo audioRendererInfo;
    audioRendererInfo.contentType = AudioStandard::ContentType::CONTENT_TYPE_UNKNOWN;
    audioRendererInfo.streamUsage = AudioStandard::STREAM_USAGE_UNKNOWN;
    audioRendererInfo.rendererFlags = 1;

    audioHapticSoundLowLatencyImpl->soundPoolPlayer_ =
        SoundPoolFactory::CreateSoundPool(MAX_SOUND_POOL_STREAMS, audioRendererInfo);
    EXPECT_NE(audioHapticSoundLowLatencyImpl->soundPoolPlayer_, nullptr);


    auto ret = audioHapticSoundLowLatencyImpl->SetLoop(loop);
    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticSoundLowLatencyImpl API
 * @tc.number: AudioHapticSoundLowLatencyImpl_018
 * @tc.desc  : Test AudioHapticSoundLowLatencyImpl::SetLoop()
 */
HWTEST_F(AudioHapticSoundLowLatencyImplUnitTest, AudioHapticSoundLowLatencyImpl_018, TestSize.Level1)
{
    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    bool parallelPlayFlag = true;
    auto audioHapticSoundLowLatencyImpl =
        std::make_shared<AudioHapticSoundLowLatencyImpl>(audioSource, muteAudio, streamUsage, parallelPlayFlag);

    EXPECT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    bool loop = true;
    audioHapticSoundLowLatencyImpl->playerState_ = AudioHapticPlayerState::STATE_PREPARED;
    audioHapticSoundLowLatencyImpl->streamID_ = -1;

    auto ret = audioHapticSoundLowLatencyImpl->SetLoop(loop);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticSoundLowLatencyImpl API
 * @tc.number: AudioHapticSoundLowLatencyImpl_019
 * @tc.desc  : Test AudioHapticSoundLowLatencyImpl::SetAudioHapticSoundCallback()
 */
HWTEST_F(AudioHapticSoundLowLatencyImplUnitTest, AudioHapticSoundLowLatencyImpl_019, TestSize.Level1)
{
    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    bool parallelPlayFlag = true;
    auto audioHapticSoundLowLatencyImpl =
        std::make_shared<AudioHapticSoundLowLatencyImpl>(audioSource, muteAudio, streamUsage, parallelPlayFlag);

    EXPECT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    auto callback = std::make_shared<AudioHapticSoundCallbackImpl>(std::make_shared<AudioHapticPlayerImpl>());
    EXPECT_NE(callback, nullptr);

    auto ret = audioHapticSoundLowLatencyImpl->SetAudioHapticSoundCallback(callback);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test AudioHapticSoundLowLatencyImpl API
 * @tc.number: AudioHapticSoundLowLatencyImpl_020
 * @tc.desc  : Test AudioHapticSoundLowLatencyImpl::SetAudioHapticSoundCallback()
 */
HWTEST_F(AudioHapticSoundLowLatencyImplUnitTest, AudioHapticSoundLowLatencyImpl_020, TestSize.Level1)
{
    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    bool parallelPlayFlag = true;
    auto audioHapticSoundLowLatencyImpl =
        std::make_shared<AudioHapticSoundLowLatencyImpl>(audioSource, muteAudio, streamUsage, parallelPlayFlag);

    EXPECT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    std::shared_ptr<AudioHapticSoundCallback> callback = nullptr;

    auto ret = audioHapticSoundLowLatencyImpl->SetAudioHapticSoundCallback(callback);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name  : Test AudioHapticSoundLowLatencyImpl API
 * @tc.number: AudioHapticSoundLowLatencyImpl_021
 * @tc.desc  : Test AudioHapticSoundLowLatencyImpl::NotifyErrorEvent()
 */
HWTEST_F(AudioHapticSoundLowLatencyImplUnitTest, AudioHapticSoundLowLatencyImpl_021, TestSize.Level1)
{
    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    bool parallelPlayFlag = true;
    auto audioHapticSoundLowLatencyImpl =
        std::make_shared<AudioHapticSoundLowLatencyImpl>(audioSource, muteAudio, streamUsage, parallelPlayFlag);

    EXPECT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    int32_t errorCode = MediaServiceErrCode::MSERR_UNSUPPORT_FILE;
    audioHapticSoundLowLatencyImpl->audioHapticPlayerCallback_.reset();
    audioHapticSoundLowLatencyImpl->NotifyErrorEvent(errorCode);
}

/**
 * @tc.name  : Test AudioHapticSoundLowLatencyImpl API
 * @tc.number: AudioHapticSoundLowLatencyImpl_022
 * @tc.desc  : Test AudioHapticSoundLowLatencyImpl::NotifyErrorEvent()
 */
HWTEST_F(AudioHapticSoundLowLatencyImplUnitTest, AudioHapticSoundLowLatencyImpl_022, TestSize.Level1)
{
    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    bool parallelPlayFlag = true;
    auto audioHapticSoundLowLatencyImpl =
        std::make_shared<AudioHapticSoundLowLatencyImpl>(audioSource, muteAudio, streamUsage, parallelPlayFlag);

    EXPECT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    int32_t errorCode = MediaServiceErrCode::MSERR_OK;

    std::shared_ptr<AudioHapticSoundCallback> sharedcb =
        std::make_shared<AudioHapticSoundCallbackImpl>(std::make_shared<AudioHapticPlayerImpl>());
        audioHapticSoundLowLatencyImpl->audioHapticPlayerCallback_ = sharedcb;

    EXPECT_NE(audioHapticSoundLowLatencyImpl->audioHapticPlayerCallback_.lock(), nullptr);

    audioHapticSoundLowLatencyImpl->NotifyErrorEvent(errorCode);
}

/**
 * @tc.name  : Test AudioHapticSoundLowLatencyImpl API
 * @tc.number: AudioHapticSoundLowLatencyImpl_023
 * @tc.desc  : Test AudioHapticSoundLowLatencyImpl::NotifyFirstFrameEvent()
 */
HWTEST_F(AudioHapticSoundLowLatencyImplUnitTest, AudioHapticSoundLowLatencyImpl_023, TestSize.Level1)
{
    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    bool parallelPlayFlag = true;
    auto audioHapticSoundLowLatencyImpl =
        std::make_shared<AudioHapticSoundLowLatencyImpl>(audioSource, muteAudio, streamUsage, parallelPlayFlag);

    EXPECT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    uint64_t latency = 0;

    audioHapticSoundLowLatencyImpl->audioHapticPlayerCallback_.reset();
    audioHapticSoundLowLatencyImpl->NotifyFirstFrameEvent(latency);
}

/**
 * @tc.name  : Test AudioHapticSoundLowLatencyImpl API
 * @tc.number: AudioHapticSoundLowLatencyImpl_024
 * @tc.desc  : Test AudioHapticSoundLowLatencyImpl::NotifyFirstFrameEvent()
 */
HWTEST_F(AudioHapticSoundLowLatencyImplUnitTest, AudioHapticSoundLowLatencyImpl_024, TestSize.Level1)
{
    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    bool parallelPlayFlag = true;
    auto audioHapticSoundLowLatencyImpl =
        std::make_shared<AudioHapticSoundLowLatencyImpl>(audioSource, muteAudio, streamUsage, parallelPlayFlag);

    EXPECT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    uint64_t latency = 0;

    std::shared_ptr<AudioHapticSoundCallback> sharedcb =
        std::make_shared<AudioHapticSoundCallbackImpl>(std::make_shared<AudioHapticPlayerImpl>());
        audioHapticSoundLowLatencyImpl->audioHapticPlayerCallback_ = sharedcb;

    EXPECT_NE(audioHapticSoundLowLatencyImpl->audioHapticPlayerCallback_.lock(), nullptr);

    audioHapticSoundLowLatencyImpl->NotifyFirstFrameEvent(latency);
}

/**
 * @tc.name  : Test AudioHapticSoundLowLatencyImpl API
 * @tc.number: AudioHapticSoundLowLatencyImpl_025
 * @tc.desc  : Test AudioHapticSoundLowLatencyImpl::NotifyEndOfStreamEvent()
 */
HWTEST_F(AudioHapticSoundLowLatencyImplUnitTest, AudioHapticSoundLowLatencyImpl_025, TestSize.Level1)
{
    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    bool parallelPlayFlag = true;
    auto audioHapticSoundLowLatencyImpl =
        std::make_shared<AudioHapticSoundLowLatencyImpl>(audioSource, muteAudio, streamUsage, parallelPlayFlag);

    EXPECT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    audioHapticSoundLowLatencyImpl->audioHapticPlayerCallback_.reset();
    audioHapticSoundLowLatencyImpl->NotifyEndOfStreamEvent();
}

/**
 * @tc.name  : Test AudioHapticSoundLowLatencyImpl API
 * @tc.number: AudioHapticSoundLowLatencyImpl_026
 * @tc.desc  : Test AudioHapticSoundLowLatencyImpl::NotifyEndOfStreamEvent()
 */
HWTEST_F(AudioHapticSoundLowLatencyImplUnitTest, AudioHapticSoundLowLatencyImpl_026, TestSize.Level1)
{
    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    bool parallelPlayFlag = true;
    auto audioHapticSoundLowLatencyImpl =
        std::make_shared<AudioHapticSoundLowLatencyImpl>(audioSource, muteAudio, streamUsage, parallelPlayFlag);

    EXPECT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    std::shared_ptr<AudioHapticSoundCallback> sharedcb =
        std::make_shared<AudioHapticSoundCallbackImpl>(std::make_shared<AudioHapticPlayerImpl>());
        audioHapticSoundLowLatencyImpl->audioHapticPlayerCallback_ = sharedcb;

    EXPECT_NE(audioHapticSoundLowLatencyImpl->audioHapticPlayerCallback_.lock(), nullptr);

    audioHapticSoundLowLatencyImpl->NotifyEndOfStreamEvent();
}

/**
 * @tc.name  : Test AHSoundLowLatencyCallback API
 * @tc.number: AudioHapticSoundLowLatencyImpl_027
 * @tc.desc  : Test AHSoundLowLatencyCallback::OnLoadCompleted()
 */
HWTEST_F(AudioHapticSoundLowLatencyImplUnitTest, AudioHapticSoundLowLatencyImpl_027, TestSize.Level1)
{
    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    bool parallelPlayFlag = true;
    auto audioHapticSoundLowLatencyImpl =
        std::make_shared<AudioHapticSoundLowLatencyImpl>(audioSource, muteAudio, streamUsage, parallelPlayFlag);

    EXPECT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    auto aHSoundLowLatencyCallback = std::make_shared<AHSoundLowLatencyCallback>(audioHapticSoundLowLatencyImpl);
    EXPECT_NE(aHSoundLowLatencyCallback, nullptr);

    int32_t soundId = 0;
    aHSoundLowLatencyCallback->soundLowLatencyImpl_.reset();

    aHSoundLowLatencyCallback->OnLoadCompleted(soundId);
}

/**
 * @tc.name  : Test AHSoundLowLatencyCallback API
 * @tc.number: AudioHapticSoundLowLatencyImpl_028
 * @tc.desc  : Test AHSoundLowLatencyCallback::OnLoadCompleted()
 */
HWTEST_F(AudioHapticSoundLowLatencyImplUnitTest, AudioHapticSoundLowLatencyImpl_028, TestSize.Level1)
{
    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    bool parallelPlayFlag = true;
    auto audioHapticSoundLowLatencyImpl =
        std::make_shared<AudioHapticSoundLowLatencyImpl>(audioSource, muteAudio, streamUsage, parallelPlayFlag);

    EXPECT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    auto aHSoundLowLatencyCallback = std::make_shared<AHSoundLowLatencyCallback>(audioHapticSoundLowLatencyImpl);
    EXPECT_NE(aHSoundLowLatencyCallback, nullptr);

    int32_t soundId = 0;

    std::shared_ptr<AudioHapticSoundLowLatencyImpl> sharedcb =
        std::make_shared<AudioHapticSoundLowLatencyImpl>(audioSource, muteAudio, streamUsage, parallelPlayFlag);
    aHSoundLowLatencyCallback->soundLowLatencyImpl_ = sharedcb;

    EXPECT_NE(aHSoundLowLatencyCallback->soundLowLatencyImpl_.lock(), nullptr);


    aHSoundLowLatencyCallback->OnLoadCompleted(soundId);
}

/**
 * @tc.name  : Test AHSoundLowLatencyCallback API
 * @tc.number: AudioHapticSoundLowLatencyImpl_029
 * @tc.desc  : Test AHSoundLowLatencyCallback::OnPlayFinished()
 */
HWTEST_F(AudioHapticSoundLowLatencyImplUnitTest, AudioHapticSoundLowLatencyImpl_029, TestSize.Level1)
{
    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    bool parallelPlayFlag = true;
    auto audioHapticSoundLowLatencyImpl =
        std::make_shared<AudioHapticSoundLowLatencyImpl>(audioSource, muteAudio, streamUsage, parallelPlayFlag);

    EXPECT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    auto aHSoundLowLatencyCallback = std::make_shared<AHSoundLowLatencyCallback>(audioHapticSoundLowLatencyImpl);
    EXPECT_NE(aHSoundLowLatencyCallback, nullptr);

    int32_t streamID = 0;
    aHSoundLowLatencyCallback->soundLowLatencyImpl_.reset();

    aHSoundLowLatencyCallback->OnPlayFinished(streamID);
}

/**
 * @tc.name  : Test AHSoundLowLatencyCallback API
 * @tc.number: AudioHapticSoundLowLatencyImpl_030
 * @tc.desc  : Test AHSoundLowLatencyCallback::OnPlayFinished()
 */
HWTEST_F(AudioHapticSoundLowLatencyImplUnitTest, AudioHapticSoundLowLatencyImpl_030, TestSize.Level1)
{
    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    bool parallelPlayFlag = true;
    auto audioHapticSoundLowLatencyImpl =
        std::make_shared<AudioHapticSoundLowLatencyImpl>(audioSource, muteAudio, streamUsage, parallelPlayFlag);

    EXPECT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    auto aHSoundLowLatencyCallback = std::make_shared<AHSoundLowLatencyCallback>(audioHapticSoundLowLatencyImpl);
    EXPECT_NE(aHSoundLowLatencyCallback, nullptr);

    int32_t streamID = 0;
    std::shared_ptr<AudioHapticSoundLowLatencyImpl> sharedcb =
        std::make_shared<AudioHapticSoundLowLatencyImpl>(audioSource, muteAudio, streamUsage, parallelPlayFlag);
    aHSoundLowLatencyCallback->soundLowLatencyImpl_ = sharedcb;

    EXPECT_NE(aHSoundLowLatencyCallback->soundLowLatencyImpl_.lock(), nullptr);

    aHSoundLowLatencyCallback->OnPlayFinished(streamID);
}

/**
 * @tc.name  : Test AHSoundLowLatencyCallback API
 * @tc.number: AudioHapticSoundLowLatencyImpl_031
 * @tc.desc  : Test AHSoundLowLatencyCallback::OnError()
 */
HWTEST_F(AudioHapticSoundLowLatencyImplUnitTest, AudioHapticSoundLowLatencyImpl_031, TestSize.Level1)
{
    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    bool parallelPlayFlag = true;
    auto audioHapticSoundLowLatencyImpl =
        std::make_shared<AudioHapticSoundLowLatencyImpl>(audioSource, muteAudio, streamUsage, parallelPlayFlag);

    EXPECT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    auto aHSoundLowLatencyCallback = std::make_shared<AHSoundLowLatencyCallback>(audioHapticSoundLowLatencyImpl);
    EXPECT_NE(aHSoundLowLatencyCallback, nullptr);

    int32_t errorCode = 0;
    aHSoundLowLatencyCallback->soundLowLatencyImpl_.reset();

    aHSoundLowLatencyCallback->OnError(errorCode);
}

/**
 * @tc.name  : Test AHSoundLowLatencyCallback API
 * @tc.number: AudioHapticSoundLowLatencyImpl_032
 * @tc.desc  : Test AHSoundLowLatencyCallback::OnError()
 */
HWTEST_F(AudioHapticSoundLowLatencyImplUnitTest, AudioHapticSoundLowLatencyImpl_032, TestSize.Level1)
{
    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    bool parallelPlayFlag = true;
    auto audioHapticSoundLowLatencyImpl =
        std::make_shared<AudioHapticSoundLowLatencyImpl>(audioSource, muteAudio, streamUsage, parallelPlayFlag);

    EXPECT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    auto aHSoundLowLatencyCallback = std::make_shared<AHSoundLowLatencyCallback>(audioHapticSoundLowLatencyImpl);
    EXPECT_NE(aHSoundLowLatencyCallback, nullptr);

    int32_t errorCode = 0;
    std::shared_ptr<AudioHapticSoundLowLatencyImpl> sharedcb =
        std::make_shared<AudioHapticSoundLowLatencyImpl>(audioSource, muteAudio, streamUsage, parallelPlayFlag);
    aHSoundLowLatencyCallback->soundLowLatencyImpl_ = sharedcb;

    EXPECT_NE(aHSoundLowLatencyCallback->soundLowLatencyImpl_.lock(), nullptr);

    aHSoundLowLatencyCallback->OnError(errorCode);
}

/**
 * @tc.name  : Test AHSoundFirstFrameCallback API
 * @tc.number: AudioHapticSoundLowLatencyImpl_033
 * @tc.desc  : Test AHSoundFirstFrameCallback::OnFirstAudioFrameWritingCallback()
 */
HWTEST_F(AudioHapticSoundLowLatencyImplUnitTest, AudioHapticSoundLowLatencyImpl_033, TestSize.Level1)
{
    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    bool parallelPlayFlag = true;
    auto audioHapticSoundLowLatencyImpl =
        std::make_shared<AudioHapticSoundLowLatencyImpl>(audioSource, muteAudio, streamUsage, parallelPlayFlag);

    EXPECT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    auto aHSoundFirstFrameCallback = std::make_shared<AHSoundFirstFrameCallback>(audioHapticSoundLowLatencyImpl);
    EXPECT_NE(aHSoundFirstFrameCallback, nullptr);

    uint64_t latency = 0;
    aHSoundFirstFrameCallback->soundLowLatencyImpl_.reset();

    aHSoundFirstFrameCallback->OnFirstAudioFrameWritingCallback(latency);
}

/**
 * @tc.name  : Test AHSoundFirstFrameCallback API
 * @tc.number: AudioHapticSoundLowLatencyImpl_034
 * @tc.desc  : Test AHSoundFirstFrameCallback::OnFirstAudioFrameWritingCallback()
 */
HWTEST_F(AudioHapticSoundLowLatencyImplUnitTest, AudioHapticSoundLowLatencyImpl_034, TestSize.Level1)
{
    AudioSource audioSource = {.audioUri = "123"};
    bool muteAudio = true;
    AudioStandard::StreamUsage streamUsage = AudioStandard::StreamUsage::STREAM_USAGE_UNKNOWN;
    bool parallelPlayFlag = true;
    auto audioHapticSoundLowLatencyImpl =
        std::make_shared<AudioHapticSoundLowLatencyImpl>(audioSource, muteAudio, streamUsage, parallelPlayFlag);

    EXPECT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    auto aHSoundFirstFrameCallback = std::make_shared<AHSoundFirstFrameCallback>(audioHapticSoundLowLatencyImpl);
    EXPECT_NE(aHSoundFirstFrameCallback, nullptr);

    uint64_t latency = 0;
    std::shared_ptr<AudioHapticSoundLowLatencyImpl> sharedcb =
        std::make_shared<AudioHapticSoundLowLatencyImpl>(audioSource, muteAudio, streamUsage, parallelPlayFlag);
    aHSoundFirstFrameCallback->soundLowLatencyImpl_ = sharedcb;

    EXPECT_NE(aHSoundFirstFrameCallback->soundLowLatencyImpl_.lock(), nullptr);

    aHSoundFirstFrameCallback->OnFirstAudioFrameWritingCallback(latency);
}
} // namespace Media
} // namespace OHOS