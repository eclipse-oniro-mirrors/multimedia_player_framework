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

    ASSERT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    AudioStandard::AudioRendererInfo audioRendererInfo;
    audioRendererInfo.contentType = AudioStandard::ContentType::CONTENT_TYPE_UNKNOWN;
    audioRendererInfo.streamUsage = AudioStandard::STREAM_USAGE_UNKNOWN;
    audioRendererInfo.rendererFlags = 1;

    audioHapticSoundLowLatencyImpl->soundPoolPlayer_ =
        SoundPoolFactory::CreateSoundPool(MAX_SOUND_POOL_STREAMS, audioRendererInfo);

    ASSERT_NE(audioHapticSoundLowLatencyImpl->soundPoolPlayer_, nullptr);
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

    ASSERT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    audioHapticSoundLowLatencyImpl->soundPoolPlayer_ = nullptr;
    // When soundPoolPlayer_ is nullptr, destructor skips ReleaseSoundInternal
    EXPECT_EQ(audioHapticSoundLowLatencyImpl->soundPoolPlayer_, nullptr);
    EXPECT_EQ(audioHapticSoundLowLatencyImpl->playerState_, AudioHapticPlayerState::STATE_NEW);
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

    ASSERT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    audioHapticSoundLowLatencyImpl->fileDes_ = 0;
    audioHapticSoundLowLatencyImpl->audioSource_ = {.audioUri = "123"};

    auto ret = audioHapticSoundLowLatencyImpl->OpenAudioSource();
    EXPECT_EQ(ret, MSERR_OPEN_FILE_FAILED);
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

    ASSERT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    audioHapticSoundLowLatencyImpl->fileDes_ = -1;
    audioHapticSoundLowLatencyImpl->audioSource_ = {.audioUri = "123"};

    auto ret = audioHapticSoundLowLatencyImpl->OpenAudioSource();
    EXPECT_EQ(ret, MSERR_OPEN_FILE_FAILED);
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

    ASSERT_NE(audioHapticSoundLowLatencyImpl, nullptr);

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

    ASSERT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    AudioStandard::AudioRendererInfo audioRendererInfo;
    audioRendererInfo.contentType = AudioStandard::ContentType::CONTENT_TYPE_UNKNOWN;
    audioRendererInfo.streamUsage = AudioStandard::STREAM_USAGE_UNKNOWN;
    audioRendererInfo.rendererFlags = 1;

    audioHapticSoundLowLatencyImpl->soundPoolPlayer_ =
        SoundPoolFactory::CreateSoundPool(MAX_SOUND_POOL_STREAMS, audioRendererInfo);
    ASSERT_NE(audioHapticSoundLowLatencyImpl->soundPoolPlayer_, nullptr);

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

    ASSERT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    AudioStandard::AudioRendererInfo audioRendererInfo;
    audioRendererInfo.contentType = AudioStandard::ContentType::CONTENT_TYPE_UNKNOWN;
    audioRendererInfo.streamUsage = AudioStandard::STREAM_USAGE_UNKNOWN;
    audioRendererInfo.rendererFlags = 1;

    audioHapticSoundLowLatencyImpl->soundPoolPlayer_ =
        SoundPoolFactory::CreateSoundPool(MAX_SOUND_POOL_STREAMS, audioRendererInfo);

    audioHapticSoundLowLatencyImpl->playerState_ = AudioHapticPlayerState::STATE_RUNNING;
    ASSERT_NE(audioHapticSoundLowLatencyImpl->soundPoolPlayer_, nullptr);

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

    ASSERT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    AudioStandard::AudioRendererInfo audioRendererInfo;
    audioRendererInfo.contentType = AudioStandard::ContentType::CONTENT_TYPE_UNKNOWN;
    audioRendererInfo.streamUsage = AudioStandard::STREAM_USAGE_UNKNOWN;
    audioRendererInfo.rendererFlags = 1;

    audioHapticSoundLowLatencyImpl->soundPoolPlayer_ =
        SoundPoolFactory::CreateSoundPool(MAX_SOUND_POOL_STREAMS, audioRendererInfo);

    audioHapticSoundLowLatencyImpl->playerState_ = AudioHapticPlayerState::STATE_PREPARED;
    ASSERT_NE(audioHapticSoundLowLatencyImpl->soundPoolPlayer_, nullptr);

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

    ASSERT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    AudioStandard::AudioRendererInfo audioRendererInfo;
    audioRendererInfo.contentType = AudioStandard::ContentType::CONTENT_TYPE_UNKNOWN;
    audioRendererInfo.streamUsage = AudioStandard::STREAM_USAGE_UNKNOWN;
    audioRendererInfo.rendererFlags = 1;

    audioHapticSoundLowLatencyImpl->soundPoolPlayer_ =
        SoundPoolFactory::CreateSoundPool(MAX_SOUND_POOL_STREAMS, audioRendererInfo);

    ASSERT_NE(audioHapticSoundLowLatencyImpl->soundPoolPlayer_, nullptr);

    audioHapticSoundLowLatencyImpl->fileDes_ = 0;

    audioHapticSoundLowLatencyImpl->ReleaseSoundPoolPlayer();
    // After ReleaseSoundPoolPlayer, soundPoolPlayer_ should be nullptr and fileDes_ should be -1
    EXPECT_EQ(audioHapticSoundLowLatencyImpl->soundPoolPlayer_, nullptr);
    EXPECT_EQ(audioHapticSoundLowLatencyImpl->soundPoolCallback_, nullptr);
    EXPECT_EQ(audioHapticSoundLowLatencyImpl->fileDes_, -1);
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

    ASSERT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    audioHapticSoundLowLatencyImpl->soundPoolPlayer_ = nullptr;
    audioHapticSoundLowLatencyImpl->fileDes_ = -1;

    audioHapticSoundLowLatencyImpl->ReleaseSoundPoolPlayer();
    // ReleaseSoundPoolPlayer with null player should not crash, state unchanged
    EXPECT_EQ(audioHapticSoundLowLatencyImpl->soundPoolPlayer_, nullptr);
    EXPECT_EQ(audioHapticSoundLowLatencyImpl->soundPoolCallback_, nullptr);
    EXPECT_EQ(audioHapticSoundLowLatencyImpl->fileDes_, -1);
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

    ASSERT_NE(audioHapticSoundLowLatencyImpl, nullptr);

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

    ASSERT_NE(audioHapticSoundLowLatencyImpl, nullptr);

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

    ASSERT_NE(audioHapticSoundLowLatencyImpl, nullptr);

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

    ASSERT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    float volume = NUM3;
    audioHapticSoundLowLatencyImpl->playerState_ = AudioHapticPlayerState::STATE_RUNNING;

    AudioStandard::AudioRendererInfo audioRendererInfo;
    audioRendererInfo.contentType = AudioStandard::ContentType::CONTENT_TYPE_UNKNOWN;
    audioRendererInfo.streamUsage = AudioStandard::STREAM_USAGE_UNKNOWN;
    audioRendererInfo.rendererFlags = 1;

    audioHapticSoundLowLatencyImpl->soundPoolPlayer_ =
        SoundPoolFactory::CreateSoundPool(MAX_SOUND_POOL_STREAMS, audioRendererInfo);

    audioHapticSoundLowLatencyImpl->streamID_ = 0;
    ASSERT_NE(audioHapticSoundLowLatencyImpl->soundPoolPlayer_, nullptr);

    auto ret = audioHapticSoundLowLatencyImpl->SetVolume(volume);
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
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

    ASSERT_NE(audioHapticSoundLowLatencyImpl, nullptr);

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

    ASSERT_NE(audioHapticSoundLowLatencyImpl, nullptr);

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

    ASSERT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    bool loop = true;
    audioHapticSoundLowLatencyImpl->playerState_ = AudioHapticPlayerState::STATE_RUNNING;
    audioHapticSoundLowLatencyImpl->streamID_ = 0;

    AudioStandard::AudioRendererInfo audioRendererInfo;
    audioRendererInfo.contentType = AudioStandard::ContentType::CONTENT_TYPE_UNKNOWN;
    audioRendererInfo.streamUsage = AudioStandard::STREAM_USAGE_UNKNOWN;
    audioRendererInfo.rendererFlags = 1;

    audioHapticSoundLowLatencyImpl->soundPoolPlayer_ =
        SoundPoolFactory::CreateSoundPool(MAX_SOUND_POOL_STREAMS, audioRendererInfo);
    ASSERT_NE(audioHapticSoundLowLatencyImpl->soundPoolPlayer_, nullptr);


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

    ASSERT_NE(audioHapticSoundLowLatencyImpl, nullptr);

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

    ASSERT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    auto callback = std::make_shared<AudioHapticSoundCallbackImpl>(std::make_shared<AudioHapticPlayerImpl>());
    ASSERT_NE(callback, nullptr);

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

    ASSERT_NE(audioHapticSoundLowLatencyImpl, nullptr);

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

    ASSERT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    int32_t errorCode = MediaServiceErrCode::MSERR_UNSUPPORT_FILE;
    audioHapticSoundLowLatencyImpl->audioHapticPlayerCallback_.reset();
    audioHapticSoundLowLatencyImpl->NotifyErrorEvent(errorCode);
    // MSERR_UNSUPPORT_FILE sets isUnsupportedFile_ to true
    EXPECT_EQ(audioHapticSoundLowLatencyImpl->isUnsupportedFile_, true);
    EXPECT_EQ(audioHapticSoundLowLatencyImpl->audioHapticPlayerCallback_.lock(), nullptr);
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

    ASSERT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    int32_t errorCode = MediaServiceErrCode::MSERR_OK;

    std::shared_ptr<AudioHapticSoundCallback> sharedcb =
        std::make_shared<AudioHapticSoundCallbackImpl>(std::make_shared<AudioHapticPlayerImpl>());
        audioHapticSoundLowLatencyImpl->audioHapticPlayerCallback_ = sharedcb;

    ASSERT_NE(audioHapticSoundLowLatencyImpl->audioHapticPlayerCallback_.lock(), nullptr);

    audioHapticSoundLowLatencyImpl->NotifyErrorEvent(errorCode);
    // MSERR_OK is not MSERR_UNSUPPORT_FILE, so isUnsupportedFile_ remains false
    EXPECT_EQ(audioHapticSoundLowLatencyImpl->isUnsupportedFile_, false);
    ASSERT_NE(audioHapticSoundLowLatencyImpl->audioHapticPlayerCallback_.lock(), nullptr);
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

    ASSERT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    uint64_t latency = 0;

    audioHapticSoundLowLatencyImpl->audioHapticPlayerCallback_.reset();
    audioHapticSoundLowLatencyImpl->NotifyFirstFrameEvent(latency);
    // Callback remains null after notification with null callback
    EXPECT_EQ(audioHapticSoundLowLatencyImpl->audioHapticPlayerCallback_.lock(), nullptr);
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

    ASSERT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    uint64_t latency = 0;

    std::shared_ptr<AudioHapticSoundCallback> sharedcb =
        std::make_shared<AudioHapticSoundCallbackImpl>(std::make_shared<AudioHapticPlayerImpl>());
        audioHapticSoundLowLatencyImpl->audioHapticPlayerCallback_ = sharedcb;

    ASSERT_NE(audioHapticSoundLowLatencyImpl->audioHapticPlayerCallback_.lock(), nullptr);

    audioHapticSoundLowLatencyImpl->NotifyFirstFrameEvent(latency);
    // NotifyFirstFrameEvent forwards event to callback, callback object remains valid
    EXPECT_EQ(audioHapticSoundLowLatencyImpl->audioHapticPlayerCallback_.lock(), sharedcb);
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

    ASSERT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    audioHapticSoundLowLatencyImpl->audioHapticPlayerCallback_.reset();
    audioHapticSoundLowLatencyImpl->NotifyEndOfStreamEvent();
    // NotifyEndOfStreamEvent sets playerState_ to STATE_STOPPED
    EXPECT_EQ(audioHapticSoundLowLatencyImpl->playerState_, AudioHapticPlayerState::STATE_STOPPED);
    EXPECT_EQ(audioHapticSoundLowLatencyImpl->audioHapticPlayerCallback_.lock(), nullptr);
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

    ASSERT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    std::shared_ptr<AudioHapticSoundCallback> sharedcb =
        std::make_shared<AudioHapticSoundCallbackImpl>(std::make_shared<AudioHapticPlayerImpl>());
        audioHapticSoundLowLatencyImpl->audioHapticPlayerCallback_ = sharedcb;

    ASSERT_NE(audioHapticSoundLowLatencyImpl->audioHapticPlayerCallback_.lock(), nullptr);

    audioHapticSoundLowLatencyImpl->NotifyEndOfStreamEvent();
    // NotifyEndOfStreamEvent sets playerState_ to STATE_STOPPED
    EXPECT_EQ(audioHapticSoundLowLatencyImpl->playerState_, AudioHapticPlayerState::STATE_STOPPED);
    ASSERT_NE(audioHapticSoundLowLatencyImpl->audioHapticPlayerCallback_.lock(), nullptr);
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

    ASSERT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    auto aHSoundLowLatencyCallback = std::make_shared<AHSoundLowLatencyCallback>(audioHapticSoundLowLatencyImpl);
    ASSERT_NE(aHSoundLowLatencyCallback, nullptr);

    int32_t soundId = 0;
    aHSoundLowLatencyCallback->soundLowLatencyImpl_.reset();

    aHSoundLowLatencyCallback->OnLoadCompleted(soundId);
    // With expired impl, OnLoadCompleted returns early
    EXPECT_EQ(aHSoundLowLatencyCallback->soundLowLatencyImpl_.lock(), nullptr);
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

    ASSERT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    auto aHSoundLowLatencyCallback = std::make_shared<AHSoundLowLatencyCallback>(audioHapticSoundLowLatencyImpl);
    ASSERT_NE(aHSoundLowLatencyCallback, nullptr);

    int32_t soundId = 0;

    std::shared_ptr<AudioHapticSoundLowLatencyImpl> sharedcb =
        std::make_shared<AudioHapticSoundLowLatencyImpl>(audioSource, muteAudio, streamUsage, parallelPlayFlag);
    aHSoundLowLatencyCallback->soundLowLatencyImpl_ = sharedcb;

    ASSERT_NE(aHSoundLowLatencyCallback->soundLowLatencyImpl_.lock(), nullptr);


    aHSoundLowLatencyCallback->OnLoadCompleted(soundId);
    // OnLoadCompleted → NotifyPreparedEvent → sets isPrepared_ = true
    EXPECT_EQ(sharedcb->isPrepared_, true);
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

    ASSERT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    auto aHSoundLowLatencyCallback = std::make_shared<AHSoundLowLatencyCallback>(audioHapticSoundLowLatencyImpl);
    ASSERT_NE(aHSoundLowLatencyCallback, nullptr);

    int32_t streamID = 0;
    aHSoundLowLatencyCallback->soundLowLatencyImpl_.reset();

    aHSoundLowLatencyCallback->OnPlayFinished(streamID);
    // With expired impl, OnPlayFinished returns early
    EXPECT_EQ(aHSoundLowLatencyCallback->soundLowLatencyImpl_.lock(), nullptr);
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

    ASSERT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    auto aHSoundLowLatencyCallback = std::make_shared<AHSoundLowLatencyCallback>(audioHapticSoundLowLatencyImpl);
    ASSERT_NE(aHSoundLowLatencyCallback, nullptr);

    int32_t streamID = 0;
    std::shared_ptr<AudioHapticSoundLowLatencyImpl> sharedcb =
        std::make_shared<AudioHapticSoundLowLatencyImpl>(audioSource, muteAudio, streamUsage, parallelPlayFlag);
    aHSoundLowLatencyCallback->soundLowLatencyImpl_ = sharedcb;

    ASSERT_NE(aHSoundLowLatencyCallback->soundLowLatencyImpl_.lock(), nullptr);

    aHSoundLowLatencyCallback->OnPlayFinished(streamID);
    // OnPlayFinished → NotifyEndOfStreamEvent → sets playerState_ = STATE_STOPPED
    EXPECT_EQ(sharedcb->playerState_, AudioHapticPlayerState::STATE_STOPPED);
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

    ASSERT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    auto aHSoundLowLatencyCallback = std::make_shared<AHSoundLowLatencyCallback>(audioHapticSoundLowLatencyImpl);
    ASSERT_NE(aHSoundLowLatencyCallback, nullptr);

    int32_t errorCode = 0;
    aHSoundLowLatencyCallback->soundLowLatencyImpl_.reset();

    aHSoundLowLatencyCallback->OnError(errorCode);
    // With expired impl, OnError returns early
    EXPECT_EQ(aHSoundLowLatencyCallback->soundLowLatencyImpl_.lock(), nullptr);
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

    ASSERT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    auto aHSoundLowLatencyCallback = std::make_shared<AHSoundLowLatencyCallback>(audioHapticSoundLowLatencyImpl);
    ASSERT_NE(aHSoundLowLatencyCallback, nullptr);

    int32_t errorCode = 0;
    std::shared_ptr<AudioHapticSoundLowLatencyImpl> sharedcb =
        std::make_shared<AudioHapticSoundLowLatencyImpl>(audioSource, muteAudio, streamUsage, parallelPlayFlag);
    aHSoundLowLatencyCallback->soundLowLatencyImpl_ = sharedcb;

    ASSERT_NE(aHSoundLowLatencyCallback->soundLowLatencyImpl_.lock(), nullptr);

    aHSoundLowLatencyCallback->OnError(errorCode);
    // OnError(0) → NotifyErrorEvent(MSERR_OK): isUnsupportedFile_ stays false, no callback to forward to
    EXPECT_EQ(sharedcb->isUnsupportedFile_, false);
    EXPECT_EQ(sharedcb->audioHapticPlayerCallback_.lock(), nullptr);
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

    ASSERT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    auto aHSoundFirstFrameCallback = std::make_shared<AHSoundFirstFrameCallback>(audioHapticSoundLowLatencyImpl);
    ASSERT_NE(aHSoundFirstFrameCallback, nullptr);

    uint64_t latency = 0;
    aHSoundFirstFrameCallback->soundLowLatencyImpl_.reset();

    aHSoundFirstFrameCallback->OnFirstAudioFrameWritingCallback(latency);
    // With expired impl, OnFirstAudioFrameWritingCallback returns early
    EXPECT_EQ(aHSoundFirstFrameCallback->soundLowLatencyImpl_.lock(), nullptr);
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

    ASSERT_NE(audioHapticSoundLowLatencyImpl, nullptr);

    auto aHSoundFirstFrameCallback = std::make_shared<AHSoundFirstFrameCallback>(audioHapticSoundLowLatencyImpl);
    ASSERT_NE(aHSoundFirstFrameCallback, nullptr);

    uint64_t latency = 0;
    std::shared_ptr<AudioHapticSoundLowLatencyImpl> sharedcb =
        std::make_shared<AudioHapticSoundLowLatencyImpl>(audioSource, muteAudio, streamUsage, parallelPlayFlag);
    aHSoundFirstFrameCallback->soundLowLatencyImpl_ = sharedcb;

    ASSERT_NE(aHSoundFirstFrameCallback->soundLowLatencyImpl_.lock(), nullptr);

    aHSoundFirstFrameCallback->OnFirstAudioFrameWritingCallback(latency);
    // OnFirstAudioFrameWritingCallback → NotifyFirstFrameEvent: no callback to forward to
    EXPECT_EQ(sharedcb->audioHapticPlayerCallback_.lock(), nullptr);
}
} // namespace Media
} // namespace OHOS