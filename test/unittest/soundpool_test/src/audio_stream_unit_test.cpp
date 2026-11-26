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

#include <chrono>
#include <memory>

#include "audio_stream_unit_test.h"
#include "media_description.h"
#include "media_errors.h"
#include "media_log.h"

using namespace OHOS;
using namespace OHOS::Media;
using namespace testing::ext;
using namespace std;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SOUNDPOOL, "AudioStreamUnitTest"};

constexpr int32_t DEFAULT_SOUND_ID = 1;
constexpr int32_t DEFAULT_STREAM_ID = 10;
constexpr int32_t DEFAULT_PCM_BUFFER_SIZE = 2048;

class FakeAudioSharedMemory : public AudioStandard::AudioSharedMemory {
public:
    uint8_t *GetBase() override
    {
        return nullptr;
    }
    size_t GetSize() override
    {
        return 0;
    }
    int GetFd() override
    {
        return -1;
    }
    std::string GetName() override
    {
        return "fake";
    }
};

class AudioStreamTestCallback : public ISoundPoolCallback {
public:
    void OnLoadCompleted(int32_t soundId) override
    {
        (void)soundId;
    }
    void OnPlayFinished(int32_t streamID) override
    {
        (void)streamID;
        playFinishedCount_++;
    }
    void OnError(int32_t errorCode) override
    {
        (void)errorCode;
        errorCount_++;
    }

    int32_t playFinishedCount_ = 0;
    int32_t errorCount_ = 0;
};

class AudioStreamTestFrameWriteCallback : public ISoundPoolFrameWriteCallback {
public:
    void OnFirstAudioFrameWritingCallback(uint64_t &latency) override
    {
        latency_ = latency;
    }

    uint64_t latency_ = 0;
};
}  // namespace

namespace OHOS {
namespace Media {
void AudioStreamUnitTest::SetUpTestCase(void)
{}

void AudioStreamUnitTest::TearDownTestCase(void)
{
    std::cout << "sleep one second to protect AudioStream safely exit." << endl;
    sleep(1);
}

void AudioStreamUnitTest::SetUp(void)
{
    Format trackFormat;
    int32_t soundID = DEFAULT_SOUND_ID;
    int32_t streamID = DEFAULT_STREAM_ID;
    audioStream_ = std::make_shared<AudioStream>(trackFormat, soundID, streamID, nullptr);
}

void AudioStreamUnitTest::TearDown(void)
{
    if (audioStream_ != nullptr) {
        audioStream_.reset();
    }
}

/**
 * @tc.name: audioStream_function_001
 * @tc.desc: function test constructor initial state and soundID/streamID getters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AudioStreamUnitTest, audioStream_function_001, TestSize.Level2)
{
    MEDIA_LOGI("audioStream_function_001 before");
    EXPECT_EQ(DEFAULT_SOUND_ID, audioStream_->GetSoundID());
    EXPECT_EQ(DEFAULT_STREAM_ID, audioStream_->GetStreamID());
    EXPECT_EQ(StreamState::PREPARED, audioStream_->GetStreamState());
    EXPECT_EQ(0, audioStream_->GetPriority());
    MEDIA_LOGI("audioStream_function_001 after");
}

/**
 * @tc.name: audioStream_function_002
 * @tc.desc: function test SetPcmSharedMemory with null and valid buffer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AudioStreamUnitTest, audioStream_function_002, TestSize.Level2)
{
    MEDIA_LOGI("audioStream_function_002 before");
    EXPECT_FALSE(audioStream_->SetPcmSharedMemory(nullptr, DEFAULT_PCM_BUFFER_SIZE));
    std::shared_ptr<AudioStandard::AudioSharedMemory> pcmBuffer = std::make_shared<FakeAudioSharedMemory>();
    EXPECT_TRUE(audioStream_->SetPcmSharedMemory(pcmBuffer, DEFAULT_PCM_BUFFER_SIZE));
    EXPECT_EQ(pcmBuffer, audioStream_->pcmBuffer_);
    EXPECT_EQ(DEFAULT_PCM_BUFFER_SIZE, audioStream_->pcmBufferSize_);
    MEDIA_LOGI("audioStream_function_002 after");
}

/**
 * @tc.name: audioStream_function_003
 * @tc.desc: function test ConfigurePlayParameters and ConfigurePlayParametersWithoutLock
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AudioStreamUnitTest, audioStream_function_003, TestSize.Level2)
{
    MEDIA_LOGI("audioStream_function_003 before");
    AudioStandard::AudioRendererInfo audioRendererInfo;
    audioRendererInfo.contentType = AudioStandard::CONTENT_TYPE_MUSIC;
    audioRendererInfo.streamUsage = AudioStandard::STREAM_USAGE_MUSIC;
    audioRendererInfo.rendererFlags = 3;

    PlayParams playParams;
    playParams.loop = 2;
    playParams.rate = static_cast<int32_t>(AudioStandard::AudioRendererRate::RENDER_RATE_DOUBLE);
    playParams.leftVolume = 0.5f;
    playParams.rightVolume = 0.5f;
    playParams.priority = 4;
    playParams.parallelPlayFlag = true;
    playParams.audioHapticsSyncId = 6;
    playParams.pitch = 1.5f;

    audioStream_->ConfigurePlayParameters(audioRendererInfo, playParams);
    EXPECT_EQ(AudioStandard::CONTENT_TYPE_MUSIC, audioStream_->audioRendererInfo_.contentType);
    EXPECT_EQ(AudioStandard::STREAM_USAGE_MUSIC, audioStream_->audioRendererInfo_.streamUsage);
    EXPECT_EQ(3, audioStream_->audioRendererInfo_.rendererFlags);
    EXPECT_EQ(2, audioStream_->playParameters_.loop);
    EXPECT_EQ(4, audioStream_->playParameters_.priority);
    EXPECT_TRUE(audioStream_->playParameters_.parallelPlayFlag);
    EXPECT_EQ(6, audioStream_->playParameters_.audioHapticsSyncId);
    EXPECT_FLOAT_EQ(1.5f, audioStream_->playParameters_.pitch);

    playParams.loop = 5;
    playParams.priority = 8;
    audioStream_->ConfigurePlayParametersWithoutLock(audioRendererInfo, playParams);
    EXPECT_EQ(5, audioStream_->playParameters_.loop);
    EXPECT_EQ(8, audioStream_->playParameters_.priority);
    MEDIA_LOGI("audioStream_function_003 after");
}

/**
 * @tc.name: audioStream_function_004
 * @tc.desc: function test SetCallback, SetStreamCallback and SetFrameWriteCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AudioStreamUnitTest, audioStream_function_004, TestSize.Level2)
{
    MEDIA_LOGI("audioStream_function_004 before");
    std::shared_ptr<ISoundPoolCallback> callback = std::make_shared<AudioStreamTestCallback>();
    std::shared_ptr<ISoundPoolFrameWriteCallback> frameWriteCallback =
        std::make_shared<AudioStreamTestFrameWriteCallback>();
    EXPECT_EQ(MSERR_OK, audioStream_->SetCallback(callback));
    EXPECT_EQ(MSERR_OK, audioStream_->SetStreamCallback(callback));
    EXPECT_EQ(MSERR_OK, audioStream_->SetFrameWriteCallback(frameWriteCallback));
    EXPECT_EQ(callback, audioStream_->callback_);
    EXPECT_EQ(callback, audioStream_->streamCallback_);
    EXPECT_EQ(frameWriteCallback, audioStream_->frameWriteCallback_);
    MEDIA_LOGI("audioStream_function_004 after");
}

/**
 * @tc.name: audioStream_function_005
 * @tc.desc: function test SetSourceDuration, SetStreamState and GetStreamState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AudioStreamUnitTest, audioStream_function_005, TestSize.Level2)
{
    MEDIA_LOGI("audioStream_function_005 before");
    audioStream_->SetSourceDuration(1234);
    EXPECT_EQ(1234, audioStream_->sourceDurationMs_);

    audioStream_->SetStreamState(StreamState::PLAYING);
    EXPECT_EQ(StreamState::PLAYING, audioStream_->GetStreamState());
    audioStream_->SetStreamState(StreamState::STOPPED);
    EXPECT_EQ(StreamState::STOPPED, audioStream_->GetStreamState());
    MEDIA_LOGI("audioStream_function_005 after");
}

/**
 * @tc.name: audioStream_function_006
 * @tc.desc: function test SetPriority, SetPriorityWithoutLock and GetPriority
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AudioStreamUnitTest, audioStream_function_006, TestSize.Level2)
{
    MEDIA_LOGI("audioStream_function_006 before");
    EXPECT_EQ(MSERR_OK, audioStream_->SetPriority(5));
    EXPECT_EQ(5, audioStream_->GetPriority());
    EXPECT_EQ(MSERR_OK, audioStream_->SetPriorityWithoutLock(9));
    EXPECT_EQ(9, audioStream_->GetPriority());
    MEDIA_LOGI("audioStream_function_006 after");
}

/**
 * @tc.name: audioStream_function_007
 * @tc.desc: function test SetVolume, SetRate and SetLoop with null audioRenderer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AudioStreamUnitTest, audioStream_function_007, TestSize.Level2)
{
    MEDIA_LOGI("audioStream_function_007 before");
    EXPECT_EQ(MSERR_INVALID_VAL, audioStream_->SetVolume(0.5f, 0.5f));
    EXPECT_EQ(MSERR_INVALID_VAL, audioStream_->SetRate(AudioStandard::AudioRendererRate::RENDER_RATE_NORMAL));
    EXPECT_EQ(MSERR_INVALID_VAL, audioStream_->SetLoop(1));
    MEDIA_LOGI("audioStream_function_007 after");
}

/**
 * @tc.name: audioStream_function_008
 * @tc.desc: function test CheckAndAlignRendererRate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AudioStreamUnitTest, audioStream_function_008, TestSize.Level2)
{
    MEDIA_LOGI("audioStream_function_008 before");
    EXPECT_EQ(AudioStandard::AudioRendererRate::RENDER_RATE_NORMAL, AudioStream::CheckAndAlignRendererRate(
        static_cast<int32_t>(AudioStandard::AudioRendererRate::RENDER_RATE_NORMAL)));
    EXPECT_EQ(AudioStandard::AudioRendererRate::RENDER_RATE_DOUBLE, AudioStream::CheckAndAlignRendererRate(
        static_cast<int32_t>(AudioStandard::AudioRendererRate::RENDER_RATE_DOUBLE)));
    EXPECT_EQ(AudioStandard::AudioRendererRate::RENDER_RATE_HALF, AudioStream::CheckAndAlignRendererRate(
        static_cast<int32_t>(AudioStandard::AudioRendererRate::RENDER_RATE_HALF)));
    EXPECT_EQ(AudioStandard::AudioRendererRate::RENDER_RATE_NORMAL, AudioStream::CheckAndAlignRendererRate(100));
    MEDIA_LOGI("audioStream_function_008 after");
}

/**
 * @tc.name: audioStream_function_009
 * @tc.desc: function test IsAudioRendererCanMix
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AudioStreamUnitTest, audioStream_function_009, TestSize.Level2)
{
    MEDIA_LOGI("audioStream_function_009 before");
    AudioStandard::AudioRendererInfo audioRendererInfo;
    audioRendererInfo.contentType = AudioStandard::CONTENT_TYPE_MUSIC;
    audioRendererInfo.streamUsage = AudioStandard::STREAM_USAGE_MUSIC;
    EXPECT_TRUE(audioStream_->IsAudioRendererCanMix(audioRendererInfo));

    audioRendererInfo.contentType = AudioStandard::CONTENT_TYPE_UNKNOWN;
    audioRendererInfo.streamUsage = AudioStandard::STREAM_USAGE_VOICE_COMMUNICATION;
    EXPECT_FALSE(audioStream_->IsAudioRendererCanMix(audioRendererInfo));
    MEDIA_LOGI("audioStream_function_009 after");
}

/**
 * @tc.name: audioStream_function_010
 * @tc.desc: function test DealAudioRendererParams
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AudioStreamUnitTest, audioStream_function_010, TestSize.Level2)
{
    MEDIA_LOGI("audioStream_function_010 before");
    Format trackFormat;
    trackFormat.PutIntValue(MediaDescriptionKey::MD_KEY_SAMPLE_RATE,
        static_cast<int32_t>(AudioStandard::SAMPLE_RATE_48000));
    trackFormat.PutIntValue(MediaDescriptionKey::MD_KEY_AUDIO_SAMPLE_FORMAT,
        static_cast<int32_t>(AudioStandard::SAMPLE_S16LE));
    trackFormat.PutIntValue(MediaDescriptionKey::MD_KEY_CHANNEL_COUNT,
        static_cast<int32_t>(AudioStandard::STEREO));
    int32_t soundID = DEFAULT_SOUND_ID;
    int32_t streamID = DEFAULT_STREAM_ID;
    std::shared_ptr<AudioStream> audioStream = std::make_shared<AudioStream>(trackFormat, soundID, streamID, nullptr);
    std::shared_ptr<AudioStandard::AudioSharedMemory> pcmBuffer = std::make_shared<FakeAudioSharedMemory>();
    EXPECT_TRUE(audioStream->SetPcmSharedMemory(pcmBuffer, DEFAULT_PCM_BUFFER_SIZE));

    AudioStandard::AudioRendererInfo audioRendererInfo;
    audioRendererInfo.contentType = AudioStandard::CONTENT_TYPE_MUSIC;
    audioRendererInfo.streamUsage = AudioStandard::STREAM_USAGE_MUSIC;
    audioRendererInfo.rendererFlags = 7;
    AudioStandard::AudioRendererOptions rendererOptions = {};
    audioStream->DealAudioRendererParams(rendererOptions, audioRendererInfo);

    EXPECT_EQ(AudioStandard::ENCODING_PCM, rendererOptions.streamInfo.encoding);
    EXPECT_EQ(AudioStandard::SAMPLE_RATE_48000, rendererOptions.streamInfo.samplingRate);
    EXPECT_EQ(AudioStandard::SAMPLE_S16LE, rendererOptions.streamInfo.format);
    EXPECT_EQ(AudioStandard::STEREO, rendererOptions.streamInfo.channels);
    EXPECT_EQ(AudioStandard::AudioConcurrencyMode::MIX_WITH_OTHERS, rendererOptions.strategy.concurrencyMode);
    EXPECT_EQ(AudioStandard::CONTENT_TYPE_MUSIC, rendererOptions.rendererInfo.contentType);
    EXPECT_EQ(AudioStandard::STREAM_USAGE_MUSIC, rendererOptions.rendererInfo.streamUsage);
    EXPECT_EQ(AudioStandard::PRIVACY_TYPE_PUBLIC, rendererOptions.privacyType);
    EXPECT_EQ(AudioStandard::PLAYER_TYPE_SOUND_POOL, rendererOptions.rendererInfo.playerType);
    EXPECT_EQ(7, rendererOptions.rendererInfo.rendererFlags);
    EXPECT_EQ(7, audioStream->rendererFlags_);
    EXPECT_EQ(static_cast<uint64_t>(DEFAULT_PCM_BUFFER_SIZE),
        rendererOptions.rendererInfo.expectedPlaybackDurationBytes);
    MEDIA_LOGI("audioStream_function_010 after");
}

/**
 * @tc.name: audioStream_function_011
 * @tc.desc: function test Release without audioRenderer resets callbacks
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AudioStreamUnitTest, audioStream_function_011, TestSize.Level2)
{
    MEDIA_LOGI("audioStream_function_011 before");
    std::shared_ptr<ISoundPoolCallback> callback = std::make_shared<AudioStreamTestCallback>();
    std::shared_ptr<ISoundPoolFrameWriteCallback> frameWriteCallback =
        std::make_shared<AudioStreamTestFrameWriteCallback>();
    EXPECT_EQ(MSERR_OK, audioStream_->SetCallback(callback));
    EXPECT_EQ(MSERR_OK, audioStream_->SetStreamCallback(callback));
    EXPECT_EQ(MSERR_OK, audioStream_->SetFrameWriteCallback(frameWriteCallback));
    EXPECT_EQ(MSERR_OK, audioStream_->Release());
    EXPECT_EQ(nullptr, audioStream_->callback_);
    EXPECT_EQ(nullptr, audioStream_->streamCallback_);
    EXPECT_EQ(nullptr, audioStream_->frameWriteCallback_);
    MEDIA_LOGI("audioStream_function_011 after");
}

/**
 * @tc.name: audioStream_function_012
 * @tc.desc: function test Stop without audioRenderer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AudioStreamUnitTest, audioStream_function_012, TestSize.Level2)
{
    MEDIA_LOGI("audioStream_function_012 before");
    EXPECT_EQ(MSERR_OK, audioStream_->Stop());
    EXPECT_EQ(MSERR_OK, audioStream_->Stop(StopTrigger::PLAYBACK_INTERRUPTED));
    EXPECT_EQ(MSERR_OK, audioStream_->Stop(StopTrigger::PLAYBACK_COMPLETED));
    MEDIA_LOGI("audioStream_function_012 after");
}

/**
 * @tc.name: audioStream_function_013
 * @tc.desc: function test Stop with PLAYBACK_COMPLETED and too short playback duration
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AudioStreamUnitTest, audioStream_function_013, TestSize.Level2)
{
    MEDIA_LOGI("audioStream_function_013 before");
    std::shared_ptr<AudioStreamTestCallback> callback = std::make_shared<AudioStreamTestCallback>();
    EXPECT_EQ(MSERR_OK, audioStream_->SetCallback(callback));
    int64_t currentTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    // Make the elapsed playback duration negative so it is always less than the minimum duration.
    audioStream_->audioStartTimeMs_.store(currentTimeMs + 1000);
    EXPECT_EQ(MSERR_INVALID_STATE, audioStream_->Stop(StopTrigger::PLAYBACK_COMPLETED));
    EXPECT_EQ(1, callback->playFinishedCount_);
    MEDIA_LOGI("audioStream_function_013 after");
}

/**
 * @tc.name: audioStream_function_014
 * @tc.desc: function test DoPlayWithNoInterrupt with invalid stream state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AudioStreamUnitTest, audioStream_function_014, TestSize.Level2)
{
    MEDIA_LOGI("audioStream_function_014 before");
    audioStream_->SetStreamState(StreamState::PLAYING);
    EXPECT_EQ(MSERR_INVALID_VAL, audioStream_->DoPlayWithNoInterrupt());
    EXPECT_EQ(InterruptMode::NO_INTERRUPT, audioStream_->interruptMode_.load());
    MEDIA_LOGI("audioStream_function_014 after");
}

/**
 * @tc.name: audioStream_function_015
 * @tc.desc: function test DoPlayWithSameSoundInterrupt with released stream state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AudioStreamUnitTest, audioStream_function_015, TestSize.Level2)
{
    MEDIA_LOGI("audioStream_function_015 before");
    audioStream_->SetStreamState(StreamState::RELEASED);
    EXPECT_EQ(MSERR_INVALID_VAL, audioStream_->DoPlayWithSameSoundInterrupt());
    EXPECT_EQ(InterruptMode::SAME_SOUND_INTERRUPT, audioStream_->interruptMode_.load());
    MEDIA_LOGI("audioStream_function_015 after");
}

/**
 * @tc.name: audioStream_function_016
 * @tc.desc: function test DoPlay without pcm shared memory
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AudioStreamUnitTest, audioStream_function_016, TestSize.Level2)
{
    MEDIA_LOGI("audioStream_function_016 before");
    EXPECT_EQ(MSERR_INVALID_VAL, audioStream_->DoPlayWithNoInterrupt());
    audioStream_->SetStreamState(StreamState::PREPARED);
    EXPECT_EQ(MSERR_INVALID_VAL, audioStream_->DoPlayWithSameSoundInterrupt());
    MEDIA_LOGI("audioStream_function_016 after");
}

/**
 * @tc.name: audioStream_function_017
 * @tc.desc: function test OnFirstFrameWriting with null and valid frame write callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AudioStreamUnitTest, audioStream_function_017, TestSize.Level2)
{
    MEDIA_LOGI("audioStream_function_017 before");
    audioStream_->OnFirstFrameWriting(100);
    std::shared_ptr<AudioStreamTestFrameWriteCallback> frameWriteCallback =
        std::make_shared<AudioStreamTestFrameWriteCallback>();
    EXPECT_EQ(MSERR_OK, audioStream_->SetFrameWriteCallback(frameWriteCallback));
    audioStream_->OnFirstFrameWriting(123);
    EXPECT_EQ(123, frameWriteCallback->latency_);
    MEDIA_LOGI("audioStream_function_017 after");
}

/**
 * @tc.name: audioStream_function_018
 * @tc.desc: function test OnInterrupt and OnStateChange
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AudioStreamUnitTest, audioStream_function_018, TestSize.Level2)
{
    MEDIA_LOGI("audioStream_function_018 before");
    AudioStandard::InterruptEvent interruptEvent;
    interruptEvent.hintType = AudioStandard::InterruptHint::INTERRUPT_HINT_PAUSE;
    audioStream_->OnInterrupt(interruptEvent);
    interruptEvent.hintType = AudioStandard::InterruptHint::INTERRUPT_HINT_STOP;
    audioStream_->OnInterrupt(interruptEvent);
    interruptEvent.hintType = AudioStandard::InterruptHint::INTERRUPT_HINT_RESUME;
    audioStream_->OnInterrupt(interruptEvent);
    audioStream_->OnStateChange(AudioStandard::RendererState::RENDERER_RUNNING,
        AudioStandard::StateChangeCmdType::CMD_FROM_SYSTEM);
    MEDIA_LOGI("audioStream_function_018 after");
}

/**
 * @tc.name: audioStream_function_019
 * @tc.desc: function test OnStaticBufferEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AudioStreamUnitTest, audioStream_function_019, TestSize.Level2)
{
    MEDIA_LOGI("audioStream_function_019 before");
    audioStream_->OnStaticBufferEvent(AudioStandard::StaticBufferEventId::BUFFER_END_EVENT);
    audioStream_->OnStaticBufferEvent(AudioStandard::StaticBufferEventId::LOOP_END_EVENT);
    audioStream_->OnStaticBufferEvent(static_cast<AudioStandard::StaticBufferEventId>(100));
    MEDIA_LOGI("audioStream_function_019 after");
}

}  // namespace Media
}  // namespace OHOS
