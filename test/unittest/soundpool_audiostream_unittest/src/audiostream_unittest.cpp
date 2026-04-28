/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "audiostream_mock.h"
#include "audiostream_unittest.h"
#include "media_errors.h"
#include "isoundpool.h"

using namespace OHOS;
using namespace OHOS::Media;
using namespace std;
using namespace testing::ext;

static const char *const g_fileNames[6] = {
    "/data/test/test_06.ogg",
    "/data/test/test_02.mp3",
    "/data/test/test_01.mp3",
    "/data/test/test_05.ogg",
    "/data/test/test_03.mp3",
    "/data/test/test_04.mp3",
};

namespace OHOS {
namespace Media {

static const std::string THREAD_POOL_NAME_AUDIO_STREAM = "OS_AudioStreamUT";

static constexpr int32_t WATING_TIME_01 = 1;
static constexpr int32_t WATING_TIME_02 = 2;
static constexpr int32_t WATING_TIME_04 = 4;
static constexpr int32_t WATING_TIME_08 = 8;
static constexpr int32_t WATING_TIME_16 = 16;
static constexpr int32_t WATING_TIME_32 = 32;

void AudioStreamTest::SetUpTestCase(void) {}

void AudioStreamTest::TearDownTestCase(void) {}

void AudioStreamTest::SetUp(void)
{
    audioStream_ = std::make_shared<SoundPoolAudioStreamMock>();
    ASSERT_NE(nullptr, audioStream_);
}

void AudioStreamTest::TearDown(void)
{
    if (isAudioStreamStopThreadPoolStarted_.load()) {
        if (stopThreadPoolForAudioStream_) {
            stopThreadPoolForAudioStream_->Stop();
        }
        isAudioStreamStopThreadPoolStarted_.store(false);
    }
    if (audioStream_) {
        audioStream_.reset();
    }
    sleep(WATING_TIME_02);
}

void AudioStreamTest::CreateAudioStream(const Format &trackFormat,
    const int32_t &soundID, const int32_t &streamID)
{
    if (audioStream_) {
        stopThreadPoolForAudioStream_ = std::make_shared<ThreadPool>(THREAD_POOL_NAME_AUDIO_STREAM);
        stopThreadPoolForAudioStream_->Start(WATING_TIME_01);
        stopThreadPoolForAudioStream_->SetMaxTaskNum(WATING_TIME_01);
        isAudioStreamStopThreadPoolStarted_.store(true);
        audioStream_->CreateAudioStream(
            trackFormat, soundID, streamID, stopThreadPoolForAudioStream_);
    } else {
        cout << "create audioStream failed" << endl;
    }
}

int32_t AudioStreamTest::GetFileFdByName(const char *fileName)
{
    int32_t loadFd = open(fileName, O_RDWR);
    if (!(loadFd > 0)) {
        cout << "Url open failed, fileName " << fileName << ", fd: " << loadFd << endl;
    }
    return loadFd;
}

/**
* @tc.name: soundpool_audioStream_test_001
* @tc.desc: function test soundpool singleton
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AudioStreamTest, soundpool_audioStream_test_001, TestSize.Level0)
{
    MEDIA_LOGI("AudioStreamTest soundpool_audioStream_test_001 before");
    std::shared_ptr<SoundPool> impl;
    EXPECT_EQ(
        MSERR_OK, SoundPoolManager::GetInstance().GetSoundPool(getpid(), impl));
    sleep(WATING_TIME_01);
    EXPECT_EQ(MSERR_OK, SoundPoolManager::GetInstance().Release(getpid()));
    EXPECT_EQ(MSERR_OK, SoundPoolManager::GetInstance().Release(321));
    MEDIA_LOGI("AudioStreamTest soundpool_audioStream_test_001 after");
}

/**
* @tc.name: soundpool_rendererInfo_test_001
* @tc.desc: function test renderInfo result
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AudioStreamTest, soundpool_rendererInfo_test_001, TestSize.Level2)
{
    MEDIA_LOGI("AudioStreamTest soundpool_rendererInfo_test_001 before");
    int32_t soundID = 1;
    int32_t streamID = 1;
    Format format;
    CreateAudioStream(format, soundID, streamID);
    AudioStandard::AudioRendererInfo audioRenderInfo1;
    audioRenderInfo1.contentType = CONTENT_TYPE_UNKNOWN;
    audioRenderInfo1.streamUsage = STREAM_USAGE_MOVIE;
    EXPECT_EQ(true, audioStream_->IsAudioRendererCanMix(audioRenderInfo1));
    sleep(WATING_TIME_01);
    AudioStandard::AudioRendererInfo audioRenderInfo2;
    audioRenderInfo2.contentType = CONTENT_TYPE_UNKNOWN;
    audioRenderInfo2.streamUsage = STREAM_USAGE_AUDIOBOOK;
    EXPECT_EQ(true, audioStream_->IsAudioRendererCanMix(audioRenderInfo2));
    sleep(WATING_TIME_01);
    AudioStandard::AudioRendererInfo audioRenderInfo3;
    audioRenderInfo3.contentType = CONTENT_TYPE_UNKNOWN;
    audioRenderInfo3.streamUsage = STREAM_USAGE_SYSTEM;
    EXPECT_EQ(false, audioStream_->IsAudioRendererCanMix(audioRenderInfo3));
    MEDIA_LOGI("AudioStreamTest soundpool_rendererInfo_test_001 after");
}

/**
* @tc.name: soundpool_createAudioRenderer_test_001
* @tc.desc: function test createAudioRenderer result
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AudioStreamTest, soundpool_createAudioRenderer_test_001, TestSize.Level2)
{
    MEDIA_LOGI("AudioStreamTest soundpool_createAudioRenderer_test_001 before");
    int32_t soundID = 1;
    int32_t streamID = 1;
    Format format;
    CreateAudioStream(format, soundID, streamID);
    audioStream_->audioStream_->streamID_ = streamID;
    AudioStandard::AudioRendererInfo audioRenderInfo;
    audioRenderInfo.contentType = CONTENT_TYPE_UNKNOWN;
    audioRenderInfo.streamUsage = STREAM_USAGE_MOVIE;
    std::string cacheDir = "/data/storage/el2/base/temp";
    struct PlayParams playParameters;
    playParameters.loop = -1;
    playParameters.rate = 1;
    playParameters.leftVolume = 0.5;
    playParameters.rightVolume = 0.3;
    playParameters.priority = 1;
    playParameters.parallelPlayFlag = true;
    playParameters.cacheDir = cacheDir;
    audioStream_->CreateAudioRenderer(streamID, audioRenderInfo, playParameters);
    EXPECT_EQ(streamID, audioStream_->audioStream_->streamID_);
    MEDIA_LOGI("AudioStreamTest soundpool_createAudioRenderer_test_001 after");
}

/**
* @tc.name: soundpool_CheckAndAlignRendererRate_test_001
* @tc.desc: function test CheckAndAlignRendererRate result
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AudioStreamTest, soundpool_CheckAndAlignRendererRate_test_001, TestSize.Level2)
{
    MEDIA_LOGI("AudioStreamTest soundpool_CheckAndAlignRendererRate_test_001 before");
    int32_t soundID = 1;
    int32_t streamID = 1;
    Format format;
    CreateAudioStream(format, soundID, streamID);
    audioStream_->audioStream_->streamID_ = streamID;
    EXPECT_EQ(AudioRendererRate::RENDER_RATE_NORMAL, audioStream_->audioStream_->CheckAndAlignRendererRate(-1));
    MEDIA_LOGI("AudioStreamTest soundpool_CheckAndAlignRendererRate_test_001 after");
}

/**
* @tc.name: soundpool_OnInterrupt_test_001
* @tc.desc: function test OnInterrupt result
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AudioStreamTest, soundpool_OnInterrupt_test_001, TestSize.Level2)
{
    MEDIA_LOGI("AudioStreamTest soundpool_OnInterrupt_test_001 before");
    int32_t soundID = 1;
    int32_t streamID = 1;
    Format format;
    CreateAudioStream(format, soundID, streamID);
    audioStream_->audioStream_->streamID_ = streamID;
    struct InterruptEvent interruptEvent;
    interruptEvent.hintType = AudioStandard::InterruptHint::INTERRUPT_HINT_PAUSE;
    audioStream_->audioStream_->OnInterrupt(interruptEvent);
    struct InterruptEvent interruptEvent2;
    interruptEvent2.hintType = AudioStandard::InterruptHint::INTERRUPT_HINT_STOP;
    audioStream_->audioStream_->OnInterrupt(interruptEvent2);
    EXPECT_EQ(streamID, audioStream_->audioStream_->streamID_);
    MEDIA_LOGI("AudioStreamTest soundpool_OnInterrupt_test_001 after");
}

/**
* @tc.name: soundpool_SoundParseOnError_test_001
* @tc.desc: function test SoundParse OnError result
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AudioStreamTest, soundpool_SoundParseOnError_test_001, TestSize.Level2)
{
    MEDIA_LOGI("AudioStreamTest soundpool_SoundParseOnError_test_001 before");
    int32_t soundID = 1;
    int32_t streamID = 1;
    bool isRawFile = true;
    Format format;
    CreateAudioStream(format, soundID, streamID);
    audioStream_->audioStream_->streamID_ = streamID;
    int32_t fd = GetFileFdByName(g_fileNames[soundID]);
    EXPECT_GT(fd, 0);
    size_t filesize = audioStream_->GetFileSizeByName(g_fileNames[soundID]);
    int64_t length = static_cast<int64_t>(filesize);
    std::shared_ptr<MediaAVCodec::AVSource> source =
        MediaAVCodec::AVSourceFactory::CreateWithFD(fd, 0, length);
    ASSERT_NE(nullptr, source);
    std::shared_ptr<MediaAVCodec::AVDemuxer> demuxer = MediaAVCodec::AVDemuxerFactory::CreateWithSource(source);
    ASSERT_NE(nullptr, demuxer);
    std::shared_ptr<MediaAVCodec::AVCodecAudioDecoder> audioDec =
        MediaAVCodec::AudioDecoderFactory::CreateByMime("audio/mpeg");
    std::shared_ptr<SoundDecoderCallback> audioDecCb_ =
        std::make_shared<SoundDecoderCallback>(soundID, audioDec, demuxer, isRawFile);
    audioDecCb_->OnError(AVCodecErrorType::AVCODEC_ERROR_INTERNAL, MSERR_INVALID_OPERATION);
    audioDecCb_->OnOutputFormatChanged(format);
    audioDecCb_->demuxer_ = nullptr;
    audioDecCb_->OnInputBufferAvailable(0, nullptr);
    audioDecCb_->demuxer_ = demuxer;
    std::shared_ptr<AVSharedMemory> buffer = std::make_shared<AVSharedMemoryBase>(1,
        AVSharedMemory::Flags::FLAGS_READ_WRITE, "testBufferMemory");
    audioDecCb_->decodeShouldCompleted_ = false;
    audioDecCb_->OnInputBufferAvailable(0, buffer);
    audioDecCb_->isRawFile_ = false;
    audioDecCb_->eosFlag_  = false;
    audioDecCb_->OnInputBufferAvailable(0, buffer);
    if (fd > 0) {
        (void)::close(fd);
    }
    EXPECT_EQ(streamID, audioStream_->audioStream_->streamID_);
    MEDIA_LOGI("AudioStreamTest soundpool_SoundParseOnError_test_001 after");
}

/**
* @tc.name: soundpool_GetSoundID_test_001
* @tc.desc: function test GetSoundID result
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AudioStreamTest, soundpool_GetSoundID_test_001, TestSize.Level2)
{
    MEDIA_LOGI("AudioStreamTest soundpool_GetSoundID_test_001 before");
    const int32_t soundID = 1;
    const int32_t streamID = 1;
    Format format;
    CreateAudioStream(format, soundID, streamID);
    audioStream_->audioStream_->streamID_ = streamID;
    audioStream_->audioStream_->soundID_ = soundID;
    EXPECT_EQ(soundID, audioStream_->audioStream_->GetSoundID());
    MEDIA_LOGI("AudioStreamTest soundpool_GetSoundID_test_001 after");
}

/**
* @tc.name: soundpool_GetStreamID_test_001
* @tc.desc: function test GetStreamID result
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AudioStreamTest, soundpool_GetStreamID_test_001, TestSize.Level2)
{
    MEDIA_LOGI("AudioStreamTest soundpool_GetStreamID_test_001 before");
    const int32_t soundID = 1;
    const int32_t streamID = 1;
    Format format;
    CreateAudioStream(format, soundID, streamID);
    audioStream_->audioStream_->streamID_ = streamID;
    audioStream_->audioStream_->soundID_ = soundID;
    EXPECT_EQ(streamID, audioStream_->audioStream_->GetStreamID());
    MEDIA_LOGI("AudioStreamTest soundpool_GetStreamID_test_001 after");
}

/**
* @tc.name: soundpool_SetSourceDuration_test_001
* @tc.desc: function test SetSourceDuration result
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AudioStreamTest, soundpool_SetSourceDuration_test_001, TestSize.Level2)
{
    MEDIA_LOGI("AudioStreamTest soundpool_SetSourceDuration_test_001 before");
    const int32_t soundID = 1;
    const int32_t streamID = 1;
    const int64_t durationMs = 1000;
    Format format;
    CreateAudioStream(format, soundID, streamID);
    audioStream_->audioStream_->streamID_ = streamID;
    audioStream_->audioStream_->soundID_ = soundID;
    audioStream_->audioStream_->SetSourceDuration(durationMs);
    EXPECT_EQ(durationMs, audioStream_->audioStream_->sourceDurationMs_);
    MEDIA_LOGI("AudioStreamTest soundpool_SetSourceDuration_test_001 after");
}

/**
* @tc.name: soundpool_SetCallback_test_001
* @tc.desc: function test SetCallback result
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AudioStreamTest, soundpool_SetCallback_test_001, TestSize.Level2)
{
    MEDIA_LOGI("AudioStreamTest soundpool_SetCallback_test_001 before");
    const int32_t soundID = 1;
    const int32_t streamID = 1;
    std::shared_ptr<ISoundPoolCallback> callbk = std::make_shared<SoundPoolCallbackMock>();
    Format format;
    CreateAudioStream(format, soundID, streamID);
    audioStream_->audioStream_->streamID_ = streamID;
    audioStream_->audioStream_->soundID_ = soundID;

    audioStream_->audioStream_->SetCallback(callbk);
    EXPECT_EQ(callbk, audioStream_->audioStream_->callback_);
    MEDIA_LOGI("AudioStreamTest soundpool_SetCallback_test_001 after");
}

/**
* @tc.name: soundpool_SetCallback_test_002
* @tc.desc: function test SetCallback result
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AudioStreamTest, soundpool_SetCallback_test_002, TestSize.Level2)
{
    MEDIA_LOGI("AudioStreamTest soundpool_SetCallback_test_002 before");
    const int32_t soundID = 1;
    const int32_t streamID = 1;
    std::shared_ptr<ISoundPoolCallback> callbk = std::make_shared<SoundPoolCallbackMock>();
    Format format;
    CreateAudioStream(format, soundID, streamID);
    audioStream_->audioStream_->streamID_ = streamID;
    audioStream_->audioStream_->soundID_ = soundID;

    EXPECT_EQ(MSERR_OK, audioStream_->audioStream_->SetCallback(callbk));
    MEDIA_LOGI("AudioStreamTest soundpool_SetCallback_test_002 after");
}

/**
* @tc.name: soundpool_SetCallback_test_003
* @tc.desc: function test SetCallback result
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AudioStreamTest, soundpool_SetCallback_test_003, TestSize.Level2)
{
    MEDIA_LOGI("AudioStreamTest soundpool_SetCallback_test_003 before");
    const int32_t soundID = 1;
    const int32_t streamID = 1;
    std::shared_ptr<ISoundPoolCallback> callbk = std::make_shared<SoundPoolCallbackMock>();
    Format format;
    CreateAudioStream(format, soundID, streamID);
    audioStream_->audioStream_->streamID_ = streamID;
    audioStream_->audioStream_->soundID_ = soundID;

    audioStream_->audioStream_->SetCallback(callbk);
    EXPECT_NE(nullptr, audioStream_->audioStream_->callback_);
    if (audioStream_->audioStream_->callback_) {
        audioStream_->audioStream_->callback_->OnLoadCompleted(soundID);
        SoundPoolCallbackMock *call =
            dynamic_cast<SoundPoolCallbackMock*>((audioStream_->audioStream_->callback_).get());
        EXPECT_NE(nullptr, call);
        EXPECT_EQ(soundID, call->GetLoadCompletedSoundId());
    }
    MEDIA_LOGI("AudioStreamTest soundpool_SetCallback_test_003 after");
}
} // namespace Media
} // namespace OHOS
