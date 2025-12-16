/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "cachebuffer_unit_test.h"
#include "media_errors.h"

using namespace OHOS;
using namespace OHOS::Media;
using namespace testing::ext;
using namespace std;

static const std::string g_fileName[6] = {
    {"/data/test/test_06.ogg"},
    {"/data/test/test_02.mp3"},
    {"/data/test/test_01.mp3"},
    {"/data/test/test_05.ogg"},
    {"/data/test/test_03.mp3"},
    {"/data/test/test_04.mp3"},
};

namespace OHOS {
namespace Media {
static const std::string THREAD_POOL_NAME_CACHE_BUFFER = "OS_UnitCacheBuf";

void AudioStreamUnitTest::SetUpTestCase(void) {}

void AudioStreamUnitTest::TearDownTestCase(void) {}

void AudioStreamUnitTest::SetUp(void)
{
    audioStream_ = std::make_shared<AudioStreamMock>();
    ASSERT_NE(nullptr, audioStream_);
}

void AudioStreamUnitTest::TearDown(void)
{
    if (isAudioStreamStopThreadPoolStarted_.load()) {
        if (audioStreamStopThreadPool_ != nullptr) {
            audioStreamStopThreadPool_->Stop();
        }
        isAudioStreamStopThreadPoolStarted_.store(false);
    }
    if (audioStream_ != nullptr) {
        audioStream_.reset();
    }
    sleep(waitTime1);
}

void AudioStreamUnitTest::CreateAudioStream(const Format &trackFormat,
    const int32_t &soundID, const int32_t &streamID)
{
    if (audioStream_ != nullptr) {
        audioStreamStopThreadPool_ = std::make_shared<ThreadPool>(THREAD_POOL_NAME_CACHE_BUFFER);
        audioStreamStopThreadPool_->Start(waitTime1);
        audioStreamStopThreadPool_->SetMaxTaskNum(waitTime1);
        isAudioStreamStopThreadPoolStarted_.store(true);
        audioStream_->CreateAudioStream(trackFormat, soundID, streamID, audioStreamStopThreadPool_);
    } else {
        cout << "create audioStream failed" << endl;
    }
}

int32_t AudioStreamUnitTest::GetFdByFileName(std::string fileName)
{
    int32_t loadFd = open(fileName.c_str(), O_RDWR);
    if (loadFd <= 0) {
        cout << "Url open failed, g_fileName " << fileName.c_str() << ", fd: " << loadFd << endl;
    }
    return loadFd;
}

/**
* @tc.name: soundpool_audioStream_001
* @tc.desc: function test soundpool singleton
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AudioStreamUnitTest, soundpool_audioStream_001, TestSize.Level0)
{
    MEDIA_LOGI("AudioStreamUnitTest soundpool_audioStream_001 before");
    std::shared_ptr<SoundPool> impl;
    EXPECT_EQ(MSERR_OK, SoundPoolManager::GetInstance().GetSoundPool(getpid(), impl));
    EXPECT_EQ(MSERR_OK, SoundPoolManager::GetInstance().GetSoundPool(getpid(), impl));
    sleep(waitTime1);
    EXPECT_EQ(MSERR_OK, SoundPoolManager::GetInstance().Release(getpid()));
    EXPECT_EQ(MSERR_OK, SoundPoolManager::GetInstance().Release(123));
    MEDIA_LOGI("AudioStreamUnitTest soundpool_audioStream_001 after");
}

/**
* @tc.name: soundpool_rendererInfo_001
* @tc.desc: function test renderInfo result
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AudioStreamUnitTest, soundpool_rendererInfo_001, TestSize.Level2)
{
    MEDIA_LOGI("AudioStreamUnitTest soundpool_rendererInfo_001 before");
    int32_t soundID = 1;
    int32_t streamID = 1;
    Format format;
    CreateAudioStream(format, soundID, streamID);
    AudioStandard::AudioRendererInfo audioRenderInfo1;
    audioRenderInfo1.contentType = CONTENT_TYPE_UNKNOWN;
    audioRenderInfo1.streamUsage = STREAM_USAGE_MOVIE;
    EXPECT_EQ(true, audioStream_->IsAudioRendererCanMix(audioRenderInfo1));
    sleep(waitTime1);
    AudioStandard::AudioRendererInfo audioRenderInfo2;
    audioRenderInfo2.contentType = CONTENT_TYPE_UNKNOWN;
    audioRenderInfo2.streamUsage = STREAM_USAGE_AUDIOBOOK;
    EXPECT_EQ(true, audioStream_->IsAudioRendererCanMix(audioRenderInfo2));
    sleep(waitTime1);
    AudioStandard::AudioRendererInfo audioRenderInfo3;
    audioRenderInfo3.contentType = CONTENT_TYPE_UNKNOWN;
    audioRenderInfo3.streamUsage = STREAM_USAGE_SYSTEM;
    EXPECT_EQ(false, audioStream_->IsAudioRendererCanMix(audioRenderInfo3));
    MEDIA_LOGI("AudioStreamUnitTest soundpool_rendererInfo_001 after");
}

/**
* @tc.name: soundpool_createAudioRenderer_001
* @tc.desc: function test createAudioRenderer result
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AudioStreamUnitTest, soundpool_createAudioRenderer_001, TestSize.Level2)
{
    MEDIA_LOGI("AudioStreamUnitTest soundpool_createAudioRenderer_001 before");
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
    MEDIA_LOGI("AudioStreamUnitTest soundpool_createAudioRenderer_001 after");
}

/**
* @tc.name: soundpool_CheckAndAlignRendererRate_001
* @tc.desc: function test CheckAndAlignRendererRate result
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AudioStreamUnitTest, soundpool_CheckAndAlignRendererRate_001, TestSize.Level2)
{
    MEDIA_LOGI("AudioStreamUnitTest soundpool_CheckAndAlignRendererRate_001 before");
    int32_t soundID = 1;
    int32_t streamID = 1;
    Format format;
    CreateAudioStream(format, soundID, streamID);
    audioStream_->audioStream_->streamID_ = streamID;
    EXPECT_EQ(AudioRendererRate::RENDER_RATE_NORMAL, audioStream_->audioStream_->CheckAndAlignRendererRate(-1));
    MEDIA_LOGI("AudioStreamUnitTest soundpool_CheckAndAlignRendererRate_001 after");
}

/**
* @tc.name: soundpool_OnInterrupt_001
* @tc.desc: function test OnInterrupt result
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AudioStreamUnitTest, soundpool_OnInterrupt_001, TestSize.Level2)
{
    MEDIA_LOGI("AudioStreamUnitTest soundpool_OnInterrupt_001 before");
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
    MEDIA_LOGI("AudioStreamUnitTest soundpool_OnInterrupt_001 after");
}

/**
* @tc.name: soundpool_SoundParseOnError_001
* @tc.desc: function test SoundParse OnError result
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AudioStreamUnitTest, soundpool_SoundParseOnError_001, TestSize.Level2)
{
    MEDIA_LOGI("AudioStreamUnitTest soundpool_SoundParseOnError_001 before");
    int32_t soundID = 1;
    int32_t streamID = 1;
    bool isRawFile = true;
    Format format;
    CreateAudioStream(format, soundID, streamID);
    audioStream_->audioStream_->streamID_ = streamID;
    int32_t fd = GetFdByFileName(g_fileName[soundID]);
    EXPECT_GT(fd, 0);
    size_t filesize = audioStream_->GetFileSize(g_fileName[soundID]);
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
    MEDIA_LOGI("AudioStreamUnitTest soundpool_SoundParseOnError_001 after");
}
} // namespace Media
} // namespace OHOS