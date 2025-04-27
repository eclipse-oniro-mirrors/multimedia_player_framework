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

void CacheBufferUnitTest::SetUpTestCase(void) {}

void CacheBufferUnitTest::TearDownTestCase(void) {}

void CacheBufferUnitTest::SetUp(void)
{
    cacheBuffer_ = std::make_shared<CacheBufferMock>();
    ASSERT_NE(nullptr, cacheBuffer_);
}

void CacheBufferUnitTest::TearDown(void)
{
    if (isCacheBufferStopThreadPoolStarted_.load()) {
        if (cacheBufferStopThreadPool_ != nullptr) {
            cacheBufferStopThreadPool_->Stop();
        }
        isCacheBufferStopThreadPoolStarted_.store(false);
    }
    if (cacheBuffer_ != nullptr) {
        cacheBuffer_.reset();
    }
    sleep(waitTime1);
}

void CacheBufferUnitTest::CreateCacheBuffer(const Format &trackFormat,
    const int32_t &soundID, const int32_t &streamID)
{
    if (cacheBuffer_ != nullptr) {
        cacheBufferStopThreadPool_ = std::make_shared<ThreadPool>(THREAD_POOL_NAME_CACHE_BUFFER);
        cacheBufferStopThreadPool_->Start(waitTime1);
        cacheBufferStopThreadPool_->SetMaxTaskNum(waitTime1);
        isCacheBufferStopThreadPoolStarted_.store(true);
        cacheBuffer_->CreateCacheBuffer(trackFormat, soundID, streamID, cacheBufferStopThreadPool_);
    } else {
        cout << "create cacheBuffer failed" << endl;
    }
}

/**
* @tc.name: soundpool_cacheBuffer_001
* @tc.desc: function test soundpool singleton
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(CacheBufferUnitTest, soundpool_cacheBuffer_001, TestSize.Level0)
{
    MEDIA_LOGI("CacheBufferUnitTest soundpool_cacheBuffer_001 before");
    std::shared_ptr<SoundPool> impl;
    EXPECT_EQ(MSERR_OK, SoundPoolManager::GetInstance().GetSoundPool(getpid(), impl));
    EXPECT_EQ(MSERR_OK, SoundPoolManager::GetInstance().SetSoundPool(getpid(), impl));
    EXPECT_EQ(MSERR_OK, SoundPoolManager::GetInstance().SetSoundPool(getpid(), impl));
    EXPECT_EQ(MSERR_OK, SoundPoolManager::GetInstance().GetSoundPool(getpid(), impl));
    sleep(waitTime1);
    EXPECT_EQ(MSERR_OK, SoundPoolManager::GetInstance().Release(getpid()));
    EXPECT_EQ(MSERR_OK, SoundPoolManager::GetInstance().Release(123));
    MEDIA_LOGI("CacheBufferUnitTest soundpool_cacheBuffer_001 after");
}

/**
* @tc.name: soundpool_rendererInfo_001
* @tc.desc: function test renderInfo result
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(CacheBufferUnitTest, soundpool_rendererInfo_001, TestSize.Level2)
{
    MEDIA_LOGI("CacheBufferUnitTest soundpool_rendererInfo_001 before");
    int32_t soundID = 1;
    int32_t streamID = 1;
    Format format;
    CreateCacheBuffer(format, soundID, streamID);
    AudioStandard::AudioRendererInfo audioRenderInfo1;
    audioRenderInfo1.contentType = CONTENT_TYPE_UNKNOWN;
    audioRenderInfo1.streamUsage = STREAM_USAGE_MOVIE;
    EXPECT_EQ(true, cacheBuffer_->IsAudioRendererCanMix(audioRenderInfo1));
    sleep(waitTime1);
    AudioStandard::AudioRendererInfo audioRenderInfo2;
    audioRenderInfo2.contentType = CONTENT_TYPE_UNKNOWN;
    audioRenderInfo2.streamUsage = STREAM_USAGE_AUDIOBOOK;
    EXPECT_EQ(true, cacheBuffer_->IsAudioRendererCanMix(audioRenderInfo2));
    sleep(waitTime1);
    AudioStandard::AudioRendererInfo audioRenderInfo3;
    audioRenderInfo3.contentType = CONTENT_TYPE_UNKNOWN;
    audioRenderInfo3.streamUsage = STREAM_USAGE_SYSTEM;
    EXPECT_EQ(false, cacheBuffer_->IsAudioRendererCanMix(audioRenderInfo3));
    MEDIA_LOGI("CacheBufferUnitTest soundpool_rendererInfo_001 after");
}

/**
* @tc.name: soundpool_createAudioRenderer_001
* @tc.desc: function test createAudioRenderer result
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(CacheBufferUnitTest, soundpool_createAudioRenderer_001, TestSize.Level2)
{
    MEDIA_LOGI("CacheBufferUnitTest soundpool_createAudioRenderer_001 before");
    int32_t soundID = 1;
    int32_t streamID = 1;
    Format format;
    format.PutIntValue(MediaAVCodec::MediaDescriptionKey::MD_KEY_SAMPLE_RATE, 8000);
    format.PutIntValue(MediaAVCodec::MediaDescriptionKey::MD_KEY_AUDIO_SAMPLE_FORMAT, 0);
    format.PutIntValue(MediaAVCodec::MediaDescriptionKey::MD_KEY_CHANNEL_COUNT, 2);

    CreateCacheBuffer(format, soundID, streamID);
    cacheBuffer_->cacheBuffer_->streamID_ = streamID;
    AudioStandard::AudioRendererInfo audioRenderInfo;
    audioRenderInfo.contentType = CONTENT_TYPE_UNKNOWN;
    audioRenderInfo.streamUsage = STREAM_USAGE_MOVIE;
    audioRenderInfo.samplingRate = SAMPLE_RATE_8000;
    audioRenderInfo.format = AudioStandard::AudioSampleFormat::SAMPLE_S16LE;

    std::string cacheDir = "/data/storage/el2/base/temp";
    struct PlayParams playParameters;
    playParameters.loop = -1;
    playParameters.rate = 1;
    playParameters.leftVolume = 0.5;
    playParameters.rightVolume = 0.3;
    playParameters.priority = 1;
    playParameters.parallelPlayFlag = true;
    playParameters.cacheDir = cacheDir;
    auto audioRender = cacheBuffer_->CreateAudioRenderer(audioRenderInfo, playParameters);
    EXPECT_TRUE(audioRender != nullptr);
    MEDIA_LOGI("CacheBufferUnitTest soundpool_createAudioRenderer_001 after");
}

/**
* @tc.name: soundpool_CheckAndAlignRendererRate_001
* @tc.desc: function test CheckAndAlignRendererRate result
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(CacheBufferUnitTest, soundpool_CheckAndAlignRendererRate_001, TestSize.Level2)
{
    MEDIA_LOGI("CacheBufferUnitTest soundpool_CheckAndAlignRendererRate_001 before");
    int32_t soundID = 1;
    int32_t streamID = 1;
    Format format;
    CreateCacheBuffer(format, soundID, streamID);
    cacheBuffer_->cacheBuffer_->streamID_ = streamID;
    EXPECT_EQ(AudioRendererRate::RENDER_RATE_NORMAL, cacheBuffer_->cacheBuffer_->CheckAndAlignRendererRate(-1));
    MEDIA_LOGI("CacheBufferUnitTest soundpool_CheckAndAlignRendererRate_001 after");
}

/**
* @tc.name: soundpool_OnWriteData_001
* @tc.desc: function test OnWriteData result
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(CacheBufferUnitTest, soundpool_OnWriteData_001, TestSize.Level2)
{
    MEDIA_LOGI("CacheBufferUnitTest soundpool_OnWriteData_001 before");
    int32_t soundID = 1;
    int32_t streamID = 1;
    Format format;
    CreateCacheBuffer(format, soundID, streamID);
    cacheBuffer_->cacheBuffer_->streamID_ = streamID;
    cacheBuffer_->cacheBuffer_->audioRenderer_ = nullptr;
    size_t length = 10;
    cacheBuffer_->cacheBuffer_->OnWriteData(length);
    EXPECT_EQ(streamID, cacheBuffer_->cacheBuffer_->streamID_);
    MEDIA_LOGI("CacheBufferUnitTest soundpool_OnWriteData_001 after");
}

/**
* @tc.name: soundpool_OnInterrupt_001
* @tc.desc: function test OnInterrupt result
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(CacheBufferUnitTest, soundpool_OnInterrupt_001, TestSize.Level2)
{
    MEDIA_LOGI("CacheBufferUnitTest soundpool_OnInterrupt_001 before");
    int32_t soundID = 1;
    int32_t streamID = 1;
    Format format;
    CreateCacheBuffer(format, soundID, streamID);
    cacheBuffer_->cacheBuffer_->streamID_ = streamID;
    struct InterruptEvent interruptEvent;
    interruptEvent.hintType = AudioStandard::InterruptHint::INTERRUPT_HINT_PAUSE;
    cacheBuffer_->cacheBuffer_->OnInterrupt(interruptEvent);
    struct InterruptEvent interruptEvent2;
    interruptEvent2.hintType = AudioStandard::InterruptHint::INTERRUPT_HINT_STOP;
    cacheBuffer_->cacheBuffer_->OnInterrupt(interruptEvent2);
    EXPECT_EQ(streamID, cacheBuffer_->cacheBuffer_->streamID_);
    MEDIA_LOGI("CacheBufferUnitTest soundpool_OnInterrupt_001 after");
}
} // namespace Media
} // namespace OHOS