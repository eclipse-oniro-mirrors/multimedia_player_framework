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

#include <iostream>
#include "common/media_core.h"
#include "lpp_audio_render_adapter_unit_test.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing;
using namespace testing::ext;
constexpr int32_t AUDIO_SAMPLE_8_BIT = 1;
constexpr int32_t AUDIO_SAMPLE_16_BIT = 2;
constexpr int32_t AUDIO_SAMPLE_24_BIT = 3;
constexpr int32_t AUDIO_SAMPLE_32_BIT = 4;
constexpr int32_t TIME_OUT_MS = 50;

void LppAudioRenderAdapterUnitTest::SetUpTestCase(void)
{
}

void LppAudioRenderAdapterUnitTest::TearDownTestCase(void)
{
}

void LppAudioRenderAdapterUnitTest::SetUp(void)
{
    renderAdapter_ = std::make_shared<LppAudioRenderAdapter>("LppAudioStreamerId_1");
    renderAdapter_->audioRenderer_ = std::make_unique<AudioStandard::AudioRenderer>();
}

void LppAudioRenderAdapterUnitTest::TearDown(void)
{
    renderAdapter_ = nullptr;
}

/**
* @tc.name    : Test Init API
* @tc.number  : Init
* @tc.desc    : Test Init interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, Init_001, TestSize.Level0)
{
    AudioStandard::AudioRenderer* audioRenderer = new AudioStandard::AudioRenderer();
    bool targetIsAllowed = false;
    EXPECT_CALL(*audioRenderer, SetOffloadAllowed(_))
        .WillOnce(
            DoAll(
                Invoke([&targetIsAllowed](bool isAllowed) { targetIsAllowed = isAllowed; }),
                Return(AudioStandard::SUCCESS)
            )
        );
    int32_t targetInterruptMode = 0;
    EXPECT_CALL(*audioRenderer, SetInterruptMode(_))
        .WillOnce(
            Invoke([&targetInterruptMode](AudioStandard::InterruptMode mode) {
                    targetInterruptMode = static_cast<int32_t>(mode);
                }
            )
        );
    void* instance = static_cast<void *>(audioRenderer);
    InstanceMgr::Get().SetInstance(instance);
    std::cout << "g_audioRendererInstance: " << instance << std::endl;
    if (instance == nullptr) {
        std::cout << "g_audioRendererInstance is nullptr" << std::endl;
    }
    renderAdapter_->rendererOptions_.streamInfo.samplingRate = AudioStandard::SAMPLE_RATE_44100;
    renderAdapter_->rendererOptions_.streamInfo.channels = AudioStandard::STEREO;
    renderAdapter_->rendererOptions_.streamInfo.format = AudioStandard::SAMPLE_S16LE;
    int32_t res = renderAdapter_->Init();
    EXPECT_EQ(res, 0);
    EXPECT_TRUE(targetIsAllowed);
    EXPECT_EQ(targetInterruptMode, 0);
}

/**
* @tc.name    : Test ReleaseRender API
* @tc.number  : ReleaseRender
* @tc.desc    : Test Init interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, ReleaseRender_001, TestSize.Level0)
{
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), Release()).WillRepeatedly(Return(true));
    // audioRenderer_ != nullptr && audioRenderer_->GetStatus() == RENDERER_RELEASED
    bool getStatusHit = false;
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), GetStatus())
        .WillOnce(
            DoAll(
                Invoke([&getStatusHit]() { getStatusHit = true; }),
                Return(AudioStandard::RendererState::RENDERER_RELEASED)
            )
        );
    renderAdapter_->ReleaseRender();
    EXPECT_TRUE(getStatusHit);

    // audioRenderer_ == nullptr
    renderAdapter_->ReleaseRender();

    // audioRenderer_ != nullptr && audioRenderer_->GetStatus() != RENDERER_RELEASED
    renderAdapter_->audioRenderer_ = std::make_unique<AudioStandard::AudioRenderer>();
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), Release()).WillRepeatedly(Return(true));
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), GetStatus()).WillOnce(Return(
        AudioStandard::RendererState::RENDERER_RUNNING));
    renderAdapter_->ReleaseRender();
}

/**
* @tc.name    : Test Stop API
* @tc.number  : Stop_001
* @tc.desc    : Test Stop
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, Stop_001, TestSize.Level0)
{
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), Pause()).WillRepeatedly(Return(false));
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), Stop()).WillRepeatedly(Return(true));
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), GetStatus()).WillOnce(Return(
        AudioStandard::RendererState::RENDERER_RUNNING));
    int32_t ret = renderAdapter_->Stop();
    EXPECT_EQ(ret, MediaServiceErrCode::MSERR_PAUSE_FAILED);
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), GetStatus()).WillRepeatedly(Return(
        AudioStandard::RendererState::RENDERER_RELEASED));
    ret = renderAdapter_->Stop();
    EXPECT_EQ(ret, MediaServiceErrCode::MSERR_OK);
}

/**
* @tc.name    : Test SetParameter API
* @tc.number  : SetParameter_001
* @tc.desc    : Test SetParameter
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, SetParameter_001, TestSize.Level0)
{
    renderAdapter_->isOffload_ = true;
    Format format;
    format.PutIntValue("sample_rate", 0);
    format.PutIntValue("audio_sample_format", 0);
    format.PutIntValue("channel_count", 0);
    int32_t ret = renderAdapter_->SetParameter(format);
    EXPECT_EQ(renderAdapter_->rendererOptions_.rendererInfo.rendererFlags, AudioStandard::AUDIO_FLAG_PCM_OFFLOAD);
    EXPECT_EQ(ret, MediaServiceErrCode::MSERR_OK);
    renderAdapter_->isOffload_ = false;
    ret = renderAdapter_->SetParameter(format);
    EXPECT_EQ(ret, MediaServiceErrCode::MSERR_OK);
}

/**
* @tc.name    : Test ReleaseCacheBuffer API
* @tc.number  : ReleaseCacheBuffer_001
* @tc.desc    : Test ReleaseCacheBuffer
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, ReleaseCacheBuffer_001, TestSize.Level0)
{
    std::shared_ptr<AVBuffer> avBuffer = std::make_shared<AVBuffer>();
    renderAdapter_->swapOutputBuffers_.push(avBuffer);
    bool isSwapBuffer = true;
    renderAdapter_->ReleaseCacheBuffer(isSwapBuffer);
    EXPECT_TRUE(renderAdapter_->swapOutputBuffers_.empty());
    isSwapBuffer = false;
    renderAdapter_->availOutputBuffers_.push(avBuffer);
    renderAdapter_->PrepareInputBufferQueue();
    renderAdapter_->ReleaseCacheBuffer(isSwapBuffer);
    EXPECT_TRUE(renderAdapter_->availOutputBuffers_.empty());
}

/**
* @tc.name    : Test HandleBufferAvailable API
* @tc.number  : HandleBufferAvailable_001
* @tc.desc    : Test HandleBufferAvailable
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, HandleBufferAvailable_001, TestSize.Level0)
{
    // set avbuffer to buffer queue
    std::shared_ptr<AVBuffer> avBuffer;
    renderAdapter_->PrepareInputBufferQueue();
    AVBufferConfig avBufferConfig;
    avBufferConfig.memoryType = MemoryType::SHARED_MEMORY;
    Status ret = renderAdapter_->inputBufferQueueProducer_->RequestBuffer(avBuffer, avBufferConfig, TIME_OUT_MS);
    EXPECT_EQ(ret, Status::OK);
    avBuffer->flag_ = 1; // EOS flag
    avBuffer->pts_ = 0;
    ret = renderAdapter_->inputBufferQueueProducer_->PushBuffer(avBuffer, true);
    EXPECT_EQ(ret, Status::OK);

    renderAdapter_->isEos_ = true;
    renderAdapter_->renderTask_ = nullptr;
    renderAdapter_->HandleBufferAvailable();
    EXPECT_TRUE(!renderAdapter_->availOutputBuffers_.empty());
}

/**
* @tc.name    : Test HandleBufferAvailable API
* @tc.number  : HandleBufferAvailable_002
* @tc.desc    : Test HandleBufferAvailable
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, HandleBufferAvailable_002, TestSize.Level0)
{
    // set avbuffer to buffer queue
    std::shared_ptr<AVBuffer> avBuffer;
    renderAdapter_->PrepareInputBufferQueue();
    AVBufferConfig avBufferConfig;
    avBufferConfig.memoryType = MemoryType::SHARED_MEMORY;
    Status ret = renderAdapter_->inputBufferQueueProducer_->RequestBuffer(avBuffer, avBufferConfig, TIME_OUT_MS);
    EXPECT_EQ(ret, Status::OK);
    avBuffer->flag_ = 1; // EOS flag
    avBuffer->pts_ = -1;
    ret = renderAdapter_->inputBufferQueueProducer_->PushBuffer(avBuffer, true);
    EXPECT_EQ(ret, Status::OK);

    renderAdapter_->HandleBufferAvailable();
    ret = renderAdapter_->inputBufferQueueConsumer_->AcquireBuffer(avBuffer);
    EXPECT_NE(ret, Status::OK);
}

/**
* @tc.name    : Test HandleBufferAvailable API
* @tc.number  : HandleBufferAvailable_003
* @tc.desc    : Test HandleBufferAvailable
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, HandleBufferAvailable_003, TestSize.Level0)
{
    // set avbuffer to buffer queue
    std::shared_ptr<AVBuffer> avBuffer;
    renderAdapter_->PrepareInputBufferQueue();
    AVBufferConfig avBufferConfig;
    avBufferConfig.memoryType = MemoryType::SHARED_MEMORY;
    Status ret = renderAdapter_->inputBufferQueueProducer_->RequestBuffer(avBuffer, avBufferConfig, TIME_OUT_MS);
    EXPECT_EQ(ret, Status::OK);
    avBuffer->flag_ = 1; // EOS flag
    avBuffer->pts_ = -1;
    ret = renderAdapter_->inputBufferQueueProducer_->PushBuffer(avBuffer, true);
    EXPECT_EQ(ret, Status::OK);

    avBuffer->memory_ = nullptr;
    renderAdapter_->HandleBufferAvailable();
    ret = renderAdapter_->inputBufferQueueConsumer_->AcquireBuffer(avBuffer);
    EXPECT_NE(ret, Status::OK);
}

/**
* @tc.name    : Test HandleBufferAvailable API
* @tc.number  : HandleBufferAvailable_004
* @tc.desc    : Test HandleBufferAvailable
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, HandleBufferAvailable_004, TestSize.Level0)
{
    // set avbuffer to buffer queue
    std::shared_ptr<AVBuffer> avBuffer;
    renderAdapter_->PrepareInputBufferQueue();
    AVBufferConfig avBufferConfig;
    avBufferConfig.memoryType = MemoryType::SHARED_MEMORY;
    Status ret = renderAdapter_->inputBufferQueueProducer_->RequestBuffer(avBuffer, avBufferConfig, TIME_OUT_MS);
    EXPECT_EQ(ret, Status::OK);
    avBuffer->flag_ = 1; // EOS flag
    avBuffer->pts_ = 0;
    ret = renderAdapter_->inputBufferQueueProducer_->PushBuffer(avBuffer, true);
    EXPECT_EQ(ret, Status::OK);

    avBuffer->memory_ = nullptr;
    renderAdapter_->HandleBufferAvailable();
    ret = renderAdapter_->inputBufferQueueConsumer_->AcquireBuffer(avBuffer);
    EXPECT_NE(ret, Status::OK);
}

/**
* @tc.name    : Test CheckBufferSize API
* @tc.number  : CheckBufferSize_001
* @tc.desc    : Test CheckBufferSize
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, CheckBufferSize_001, TestSize.Level0)
{
    renderAdapter_->isAudioVivid_ = true;
    size_t length = 1;
    renderAdapter_->isEos_ = false;
    bool ret = renderAdapter_->CheckBufferSize(length);
    EXPECT_EQ(ret, false);
    EXPECT_EQ(renderAdapter_->maxCbDataSize_, renderAdapter_->availDataSize_.load());

    renderAdapter_->isAudioVivid_ = false;
    ret = renderAdapter_->CheckBufferSize(length);
    EXPECT_EQ(ret, false);
    EXPECT_EQ(renderAdapter_->maxCbDataSize_, length);
}

/**
* @tc.name    : Test CopyBufferData API
* @tc.number  : CopyBufferData_001
* @tc.desc    : Test CopyBufferData
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, CopyBufferData_001, TestSize.Level0)
{
    size_t bufferSize = 1024;
    size_t cacheBufferSize = 1;

    AudioStandard::BufferDesc bufferDesc;
    bufferDesc.buffer = new uint8_t[bufferSize];
    bufferDesc.metaBuffer = new uint8_t[256];
    bufferDesc.bufLength = 1024;
    bufferDesc.metaLength = 4;
    bufferDesc.dataLength = 0;

    std::shared_ptr<AVBuffer> avbuffer = AVBuffer::CreateAVBuffer();
    uint8_t data[bufferSize];
    avbuffer->memory_ = AVMemory::CreateAVMemory(data, bufferSize, bufferSize);
    std::vector<uint8_t> metaData = {0x01, 0x02, 0x03, 0x04};
    avbuffer->meta_->SetData(Tag::OH_MD_KEY_AUDIO_VIVID_METADATA, metaData);
    avbuffer->pts_ = 0;
    renderAdapter_->currentQueuedBufferOffset_ = 0;
    int64_t bufferPts = 0;

    bool ret = renderAdapter_->CopyBufferData(bufferDesc, avbuffer, bufferSize, cacheBufferSize, bufferPts);
    EXPECT_EQ(ret, true);

    cacheBufferSize = 2;
    bufferSize = 1;
    ret = renderAdapter_->CopyBufferData(bufferDesc, avbuffer, bufferSize, cacheBufferSize, bufferPts);
    EXPECT_EQ(ret, false);
}

/**
* @tc.name    : Test CopyAudioVividBufferData API
* @tc.number  : CopyAudioVividBufferData_001
* @tc.desc    : Test CopyAudioVividBufferData
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, CopyAudioVividBufferData_001, TestSize.Level0)
{
    size_t bufferSize = 1024;
    size_t cacheBufferSize = 1;

    AudioStandard::BufferDesc bufferDesc;
    bufferDesc.buffer = new uint8_t[bufferSize];
    bufferDesc.metaBuffer = new uint8_t[256];
    bufferDesc.bufLength = 1024;
    bufferDesc.metaLength = 4;
    bufferDesc.dataLength = 0;

    std::shared_ptr<AVBuffer> avbuffer = AVBuffer::CreateAVBuffer();
    uint8_t data[bufferSize];
    avbuffer->memory_ = AVMemory::CreateAVMemory(data, bufferSize, bufferSize);
    std::vector<uint8_t> metaData = {0x01, 0x02, 0x03, 0x04};
    avbuffer->meta_->SetData(Tag::OH_MD_KEY_AUDIO_VIVID_METADATA, metaData);
    avbuffer->pts_ = 0;
    renderAdapter_->currentQueuedBufferOffset_ = 0;
    int64_t bufferPts = 0;
    bool ret = renderAdapter_->CopyAudioVividBufferData(bufferDesc, avbuffer, bufferSize, cacheBufferSize, bufferPts);
    EXPECT_EQ(ret, true);

    bufferDesc.metaLength = 2;
    ret = renderAdapter_->CopyAudioVividBufferData(bufferDesc, avbuffer, bufferSize, cacheBufferSize, bufferPts);
    EXPECT_EQ(ret, true);

    bufferDesc.metaLength = 0;
    metaData.clear();
    avbuffer->meta_->SetData(Tag::OH_MD_KEY_AUDIO_VIVID_METADATA, metaData);
    ret = renderAdapter_->CopyAudioVividBufferData(bufferDesc, avbuffer, bufferSize, cacheBufferSize, bufferPts);
    EXPECT_EQ(ret, true);

    bufferDesc.metaLength = -1;
    ret = renderAdapter_->CopyAudioVividBufferData(bufferDesc, avbuffer, bufferSize, cacheBufferSize, bufferPts);
    EXPECT_EQ(ret, true);

    delete[] bufferDesc.buffer;
    delete[] bufferDesc.metaBuffer;
}

/**
* @tc.name    : Test ClearInputBuffer API
* @tc.number  : ClearInputBuffer_001
* @tc.desc    : Test ClearInputBuffer
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, ClearInputBuffer_001, TestSize.Level0)
{
    // set avbuffer to buffer queue
    std::shared_ptr<AVBuffer> avBuffer;
    renderAdapter_->PrepareInputBufferQueue();
    AVBufferConfig avBufferConfig;
    avBufferConfig.memoryType = MemoryType::SHARED_MEMORY;
    Status ret = renderAdapter_->inputBufferQueueProducer_->RequestBuffer(avBuffer, avBufferConfig, TIME_OUT_MS);
    EXPECT_EQ(ret, Status::OK);
    avBuffer->flag_ = 1; // EOS flag
    avBuffer->pts_ = 0;
    ret = renderAdapter_->inputBufferQueueProducer_->PushBuffer(avBuffer, true);
    EXPECT_EQ(ret, Status::OK);
    renderAdapter_->ClearInputBuffer();
    ret = renderAdapter_->inputBufferQueueConsumer_->AcquireBuffer(avBuffer);
    EXPECT_NE(ret, Status::OK);
}

/**
* @tc.name    : Test ClearAvailableOutputBuffers API
* @tc.number  : ClearAvailableOutputBuffers_001
* @tc.desc    : Test ClearAvailableOutputBuffers
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, ClearAvailableOutputBuffers_001, TestSize.Level0)
{
    // set avbuffer to buffer queue
    std::shared_ptr<AVBuffer> avBuffer = std::make_shared<AVBuffer>();
    renderAdapter_->PrepareInputBufferQueue();
    renderAdapter_->swapOutputBuffers_.push(avBuffer);
    renderAdapter_->availOutputBuffers_.push(avBuffer);
    renderAdapter_->ClearAvailableOutputBuffers();
    EXPECT_TRUE(renderAdapter_->swapOutputBuffers_.empty());
    EXPECT_TRUE(renderAdapter_->availOutputBuffers_.empty());
}

/**
* @tc.name    : Test GetSampleFormatBytes API
* @tc.number  : GetSampleFormatBytes_001
* @tc.desc    : Test GetSampleFormatBytes
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, GetSampleFormatBytes_001, TestSize.Level0)
{
    AudioStandard::AudioSampleFormat format;
    format = AudioStandard::AudioSampleFormat::SAMPLE_U8;
    int32_t ret = renderAdapter_->GetSampleFormatBytes(format);
    EXPECT_EQ(ret, AUDIO_SAMPLE_8_BIT);

    format = AudioStandard::AudioSampleFormat::SAMPLE_S16LE;
    ret = renderAdapter_->GetSampleFormatBytes(format);
    EXPECT_EQ(ret, AUDIO_SAMPLE_16_BIT);

    format = AudioStandard::AudioSampleFormat::SAMPLE_S24LE;
    ret = renderAdapter_->GetSampleFormatBytes(format);
    EXPECT_EQ(ret, AUDIO_SAMPLE_24_BIT);

    format = AudioStandard::AudioSampleFormat::SAMPLE_S32LE;
    ret = renderAdapter_->GetSampleFormatBytes(format);
    EXPECT_EQ(ret, AUDIO_SAMPLE_32_BIT);

    format = AudioStandard::AudioSampleFormat::SAMPLE_F32LE;
    ret = renderAdapter_->GetSampleFormatBytes(format);
    EXPECT_EQ(ret, AUDIO_SAMPLE_32_BIT);

    format = AudioStandard::AudioSampleFormat::INVALID_WIDTH;
    ret = renderAdapter_->GetSampleFormatBytes(format);
    EXPECT_EQ(ret, 0);
}

/**
* @tc.name    : Test FillAudioBuffer API
* @tc.number  : FillAudioBuffer_001
* @tc.desc    : Test FillAudioBuffer
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, FillAudioBuffer_001, TestSize.Level0)
{
    size_t bufferSize = 1024;
    AudioStandard::BufferDesc bufferDesc;
    bufferDesc.buffer = new uint8_t[bufferSize];
    bufferDesc.metaBuffer = new uint8_t[256];
    bufferDesc.bufLength = 1024;
    bufferDesc.metaLength = 4;
    bufferDesc.dataLength = 0;
    renderAdapter_->PrepareInputBufferQueue();
    auto allocator = AVAllocatorFactory::CreateSharedAllocator(MemoryFlag::MEMORY_READ_WRITE);
    std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer(allocator, bufferSize);
    EXPECT_NE(buffer->memory_, nullptr);
    buffer->flag_ = 1;
    renderAdapter_->swapOutputBuffers_.push(buffer);
    int64_t bufferPts = Plugins::HST_TIME_NONE;
    renderAdapter_->FillAudioBuffer(bufferSize, bufferDesc, bufferPts);
    renderAdapter_->swapOutputBuffers_.pop();
    renderAdapter_->availOutputBuffers_.push(buffer);
    renderAdapter_->FillAudioBuffer(bufferSize, bufferDesc, bufferPts);
    buffer->flag_ = 0;
    buffer->pts_ = 0;
    renderAdapter_->FillAudioBuffer(bufferSize, bufferDesc, bufferPts);
    renderAdapter_->currentQueuedBufferOffset_ = 0;
    buffer->memory_->SetSize(bufferSize);
    renderAdapter_->FillAudioBuffer(bufferSize, bufferDesc, bufferPts);
    EXPECT_EQ(bufferPts, 0);
}

/**
* @tc.name    : Test LoudnessGain API
* @tc.number  : LoudnessGain_001
* @tc.desc    : Test LoudnessGain
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, LoudnessGain_001, TestSize.Level0)
{
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), SetLoudnessGain(_)).WillRepeatedly(Return(AudioStandard::SUCCESS));
    int32_t ret = renderAdapter_->SetLoudnessGain(0);
    EXPECT_EQ(ret, MediaServiceErrCode::MSERR_OK);
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), SetLoudnessGain(_)).WillRepeatedly(Return(AudioStandard::ERROR));
    ret = renderAdapter_->SetLoudnessGain(0);
    EXPECT_EQ(ret, MediaServiceErrCode::MSERR_AUD_RENDER_FAILED);
}

/**
 * @tc.name    : Test Prepare API
 * @tc.number  : Prepare_001
 * @tc.desc    : Test Prepare when audioRenderer_ is nullptr
 */
HWTEST_F(LppAudioRenderAdapterUnitTest, Prepare_001, TestSize.Level1)
{
    renderAdapter_->audioRenderer_ = nullptr;
    int32_t ret = renderAdapter_->Prepare();
    EXPECT_EQ(ret, MediaServiceErrCode::MSERR_INVALID_OPERATION);
}

/**
 * @tc.name    : Test Prepare API
 * @tc.number  : Prepare_002
 * @tc.desc    : Test Prepare with all operations succeeding (success path)
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppAudioRenderAdapterUnitTest, Prepare_002, TestSize.Level0)
{
    std::vector<AudioStandard::AudioEncodingType> encodingTypes = {
        AudioStandard::AudioEncodingType::ENCODING_PCM
    };

    EXPECT_CALL(*(renderAdapter_->audioRenderer_), SetRenderMode(_))
        .WillOnce(Return(AudioStandard::SUCCESS));
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), SetRendererWriteCallback(_))
        .WillOnce(Return(AudioStandard::SUCCESS));
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), SetBufferDuration(_))
        .WillOnce(Return(AudioStandard::SUCCESS));
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), SetRendererCallback(_))
        .WillOnce(Return(AudioStandard::SUCCESS));
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), RegisterOutputDeviceChangeWithInfoCallback(_))
        .WillOnce(Return(AudioStandard::SUCCESS));
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), SetRendererFirstFrameWritingCallback(_))
        .WillOnce(Return(AudioStandard::SUCCESS));
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), RegisterAudioPolicyServerDiedCb(_, _))
        .WillOnce(Return(AudioStandard::SUCCESS));
    
    int32_t ret = renderAdapter_->Prepare();
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_NE(renderAdapter_->renderTask_, nullptr);
    EXPECT_NE(renderAdapter_->inputBufferQueue_, nullptr);
}

/**
 * @tc.name    : Test Prepare API
 * @tc.number  : Prepare_003
 * @tc.desc    : Test Prepare when PCM encoding is not supported
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppAudioRenderAdapterUnitTest, Prepare_003, TestSize.Level1)
{
    int32_t ret = renderAdapter_->Prepare();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name    : Test Prepare API
 * @tc.number  : Prepare_005
 * @tc.desc    : Test Prepare when SetRenderMode fails
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppAudioRenderAdapterUnitTest, Prepare_005, TestSize.Level1)
{
    std::vector<AudioStandard::AudioEncodingType> encodingTypes = {
        AudioStandard::AudioEncodingType::ENCODING_PCM
    };

    EXPECT_CALL(*(renderAdapter_->audioRenderer_), SetRenderMode(_))
        .WillOnce(Return(AudioStandard::ERROR));
    
    int32_t ret = renderAdapter_->Prepare();
    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name    : Test Prepare API
 * @tc.number  : Prepare_006
 * @tc.desc    : Test Prepare when SetRendererWriteCallback fails
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppAudioRenderAdapterUnitTest, Prepare_006, TestSize.Level1)
{
    std::vector<AudioStandard::AudioEncodingType> encodingTypes = {
        AudioStandard::AudioEncodingType::ENCODING_PCM
    };

    EXPECT_CALL(*(renderAdapter_->audioRenderer_), SetRenderMode(_))
        .WillOnce(Return(AudioStandard::SUCCESS));
    
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), SetRendererWriteCallback(_))
        .WillOnce(Return(AudioStandard::ERROR));
    
    int32_t ret = renderAdapter_->Prepare();
    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name    : Test Prepare API
 * @tc.number  : Prepare_007
 * @tc.desc    : Test Prepare when SetBufferDuration fails
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppAudioRenderAdapterUnitTest, Prepare_007, TestSize.Level1)
{
    std::vector<AudioStandard::AudioEncodingType> encodingTypes = {
        AudioStandard::AudioEncodingType::ENCODING_PCM
    };

    EXPECT_CALL(*(renderAdapter_->audioRenderer_), SetRenderMode(_))
        .WillOnce(Return(AudioStandard::SUCCESS));
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), SetRendererWriteCallback(_))
        .WillOnce(Return(AudioStandard::SUCCESS));
    
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), SetBufferDuration(_))
        .WillOnce(Return(AudioStandard::ERROR));
    
    int32_t ret = renderAdapter_->Prepare();
    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name    : Test Prepare API
 * @tc.number  : Prepare_008
 * @tc.desc    : Test Prepare when RegisterAudioPolicyServerDiedCb fails
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppAudioRenderAdapterUnitTest, Prepare_008, TestSize.Level1)
{
    std::vector<AudioStandard::AudioEncodingType> encodingTypes = {
        AudioStandard::AudioEncodingType::ENCODING_PCM
    };
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), SetRenderMode(_))
        .WillOnce(Return(AudioStandard::SUCCESS));
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), SetRendererWriteCallback(_))
        .WillOnce(Return(AudioStandard::SUCCESS));
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), SetBufferDuration(_))
        .WillOnce(Return(AudioStandard::SUCCESS));
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), SetRendererCallback(_))
        .WillOnce(Return(AudioStandard::SUCCESS));
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), RegisterOutputDeviceChangeWithInfoCallback(_))
        .WillOnce(Return(AudioStandard::SUCCESS));
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), SetRendererFirstFrameWritingCallback(_))
        .WillOnce(Return(AudioStandard::SUCCESS));
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), RegisterAudioPolicyServerDiedCb(_, _))
        .WillOnce(Return(AudioStandard::ERROR));
    
    int32_t ret = renderAdapter_->Prepare();
    EXPECT_NE(ret, MSERR_OK);
}

/**
 * @tc.name    : Test Prepare API
 * @tc.number  : Prepare_009
 * @tc.desc    : Test Prepare when PrepareInputBufferQueue fails (inputBufferQueue already created)
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(LppAudioRenderAdapterUnitTest, Prepare_009, TestSize.Level1)
{
    std::vector<AudioStandard::AudioEncodingType> encodingTypes = {
        AudioStandard::AudioEncodingType::ENCODING_PCM
    };

    EXPECT_CALL(*(renderAdapter_->audioRenderer_), SetRenderMode(_))
        .WillOnce(Return(AudioStandard::SUCCESS));
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), SetRendererWriteCallback(_))
        .WillOnce(Return(AudioStandard::SUCCESS));
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), SetBufferDuration(_))
        .WillOnce(Return(AudioStandard::SUCCESS));
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), SetRendererCallback(_))
        .WillOnce(Return(AudioStandard::SUCCESS));
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), RegisterOutputDeviceChangeWithInfoCallback(_))
        .WillOnce(Return(AudioStandard::SUCCESS));
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), SetRendererFirstFrameWritingCallback(_))
        .WillOnce(Return(AudioStandard::SUCCESS));
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), RegisterAudioPolicyServerDiedCb(_, _))
        .WillOnce(Return(AudioStandard::SUCCESS));
    
    renderAdapter_->inputBufferQueue_ = AVBufferQueue::Create(20, MemoryType::SHARED_MEMORY, "TestQueue");
    
    int32_t ret = renderAdapter_->Prepare();
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/**
* @tc.name    : Test Start API
* @tc.number  : Start_001
* @tc.desc    : Test Start when audioRenderer_ is nullptr
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, Start_001, TestSize.Level1)
{
    renderAdapter_->audioRenderer_ = nullptr;
    int32_t ret = renderAdapter_->Start();
    EXPECT_EQ(ret, MediaServiceErrCode::MSERR_INVALID_OPERATION);
}

/**
* @tc.name    : Test Start API
* @tc.number  : Start_002
* @tc.desc    : Test Start when renderTask_ is nullptr
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, Start_002, TestSize.Level1)
{
    renderAdapter_->renderTask_ = nullptr;
    int32_t ret = renderAdapter_->Start();
    EXPECT_EQ(ret, MediaServiceErrCode::MSERR_INVALID_OPERATION);
}

/**
* @tc.name    : Test Start API
* @tc.number  : Start_003
* @tc.desc    : Test Start when audioRenderer_->Start fails
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, Start_003, TestSize.Level1)
{
    renderAdapter_->renderTask_ = std::make_unique<Task>("Test", "test", TaskType::SINGLETON, TaskPriority::NORMAL, false);
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), Start()).WillOnce(Return(false));
    int32_t ret = renderAdapter_->Start();
    EXPECT_EQ(ret, MediaServiceErrCode::MSERR_START_FAILED);
}

/**
* @tc.name    : Test Start API
* @tc.number  : Start_004
* @tc.desc    : Test Start with all operations succeeding (success path)
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, Start_004, TestSize.Level0)
{
    renderAdapter_->renderTask_ = std::make_unique<Task>("Test", "test", TaskType::SINGLETON, TaskPriority::NORMAL, false);
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), Start()).WillOnce(Return(true));
    int32_t ret = renderAdapter_->Start();
    EXPECT_EQ(ret, MediaServiceErrCode::MSERR_OK);
}

/**
* @tc.name    : Test Pause API
* @tc.number  : Pause_001
* @tc.desc    : Test Pause when audioRenderer_ is nullptr
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, Pause_001, TestSize.Level1)
{
    renderAdapter_->audioRenderer_ = nullptr;
    int32_t ret = renderAdapter_->Pause();
    EXPECT_EQ(ret, MediaServiceErrCode::MSERR_INVALID_OPERATION);
}

/**
* @tc.name    : Test Pause API
* @tc.number  : Pause_002
* @tc.desc    : Test Pause when renderer is already paused or stopped
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, Pause_002, TestSize.Level1)
{
    renderAdapter_->renderTask_ = std::make_unique<Task>("Test", "test", TaskType::SINGLETON, TaskPriority::NORMAL, false);
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), GetStatus())
        .WillOnce(Return(AudioStandard::RendererState::RENDERER_PAUSED));
    int32_t ret = renderAdapter_->Pause();
    EXPECT_EQ(ret, MediaServiceErrCode::MSERR_OK);
}

/**
* @tc.name    : Test Pause API
* @tc.number  : Pause_003
* @tc.desc    : Test Pause when audioRenderer_->Pause fails
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, Pause_003, TestSize.Level1)
{
    renderAdapter_->renderTask_ = std::make_unique<Task>("Test", "test", TaskType::SINGLETON, TaskPriority::NORMAL, false);
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), GetStatus())
        .WillOnce(Return(AudioStandard::RendererState::RENDERER_RUNNING));
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), Pause()).WillOnce(Return(false));
    int32_t ret = renderAdapter_->Pause();
    EXPECT_EQ(ret, MediaServiceErrCode::MSERR_AUD_RENDER_FAILED);
}

/**
* @tc.name    : Test Pause API
* @tc.number  : Pause_004
* @tc.desc    : Test Pause with all operations succeeding (success path)
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, Pause_004, TestSize.Level0)
{
    renderAdapter_->renderTask_ = std::make_unique<Task>("Test", "test", TaskType::SINGLETON, TaskPriority::NORMAL, false);
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), GetStatus())
        .WillOnce(Return(AudioStandard::RendererState::RENDERER_RUNNING));
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), Pause()).WillOnce(Return(true));
    int32_t ret = renderAdapter_->Pause();
    EXPECT_EQ(ret, MediaServiceErrCode::MSERR_OK);
}

/**
* @tc.name    : Test Pause API
* @tc.number  : Pause_005
* @tc.desc    : Test Pause when renderer state is RENDERER_STOPPED
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, Pause_005, TestSize.Level1)
{
    renderAdapter_->renderTask_ = std::make_unique<Task>("Test", "test", TaskType::SINGLETON, TaskPriority::NORMAL, false);
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), GetStatus())
        .WillOnce(Return(AudioStandard::RendererState::RENDERER_STOPPED));
    int32_t ret = renderAdapter_->Pause();
    EXPECT_EQ(ret, MediaServiceErrCode::MSERR_OK);
}

/**
* @tc.name    : Test Resume API
* @tc.number  : Resume_001
* @tc.desc    : Test Resume when audioRenderer_ is nullptr
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, Resume_001, TestSize.Level1)
{
    renderAdapter_->audioRenderer_ = nullptr;
    int32_t ret = renderAdapter_->Resume();
    EXPECT_EQ(ret, MediaServiceErrCode::MSERR_INVALID_OPERATION);
}

/**
* @tc.name    : Test Resume API
* @tc.number  : Resume_002
* @tc.desc    : Test Resume when renderTask_ is nullptr
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, Resume_002, TestSize.Level1)
{
    renderAdapter_->renderTask_ = nullptr;
    int32_t ret = renderAdapter_->Resume();
    EXPECT_EQ(ret, MediaServiceErrCode::MSERR_INVALID_OPERATION);
}

/**
* @tc.name    : Test Resume API
* @tc.number  : Resume_003
* @tc.desc    : Test Resume when audioRenderer_->Start fails
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, Resume_003, TestSize.Level1)
{
    renderAdapter_->renderTask_ = std::make_unique<Task>("Test", "test", TaskType::SINGLETON, TaskPriority::NORMAL, false);
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), Start()).WillOnce(Return(false));
    int32_t ret = renderAdapter_->Resume();
    EXPECT_EQ(ret, MediaServiceErrCode::MSERR_START_FAILED);
}

/**
* @tc.name    : Test Resume API
* @tc.number  : Resume_004
* @tc.desc    : Test Resume with all operations succeeding (success path)
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, Resume_004, TestSize.Level0)
{
    renderAdapter_->renderTask_ = std::make_unique<Task>("Test", "test", TaskType::SINGLETON, TaskPriority::NORMAL, false);
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), Start()).WillOnce(Return(true));
    int32_t ret = renderAdapter_->Resume();
    EXPECT_EQ(ret, MediaServiceErrCode::MSERR_OK);
}

/**
* @tc.name    : Test Flush API
* @tc.number  : Flush_001
* @tc.desc    : Test Flush when audioRenderer_ is nullptr
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, Flush_001, TestSize.Level1)
{
    renderAdapter_->audioRenderer_ = nullptr;
    int32_t ret = renderAdapter_->Flush();
    EXPECT_EQ(ret, MediaServiceErrCode::MSERR_INVALID_OPERATION);
}

/**
* @tc.name    : Test Flush API
* @tc.number  : Flush_002
* @tc.desc    : Test Flush when audioRenderer_->Flush fails
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, Flush_002, TestSize.Level1)
{
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), Flush()).WillOnce(Return(false));
    int32_t ret = renderAdapter_->Flush();
    EXPECT_EQ(ret, MediaServiceErrCode::MSERR_AUD_RENDER_FAILED);
}

/**
* @tc.name    : Test Flush API
* @tc.number  : Flush_003
* @tc.desc    : Test Flush with all operations succeeding (success path)
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, Flush_003, TestSize.Level0)
{
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), Flush()).WillOnce(Return(true));
    renderAdapter_->PrepareInputBufferQueue();
    std::shared_ptr<AVBuffer> buffer = std::make_shared<AVBuffer>();
    renderAdapter_->swapOutputBuffers_.push(buffer);
    renderAdapter_->availOutputBuffers_.push(buffer);
    renderAdapter_->isEos_ = true;
    renderAdapter_->currentQueuedBufferOffset_ = 100;
    renderAdapter_->availDataSize_.store(1000);
    int32_t ret = renderAdapter_->Flush();
    EXPECT_EQ(ret, MediaServiceErrCode::MSERR_OK);
    EXPECT_EQ(renderAdapter_->isEos_, false);
    EXPECT_EQ(renderAdapter_->currentQueuedBufferOffset_, 0);
    EXPECT_EQ(renderAdapter_->availDataSize_.load(), 0);
}

/**
* @tc.name    : Test SetSpeed API
* @tc.number  : SetSpeed_001
* @tc.desc    : Test SetSpeed when audioRenderer_ is nullptr
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, SetSpeed_001, TestSize.Level1)
{
    renderAdapter_->audioRenderer_ = nullptr;
    int32_t ret = renderAdapter_->SetSpeed(1.0f);
    EXPECT_EQ(ret, MediaServiceErrCode::MSERR_NO_MEMORY);
}

/**
* @tc.name    : Test SetSpeed API
* @tc.number  : SetSpeed_002
* @tc.desc    : Test SetSpeed when audioRenderer_->SetSpeed fails
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, SetSpeed_002, TestSize.Level1)
{
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), SetSpeed(_)).WillOnce(Return(AudioStandard::ERROR));
    int32_t ret = renderAdapter_->SetSpeed(1.0f);
    EXPECT_EQ(ret, MediaServiceErrCode::MSERR_AUD_RENDER_FAILED);
}

/**
* @tc.name    : Test SetVolume API
* @tc.number  : SetVolume_001
* @tc.desc    : Test SetVolume when audioRenderer_ is nullptr
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, SetVolume_001, TestSize.Level1)
{
    renderAdapter_->audioRenderer_ = nullptr;
    int32_t ret = renderAdapter_->SetVolume(1.0f);
    EXPECT_EQ(ret, MediaServiceErrCode::MSERR_NO_MEMORY);
}

/**
* @tc.name    : Test SetVolume API
* @tc.number  : SetVolume_002
* @tc.desc    : Test SetVolume when audioRenderer_->SetVolume fails
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, SetVolume_002, TestSize.Level1)
{
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), SetVolume(_)).WillOnce(Return(AudioStandard::ERROR));
    int32_t ret = renderAdapter_->SetVolume(1.0f);
    EXPECT_EQ(ret, MediaServiceErrCode::MSERR_AUD_RENDER_FAILED);
}

/**
 * @tc.name    : Test GetAudioPosition API
 * @tc.number  : GetAudioPosition_001
 * @tc.desc    : Test GetAudioPosition when audioRenderer_ is nullptr
 */
HWTEST_F(LppAudioRenderAdapterUnitTest, GetAudioPosition_001, TestSize.Level1)
{
    renderAdapter_->audioRenderer_ = nullptr;
    timespec time;
    uint32_t framePosition;
    int32_t ret = renderAdapter_->GetAudioPosition(time, framePosition);
    EXPECT_EQ(ret, MediaServiceErrCode::MSERR_INVALID_OPERATION);
}

/**
 * @tc.name    : Test GetAudioPosition API
 * @tc.number  : GetAudioPosition_002
 * @tc.desc    : Test GetAudioPosition when framePosition is 0
 */
HWTEST_F(LppAudioRenderAdapterUnitTest, GetAudioPosition_002, TestSize.Level1)
{
    AudioStandard::Timestamp timestamp;
    timestamp.framePosition = 0;
    EXPECT_CALL(*(renderAdapter_->audioRenderer_), GetAudioTimestampInfo(_, _))
        .WillOnce(DoAll(SetArgReferee<0>(timestamp), Return(MSERR_OK)));
    timespec time;
    uint32_t framePosition;
    int32_t ret = renderAdapter_->GetAudioPosition(time, framePosition);
    EXPECT_EQ(ret, MediaServiceErrCode::MSERR_INVALID_OPERATION);
}

/**
 * @tc.name    : Test OnWriteData API
 * @tc.number  : OnWriteData_001
 * @tc.desc    : Test OnWriteData when audioRenderer_ is nullptr
 */
HWTEST_F(LppAudioRenderAdapterUnitTest, OnWriteData_001, TestSize.Level1)
{
    renderAdapter_->audioRenderer_ = nullptr;
    renderAdapter_->OnWriteData(1024);
}

/**
 * @tc.name    : Test OnWriteData API
 * @tc.number  : OnWriteData_002
 * @tc.desc    : Test OnWriteData when CheckBufferSize returns false
 */
HWTEST_F(LppAudioRenderAdapterUnitTest, OnWriteData_002, TestSize.Level1)
{
    renderAdapter_->isEos_ = false;
    renderAdapter_->availDataSize_.store(0);
    AudioStandard::BufferDesc bufDesc;
    bufDesc.buffer = new uint8_t[1024];
    bufDesc.bufLength = 1024;
    renderAdapter_->OnWriteData(1024);
    delete[] bufDesc.buffer;
}

/**
* @tc.name    : Test Reset API
* @tc.number  : Reset_001
* @tc.desc    : Test Reset
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, Reset_001, TestSize.Level1)
{
    int32_t ret = renderAdapter_->Reset();
    EXPECT_EQ(ret, MediaServiceErrCode::MSERR_OK);
}

/**
* @tc.name    : Test GetBufferQueueProducer API
* @tc.number  : GetBufferQueueProducer_001
* @tc.desc    : Test GetBufferQueueProducer
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, GetBufferQueueProducer_001, TestSize.Level1)
{
    renderAdapter_->PrepareInputBufferQueue();
    auto producer = renderAdapter_->GetBufferQueueProducer();
    EXPECT_NE(producer, nullptr);
}

/**
* @tc.name    : Test OnBufferAvailable API
* @tc.number  : OnBufferAvailable_001
* @tc.desc    : Test OnBufferAvailable when renderTask_ is nullptr
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, OnBufferAvailable_001, TestSize.Level1)
{
    renderAdapter_->renderTask_ = std::make_unique<Task>("Test", "test", TaskType::SINGLETON,
        TaskPriority::NORMAL, false);
    renderAdapter_->OnBufferAvailable();
}

/**
 * @tc.name    : Test Enqueue API
 * @tc.number  : Enqueue_001
 * @tc.desc    : Test Enqueue when audioRenderer_ is nullptr
 */
HWTEST_F(LppAudioRenderAdapterUnitTest, Enqueue_001, TestSize.Level1)
{
    renderAdapter_->audioRenderer_ = nullptr;
    AudioStandard::BufferDesc bufDesc;
    bufDesc.dataLength = 100;
    renderAdapter_->Enqueue(bufDesc);
}

/**
 * @tc.name    : Test DriveBufferCircle API
 * @tc.number  : DriveBufferCircle_001
 * @tc.desc    : Test DriveBufferCircle when isEos_ is true
 */
HWTEST_F(LppAudioRenderAdapterUnitTest, DriveBufferCircle_001, TestSize.Level1)
{
    renderAdapter_->isEos_ = true;
    renderAdapter_->DriveBufferCircle();
}

/**
 * @tc.name    : Test DriveBufferCircle API
 * @tc.number  : DriveBufferCircle_002
 * @tc.desc    : Test DriveBufferCircle when availOutputBuffers_ is empty
 */
HWTEST_F(LppAudioRenderAdapterUnitTest, DriveBufferCircle_002, TestSize.Level1)
{
    renderAdapter_->isEos_ = false;
    renderAdapter_->availOutputBuffers_ = {};
    renderAdapter_->DriveBufferCircle();
}

/**
 * @tc.name    : Test DriveBufferCircle API
 * @tc.number  : DriveBufferCircle_003
 * @tc.desc    : Test DriveBufferCircle when inputBufferQueue_ is nullptr
 */
HWTEST_F(LppAudioRenderAdapterUnitTest, DriveBufferCircle_003, TestSize.Level1)
{
    renderAdapter_->isEos_ = false;
    std::shared_ptr<AVBuffer> buffer = std::make_shared<AVBuffer>();
    renderAdapter_->availOutputBuffers_.push(buffer);
    renderAdapter_->inputBufferQueue_ = nullptr;
    renderAdapter_->DriveBufferCircle();
}

/**
 * @tc.name    : Test DriveBufferCircle API
 * @tc.number  : DriveBufferCircle_004
 * @tc.desc    : Test DriveBufferCircle when availDataSize >= maxCbDataSize_
 */
HWTEST_F(LppAudioRenderAdapterUnitTest, DriveBufferCircle_004, TestSize.Level1)
{
    renderAdapter_->isEos_ = false;
    std::shared_ptr<AVBuffer> buffer = std::make_shared<AVBuffer>();
    renderAdapter_->availOutputBuffers_.push(buffer);
    renderAdapter_->PrepareInputBufferQueue();
    renderAdapter_->availDataSize_.store(10000);
    renderAdapter_->maxCbDataSize_ = 100;
    renderAdapter_->DriveBufferCircle();
}

/**
 * @tc.name    : Test CopyBuffer API
 * @tc.number  : CopyBuffer_001
 * @tc.desc    : Test CopyBuffer when buffer is nullptr
 */
HWTEST_F(LppAudioRenderAdapterUnitTest, CopyBuffer_001, TestSize.Level1)
{
    std::shared_ptr<AVBuffer> buffer = nullptr;
    auto result = renderAdapter_->CopyBuffer(buffer);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name    : Test CopyBuffer API
 * @tc.number  : CopyBuffer_002
 * @tc.desc    : Test CopyBuffer when buffer->memory_ is nullptr
 */
HWTEST_F(LppAudioRenderAdapterUnitTest, CopyBuffer_002, TestSize.Level1)
{
    std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer();
    buffer->memory_ = nullptr;
    auto result = renderAdapter_->CopyBuffer(buffer);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name    : Test CopyBuffer API
 * @tc.number  : CopyBuffer_003
 * @tc.desc    : Test CopyBuffer when buffer has AudioVivid metadata (should fail)
 */
HWTEST_F(LppAudioRenderAdapterUnitTest, CopyBuffer_003, TestSize.Level1)
{
    auto allocator = AVAllocatorFactory::CreateSharedAllocator(MemoryFlag::MEMORY_READ_WRITE);
    std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer(allocator, 1024);
    buffer->memory_->SetSize(1024);
    std::vector<uint8_t> metaData = {0x01, 0x02, 0x03, 0x04};
    buffer->meta_->SetData(Tag::OH_MD_KEY_AUDIO_VIVID_METADATA, metaData);
    auto result = renderAdapter_->CopyBuffer(buffer);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name    : Test UpdateTimeAnchor API
 * @tc.number  : UpdateTimeAnchor_001
 * @tc.desc    : Test UpdateTimeAnchor when bufferPts is HST_TIME_NONE
 */
HWTEST_F(LppAudioRenderAdapterUnitTest, UpdateTimeAnchor_001, TestSize.Level1)
{
    int64_t bufferPts = Plugins::HST_TIME_NONE;
    renderAdapter_->UpdateTimeAnchor(bufferPts);
}

/**
 * @tc.name    : Test UpdateTimeAnchor API
 * @tc.number  : UpdateTimeAnchor_002
 * @tc.desc    : Test UpdateTimeAnchor when sampleFormatBytes_ is 0
 */
HWTEST_F(LppAudioRenderAdapterUnitTest, UpdateTimeAnchor_002, TestSize.Level1)
{
    int64_t bufferPts = 1000;
    renderAdapter_->sampleFormatBytes_ = 0;
    renderAdapter_->UpdateTimeAnchor(bufferPts);
}

/**
 * @tc.name    : Test UpdateTimeAnchor API
 * @tc.number  : UpdateTimeAnchor_003
 * @tc.desc    : Test UpdateTimeAnchor when eventReceiver_ is nullptr
 */
HWTEST_F(LppAudioRenderAdapterUnitTest, UpdateTimeAnchor_003, TestSize.Level1)
{
    int64_t bufferPts = 1000;
    renderAdapter_->sampleFormatBytes_ = 2;
    renderAdapter_->sampleRate_ = 44100;
    renderAdapter_->audioChannelCount_ = 2;
    renderAdapter_->writtenCnt_ = 100;
    renderAdapter_->eventReceiver_ = nullptr;
    renderAdapter_->UpdateTimeAnchor(bufferPts);
}

/**
 * @tc.name    : Test GetLatency API
 * @tc.number  : GetLatency_001
 * @tc.desc    : Test GetLatency when time info is invalid
 */
HWTEST_F(LppAudioRenderAdapterUnitTest, GetLatency_001, TestSize.Level1)
{
    renderAdapter_->curPts_ = Plugins::HST_TIME_NONE;
    renderAdapter_->anchorPts_ = Plugins::HST_TIME_NONE;
    renderAdapter_->curClock_ = Plugins::HST_TIME_NONE;
    renderAdapter_->anchorClock_ = Plugins::HST_TIME_NONE;
    int64_t latency = 0;
    renderAdapter_->GetLatency(latency);
}

/**
* @tc.name    : Test GetCurrentPosition API
* @tc.number  : GetCurrentPosition_001
* @tc.desc    : Test GetCurrentPosition when anchor is invalid
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, GetCurrentPosition_001, TestSize.Level1)
{
    renderAdapter_->anchorPts_ = Plugins::HST_TIME_NONE;
    renderAdapter_->anchorClock_ = Plugins::HST_TIME_NONE;
    int64_t position = 0;
    int32_t ret = renderAdapter_->GetCurrentPosition(position);
    EXPECT_EQ(ret, MediaServiceErrCode::MSERR_INVALID_STATE);
}

/**
 * @tc.name    : Test DropEosBuffer API
 * @tc.number  : DropEosBuffer_001
 * @tc.desc    : Test DropEosBuffer when isEos_ is false
 */
HWTEST_F(LppAudioRenderAdapterUnitTest, DropEosBuffer_001, TestSize.Level1)
{
    renderAdapter_->isEos_ = false;
    renderAdapter_->DropEosBuffer();
}

/**
 * @tc.name    : Test DropEosBuffer API
 * @tc.number  : DropEosBuffer_002
 * @tc.desc    : Test DropEosBuffer when availOutputBuffers_ is empty
 */
HWTEST_F(LppAudioRenderAdapterUnitTest, DropEosBuffer_002, TestSize.Level1)
{
    renderAdapter_->isEos_ = true;
    renderAdapter_->availOutputBuffers_ = {};
    renderAdapter_->DropEosBuffer();
}

/**
 * @tc.name    : Test DropEosBuffer API
 * @tc.number  : DropEosBuffer_003
 * @tc.desc    : Test DropEosBuffer when buffer is not EOS buffer
 */
HWTEST_F(LppAudioRenderAdapterUnitTest, DropEosBuffer_003, TestSize.Level1)
{
    renderAdapter_->isEos_ = true;
    std::shared_ptr<AVBuffer> buffer = std::make_shared<AVBuffer>();
    buffer->flag_ = 0;
    renderAdapter_->availOutputBuffers_.push(buffer);
    renderAdapter_->PrepareInputBufferQueue();
    renderAdapter_->DropEosBuffer();
}

/**
 * @tc.name    : Test DropEosBuffer API
 * @tc.number  : DropEosBuffer_004
 * @tc.desc    : Test DropEosBuffer when renderTask_ is nullptr
 */
HWTEST_F(LppAudioRenderAdapterUnitTest, DropEosBuffer_004, TestSize.Level1)
{
    renderAdapter_->isEos_ = true;
    std::shared_ptr<AVBuffer> buffer = std::make_shared<AVBuffer>();
    buffer->flag_ = static_cast<uint32_t>(Plugins::AVBufferFlag::EOS);
    renderAdapter_->availOutputBuffers_.push(buffer);
    renderAdapter_->PrepareInputBufferQueue();
    renderAdapter_->renderTask_ = nullptr;
    renderAdapter_->DropEosBuffer();
}

/**
 * @tc.name    : Test HandleEos API
 * @tc.number  : HandleEos_001
 * @tc.desc    : Test HandleEos when isEos_ is false
 */
HWTEST_F(LppAudioRenderAdapterUnitTest, HandleEos_001, TestSize.Level1)
{
    renderAdapter_->isEos_ = false;
    renderAdapter_->HandleEos();
}

/**
 * @tc.name    : Test HandleEos API
 * @tc.number  : HandleEos_002
 * @tc.desc    : Test HandleEos when audioRenderer_ is nullptr
 */
HWTEST_F(LppAudioRenderAdapterUnitTest, HandleEos_002, TestSize.Level1)
{
    renderAdapter_->isEos_ = true;
    renderAdapter_->audioRenderer_ = nullptr;
    renderAdapter_->HandleEos();
}

/**
 * @tc.name    : Test HandleEos API
 * @tc.number  : HandleEos_003
 * @tc.desc    : Test HandleEos when eventReceiver_ is nullptr
 */
HWTEST_F(LppAudioRenderAdapterUnitTest, HandleEos_003, TestSize.Level1)
{
    renderAdapter_->isEos_ = true;
    renderAdapter_->eventReceiver_ = nullptr;
    renderAdapter_->HandleEos();
}

/**
* @tc.name    : Test SetEventReceiver API
* @tc.number  : SetEventReceiver_001
* @tc.desc    : Test SetEventReceiver
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, SetEventReceiver_001, TestSize.Level1)
{
    auto mockReceiver = std::make_shared<MockEventReceiver>();
    renderAdapter_->SetEventReceiver(mockReceiver);
    EXPECT_NE(renderAdapter_->eventReceiver_, nullptr);
}

/**
* @tc.name    : Test OnInterrupt API
* @tc.number  : OnInterrupt_001
* @tc.desc    : Test OnInterrupt when eventReceiver_ is nullptr
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, OnInterrupt_001, TestSize.Level1)
{
    renderAdapter_->eventReceiver_ = nullptr;
    OHOS::AudioStandard::InterruptEvent event;
    renderAdapter_->OnInterrupt(event);
}

/**
 * @tc.name    : Test OnInterrupt API
 * @tc.number  : OnInterrupt_002
 * @tc.desc    : Test OnInterrupt with valid eventReceiver_
 */
HWTEST_F(LppAudioRenderAdapterUnitTest, OnInterrupt_002, TestSize.Level1)
{
    auto mockReceiver = std::make_shared<MockEventReceiver>();
    renderAdapter_->SetEventReceiver(mockReceiver);
    OHOS::AudioStandard::InterruptEvent event;
    event.forceType = 0;
    event.hintType = 2;
    EXPECT_CALL(*mockReceiver, OnEvent(_)).Times(1);
    renderAdapter_->OnInterrupt(event);
}

/**
* @tc.name    : Test OnOutputDeviceChange API
* @tc.number  : OnOutputDeviceChange_001
* @tc.desc    : Test OnOutputDeviceChange when eventReceiver_ is nullptr
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, OnOutputDeviceChange_001, TestSize.Level1)
{
    renderAdapter_->eventReceiver_ = nullptr;
    AudioStandard::AudioDeviceDescriptor deviceInfo;
    renderAdapter_->OnOutputDeviceChange(deviceInfo, AudioStandard::AudioStreamDeviceChangeReason::DUMMY2);
}

/**
 * @tc.name    : Test OnOutputDeviceChange API
 * @tc.number  : OnOutputDeviceChange_002
 * @tc.desc    : Test OnOutputDeviceChange with valid eventReceiver_
 */
HWTEST_F(LppAudioRenderAdapterUnitTest, OnOutputDeviceChange_002, TestSize.Level1)
{
    auto mockReceiver = std::make_shared<MockEventReceiver>();
    renderAdapter_->SetEventReceiver(mockReceiver);
    AudioStandard::AudioDeviceDescriptor deviceInfo;
    EXPECT_CALL(*mockReceiver, OnEvent(_)).Times(1);
    renderAdapter_->OnOutputDeviceChange(deviceInfo, AudioStandard::AudioStreamDeviceChangeReason::DUMMY2);
}

/**
* @tc.name    : Test OnError API
* @tc.number  : OnError_001
* @tc.desc    : Test OnError when eventReceiver_ is nullptr
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, OnError_001, TestSize.Level1)
{
    renderAdapter_->eventReceiver_ = nullptr;
    renderAdapter_->OnError(AudioStandard::AudioErrors::ERROR_INVALID_PARAM);
}

/**
 * @tc.name    : Test OnError API
 * @tc.number  : OnError_002
 * @tc.desc    : Test OnError with valid eventReceiver_
 */
HWTEST_F(LppAudioRenderAdapterUnitTest, OnError_002, TestSize.Level1)
{
    auto mockReceiver = std::make_shared<MockEventReceiver>();
    renderAdapter_->SetEventReceiver(mockReceiver);
    EXPECT_CALL(*mockReceiver, OnEvent(_)).Times(1);
    renderAdapter_->OnError(AudioStandard::AudioErrors::ERROR_INVALID_PARAM);
}

/**
* @tc.name    : Test OnAudioPolicyServiceDied API
* @tc.number  : OnAudioPolicyServiceDied_001
* @tc.desc    : Test OnAudioPolicyServiceDied when eventReceiver_ is nullptr
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, OnAudioPolicyServiceDied_001, TestSize.Level1)
{
    renderAdapter_->eventReceiver_ = nullptr;
    renderAdapter_->OnAudioPolicyServiceDied();
}

/**
 * @tc.name    : Test OnAudioPolicyServiceDied API
 * @tc.number  : OnAudioPolicyServiceDied_002
 * @tc.desc    : Test OnAudioPolicyServiceDied with valid eventReceiver_
 */
HWTEST_F(LppAudioRenderAdapterUnitTest, OnAudioPolicyServiceDied_002, TestSize.Level1)
{
    auto mockReceiver = std::make_shared<MockEventReceiver>();
    renderAdapter_->SetEventReceiver(mockReceiver);
    EXPECT_CALL(*mockReceiver, OnEvent(_)).Times(1);
    renderAdapter_->OnAudioPolicyServiceDied();
}

/**
* @tc.name    : Test OnFirstFrameWriting API
* @tc.number  : OnFirstFrameWriting_001
* @tc.desc    : Test OnFirstFrameWriting when eventReceiver_ is nullptr
*/
HWTEST_F(LppAudioRenderAdapterUnitTest, OnFirstFrameWriting_001, TestSize.Level1)
{
    renderAdapter_->eventReceiver_ = nullptr;
    renderAdapter_->OnFirstFrameWriting(0);
}

/**
 * @tc.name    : Test OnFirstFrameWriting API
 * @tc.number  : OnFirstFrameWriting_002
 * @tc.desc    : Test OnFirstFrameWriting with valid eventReceiver_
 */
HWTEST_F(LppAudioRenderAdapterUnitTest, OnFirstFrameWriting_002, TestSize.Level1)
{
    auto mockReceiver = std::make_shared<MockEventReceiver>();
    renderAdapter_->SetEventReceiver(mockReceiver);
    EXPECT_CALL(*mockReceiver, OnEvent(_)).Times(1);
    renderAdapter_->OnFirstFrameWriting(1000);
}
} // namespace Media
} // namespace OHOS