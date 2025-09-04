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
} // namespace Media
} // namespace OHOS
