/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"
#include "codec/audio/encoder/audio_encoder.h"
#include <native_avcodec_audioencoder.h>
#include <avcodec_mime_type.h>
#include "ut_common_data.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {

class AudioEncoderTest : public testing::Test {
protected:
    void SetUp() override
    {
        audioEncoder_ = new AudioEncoder(1, encodeCallback_);
        codec_ = OH_AudioEncoder_CreateByMime((MediaAVCodec::AVCodecMimeType::MEDIA_MIMETYPE_AUDIO_AAC).data());
        uint32_t buffersize = 1024 * 1024;
        sampleMem_ = OH_AVMemory_Create(buffersize);
        format_ = OH_AVFormat_Create();
    }

    void TearDown() override
    {
        if (audioEncoder_ != nullptr) {
            delete audioEncoder_;
            audioEncoder_ = nullptr;
        }
        if (codec_ != nullptr) {
            OH_AudioEncoder_Destroy(codec_);
            codec_ = nullptr;
        }
        if (sampleMem_ != nullptr) {
            OH_AVMemory_Destroy(sampleMem_);
            sampleMem_ = nullptr;
        }
        if (format_ != nullptr) {
            OH_AVFormat_Destroy(format_);
            format_ = nullptr;
        }
    }

private:
    AudioEncoder* audioEncoder_ = nullptr;
    CodecOnOutData encodeCallback_;
    OH_AVCodec* codec_ = nullptr;
    OH_AVMemory* sampleMem_ = nullptr;
    OH_AVFormat* format_ = nullptr;
};

// test AudioEncoder Start method
HWTEST_F(AudioEncoderTest, AudioEncoder_Start, TestSize.Level0)
{
    EXPECT_EQ(audioEncoder_->Start(), VEFError::ERR_INTERNAL_ERROR);
}

// test AudioEncoder Stop method
HWTEST_F(AudioEncoderTest, AudioEncoder_Stop, TestSize.Level0)
{
    EXPECT_EQ(audioEncoder_->Stop(), VEFError::ERR_INTERNAL_ERROR);
}


// test AudioEncoder Finish method
HWTEST_F(AudioEncoderTest, AudioEncoder_Finish, TestSize.Level0)
{
    EXPECT_EQ(audioEncoder_->Flush(), VEFError::ERR_INTERNAL_ERROR);
}

// test AudioEncoder CreateDecoder method
HWTEST_F(AudioEncoderTest, AudioEncoder_CreateDecoder, TestSize.Level0)
{
    EXPECT_EQ(audioEncoder_->CreateEncoder(), VEFError::ERR_INTERNAL_ERROR);
}

HWTEST_F(AudioEncoderTest, AudioEncoder_CodecOnErrorInner, TestSize.Level0)
{
    audioEncoder_->CodecOnErrorInner(codec_, 0);
    audioEncoder_->CodecOnErrorInner(nullptr, 0);
    EXPECT_EQ(audioEncoder_->Start(), VEFError::ERR_INTERNAL_ERROR);
}

HWTEST_F(AudioEncoderTest, AudioEncoder_CodecOnStreamChangedInner, TestSize.Level0)
{
    audioEncoder_->CodecOnStreamChangedInner(format_);
    audioEncoder_->CodecOnStreamChangedInner(nullptr);
    EXPECT_EQ(audioEncoder_->Start(), VEFError::ERR_INTERNAL_ERROR);
}

HWTEST_F(AudioEncoderTest, AudioEncoder_CodecOnNewOutputDataInner, TestSize.Level0)
{
    OH_AVCodecBufferAttr attr;
    attr.size = 1024 * 1024;
    attr.pts = 100;
    attr.flags = 1;
    audioEncoder_->CodecOnNewOutputDataInner(nullptr, 1, nullptr, nullptr);
    audioEncoder_->CodecOnNewOutputDataInner(codec_, 1, nullptr, nullptr);
    audioEncoder_->CodecOnNewOutputDataInner(codec_, 1, sampleMem_, nullptr);
    audioEncoder_->CodecOnNewOutputDataInner(nullptr, 1, sampleMem_, &attr);
    audioEncoder_->CodecOnNewOutputDataInner(codec_, 1, nullptr, &attr);
    EXPECT_EQ(audioEncoder_->Start(), VEFError::ERR_INTERNAL_ERROR);
}

HWTEST_F(AudioEncoderTest, AudioEncoder_CodecOnNeedInputDataInnerr, TestSize.Level0)
{
    audioEncoder_->CodecOnNeedInputDataInner(nullptr, 1, nullptr);
    audioEncoder_->CodecOnNeedInputDataInner(nullptr, 1, sampleMem_);
    audioEncoder_->CodecOnNeedInputDataInner(codec_, 1, nullptr);
    EXPECT_EQ(audioEncoder_->Start(), VEFError::ERR_INTERNAL_ERROR);
}

HWTEST_F(AudioEncoderTest, AudioEncoder_CodecOnNeedInputDataInnerr_1, TestSize.Level0)
{
    std::string fileName = "H264_AAC_multi_track.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    VideoDecodeCallbackTester* deCb = new VideoDecodeCallbackTester();
    auto decoderEngine = IVideoDecoderEngine::Create(srcFd, deCb);
    ASSERT_NE(decoderEngine, nullptr);
    VideoEncodeParam enCodeParam = VideoResource::instance().getEncodeParam(srcFd, decoderEngine);
    VideoEncodeCallbackTester* enCb = new VideoEncodeCallbackTester();
    auto encoderEngine = IVideoEncoderEngine::Create(enCodeParam, enCb);
    ASSERT_NE(encoderEngine, nullptr);
    std::shared_ptr<PcmData> pcmData = std::make_shared<PcmData>();
    pcmData->flags = 12;
    pcmData->pts = 100;
    pcmData->dataSize = 0;
    pcmData->data = nullptr;
    audioEncoder_->pcmInputBufferQueue_->Enqueue(pcmData);
    EXPECT_EQ(audioEncoder_->pcmInputBufferQueue_->queue_.size(), 1);
    audioEncoder_->CodecOnNeedInputDataInner(codec_, 1, sampleMem_);
    EXPECT_EQ(audioEncoder_->pcmInputBufferQueue_->queue_.size(), 0);
    (void)close(srcFd);
}

HWTEST_F(AudioEncoderTest, AudioEncoder_CodecOnNeedInputDataInnerr_flag_one, TestSize.Level0)
{
    std::string fileName = "H264_AAC_multi_track.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    VideoDecodeCallbackTester* deCb = new VideoDecodeCallbackTester();
    auto decoderEngine = IVideoDecoderEngine::Create(srcFd, deCb);
    ASSERT_NE(decoderEngine, nullptr);
    VideoEncodeParam enCodeParam = VideoResource::instance().getEncodeParam(srcFd, decoderEngine);
    VideoEncodeCallbackTester* enCb = new VideoEncodeCallbackTester();
    auto encoderEngine = IVideoEncoderEngine::Create(enCodeParam, enCb);
    ASSERT_NE(encoderEngine, nullptr);
    std::shared_ptr<PcmData> pcmData = std::make_shared<PcmData>();
    pcmData->flags = 1;
    pcmData->pts = 100;
    pcmData->dataSize = 0;
    pcmData->data = nullptr;
    audioEncoder_->pcmInputBufferQueue_->Enqueue(pcmData);
    EXPECT_EQ(audioEncoder_->pcmInputBufferQueue_->queue_.size(), 1);
    audioEncoder_->CodecOnNeedInputDataInner(codec_, 1, sampleMem_);
    EXPECT_EQ(audioEncoder_->pcmInputBufferQueue_->queue_.size(), 0);
    (void)close(srcFd);
}

HWTEST_F(AudioEncoderTest, AudioEncoder_CodecOnNeedInputDataInnerr_dataSize_9, TestSize.Level0)
{
    std::string fileName = "H264_AAC_multi_track.mp4";
    int32_t srcFd = VideoResource::instance().getFileResource(fileName);
    VideoDecodeCallbackTester* deCb = new VideoDecodeCallbackTester();
    auto decoderEngine = IVideoDecoderEngine::Create(srcFd, deCb);
    ASSERT_NE(decoderEngine, nullptr);
    VideoEncodeParam enCodeParam = VideoResource::instance().getEncodeParam(srcFd, decoderEngine);
    VideoEncodeCallbackTester* enCb = new VideoEncodeCallbackTester();
    auto encoderEngine = IVideoEncoderEngine::Create(enCodeParam, enCb);
    ASSERT_NE(encoderEngine, nullptr);
    std::shared_ptr<PcmData> pcmData = std::make_shared<PcmData>();
    pcmData->flags = 12;
    pcmData->pts = 100;
    pcmData->dataSize = 9;
    pcmData->data = nullptr;
    audioEncoder_->pcmInputBufferQueue_->Enqueue(pcmData);
    EXPECT_EQ(audioEncoder_->pcmInputBufferQueue_->queue_.size(), 1);
    audioEncoder_->CodecOnNeedInputDataInner(codec_, 1, sampleMem_);
    EXPECT_EQ(audioEncoder_->pcmInputBufferQueue_->queue_.size(), 0);
    (void)close(srcFd);
}

HWTEST_F(AudioEncoderTest, AudioEncoder_PushPcmData, TestSize.Level0)
{
    OH_AVCodecBufferAttr attr;
    attr.size = 1024 * 1024;
    attr.pts = 100;
    attr.flags = 1;
    EXPECT_EQ(audioEncoder_->PushPcmData(1, attr), VEFError::ERR_INTERNAL_ERROR);
}
} // namespace Media
} // namespace OHOS