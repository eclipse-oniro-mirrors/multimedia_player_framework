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
#include <native_avcodec_audiodecoder.h>
#include <avcodec_mime_type.h>
#include "codec/audio/decoder/audio_decoder.h"
#include "codec/video/decoder/video_demuxer.h"
#include <fcntl.h>

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {

class AudioDecoderTest : public testing::Test {
protected:
    void SetUp() override
    {
        std::function packetReader = [&](OH_AVCodec*, OH_AVMemory* data, OH_AVCodecBufferAttr* attr) -> VEFError {
            return VEFError::ERR_OK;
        };
        std::function onDecodeFrame = [&](uint64_t pts) -> void {};
        std::function onDecodeResult = [&](CodecResult result) -> void {};
        audioDecoder_ = new AudioDecoder(1, packetReader, onDecodeFrame, onDecodeResult);
        codec_ = OH_AudioDecoder_CreateByMime((MediaAVCodec::AVCodecMimeType::MEDIA_MIMETYPE_AUDIO_AAC).data());
        uint32_t buffersize = 1024 * 1024;
        sampleMem_ = OH_AVMemory_Create(buffersize);
        format_ = OH_AVFormat_Create();
    }

    void TearDown() override
    {
        if (audioDecoder_ != nullptr) {
            delete audioDecoder_;
            audioDecoder_ = nullptr;
        }
        if (codec_ != nullptr) {
            OH_AudioDecoder_Destroy(codec_);
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
    AudioDecoder* audioDecoder_ = nullptr;
    OH_AVCodec* codec_ = nullptr;
    OH_AVMemory* sampleMem_ = nullptr;
    OH_AVFormat* format_ = nullptr;
};

// test AudioDecoder Init method
HWTEST_F(AudioDecoderTest, AudioDecoder_Init, TestSize.Level0)
{
    EXPECT_EQ(audioDecoder_->Init(nullptr), VEFError::ERR_INTERNAL_ERROR);
    std::function packetReader = [&](OH_AVCodec*, OH_AVMemory* data, OH_AVCodecBufferAttr* attr) -> VEFError {
        return VEFError::ERR_OK;
    };
    std::function onDecodeFrame = [&](uint64_t pts) -> void {};
    std::function onDecodeResult = [&](CodecResult result) -> void {};
    OH_AVFormat* format = OH_AVFormat_Create();
    auto audioDecoder1 = new AudioDecoder(1, packetReader, nullptr, nullptr);
    EXPECT_EQ(audioDecoder1->Init(format), VEFError::ERR_INTERNAL_ERROR);
    auto audioDecoder2 = new AudioDecoder(1, packetReader, onDecodeFrame, nullptr);
    EXPECT_EQ(audioDecoder2->Init(format), VEFError::ERR_INTERNAL_ERROR);
    auto audioDecoder3 = new AudioDecoder(1, nullptr, onDecodeFrame, onDecodeResult);
    EXPECT_EQ(audioDecoder3->Init(format), VEFError::ERR_INTERNAL_ERROR);
    auto audioDecoder4 = new AudioDecoder(1, nullptr, nullptr, nullptr);
    EXPECT_EQ(audioDecoder4->Init(format), VEFError::ERR_INTERNAL_ERROR);
}

// test AudioDecoder Start method
HWTEST_F(AudioDecoderTest, AudioDecoder_Start, TestSize.Level0)
{
    EXPECT_EQ(audioDecoder_->Start(), VEFError::ERR_INTERNAL_ERROR);
}

// test AudioDecoder ConfigureDecoder method
HWTEST_F(AudioDecoderTest, AudioDecoder_ConfigureDecoder, TestSize.Level0)
{
    EXPECT_EQ(audioDecoder_->ConfigureDecoder(format_), VEFError::ERR_INTERNAL_ERROR);
}

// test AudioDecoder CreatDecoder method
HWTEST_F(AudioDecoderTest, AudioDecoder_CreateDecoder, TestSize.Level0)
{
    audioDecoder_->CodecOnErrorInner(codec_, 0);
    audioDecoder_->CodecOnErrorInner(nullptr, 0);
    EXPECT_EQ(audioDecoder_->CreateDecoder(), VEFError::ERR_INTERNAL_ERROR);
}

HWTEST_F(AudioDecoderTest, AudioDecoder_CodecOnStreamChangedInner, TestSize.Level0)
{
    audioDecoder_->CodecOnStreamChangedInner(format_);
    audioDecoder_->CodecOnStreamChangedInner(nullptr);
    EXPECT_EQ(audioDecoder_->CreateDecoder(), VEFError::ERR_INTERNAL_ERROR);
}

HWTEST_F(AudioDecoderTest, AudioDecoder_CodecOnNeedInputDataInner, TestSize.Level0)
{
    audioDecoder_->CodecOnNeedInputDataInner(nullptr, 1, nullptr);
    audioDecoder_->CodecOnNeedInputDataInner(nullptr, 1, sampleMem_);
    audioDecoder_->CodecOnNeedInputDataInner(codec_, 1, nullptr);
    audioDecoder_->CodecOnNeedInputDataInner(codec_, 1, sampleMem_);
    EXPECT_EQ(audioDecoder_->CreateDecoder(), VEFError::ERR_INTERNAL_ERROR);
}

HWTEST_F(AudioDecoderTest, AudioDecoder_CodecOnNewOutputDataInner, TestSize.Level0)
{
    OH_AVCodecBufferAttr attr;
    attr.size = 1024 * 1024;
    attr.pts = 100;
    attr.flags = 1;
    audioDecoder_->CodecOnNewOutputDataInner(nullptr, 1, nullptr, nullptr);
    audioDecoder_->CodecOnNewOutputDataInner(codec_, 1, nullptr, nullptr);
    audioDecoder_->CodecOnNewOutputDataInner(codec_, 1, sampleMem_, nullptr);
    audioDecoder_->CodecOnNewOutputDataInner(nullptr, 1, sampleMem_, &attr);
    audioDecoder_->CodecOnNewOutputDataInner(codec_, 1, nullptr, &attr);
    EXPECT_EQ(audioDecoder_->CreateDecoder(), VEFError::ERR_INTERNAL_ERROR);
}
} // namespace Media
} // namespace OHOS