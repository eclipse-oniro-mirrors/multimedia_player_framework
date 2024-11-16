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
    }

    void TearDown() override
    {
        if (audioDecoder_ != nullptr) {
            delete audioDecoder_;
            audioDecoder_ = nullptr;
        }
    }

private:
    AudioDecoder* audioDecoder_;
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
    EXPECT_EQ(audioDecoder1->Init(format),VEFError::ERR_INTERNAL_ERROR);
    auto audioDecoder2 = new AudioDecoder(1, packetReader, onDecodeFrame, nullptr);
    EXPECT_EQ(audioDecoder2->Init(format),VEFError::ERR_INTERNAL_ERROR);
    auto audioDecoder3 = new AudioDecoder(1, nullptr, onDecodeFrame, onDecodeResult);
    EXPECT_EQ(audioDecoder3->Init(format),VEFError::ERR_INTERNAL_ERROR);
    auto audioDecoder4 = new AudioDecoder(1, nullptr, nullptr, nullptr);
    EXPECT_EQ(audioDecoder4->Init(format),VEFError::ERR_INTERNAL_ERROR);
}

// test AudioDecoder Start method
HWTEST_F(AudioDecoderTest, AudioDecoder_Start, TestSize.Level0)
{
    EXPECT_EQ(audioDecoder_->Start(), VEFError::ERR_INTERNAL_ERROR);
}

// test AudioDecoder ConfigureDecoder method
HWTEST_F(AudioDecoderTest, AudioDecoder_ConfigureDecoder, TestSize.Level0)
{
    OH_AVFormat* format = OH_AVFormat_Create();
    EXPECT_EQ(audioDecoder_->ConfigureDecoder(format), VEFError::ERR_INTERNAL_ERROR);
    OH_AVFormat_Destroy(format);
}

// test AudioDecoder CreatDecoder method
HWTEST_F(AudioDecoderTest, AudioDecoder_CreateDecoder, TestSize.Level0)
{
    audioDecoder_->codecMime_ = "audio/acc";
    EXPECT_EQ(audioDecoder_->CreateDecoder(), VEFError::ERR_INTERNAL_ERROR);
}
} // namespace Media
} // namespace OHOS