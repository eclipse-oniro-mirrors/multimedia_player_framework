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

#ifndef OH_VEF_AUDIO_DECODER_H
#define OH_VEF_AUDIO_DECODER_H

#include "codec/common/codec_decoder.h"
#include <cstdint>
#include "codec/audio/pcm_buffer_queue.h"

namespace OHOS {
namespace Media {

class AudioDecoder : public CodecDecoder {
public:
    AudioDecoder(uint64_t id, const CodecOnInData& packetReadFunc,
        const CodecOnDecodeFrame& onDecodeFrameCallback, const CodecOnDecodeResult& onDecodeResultCallback);
    ~AudioDecoder();

public:
    VEFError Init(OH_AVFormat* format) override;
    VEFError Start() override;
    VEFError Stop() override;
    void SetPcmOutputBufferQueue(std::shared_ptr<PcmBufferQueue>& queue);

protected:
    void CodecOnErrorInner(OH_AVCodec* codec, int32_t errorCode) override;

private:
    VEFError CreateDecoder();
    VEFError ConfigureDecoder(OH_AVFormat* format);
    void CodecOnStreamChangedInner(OH_AVFormat* format) override;
    void CodecOnNeedInputDataInner(OH_AVCodec* codec, uint32_t index, OH_AVMemory* data) override;
    void CodecOnNewOutputDataInner(OH_AVCodec* codec, uint32_t index, OH_AVMemory* data,
        OH_AVCodecBufferAttr* attr) override;
private:
    CodecOnInData packetReadFunc_{ nullptr };
    CodecOnDecodeFrame onDecodeFrameCallback_{ nullptr };
    CodecOnDecodeResult onDecodeResultCallback_{ nullptr };
    std::shared_ptr<PcmBufferQueue> pcmInputBufferQueue_;
};
} // namespace Media
} // namespace OHOS

#endif // OH_VEF_AUDIO_DECODER_H