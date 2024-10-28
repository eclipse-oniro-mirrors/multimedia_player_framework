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

#ifndef OH_VEF_CODEC_DECODER_H
#define OH_VEF_CODEC_DECODER_H

#include <string>
#include "codec/common/codec_common.h"

namespace OHOS {
namespace Media {

class CodecDecoder {
public:
    CodecDecoder() = delete;
    CodecDecoder(uint64_t id, std::string logTag);
    virtual ~CodecDecoder();

    virtual VEFError Init(OH_AVFormat* format) = 0;
    virtual VEFError Start() = 0;
    virtual VEFError Stop() = 0;

protected:
    OH_AVCodecAsyncCallback GetAVCodecAsyncCallback();
    virtual void CodecOnErrorInner(OH_AVCodec* codec, int32_t errorCode) = 0;

    uint64_t id_ { 0 };
    std::string logTag_;
    OH_AVCodec* decoder_ { nullptr };
    std::string codecMime_;
    CodecState state_;

private:
    virtual void CodecOnStreamChangedInner(OH_AVFormat* format) = 0;
    virtual void CodecOnNeedInputDataInner(OH_AVCodec* codec, uint32_t index, OH_AVMemory* data) = 0;
    virtual void CodecOnNewOutputDataInner(OH_AVCodec* codec, uint32_t index, OH_AVMemory* data,
        OH_AVCodecBufferAttr* attr) = 0;
};
} // namespace Media
} // namespace OHOS

#endif // OH_VEF_CODEC_DECODER_H