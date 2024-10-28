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

#ifndef OH_VEF_CODEC_COMMON_H
#define OH_VEF_CODEC_COMMON_H

#include <memory>
#include <functional>
#include <native_avcodec_base.h>
#include "video_editor.h"

namespace OHOS {
namespace Media {

enum class CodecType : uint32_t { VIDEO = 0, AUDIO };
enum class CodecResult : uint32_t { SUCCESS = 0, FAILED, CANCELED };
enum class CodecState : uint32_t { INIT = 0, RUNNING, FINISH_SUCCESS, FINISH_FAILED, CANCEL };

using CodecOnInData = std::function<VEFError(OH_AVCodec* codec, OH_AVMemory* data, OH_AVCodecBufferAttr* attr)>;
using CodecOnOutData = std::function<VEFError(OH_AVCodec* codec, uint32_t index, OH_AVMemory* data,
    OH_AVCodecBufferAttr* attr)>;
using CodecOnDecodeFrame = std::function<void(uint64_t pts)>;
using CodecOnDecodeResult = std::function<void(CodecResult result)>;

struct PcmData {
    std::shared_ptr<uint8_t> data = nullptr;
    int32_t dataSize = 0;
    int64_t pts = 0;
    uint32_t flags = 0;
};
} // namespace Media
} // namespace OHOS

#endif // OH_VEF_CODEC_COMMON_H