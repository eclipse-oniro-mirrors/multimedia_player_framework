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

#include "codec/common/codec_encoder.h"
#include "codec/util/codec_util.h"
#include "media_log.h"

namespace OHOS {
namespace Media {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_VIDEOEDITOR, "VideoEditorEncode"};
}

CodecEncoder::CodecEncoder(uint64_t id, std::string logTag)
    : id_(id), logTag_(logTag + "-" + std::to_string(id))
{
}

CodecEncoder::~CodecEncoder()
{
}

OH_AVCodecAsyncCallback CodecEncoder::GetAVCodecAsyncCallback()
{
    auto CodecOnErrorImpl = [](OH_AVCodec* codec, int32_t errorCode, void* context) {
        auto error = static_cast<OH_AVErrCode>(errorCode);
        CodecEncoder* encoder = static_cast<CodecEncoder*>(context);
        if (encoder == nullptr) {
            MEDIA_LOGE("encoder CodecOnError, context is nullptr, error: %{public}d(%{public}s).", error,
                CodecUtil::GetCodecErrorStr(error));
            return;
        }
        encoder->CodecOnErrorInner(codec, errorCode);
    };
    auto CodecOnStreamChangedImpl = [](OH_AVCodec*, OH_AVFormat* format, void* context) {
        CodecEncoder* encoder = static_cast<CodecEncoder*>(context);
        if (encoder == nullptr) {
            MEDIA_LOGE("encoder CodecOnStreamChanged, context is nullptr.");
            return;
        }
        encoder->CodecOnStreamChangedInner(format);
    };
    auto CodecOnNeedInputDataImpl = [](OH_AVCodec* codec, uint32_t index, OH_AVMemory* data, void* context) {
        CodecEncoder* encoder = static_cast<CodecEncoder*>(context);
        if (encoder == nullptr) {
            MEDIA_LOGE("encoder CodecOnNeedInputData, context is nullptr.");
            return;
        }
        encoder->CodecOnNeedInputDataInner(codec, index, data);
    };
    auto CodecOnNewOutputDataImpl = [](OH_AVCodec* codec, uint32_t index, OH_AVMemory* data, OH_AVCodecBufferAttr* attr,
        void* context) {
        CodecEncoder* encoder = static_cast<CodecEncoder*>(context);
        if (encoder == nullptr) {
            MEDIA_LOGE("encoder CodecOnNewOutputData, context is nullptr.");
            return;
        }
        encoder->CodecOnNewOutputDataInner(codec, index, data, attr);
    };
    // 设置回调
    return { CodecOnErrorImpl, CodecOnStreamChangedImpl, CodecOnNeedInputDataImpl, CodecOnNewOutputDataImpl };
}
} // namespace Media
} // namespace OHOS