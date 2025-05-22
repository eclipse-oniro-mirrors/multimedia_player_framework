/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "avtranscoder_ffi.h"
#include "cj_avtranscoder.h"
#include "media_log.h"

namespace OHOS {
namespace Media {
using namespace OHOS::FFI;

extern "C" {
int64_t FfiAVTranscoderCreateAVTranscoder(int32_t* errCode)
{
    if (errCode == nullptr) {
        MEDIA_LOGE("[CJAVTranscoder] errCode is nullptr!");
        return INVALID_ID;
    }
    return CJAVTranscoder::CreateAVTranscoder(errCode);
}

int32_t FfiAVTranscoderPrepare(int64_t id, CAVTransCoderConfig config)
{
    auto cjAVTranscoder = FFIData::GetData<CJAVTranscoder>(id);
    if (cjAVTranscoder == nullptr) {
        MEDIA_LOGE("[CJAVTranscoder] instance is nullptr!");
        return MSERR_EXT_API9_NO_MEMORY;
    }

    std::shared_ptr<TransCoder> transCoder = cjAVTranscoder->transCoder_;
    if (!transCoder) {
        MEDIA_LOGE("[CJAVTranscoder] transCoder_ is nullptr!");
        return MSERR_EXT_API9_NO_MEMORY;
    }

    return cjAVTranscoder->Prepare(transCoder, config);
}

int32_t FfiAVTranscoderStart(int64_t id)
{
    auto cjAVTranscoder = FFIData::GetData<CJAVTranscoder>(id);
    if (cjAVTranscoder == nullptr) {
        MEDIA_LOGE("[CJAVTranscoder] instance is nullptr!");
        return MSERR_EXT_API9_NO_MEMORY;
    }

    std::shared_ptr<TransCoder> transCoder = cjAVTranscoder->transCoder_;
    if (!transCoder) {
        MEDIA_LOGE("[CJAVTranscoder] transCoder_ is nullptr!");
        return MSERR_EXT_API9_NO_MEMORY;
    }

    return cjAVTranscoder->Start(transCoder);
}

int32_t FfiAVTranscoderPause(int64_t id)
{
    auto cjAVTranscoder = FFIData::GetData<CJAVTranscoder>(id);
    if (cjAVTranscoder == nullptr) {
        MEDIA_LOGE("[CJAVTranscoder] instance is nullptr!");
        return MSERR_EXT_API9_NO_MEMORY;
    }

    std::shared_ptr<TransCoder> transCoder = cjAVTranscoder->transCoder_;
    if (!transCoder) {
        MEDIA_LOGE("[CJAVTranscoder] transCoder_ is nullptr!");
        return MSERR_EXT_API9_NO_MEMORY;
    }

    return cjAVTranscoder->Pause(transCoder);
}

int32_t FfiAVTranscoderResume(int64_t id)
{
    auto cjAVTranscoder = FFIData::GetData<CJAVTranscoder>(id);
    if (cjAVTranscoder == nullptr) {
        MEDIA_LOGE("[CJAVTranscoder] instance is nullptr!");
        return MSERR_EXT_API9_NO_MEMORY;
    }

    std::shared_ptr<TransCoder> transCoder = cjAVTranscoder->transCoder_;
    if (!transCoder) {
        MEDIA_LOGE("[CJAVTranscoder] transCoder_ is nullptr!");
        return MSERR_EXT_API9_NO_MEMORY;
    }

    return cjAVTranscoder->Resume(transCoder);
}

int32_t FfiAVTranscoderCancel(int64_t id)
{
    auto cjAVTranscoder = FFIData::GetData<CJAVTranscoder>(id);
    if (cjAVTranscoder == nullptr) {
        MEDIA_LOGE("[CJAVTranscoder] instance is nullptr!");
        return MSERR_EXT_API9_NO_MEMORY;
    }

    std::shared_ptr<TransCoder> transCoder = cjAVTranscoder->transCoder_;
    if (!transCoder) {
        MEDIA_LOGE("[CJAVTranscoder] transCoder_ is nullptr!");
        return MSERR_EXT_API9_NO_MEMORY;
    }

    return cjAVTranscoder->Cancel(transCoder);
}

int32_t FfiAVTranscoderRelease(int64_t id)
{
    auto cjAVTranscoder = FFIData::GetData<CJAVTranscoder>(id);
    if (cjAVTranscoder == nullptr) {
        MEDIA_LOGE("[CJAVTranscoder] instance is nullptr!");
        return MSERR_EXT_API9_NO_MEMORY;
    }

    std::shared_ptr<TransCoder> transCoder = cjAVTranscoder->transCoder_;
    if (!transCoder) {
        MEDIA_LOGE("[CJAVTranscoder] transCoder_ is nullptr!");
        return MSERR_EXT_API9_NO_MEMORY;
    }

    return cjAVTranscoder->Release(transCoder);
}

CAVFileDescriptor FfiAVTranscoderGetFdSrc(int64_t id, int32_t* errCode)
{
    if (errCode == nullptr) {
        MEDIA_LOGE("[CJAVTranscoder] errCode is nullptr!");
        return CAVFileDescriptor{0};
    }
    auto cjAVTranscoder = FFIData::GetData<CJAVTranscoder>(id);
    if (cjAVTranscoder == nullptr) {
        *errCode = MSERR_EXT_API9_NO_MEMORY;
        return CAVFileDescriptor{0};
    }
    *errCode = MSERR_EXT_API9_OK;
    return cjAVTranscoder->GetInputFile();
}

int32_t FfiAVTranscoderSetFdSrc(int64_t id, CAVFileDescriptor fdSrc)
{
    auto cjAVTranscoder = FFIData::GetData<CJAVTranscoder>(id);
    if (cjAVTranscoder == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }

    std::shared_ptr<TransCoder> transCoder = cjAVTranscoder->transCoder_;
    if (!transCoder) {
        MEDIA_LOGE("[CJAVTranscoder] transCoder_ is nullptr!");
        return MSERR_EXT_API9_NO_MEMORY;
    }

    return cjAVTranscoder->SetInputFile(transCoder, fdSrc);
}

int32_t FfiAVTranscoderGetFdDst(int64_t id, int32_t* errCode)
{
    if (errCode == nullptr) {
        MEDIA_LOGE("[CJAVTranscoder] errCode is nullptr!");
        return 0;
    }
    auto cjAVTranscoder = FFIData::GetData<CJAVTranscoder>(id);
    if (cjAVTranscoder == nullptr) {
        *errCode = MSERR_EXT_API9_NO_MEMORY;
        return 0;
    }
    *errCode = MSERR_EXT_API9_OK;
    return cjAVTranscoder->GetOutputFile();
}

int32_t FfiAVTranscoderSetFdDst(int64_t id, int32_t fdDst)
{
    auto cjAVTranscoder = FFIData::GetData<CJAVTranscoder>(id);
    if (cjAVTranscoder == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }

    std::shared_ptr<TransCoder> transCoder = cjAVTranscoder->transCoder_;
    if (!transCoder) {
        MEDIA_LOGE("[CJAVTranscoder] transCoder_ is nullptr!");
        return MSERR_EXT_API9_NO_MEMORY;
    }

    return cjAVTranscoder->SetOutputFile(transCoder, fdDst);
}

int32_t FfiAVTranscoderOnProgressUpdate(int64_t id, int64_t callbackId)
{
    auto cjAVTranscoder = FFIData::GetData<CJAVTranscoder>(id);
    if (cjAVTranscoder == nullptr) {
        MEDIA_LOGE("[CJAVTranscoder] instance is nullptr!");
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return cjAVTranscoder->OnProgressUpdate(callbackId);
}

int32_t FfiAVTranscoderOffProgressUpdate(int64_t id)
{
    auto cjAVTranscoder = FFIData::GetData<CJAVTranscoder>(id);
    if (cjAVTranscoder == nullptr) {
        MEDIA_LOGE("[CJAVTranscoder] instance is nullptr!");
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return cjAVTranscoder->OffProgressUpdate();
}

int32_t FfiAVTranscoderOnComplete(int64_t id, int64_t callbackId)
{
    auto cjAVTranscoder = FFIData::GetData<CJAVTranscoder>(id);
    if (cjAVTranscoder == nullptr) {
        MEDIA_LOGE("[CJAVTranscoder] instance is nullptr!");
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return cjAVTranscoder->OnComplete(callbackId);
}

int32_t FfiAVTranscoderOffComplete(int64_t id)
{
    auto cjAVTranscoder = FFIData::GetData<CJAVTranscoder>(id);
    if (cjAVTranscoder == nullptr) {
        MEDIA_LOGE("[CJAVTranscoder] instance is nullptr!");
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return cjAVTranscoder->OffComplete();
}

int32_t FfiAVTranscoderOnError(int64_t id, int64_t callbackId)
{
    auto cjAVTranscoder = FFIData::GetData<CJAVTranscoder>(id);
    if (cjAVTranscoder == nullptr) {
        MEDIA_LOGE("[CJAVTranscoder] instance is nullptr!");
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return cjAVTranscoder->OnError(callbackId);
}

int32_t FfiAVTranscoderOffError(int64_t id)
{
    auto cjAVTranscoder = FFIData::GetData<CJAVTranscoder>(id);
    if (cjAVTranscoder == nullptr) {
        MEDIA_LOGE("[CJAVTranscoder] instance is nullptr!");
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return cjAVTranscoder->OffError();
}
}
}
}