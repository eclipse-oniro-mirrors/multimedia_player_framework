/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "cj_media_data_source_callback.h"

#include "media_errors.h"
#include "media_log.h"
#include "cj_lambda.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "CJMediaDataSourceCallback"};
}

namespace OHOS {
namespace Media {
CJMediaDataSourceCallback::CJMediaDataSourceCallback(int64_t fileSize) : size_(fileSize)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

CJMediaDataSourceCallback::~CJMediaDataSourceCallback()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

int32_t CJMediaDataSourceCallback::ReadAt(const std::shared_ptr<AVSharedMemory> &mem, uint32_t length, int64_t pos)
{
    if (cb_ == nullptr) {
        return SOURCE_ERROR_IO;
    }
    int32_t size = mem->GetSize();
    if (size <= 0) {
        return SOURCE_ERROR_IO;
    }
    uint8_t *head = static_cast<uint8_t *>(malloc(sizeof(uint8_t) * size));
    if (head == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    uint8_t *raw = mem->GetBase();
    for (int32_t i = 0; i < size; i++) {
        head[i] = raw[i];
    }
    CArrUI8 buffer = CArrUI8{.head = head, .size = size};
    auto res = cb_(buffer, length, pos);
    free(head);
    return res;
}

int32_t CJMediaDataSourceCallback::ReadAt(int64_t pos, uint32_t length, const std::shared_ptr<AVSharedMemory> &mem)
{
    (void)pos;
    (void)length;
    (void)mem;
    return MSERR_OK;
}

int32_t CJMediaDataSourceCallback::ReadAt(uint32_t length, const std::shared_ptr<AVSharedMemory> &mem)
{
    (void)length;
    (void)mem;
    return MSERR_OK;
}

int32_t CJMediaDataSourceCallback::GetSize(int64_t &size)
{
    size = size_;
    return MSERR_OK;
}

int64_t CJMediaDataSourceCallback::GetCallbackId()
{
    return callbackId_;
}

void CJMediaDataSourceCallback::SetCallback(int64_t callbackId)
{
    auto cFunc = reinterpret_cast<int32_t (*)(const CArrUI8 mem, uint32_t length, int64_t pos)>(callbackId);
    cb_ = [lambda = CJLambda::Create(cFunc)](const CArrUI8 mem, uint32_t length, int64_t pos) -> int32_t {
        auto res = lambda(mem, length, pos);
        return res;
    };
    callbackId_ = callbackId;
}

void CJMediaDataSourceCallback::ClearCallbackReference()
{
    cb_ = nullptr;
    callbackId_ = -1;
    MEDIA_LOGD("callback has been clear");
}
} // namespace Media
} // namespace OHOS
