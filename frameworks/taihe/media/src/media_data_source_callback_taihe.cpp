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

#include "media_data_source_callback_taihe.h"
#include "media_log.h"
#include "media_errors.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "MediaDataSourceCallback"};
}

namespace ANI {
namespace Media {

MediaDataSourceCallback::MediaDataSourceCallback(int64_t fileSize)
    : size_(fileSize)
{
}

MediaDataSourceCallback::~MediaDataSourceCallback()
{
}

int32_t MediaDataSourceCallback::ReadAt(const std::shared_ptr<OHOS::Media::AVSharedMemory> &mem,
    uint32_t length, int64_t pos)
{
    (void)length;
    (void)mem;
    return OHOS::Media::MSERR_OK;
}

int32_t MediaDataSourceCallback::ReadAt(int64_t pos, uint32_t length,
    const std::shared_ptr<OHOS::Media::AVSharedMemory> &mem)
{
    (void)pos;
    (void)length;
    (void)mem;
    return OHOS::Media::MSERR_OK;
}

int32_t MediaDataSourceCallback::ReadAt(uint32_t length, const std::shared_ptr<OHOS::Media::AVSharedMemory> &mem)
{
    (void)length;
    (void)mem;
    return OHOS::Media::MSERR_OK;
}

int32_t MediaDataSourceCallback::GetSize(int64_t &size)
{
    size = size_;
    return OHOS::Media::MSERR_OK;
}

void MediaDataSourceCallback::SaveCallbackReference(const std::string &name, std::shared_ptr<AutoRef> ref)
{
    MEDIA_LOGD("Add Callback: %{public}s", name.c_str());
    std::lock_guard<std::mutex> lock(mutex_);
    refMap_[name] = ref;
}

int32_t MediaDataSourceCallback::GetCallback(const std::string &name, std::shared_ptr<uintptr_t> &callback)
{
    (void)name;
    if (refMap_.find(READAT_CALLBACK_NAME) == refMap_.end()) {
        return OHOS::Media::MSERR_INVALID_VAL;
    }
    auto ref = refMap_.at(READAT_CALLBACK_NAME);
    callback = ref->callbackRef_;
    return OHOS::Media::MSERR_OK;
}

void MediaDataSourceCallback::ClearCallbackReference()
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::map<std::string, std::shared_ptr<AutoRef>> temp;
    temp.swap(refMap_);
    MEDIA_LOGD("callback has been clear");
    if (cb_) {
        cb_->isExit_ = true;
        cb_->cond_.notify_all();
    }
}

} // namespace Media
} // namespace OHOS
