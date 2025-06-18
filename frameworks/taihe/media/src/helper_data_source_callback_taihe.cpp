/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "helper_data_source_callback_taihe.h"
#include "avsharedmemory.h"
#include "media_dfx.h"
#include "media_log.h"
#include "media_errors.h"
#include "scope_guard.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_METADATA, "HelperDataSourceCallback"};
}

namespace OHOS {
namespace Media {
const std::string HELPER_READAT_CALLBACK_NAME = "readAt";

HelperDataSourceTHCallback::~HelperDataSourceTHCallback()
{
    isExit_ = true;
    cond_.notify_all();
    memory_ = nullptr;
}

void HelperDataSourceTHCallback::WaitResult()
{
    std::unique_lock<std::mutex> lock(mutexCond_);
    if (!setResult_) {
        static constexpr int32_t timeout = 100;
        cond_.wait_for(lock, std::chrono::milliseconds(timeout), [this]() { return setResult_ || isExit_; });
        if (!setResult_) {
            readSize_ = 0;
            if (isExit_) {
                MEDIA_LOGW("Reset, ReadAt has been cancel!");
            } else {
                MEDIA_LOGW("timeout 100ms!");
            }
        }
    }
    setResult_ = false;
}

HelperDataSourceCallback::HelperDataSourceCallback(ani_env *env, int64_t fileSize)
    : size_(fileSize)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

HelperDataSourceCallback::~HelperDataSourceCallback()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

int32_t HelperDataSourceCallback::ReadAt(const std::shared_ptr<AVSharedMemory> &mem,
    uint32_t length, int64_t pos)
{
    MEDIA_LOGD("ReadAt in");
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (refMap_.find(HELPER_READAT_CALLBACK_NAME) == refMap_.end()) {
            return SOURCE_ERROR_IO;
        }
        cb_ = std::make_shared<HelperDataSourceTHCallback>(HELPER_READAT_CALLBACK_NAME, mem, length, pos);
        CHECK_AND_RETURN_RET_LOG(cb_ != nullptr, 0, "Failed to Create HelperDataSourceTHCallback");
        cb_->callback_ = refMap_.at(HELPER_READAT_CALLBACK_NAME);
    }
    ON_SCOPE_EXIT(0) {
        cb_ = nullptr;
    };

    HelperDataSourceTHCallbackWraper *cbWrap = new(std::nothrow) HelperDataSourceTHCallbackWraper();
    ON_SCOPE_EXIT(1) {
        if (cbWrap != nullptr) {
            delete cbWrap;
        }
    };
    CHECK_AND_RETURN_RET_LOG(cbWrap != nullptr, 0, "Failed to new HelperDataSourceTHCallbackWraper");
    cbWrap->cb_ = cb_;

    auto ret = UvWork(cbWrap);
    CHECK_AND_RETURN_RET_LOG(ret == ANI_OK, SOURCE_ERROR_IO,
                             "Failed to SendEvent, ret = %{public}d", ret);
    CANCEL_SCOPE_EXIT_GUARD(1);
    cb_->WaitResult();
    MEDIA_LOGD("HelperDataSourceCallback ReadAt out");
    return cb_->readSize_;
}

ani_status HelperDataSourceCallback::UvWork(HelperDataSourceTHCallbackWraper *cbWrap)
{
    MEDIA_LOGD("begin UvWork");
    return ANI_OK;
}

int32_t HelperDataSourceCallback::ReadAt(int64_t pos, uint32_t length,
    const std::shared_ptr<AVSharedMemory> &mem)
{
    (void)pos;
    (void)length;
    (void)mem;
    return MSERR_OK;
}

int32_t HelperDataSourceCallback::ReadAt(uint32_t length, const std::shared_ptr<AVSharedMemory> &mem)
{
    (void)length;
    (void)mem;
    return MSERR_OK;
}

int32_t HelperDataSourceCallback::GetSize(int64_t &size)
{
    size = size_;
    return MSERR_OK;
}

void HelperDataSourceCallback::SaveCallbackReference(const std::string &name, std::shared_ptr<ANI::Media::AutoRef> ref)
{
    MEDIA_LOGD("Add Callback: %{public}s", name.c_str());
    std::lock_guard<std::mutex> lock(mutex_);
    refMap_[name] = ref;
}

int32_t HelperDataSourceCallback::GetCallback(const std::string &name, std::shared_ptr<uintptr_t> &callback)
{
    (void)name;
    if (refMap_.find(HELPER_READAT_CALLBACK_NAME) == refMap_.end()) {
        return MSERR_INVALID_VAL;
    }
    auto ref = refMap_.at(HELPER_READAT_CALLBACK_NAME);
    callback = ref->callbackRef_;
    return MSERR_OK;
}

void HelperDataSourceCallback::ClearCallbackReference()
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::map<std::string, std::shared_ptr<ANI::Media::AutoRef>> temp;
    temp.swap(refMap_);
    MEDIA_LOGD("callback has been clear");
    if (cb_) {
        cb_->isExit_ = true;
        cb_->cond_.notify_all();
    }
}
} // namespace Media
} // namespace ANI
