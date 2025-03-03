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

#include "cj_helperdatasourcecallback.h"
#include "cj_lambda.h"
#include "media_errors.h"
#include "media_log.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_METADATA, "CJHelperDataSourceCallback"};
}

namespace OHOS {
namespace Media {
const std::string HELPER_READAT_CALLBACK_NAME = "readAt";

HelperDataSourceCJCallback::~HelperDataSourceCJCallback()
{
    isExit_ = true;
    cond_.notify_all();
    memory_ = nullptr;
}

void HelperDataSourceCJCallback::WaitResult()
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

CJHelperDataSourceCallback::CJHelperDataSourceCallback(int64_t fileSize) : size_(fileSize)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

CJHelperDataSourceCallback::~CJHelperDataSourceCallback()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

int32_t CJHelperDataSourceCallback::ReadAt(
    const std::shared_ptr<AVSharedMemory> &mem, uint32_t length, int64_t pos)
{
    int32_t ret = 0;
    MEDIA_LOGD("ReadAt in");
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (funcMap_.find(HELPER_READAT_CALLBACK_NAME) == funcMap_.end()) {
            return SOURCE_ERROR_IO;
        }
        cb_ = std::make_shared<HelperDataSourceCJCallback>(HELPER_READAT_CALLBACK_NAME, mem, length, pos);
        CHECK_AND_RETURN_RET_LOG(cb_ != nullptr, 0, "Failed to Create HelperDataSourceCJCallback");
        cb_->callback_ = funcMap_.at(HELPER_READAT_CALLBACK_NAME).second;
    }
    do {
        MEDIA_LOGD("length is %{public}u", length);
        auto arraybuffer = mem->GetBase();
        if (arraybuffer == nullptr) {
            MEDIA_LOGE("Failed to get arraybuffer.");
        }
        ret = cb_->callback_(arraybuffer, length, pos);
        std::unique_lock<std::mutex> lock(cb_->mutexCond_);
        cb_->setResult_ = true;
        cb_->cond_.notify_all();
    } while (0);
    cb_->WaitResult();
    return ret;
}

int32_t CJHelperDataSourceCallback::GetSize(int64_t &size)
{
    size = size_;
    return MSERR_OK;
}

int32_t CJHelperDataSourceCallback::GetCallbackId(int64_t &id)
{
    return MSERR_OK;
}

int32_t CJHelperDataSourceCallback::ReadAt(int64_t pos, uint32_t length, const std::shared_ptr<AVSharedMemory> &mem)
{
    (void)pos;
    (void)length;
    (void)mem;
    return MSERR_OK;
}

int32_t CJHelperDataSourceCallback::ReadAt(uint32_t length, const std::shared_ptr<AVSharedMemory> &mem)
{
    (void)length;
    (void)mem;
    return MSERR_OK;
}

int32_t CJHelperDataSourceCallback::SaveCallbackReference(const std::string &name, int64_t id)
{
    std::lock_guard<std::mutex> lock(mutex_);
    funcMap_[name].first = id;
    auto func = reinterpret_cast<int32_t(*)(uint8_t*, uint32_t, int64_t)>(id);
    funcMap_[name].second = [lambda = CJLambda::Create(func)](uint8_t* mem, uint32_t length, int64_t pos) -> int32_t {
        auto res = lambda(mem, length, pos);
        return res;
    };
    if (funcMap_[name].second == nullptr) {
        return MSERR_INVALID_VAL;
    }
    return MSERR_OK;
}

void CJHelperDataSourceCallback::ClearCallbackReference()
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::map<std::string, std::pair<int64_t, std::function<int32_t(uint8_t *, uint32_t, int64_t)>>> temp;
    temp.swap(funcMap_);
    MEDIA_LOGD("callback has been clear");
}

} // namespace Media
} // namespace OHOS
