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

using DataSrcCallback = taihe::callback<int32_t(taihe::array_view<uint8_t>, int64_t, taihe::optional_view<int64_t>)>;

namespace ANI {
namespace Media {
MediaDataSourceTHCallback::~MediaDataSourceTHCallback()
{
    isExit_ = true;
    cond_.notify_all();
    memory_ = nullptr;
}

void MediaDataSourceTHCallback::WaitResult()
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

MediaDataSourceCallback::MediaDataSourceCallback(int64_t fileSize)
    : size_(fileSize)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

MediaDataSourceCallback::~MediaDataSourceCallback()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

int32_t MediaDataSourceCallback::ReadAt(const std::shared_ptr<OHOS::Media::AVSharedMemory> &mem,
    uint32_t length, int64_t pos)
{
    MEDIA_LOGD("MediaDataSourceCallback ReadAt in");
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (refMap_.find(READAT_CALLBACK_NAME) == refMap_.end()) {
            return OHOS::Media::SOURCE_ERROR_IO;
        }
        cb_ = std::make_shared<MediaDataSourceTHCallback>(READAT_CALLBACK_NAME, mem, length, pos);
        CHECK_AND_RETURN_RET_LOG(cb_ != nullptr, 0, "Failed to Create MediaDataSourceTHCallback");
        cb_->callback_ = refMap_.at(READAT_CALLBACK_NAME);
    }

    MediaDataSourceTHCallbackWraper *cbWrap = new(std::nothrow) MediaDataSourceTHCallbackWraper();
    CHECK_AND_RETURN_RET_LOG(cbWrap != nullptr, 0, "Failed to new MediaDataSourceTHCallbackWraper");
    cbWrap->cb_ = cb_;

    UvWork(cbWrap);
    cb_->WaitResult();
    MEDIA_LOGD("ReadAt out");
    return cb_->readSize_;
}

void MediaDataSourceCallback::UvWork(MediaDataSourceTHCallbackWraper *cbWrap)
{
    MEDIA_LOGD("begin UvWork");
    auto task = [cbWrap]() {
        CHECK_AND_RETURN_LOG(cbWrap != nullptr, "MediaDataSourceTHCallbackWraper is nullptr");
        std::shared_ptr<MediaDataSourceTHCallback> event = cbWrap->cb_.lock();
        do {
            CHECK_AND_BREAK_LOG(event != nullptr, "MediaDataSourceTHCallback is nullptr");
            MEDIA_LOGD("length is %{public}u", event->length_);
            std::shared_ptr<AutoRef> ref = event->callback_.lock();
            CHECK_AND_BREAK_LOG(ref != nullptr, "%{public}s AutoRef is nullptr", event->callbackName_.c_str());

            auto func = ref->callbackRef_;
            CHECK_AND_RETURN_LOG(func != nullptr, "failed to get callback");
            std::shared_ptr<DataSrcCallback> cacheCallback = std::reinterpret_pointer_cast<DataSrcCallback>(func);
            MEDIA_LOGD("call Taihe function");

            CHECK_AND_BREAK_LOG(event->memory_ != nullptr, "failed to checkout memory");
            uint8_t *base = event->memory_->GetBase();
            int64_t length = static_cast<int64_t>(event->length_);
            std::vector<uint8_t> buffer(base, base + length);
            taihe::array_view<uint8_t> bufferView = taihe::array_view<uint8_t>(buffer);
            if (event->pos_ != -1) {
                int64_t pos = event->pos_;
                event->readSize_ = (*cacheCallback)(bufferView, length, taihe::optional<int64_t>::make(pos));
            } else {
                event->readSize_ = (*cacheCallback)(bufferView, length, taihe::optional<int64_t>(std::nullopt));
            }

            std::unique_lock<std::mutex> lock(event->mutexCond_);
            event->setResult_ = true;
            event->cond_.notify_all();
        } while (0);
        delete cbWrap;
    };
    bool ret = mainHandler_->PostTask(task, "dataSrc", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
    if (!ret) {
        MEDIA_LOGE("Failed to PostTask!");
        delete cbWrap;
    }
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
    if (mainHandler_ == nullptr) {
        std::shared_ptr<OHOS::AppExecFwk::EventRunner> runner = OHOS::AppExecFwk::EventRunner::GetMainEventRunner();
        mainHandler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);
    }
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
} // namespace ANI
