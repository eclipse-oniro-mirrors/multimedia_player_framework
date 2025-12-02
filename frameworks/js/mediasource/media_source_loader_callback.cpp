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

#include "media_source_loader_callback.h"
#include "buffer/avsharedmemory.h"
#include "media_dfx.h"
#include "media_log.h"
#include "media_errors.h"
#include "loading_request.h"
#include "scope_guard.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "MediaSourceLoaderCallback"};
constexpr size_t ARRAY_ARG_COUNTS_ONE = 1;
constexpr size_t ARRAY_ARG_COUNTS_THREE = 3;
constexpr int32_t INDEX_A = 0;
constexpr int32_t INDEX_B = 1;
constexpr int32_t INDEX_C = 2;
}

namespace OHOS {
namespace Media {
MediaDataSourceLoaderJsCallback::~MediaDataSourceLoaderJsCallback()
{
    isExit_ = true;
    cond_.notify_all();
}

void MediaDataSourceLoaderJsCallback::WaitResult()
{
    std::unique_lock<std::mutex> lock(mutexCond_);
    if (!setResult_) {
        static constexpr int32_t timeout = 200;
        cond_.wait_for(lock, std::chrono::milliseconds(timeout), [this]() { return setResult_ || isExit_; });
        if (!setResult_) {
            uuid_ = 0;
            if (isExit_) {
                MEDIA_LOGW("Reset, OPen has been cancel!");
            } else {
                MEDIA_LOGW("timeout 100ms!");
            }
        }
    }
    setResult_ = false;
}

MediaSourceLoaderCallback::MediaSourceLoaderCallback(napi_env env)
    : env_(env)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

MediaSourceLoaderCallback::~MediaSourceLoaderCallback()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
    env_ = nullptr;
}

int64_t MediaSourceLoaderCallback::Open(std::shared_ptr<LoadingRequest> &request)
{
    MediaTrace trace("MediaSourceLoaderCallback::open");
    MEDIA_LOGI("<< open");
    std::lock_guard<std::mutex> lock(mutex_);

    if (refMap_.find(FunctionName::SOURCE_OPEN) == refMap_.end()) {
        MEDIA_LOGE("can not find read callback!");
        return 0;
    }

    jsCb_ = std::make_shared<MediaDataSourceLoaderJsCallback>();
    CHECK_AND_RETURN_RET_LOG(jsCb_ != nullptr, 0, "cb is nullptr");
    jsCb_->autoRef_ = refMap_.at(FunctionName::SOURCE_OPEN);
    jsCb_->callbackName_ = FunctionName::SOURCE_OPEN;
    jsCb_->request_ = request;

    napi_status ret = napi_send_event(env_, [jsCb = jsCb_] () {
        CHECK_AND_RETURN_LOG(jsCb != nullptr, "request is nullptr");
        MEDIA_LOGD("CallBack %{public}s start", jsCb->callbackName_.c_str());
        do {
            std::shared_ptr<AutoRef> ref = jsCb->autoRef_.lock();
            CHECK_AND_RETURN_LOG(ref != nullptr, "%{public}s AutoRef is nullptr", jsCb->callbackName_.c_str());
            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(ref->env_, &scope);
            CHECK_AND_RETURN_LOG(scope != nullptr,  "%{public}s scope is nullptr", jsCb->callbackName_.c_str());
            ON_SCOPE_EXIT(0) {
                napi_close_handle_scope(ref->env_, scope);
            };
            napi_value jsCallback = nullptr;
            napi_status napiStatus = napi_get_reference_value(ref->env_, ref->cb_, &jsCallback);
            CHECK_AND_RETURN_LOG(napiStatus == napi_ok && jsCallback != nullptr,
                "%{public}s failed to napi_get_reference_value", jsCb->callbackName_.c_str());

            napi_value args[ARRAY_ARG_COUNTS_ONE] = { nullptr };
            args[0] = MediaSourceLoadingRequestNapi::CreateLoadingRequest(ref->env_, jsCb->request_);

            napi_value result = nullptr;
            napiStatus = napi_call_function(ref->env_, nullptr, jsCallback, ARRAY_ARG_COUNTS_ONE, args, &result);
            CHECK_AND_RETURN_LOG(napiStatus == napi_ok, "%{public}s failed to napi_call_function",
                jsCb->callbackName_.c_str());
            napiStatus = napi_get_value_int64(ref->env_, result, &jsCb->uuid_);
            CHECK_AND_BREAK_LOG(napiStatus == napi_ok, "get uuid failed");
            std::unique_lock<std::mutex> lock(jsCb->mutexCond_);
            jsCb->setResult_ = true;
            jsCb->cond_.notify_all();
        } while (0);
    }, napi_eprio_immediate, "AVPlayer MediaSourceLoaderCallback::Open");
    if (ret != napi_ok) {
        MEDIA_LOGE("Failed to execute libuv work queue");
        return jsCb_->uuid_;
    }
    jsCb_->WaitResult();
    MEDIA_LOGI("MediaSourceLoaderCallback open out");
    return jsCb_->uuid_;
}

void MediaSourceLoaderCallback::Read(int64_t uuid, int64_t requestedOffset, int64_t requestedLength)
{
    MediaTrace trace("MediaSourceLoaderCallback::read, uuid: " + std::to_string(uuid) +
        " offset: " + std::to_string(requestedOffset) + " Length:" + std::to_string(requestedLength));
    MEDIA_LOGI("<< read");
    std::lock_guard<std::mutex> lock(mutex_);

    if (refMap_.find(FunctionName::SOURCE_READ) == refMap_.end()) {
        MEDIA_LOGE("can not find read callback!");
        return;
    }

    jsCb_ = std::make_shared<MediaDataSourceLoaderJsCallback>();
    CHECK_AND_RETURN_LOG(jsCb_ != nullptr, "cb is nullptr");

    jsCb_->autoRef_ = refMap_.at(FunctionName::SOURCE_READ);
    jsCb_->callbackName_ = FunctionName::SOURCE_READ;
    jsCb_->uuid_ = uuid;
    jsCb_->requestedOffset_ = requestedOffset;
    jsCb_->requestedLength_ = requestedLength;

    napi_status ret = napi_send_event(env_, [jsCb = jsCb_] () {
        CHECK_AND_RETURN_LOG(jsCb != nullptr, "request is nullptr");
        MEDIA_LOGD("CallBack %{public}s start", jsCb->callbackName_.c_str());
        do {
            std::shared_ptr<AutoRef> ref = jsCb->autoRef_.lock();
            CHECK_AND_RETURN_LOG(ref != nullptr, "%{public}s AutoRef is nullptr", jsCb->callbackName_.c_str());
            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(ref->env_, &scope);
            CHECK_AND_RETURN_LOG(scope != nullptr,  "%{public}s scope is nullptr", jsCb->callbackName_.c_str());
            ON_SCOPE_EXIT(0) {
                napi_close_handle_scope(ref->env_, scope);
            };
            napi_value jsCallback = nullptr;
            napi_status napiStatus = napi_get_reference_value(ref->env_, ref->cb_, &jsCallback);
            CHECK_AND_RETURN_LOG(napiStatus == napi_ok && jsCallback != nullptr,
                "%{public}s failed to napi_get_reference_value", jsCb->callbackName_.c_str());

            napi_value args[ARRAY_ARG_COUNTS_THREE] = { nullptr };
            CHECK_AND_BREAK_LOG(napi_create_int64(ref->env_, jsCb->uuid_, &args[INDEX_A]) == napi_ok,
                "set uuid failed");
            CHECK_AND_BREAK_LOG(napi_create_int64(ref->env_, jsCb->requestedOffset_, &args[INDEX_B]) == napi_ok,
                "set requestedOffset failed");
            CHECK_AND_BREAK_LOG(napi_create_int64(ref->env_, jsCb->requestedLength_, &args[INDEX_C]) == napi_ok,
                "set requestedLength failed");

            napi_value result = nullptr;
            napiStatus = napi_call_function(ref->env_, nullptr, jsCallback, ARRAY_ARG_COUNTS_THREE, args, &result);
            CHECK_AND_RETURN_LOG(napiStatus == napi_ok,
                "%{public}s failed to napi_call_function", jsCb->callbackName_.c_str());
        } while (0);
    }, napi_eprio_immediate, "AVPlayer MediaSourceLoaderCallback::Read");
    if (ret != napi_ok) {
        MEDIA_LOGE("Failed to execute libuv work queue");
    }
}

void MediaSourceLoaderCallback::Close(int64_t uuid)
{
    MediaTrace trace("MediaSourceLoaderCallback::close, uuid: " + std::to_string(uuid));
    MEDIA_LOGI("<< close");
    std::lock_guard<std::mutex> lock(mutex_);

    if (refMap_.find(FunctionName::SOURCE_CLOSE) == refMap_.end()) {
        MEDIA_LOGE("can not find read callback!");
        return;
    }

    jsCb_ = std::make_shared<MediaDataSourceLoaderJsCallback>();
    CHECK_AND_RETURN_LOG(jsCb_ != nullptr, "cb is nullptr");

    jsCb_->autoRef_ = refMap_.at(FunctionName::SOURCE_CLOSE);
    jsCb_->callbackName_ = FunctionName::SOURCE_CLOSE;
    jsCb_->uuid_ = uuid;

    napi_status ret = napi_send_event(env_, [jsCb = jsCb_] () {
        CHECK_AND_RETURN_LOG(jsCb != nullptr, "request is nullptr");
        MEDIA_LOGD("CallBack %{public}s start", jsCb->callbackName_.c_str());
        do {
            std::shared_ptr<AutoRef> ref = jsCb->autoRef_.lock();
            CHECK_AND_RETURN_LOG(ref != nullptr, "%{public}s AutoRef is nullptr", jsCb->callbackName_.c_str());
            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(ref->env_, &scope);
            CHECK_AND_RETURN_LOG(scope != nullptr,  "%{public}s scope is nullptr", jsCb->callbackName_.c_str());
            ON_SCOPE_EXIT(0) {
                napi_close_handle_scope(ref->env_, scope);
            };
            napi_value jsCallback = nullptr;
            napi_status napiStatus = napi_get_reference_value(ref->env_, ref->cb_, &jsCallback);
            CHECK_AND_RETURN_LOG(napiStatus == napi_ok && jsCallback != nullptr,
                "%{public}s failed to napi_get_reference_value", jsCb->callbackName_.c_str());

            napi_value args[ARRAY_ARG_COUNTS_ONE] = { nullptr };
            CHECK_AND_BREAK_LOG(napi_create_int64(ref->env_, jsCb->uuid_, &args[INDEX_A]) == napi_ok,
                "set uuid failed");

            napi_value result = nullptr;
            napiStatus = napi_call_function(ref->env_, nullptr, jsCallback, ARRAY_ARG_COUNTS_ONE, args, &result);
            CHECK_AND_RETURN_LOG(napiStatus == napi_ok,
                "%{public}s failed to napi_call_function", jsCb->callbackName_.c_str());
        } while (0);
    }, napi_eprio_immediate, "AVPlayer MediaSourceLoaderCallback::Close");
    if (ret != napi_ok) {
        MEDIA_LOGE("Failed to execute libuv work queue");
    }
}

void MediaSourceLoaderCallback::SaveCallbackReference(const std::string &name, std::shared_ptr<AutoRef> ref)
{
    MEDIA_LOGI("Add Callback: %{public}s", name.c_str());
    std::lock_guard<std::mutex> lock(mutex_);
    refMap_[name] = ref;
}

void MediaSourceLoaderCallback::ClearCallbackReference()
{
    MEDIA_LOGI("ClearCallbackReference");
    std::lock_guard<std::mutex> lock(mutex_);
    std::map<std::string, std::shared_ptr<AutoRef>> temp;
    temp.swap(refMap_);
    MEDIA_LOGI("callback has been clear");
    if (jsCb_) {
        jsCb_->isExit_ = true;
        jsCb_->cond_.notify_all();
    }
}
} // namespace Media
} // namespace OHOS
