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

#include "avmetadatahelper_callback.h"
#include "pixel_map_napi.h"
#include <uv.h>
#include "media_errors.h"
#include "media_log.h"
#include "scope_guard.h"
#include "event_queue.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_METADATA, "AVMetadataHelperCallback"};
}

namespace OHOS {
namespace Media {
class NapiCallback {
public:
    struct Base {
        std::weak_ptr<AutoRef> callback;
        std::string callbackName = "unknown";
        Base() = default;
        virtual ~Base() = default;
        virtual void UvWork()
        {
            std::shared_ptr<AutoRef> ref = callback.lock();
            CHECK_AND_RETURN_LOG(ref != nullptr,
                "%{public}s AutoRef is nullptr", callbackName.c_str());

            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(ref->env_, &scope);
            CHECK_AND_RETURN_LOG(scope != nullptr,
                "%{public}s scope is nullptr", callbackName.c_str());
            ON_SCOPE_EXIT(0) {
                napi_close_handle_scope(ref->env_, scope);
            };

            napi_value jsCallback = nullptr;
            napi_status status = napi_get_reference_value(ref->env_, ref->cb_, &jsCallback);
            CHECK_AND_RETURN_LOG(status == napi_ok && jsCallback != nullptr,
                "%{public}s failed to napi_get_reference_value", callbackName.c_str());

            // Call back function
            napi_value result = nullptr;
            status = napi_call_function(ref->env_, nullptr, jsCallback, 0, nullptr, &result);
            CHECK_AND_RETURN_LOG(status == napi_ok,
                "%{public}s failed to napi_call_function", callbackName.c_str());
        }
        virtual void JsCallback()
        {
            UvWork();
            delete this;
        }
    };

    struct Error : public Base {
        std::string errorMsg = "unknown";
        MediaServiceExtErrCodeAPI9 errorCode = MSERR_EXT_API9_UNSUPPORT_FORMAT;
        void UvWork() override
        {
            std::shared_ptr<AutoRef> ref = callback.lock();
            CHECK_AND_RETURN_LOG(ref != nullptr,
                "%{public}s AutoRef is nullptr", callbackName.c_str());

            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(ref->env_, &scope);
            CHECK_AND_RETURN_LOG(scope != nullptr,
                "%{public}s scope is nullptr", callbackName.c_str());
            ON_SCOPE_EXIT(0) {
                napi_close_handle_scope(ref->env_, scope);
            };

            napi_value jsCallback = nullptr;
            napi_status status = napi_get_reference_value(ref->env_, ref->cb_, &jsCallback);
            CHECK_AND_RETURN_LOG(status == napi_ok && jsCallback != nullptr,
                "%{public}s failed to napi_get_reference_value", callbackName.c_str());

            napi_value args[1] = {nullptr};
            (void)CommonNapi::CreateError(ref->env_, errorCode, errorMsg, args[0]);

            // Call back function
            napi_value result = nullptr;
            status = napi_call_function(ref->env_, nullptr, jsCallback, 1, args, &result);
            CHECK_AND_RETURN_LOG(status == napi_ok,
                "%{public}s failed to napi_call_function", callbackName.c_str());
        }
    };

    static void CompleteCallback(napi_env env, NapiCallback::Base *jsCb)
    {
        CHECK_AND_RETURN(jsCb != nullptr);
        std::string taskname = "CompleteCallback";
        napi_status ret = napi_send_event(env, [jsCb] () {
            CHECK_AND_RETURN_LOG(jsCb != nullptr, "jsCb is nullptr");
            MEDIA_LOGI("JsCallBack %{public}s start", jsCb->callbackName.c_str());
            jsCb->UvWork();
            delete jsCb;
        }, napi_eprio_high, taskname.c_str());
        if (ret != napi_ok) {
            MEDIA_LOGE("Failed to execute libuv work queue, ret = %{public}d", ret);
            delete jsCb;
        }
    }
};

AVMetadataHelperCallback::AVMetadataHelperCallback(napi_env env) : env_(env)
{
    MEDIA_LOGI("AVMetadataHelperCallback Instances create");
}

AVMetadataHelperCallback::AVMetadataHelperCallback(napi_env env, AVMetadataHelperNotify *listener)
    : env_(env), listener_(listener)
{
    onInfoFuncs_[HELPER_INFO_TYPE_STATE_CHANGE] =
        [this](const int32_t extra, const Format &infoBody) { OnStateChangeCb(extra, infoBody); };
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

AVMetadataHelperCallback::~AVMetadataHelperCallback()
{
    helper_ = nullptr;
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

void AVMetadataHelperCallback::setHelper(const std::shared_ptr<AVMetadataHelper> &helper)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_LOG(helper != nullptr, "AVMetadataHelper is nullptr");
    helper_ = helper;
}

void AVMetadataHelperCallback::OnError(int32_t errorCode, const std::string &errorMsg)
{
    if (errorCode == HelperErrorType::INVALID_RESULT) {
        MEDIA_LOGE("OnError: errorCode %{public}d, errorMsg %{public}s", errorCode, errorMsg.c_str());
        AVMetadataHelperCallback::OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, errorMsg);
        return;
    }
    MediaServiceExtErrCodeAPI9 errorCodeApi9 = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(errorCode));
    AVMetadataHelperCallback::OnErrorCb(errorCodeApi9, errorMsg);
}

void AVMetadataHelperCallback::OnErrorCb(MediaServiceExtErrCodeAPI9 errorCode, const std::string &errorMsg)
{
    std::string message = MSExtAVErrorToString(errorCode) + errorMsg;
    MEDIA_LOGE("OnErrorCb:errorCode %{public}d, errorMsg %{public}s", errorCode, message.c_str());
    std::lock_guard<std::mutex> lock(mutex_);
    if (refMap_.find(AVMetadataHelperEvent::EVENT_ERROR) == refMap_.end()) {
        MEDIA_LOGW("can not find error callback!");
        return;
    }

    NapiCallback::Error *cb = new(std::nothrow) NapiCallback::Error();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new Error");

    cb->callback = refMap_.at(AVMetadataHelperEvent::EVENT_ERROR);
    cb->callbackName = AVMetadataHelperEvent::EVENT_ERROR;
    cb->errorCode = errorCode;
    cb->errorMsg = message;
    NapiCallback::CompleteCallback(env_, cb);
}

void AVMetadataHelperCallback::OnInfo(HelperOnInfoType type, int32_t extra, const Format &infoBody)
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("OnInfo is called, OnInfoType: %{public}d", type);
    if (onInfoFuncs_.count(type) > 0) {
        onInfoFuncs_[type](extra, infoBody);
    } else {
        MEDIA_LOGI("OnInfo: no member func supporting, %{public}d", type);
    }
}

void AVMetadataHelperCallback::OnPixelComplete(HelperOnInfoType type,
                                               const std::shared_ptr<AVBuffer> &reAvbuffer_,
                                               const FrameInfo &info,
                                               const PixelMapParams &param)
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("OnPixelComplete is called, OnPixelCompleteType: %{public}d", type);
    CHECK_AND_RETURN_LOG(type == HelperOnInfoType::HELPER_INFO_TYPE_PIXEL, "HelperOnInfoType Error");
    CHECK_AND_RETURN_LOG(helper_ != nullptr, "helper_ is nullptr");
    auto pixelMap = helper_->ProcessPixelMap(reAvbuffer_, param, FrameScaleMode::ASPECT_RATIO);
    SendPixelCompleteCallback(info, pixelMap);
}

void AVMetadataHelperCallback::SendPixelCompleteCallback(const FrameInfo &info,
    const std::shared_ptr<PixelMap> &pixelMap)
{
    if (refMap_.find(AVMetadataHelperEvent::EVENT_PIXEL_COMPLETE) == refMap_.end()) {
        MEDIA_LOGW("can not find pixelcomplete callback!");
        return;
    }
    AVMetadataJsCallback *cb = new(std::nothrow) AVMetadataJsCallback();
    CHECK_AND_RETURN_LOG(cb != nullptr, "cb is nullptr");
    cb->autoRef = refMap_.at(AVMetadataHelperEvent::EVENT_PIXEL_COMPLETE);
    cb->requestedTimeUs = info.requestedTimeUs;
    cb->actualTimeUs = info.actualTimeUs;
    cb->fetchResult = static_cast<FetchResult>(info.fetchResult);
    cb->pixel_ = pixelMap;
    cb->errorCode = info.err;
    MEDIA_LOGI("AVMetadataHelperCallback::SendPixelCompleteCallback cb->errorCode, %{public}d", cb->errorCode);
    switch (info.err) {
        case OPERATION_NOT_ALLOWED:
            cb->errorMs = "OPERATION_NOT_ALLOWED";
            break;
        case FETCH_TIMEOUT:
            cb->errorMs = "FETCH_TIMEOUT";
            break;
        case UNSUPPORTED_FORMAT:
            cb->errorMs = "UNSUPPORTED_FORMAT";
            break;
        default:
            cb->errorMs = "NO_ERR";
    }
}

void AVMetadataHelperCallback::OnJsPixelCompleteCallback(AVMetadataJsCallback *jsCb) const
{
    auto task = [event = jsCb]() {
        CHECK_AND_RETURN_LOG(event != nullptr, "jsCb is nullptr");
        std::string request = event->callbackName;
        do {
            std::shared_ptr<AutoRef> ref = event->autoRef;
            CHECK_AND_BREAK_LOG(ref != nullptr, "%{public}s AutoRef is nullptr", request.c_str());
            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(ref->env_, &scope);
            CHECK_AND_BREAK_LOG(scope != nullptr, "%{public}s scope is nullptr", request.c_str());
            ON_SCOPE_EXIT(0) {
                napi_close_handle_scope(ref->env_, scope);
            };
            const size_t argCount = 2;
            napi_value args[argCount] = {nullptr};
            napi_value jsCallback = nullptr;
            napi_value imageResult = nullptr;
            napi_get_undefined(ref->env_, &args[0]);
            napi_get_undefined(ref->env_, &args[1]);
            napi_get_undefined(ref->env_, &imageResult);
            napi_value frameInfo = nullptr;
            napi_create_object(ref->env_, &frameInfo);
            CHECK_AND_CONTINUE_LOG(CommonNapi::SetPropertyInt64(ref->env_, frameInfo, "requestedTimeUs",
                event->requestedTimeUs), "Set RequestedTimeUs failed");
            CHECK_AND_CONTINUE_LOG(CommonNapi::SetPropertyInt64(ref->env_, frameInfo, "actualTimeUs",
                event->actualTimeUs), "Set actualTimeUs failed");
            CHECK_AND_CONTINUE_LOG(CommonNapi::SetPropertyInt32(ref->env_, frameInfo, "result",
                event->fetchResult), "Set fetchResult failed");
            if (event->pixel_ != nullptr) {
                imageResult = Media::PixelMapNapi::CreatePixelMap(ref->env_, event->pixel_);
            }
            napi_set_named_property(ref->env_, frameInfo, "image", imageResult);
            args[1] = frameInfo;
            if (event->errorCode != 0) {
                napi_create_uint32(ref->env_, event->fetchResult, &args[0]);
                (void)CommonNapi::CreateError(ref->env_, event->errorCode, event->errorMs, jsCallback);
                args[0] = jsCallback;
            }
            napi_status nstatus = napi_get_reference_value(ref->env_, ref->cb_, &jsCallback);
            CHECK_AND_BREAK_LOG(nstatus == napi_ok && jsCallback != nullptr, "%{public}s get reference value fail",
                                request.c_str());
            napi_value result = nullptr;
            nstatus = napi_call_function(ref->env_, nullptr, jsCallback, argCount, args, &result);
            CHECK_AND_BREAK_LOG(nstatus == napi_ok, "%{public}s fail to napi call function", request.c_str());
        } while (0);
        delete event;
        };
    auto ret = napi_send_event(env_, task, napi_eprio_immediate);
    if (ret != napi_status::napi_ok) { delete jsCb; }
}

void AVMetadataHelperCallback::OnStateChangeCb(const int32_t extra, const Format &infoBody)
{
    HelperStates state = static_cast<HelperStates>(extra);
    MEDIA_LOGI("OnStateChanged is called, current state: %{public}d", state);

    if (listener_ != nullptr) {
        listener_->NotifyState(state);
    }
}

void AVMetadataHelperCallback::SaveCallbackReference(const std::string &name, std::shared_ptr<AutoRef> ref)
{
    std::lock_guard<std::mutex> lock(mutex_);
    refMap_[name] = ref;
}

void AVMetadataHelperCallback::ClearCallbackReference()
{
    std::lock_guard<std::mutex> lock(mutex_);
    refMap_.clear();
}

void AVMetadataHelperCallback::ClearCallbackReference(const std::string &name)
{
    std::lock_guard<std::mutex> lock(mutex_);
    refMap_.erase(name);
}

void AVMetadataHelperCallback::Start()
{
    isloaded_ = true;
}

void AVMetadataHelperCallback::Pause()
{
    isloaded_ = false;
}

void AVMetadataHelperCallback::Release()
{
    std::lock_guard<std::mutex> lock(mutex_);

    Format infoBody;
    AVMetadataHelperCallback::OnStateChangeCb(HelperStates::HELPER_RELEASED, infoBody);
    listener_ = nullptr;
}
} // namespace Media
} // namespace OHOS