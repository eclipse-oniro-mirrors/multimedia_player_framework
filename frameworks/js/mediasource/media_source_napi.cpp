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

#include "media_source_napi.h"
#include "media_log.h"
#include "media_dfx.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "MediaSourceNapi"};
constexpr uint32_t MAX_MEDIA_STREAM_ARRAY_LENGTH = 10;
}

namespace OHOS {
namespace Media {
using namespace FunctionName;
const std::string CLASS_NAME = "MediaSource";
thread_local napi_ref MediaSourceNapi::constructor_ = nullptr;

napi_value MediaSourceNapi::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor staticProperty[] = {
        {"createMediaSourceWithUrl", nullptr, JsCreateMediaSourceWithUrl,
            nullptr, nullptr, nullptr, napi_writable, nullptr },
        {"createMediaSourceWithStreamData", nullptr, JsCreateMediaSourceWithStreamData,
            nullptr, nullptr, nullptr, napi_writable, nullptr },
    };

    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("setMimeType", JsSetMimeType),
        DECLARE_NAPI_FUNCTION("setMediaResourceLoaderDelegate", JsSetMediaResourceLoaderDelegate),
    };

    napi_value constructor = nullptr;
    napi_status status = napi_define_class(env, CLASS_NAME.c_str(), NAPI_AUTO_LENGTH, Constructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &constructor);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "Failed to define AVPlayer class");

    status = napi_create_reference(env, constructor, 1, &constructor_);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "Failed to create reference of constructor");

    status = napi_set_named_property(env, exports, CLASS_NAME.c_str(), constructor);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "Failed to set constructor");

    status = napi_define_properties(env, exports, sizeof(staticProperty) / sizeof(staticProperty[0]), staticProperty);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "Failed to define static function");
    return exports;
}

std::shared_ptr<AVMediaSourceTmp> MediaSourceNapi::GetMediaSource(napi_env env, napi_value jsMediaSource)
{
    MediaSourceNapi *mediaSource = nullptr;
    napi_status status = napi_unwrap(env, jsMediaSource, reinterpret_cast<void **>(&mediaSource));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && mediaSource != nullptr, nullptr, "failed to napi_unwrap");

    return mediaSource->mediaSource_;
}

std::shared_ptr<MediaSourceLoaderCallback> MediaSourceNapi::GetSourceLoader(napi_env env, napi_value jsMediaSource)
{
    MediaSourceNapi *mediaSource = nullptr;
    napi_status status = napi_unwrap(env, jsMediaSource, reinterpret_cast<void **>(&mediaSource));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && mediaSource != nullptr, nullptr, "failed to napi_unwrap");

    return mediaSource->mediaSourceLoaderCb_;
}

napi_value MediaSourceNapi::Constructor(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    size_t argCount = 0;
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argCount, nullptr, &jsThis, nullptr);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, result, "failed to napi_get_cb_info");

    MediaSourceNapi *jsMediaSource = new(std::nothrow) MediaSourceNapi();
    CHECK_AND_RETURN_RET_LOG(jsMediaSource != nullptr, result, "failed to new MediaSourceNapi");

    jsMediaSource->env_ = env;
    jsMediaSource->mediaSource_ = std::make_shared<AVMediaSourceTmp>();
    if (jsMediaSource->mediaSource_ == nullptr) {
        delete jsMediaSource;
        MEDIA_LOGE("Failed to Create MediaSource");
        return result;
    }

    status = napi_wrap(env, jsThis, reinterpret_cast<void *>(jsMediaSource),
        MediaSourceNapi::Destructor, nullptr, nullptr);
    if (status != napi_ok) {
        delete jsMediaSource;
        MEDIA_LOGE("Failed to wrap native instance");
        return result;
    }

    MEDIA_LOGI("0x%{public}06" PRIXPTR " Constructor success", FAKE_POINTER(jsMediaSource));
    return jsThis;
}

void MediaSourceNapi::Destructor(napi_env env, void *nativeObject, void *finalize)
{
    (void)env;
    (void)finalize;
    if (nativeObject != nullptr) {
        MediaSourceNapi *jsMediaSource = reinterpret_cast<MediaSourceNapi *>(nativeObject);
        jsMediaSource->mediaSource_ = nullptr;
        if (jsMediaSource->mediaSourceLoaderCb_ != nullptr) {
            jsMediaSource->mediaSourceLoaderCb_->ClearCallbackReference();
            jsMediaSource->mediaSourceLoaderCb_ = nullptr;
        }
        delete jsMediaSource;
    }
    MEDIA_LOGI("Destructor success");
}

napi_value MediaSourceNapi::JsCreateMediaSourceWithUrl(napi_env env, napi_callback_info info)
{
    MEDIA_LOGD("JsCreateMediaSourceWithUrl In");
    size_t argCount = 2;
    napi_value args[2] = { nullptr };
    napi_value jsMediaSource = nullptr;
    napi_get_undefined(env, &jsMediaSource);
    napi_status status = napi_get_cb_info(env, info, &argCount, args, nullptr, nullptr);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "failed to napi_get_cb_info");

    napi_valuetype valueType = napi_undefined;
    if (argCount < 1 || napi_typeof(env, args[0], &valueType) != napi_ok || valueType != napi_string) {
        return nullptr;
    }

    napi_value constructor = nullptr;
    napi_status ret = napi_get_reference_value(env, constructor_, &constructor);
    if (ret != napi_ok || constructor == nullptr) {
        return nullptr;
    }
    napi_new_instance(env, constructor, 0, nullptr, &jsMediaSource);

    std::shared_ptr<AVMediaSourceTmp> mediaSource = GetMediaSource(env, jsMediaSource);
    if (mediaSource == nullptr) {
        MEDIA_LOGE("JsCreateMediaSourceWithUrl GetMediaSource fail");
        return nullptr;
    }
    mediaSource->url = CommonNapi::GetStringArgument(env, args[0]);
    MEDIA_LOGE("JsCreateMediaSourceWithUrl get map");
    (void)CommonNapi::GetPropertyMap(env, args[1], mediaSource->header);
    return jsMediaSource;
}

napi_value MediaSourceNapi::JsCreateMediaSourceWithStreamData(napi_env env, napi_callback_info info)
{
    MEDIA_LOGD("JsCreateMediaSourceWithStreamData In");
    size_t argCount = 1;
    napi_value args[1] = { nullptr };
    napi_value jsMediaSource = nullptr;
    napi_get_undefined(env, &jsMediaSource);
    napi_status status = napi_get_cb_info(env, info, &argCount, args, nullptr, nullptr);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "failed to napi_get_cb_info");
 
    bool isArray = false;
    if (argCount < 1 || napi_is_array(env, args[0], &isArray) != napi_ok || !isArray) {
        return nullptr;
    }
 
    uint32_t length = 0;
    if (napi_get_array_length(env, args[0], &length) != napi_ok || length == 0)  {
        return nullptr;
    }
    CHECK_AND_RETURN_RET_LOG(length <= MAX_MEDIA_STREAM_ARRAY_LENGTH, nullptr, "length Array<MediaStream> is too long");
 
    napi_value constructor = nullptr;
    napi_status ret = napi_get_reference_value(env, constructor_, &constructor);
    if (ret != napi_ok || constructor == nullptr) {
        return nullptr;
    }
    napi_new_instance(env, constructor, 0, nullptr, &jsMediaSource);
 
    std::shared_ptr<AVMediaSourceTmp> mediaSource = GetMediaSource(env, jsMediaSource);
    if (mediaSource == nullptr) {
        MEDIA_LOGE("JsCreateMediaSourceWithStreamData GetMediaSource fail");
        return nullptr;
    }
 
    for (uint32_t i = 0; i < length; i++) {
        napi_value element;
        AVPlayMediaStreamTmp mediaStream;
        status = napi_get_element(env, args[0], i, &element);
        if (status != napi_ok) {
            return nullptr;
        }
        if (!CommonNapi::GetPlayMediaStreamData(env, element, mediaStream)) {
            return nullptr;
        }
        MEDIA_LOGI("url=%{private}s width=%{public}d height=%{public}d bitrate=%{public}d",
            mediaStream.url.c_str(),
            mediaStream.width,
            mediaStream.height,
            mediaStream.bitrate);
        mediaSource->AddAVPlayMediaStreamTmp(mediaStream);
    }
    MEDIA_LOGD("JsCreateMediaSourceWithStreamData get mediaStreamVec length=%{public}u", length);
    return jsMediaSource;
}

napi_value MediaSourceNapi::JsSetMimeType(napi_env env, napi_callback_info info)
{
    MEDIA_LOGI("JsSetMimeType In");
    napi_value undefinedResult = nullptr;
    napi_get_undefined(env, &undefinedResult);
    size_t argCount = 1;
    napi_value args[1] = {nullptr};
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argCount, args, &jsThis, nullptr);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, undefinedResult, "failed to napi_get_cb_info");

    napi_valuetype valueType = napi_undefined;
    if (argCount < 1 || napi_typeof(env, args[0], &valueType) != napi_ok || valueType != napi_string) {
        return undefinedResult;
    }

    std::string mimeType = CommonNapi::GetStringArgument(env, args[0]);
    std::shared_ptr<AVMediaSourceTmp> mediaSource = GetMediaSource(env, jsThis);

    if (mediaSource == nullptr) {
        MEDIA_LOGE("Fail to get mediaSource instance.");
        return undefinedResult;
    }
    if (mimeType.empty()) {
        MEDIA_LOGE("MimeType is empty.");
        return undefinedResult;
    }

    mediaSource->SetMimeType(mimeType);

    return undefinedResult;
}

napi_value MediaSourceNapi::JsSetMediaResourceLoaderDelegate(napi_env env, napi_callback_info info)
{
    MediaTrace trace("MediaSourceNapi::SetMediaResourceLoaderDelegate");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsSetMediaResourceLoaderDelegate In");

    napi_value args[1] = { nullptr };
    size_t argCount = 1;

    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argCount, args, &jsThis, nullptr);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && jsThis != nullptr, nullptr, "failed to napi_get_cb_info");

    MediaSourceNapi *mediaSource = nullptr;
    status = napi_unwrap(env, jsThis, reinterpret_cast<void **>(&mediaSource));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && mediaSource != nullptr, nullptr, "failed to napi_unwrap");

    napi_valuetype valueType = napi_undefined;
    if (argCount < 1 || napi_typeof(env, args[0], &valueType) != napi_ok || valueType != napi_object) {
        MEDIA_LOGE("SetMediaResourceLoaderDelegate invalid parameters");
        return result;
    }

    mediaSource->mediaSourceLoaderCb_ = std::make_shared<MediaSourceLoaderCallback>(env);
    CHECK_AND_RETURN_RET_LOG(mediaSource->mediaSourceLoaderCb_ != nullptr, result, "Cb_ is nullptr");

    napi_value callback = nullptr;
    napi_ref ref = nullptr;
    napi_get_named_property(env, args[0], SOURCE_OPEN.c_str(), &callback);
    status = napi_create_reference(env, callback, 1, &ref);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && ref != nullptr, result, "failed to create open reference!");
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, ref);
    CHECK_AND_RETURN_RET_LOG(autoRef != nullptr, result, "open is nullptr");
    mediaSource->mediaSourceLoaderCb_->SaveCallbackReference(SOURCE_OPEN, autoRef);

    napi_get_named_property(env, args[0], SOURCE_READ.c_str(), &callback);
    status = napi_create_reference(env, callback, 1, &ref);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && ref != nullptr, result, "failed to create read reference!");
    autoRef = std::make_shared<AutoRef>(env, ref);
    CHECK_AND_RETURN_RET_LOG(autoRef != nullptr, result, "read is nullptr");
    mediaSource->mediaSourceLoaderCb_->SaveCallbackReference(SOURCE_READ, autoRef);

    napi_get_named_property(env, args[0], SOURCE_CLOSE.c_str(), &callback);
    status = napi_create_reference(env, callback, 1, &ref);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && ref != nullptr, result, "failed to create close reference!");
    autoRef = std::make_shared<AutoRef>(env, ref);
    CHECK_AND_RETURN_RET_LOG(autoRef != nullptr, result, "close is nullptr");
    mediaSource->mediaSourceLoaderCb_->SaveCallbackReference(SOURCE_CLOSE, autoRef);
    MEDIA_LOGI("JsSetMediaResourceLoaderDelegate Out");
    return result;
}
} // Media
} // OHOS