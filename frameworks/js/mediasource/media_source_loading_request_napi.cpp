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

#include "media_source_loading_request_napi.h"
#include "media_log.h"
#include "media_dfx.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "MediaSourceLoadingRequestNapi"};
constexpr size_t ARRAY_ARG_COUNTS_ONE = 1;
constexpr size_t ARRAY_ARG_COUNTS_TWO = 2;
constexpr size_t ARRAY_ARG_COUNTS_THREE = 3;
constexpr int32_t INDEX_A = 0;
constexpr int32_t INDEX_B = 1;
constexpr int32_t INDEX_C = 2;
}

namespace OHOS {
namespace Media {
const std::string CLASS_NAME = "LoadingRequest";
thread_local napi_ref MediaSourceLoadingRequestNapi::constructor_ = nullptr;
MediaSourceLoadingRequestNapi::MediaSourceLoadingRequestNapi()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " ctor", FAKE_POINTER(this));
}

MediaSourceLoadingRequestNapi::~MediaSourceLoadingRequestNapi()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " dtor", FAKE_POINTER(this));
}

napi_value MediaSourceLoadingRequestNapi::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("respondData", JsRespondData),
        DECLARE_NAPI_FUNCTION("respondHeader", JsRespondHeader),
        DECLARE_NAPI_FUNCTION("finishLoading", JsFinishLoading),

        DECLARE_NAPI_GETTER("url", JsGetUrl),
        DECLARE_NAPI_GETTER("header", JsGetHeader),
    };

    napi_value constructor = nullptr;
    napi_status status = napi_define_class(env, CLASS_NAME.c_str(), NAPI_AUTO_LENGTH, Constructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &constructor);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "Failed to define Request class");

    status = napi_create_reference(env, constructor, 1, &constructor_);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "Failed to create reference of constructor");

    status = napi_set_named_property(env, exports, CLASS_NAME.c_str(), constructor);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "Failed to set constructor");

    return exports;
}

napi_value MediaSourceLoadingRequestNapi::Constructor(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    size_t argc = ARRAY_ARG_COUNTS_ONE;
    napi_value args[ARRAY_ARG_COUNTS_ONE] = { 0 };
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argc, args, &jsThis, nullptr);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, result, "failed to napi_get_cb_info");
    uint64_t requestId = 0;
    bool lossLess = false;
    napi_get_value_bigint_uint64(env, args[0], &requestId, &lossLess);
    if (!lossLess) {
        MEDIA_LOGE("BigInt values have no lossless converted");
        return result;
    }
    MediaSourceLoadingRequestNapi *jsRequest = new(std::nothrow) MediaSourceLoadingRequestNapi();
    CHECK_AND_RETURN_RET_LOG(jsRequest != nullptr, result, "failed to new MediaSourceLoadingRequestNapi");

    jsRequest->env_ = env;
    jsRequest->request_ = RequestContainer::GetInstance().Find(requestId);
    CHECK_AND_RETURN_RET_LOG(jsRequest->request_ != nullptr, result, "failed to getRequest");

    status = napi_wrap(env, jsThis, reinterpret_cast<void *>(jsRequest),
        MediaSourceLoadingRequestNapi::Destructor, nullptr, nullptr);
    if (status != napi_ok) {
        delete jsRequest;
        MEDIA_LOGE("Failed to wrap native instance");
        return result;
    }

    RequestContainer::GetInstance().Erase(requestId);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Constructor success", FAKE_POINTER(jsRequest));
    return jsThis;
}

void MediaSourceLoadingRequestNapi::Destructor(napi_env env, void *nativeObject, void *finalize)
{
    (void)env;
    (void)finalize;
    if (nativeObject != nullptr) {
        MediaSourceLoadingRequestNapi *jsRequest = reinterpret_cast<MediaSourceLoadingRequestNapi *>(nativeObject);
        delete jsRequest;
    }
    MEDIA_LOGD("Destructor success");
}

napi_value MediaSourceLoadingRequestNapi::CreateLoadingRequest(napi_env env,
    std::shared_ptr<LoadingRequest> request)
{
    MediaTrace trace("MediaSourceLoadingRequestNapi::CreateLoadingRequest");
    MEDIA_LOGD("CreateLoadingRequest >>");
    CHECK_AND_RETURN_RET_LOG(request != nullptr, nullptr, "request nullptr");
    napi_status status;
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    if (constructor_ == nullptr) {
        napi_value exports = nullptr;
        napi_create_object(env, &exports);
        MediaSourceLoadingRequestNapi::Init(env, exports);
    }
    
    napi_value constructor = nullptr;
    status = napi_get_reference_value(env, constructor_, &constructor);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "Failed to get");
    
    size_t argc = ARRAY_ARG_COUNTS_ONE;
    napi_value args[ARRAY_ARG_COUNTS_ONE] = { 0 };
    napi_create_bigint_uint64(env, request->GetUniqueId(), &args[0]);
    RequestContainer::GetInstance().Insert(request->GetUniqueId(), request);

    status = napi_new_instance(env, constructor, argc, args, &result);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "Failed to new_instance");
    return result;
}

napi_value MediaSourceLoadingRequestNapi::JsRespondData(napi_env env, napi_callback_info info)
{
    MediaTrace trace("MediaSourceLoadingRequestNapi::JsRespondData");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsRespondData In");

    size_t argCount = ARRAY_ARG_COUNTS_THREE; // args[0]:uuid, args[1]:offset, args[2]:arrayBuffer
    napi_value args[ARRAY_ARG_COUNTS_THREE] = { nullptr };
    MediaSourceLoadingRequestNapi* jsRequest =
        MediaSourceLoadingRequestNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(jsRequest != nullptr, result, "failed to GetJsInstance");

    int64_t uuid = 0;
    int64_t offset = 0;
    void *arrayBuffer = nullptr;
    size_t arrayBufferSize = 0;
    
    CHECK_AND_RETURN_RET_LOG(napi_get_value_int64(env, args[INDEX_A], &uuid) == napi_ok, result, "get uuid fail");
    CHECK_AND_RETURN_RET_LOG(napi_get_value_int64(env, args[INDEX_B], &offset) == napi_ok, result, "get offset fail");
    CommonNapi::GetPropertyArrayBuffer(env, args[INDEX_C], &arrayBuffer, &arrayBufferSize);
    auto buffer = std::make_shared<AVSharedMemoryBase>(static_cast<int32_t>(arrayBufferSize),
        AVSharedMemory::FLAGS_READ_WRITE, "userBuffer");
    CHECK_AND_RETURN_RET_LOG(buffer != nullptr, result, "get buffer fail");
    buffer->Init();
    buffer->Write(static_cast<uint8_t *>(arrayBuffer), arrayBufferSize);
    MEDIA_LOGI("JsRespondData getSize: %{public}d", buffer->GetSize());
    napi_create_int32(env, jsRequest->request_->RespondData(uuid, offset, buffer), &result);
    return result;
}

napi_value MediaSourceLoadingRequestNapi::JsRespondHeader(napi_env env, napi_callback_info info)
{
    MediaTrace trace("MediaSourceLoadingRequestNapi::JsRespondHeader");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsRespondHeader In");

    size_t argCount = ARRAY_ARG_COUNTS_THREE; // args[0]:uuid, args[1]:header, args[2]:redirctUrl
    napi_value args[ARRAY_ARG_COUNTS_THREE] = { nullptr };
    MediaSourceLoadingRequestNapi* jsRequest =
        MediaSourceLoadingRequestNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(jsRequest != nullptr, result, "failed to GetJsInstance");
    MEDIA_LOGI("JsRespondHeader argCount %{public}d", static_cast<int32_t>(argCount));
    int64_t uuid = 0;
    std::map<std::string, std::string> header {};
    CHECK_AND_RETURN_RET_LOG(napi_get_value_int64(env, args[INDEX_A], &uuid) == napi_ok, result, "get uuid fail");
    MEDIA_LOGI("JsRespondHeader uuid" PRId64, uuid);
    CommonNapi::GetPropertyMap(env, args[INDEX_B], header);
    for (auto [x, y]: header) {
        MEDIA_LOGI("JsRespondHeader x %{private}s, y %{private}s", x.c_str(), y.c_str());
    }
    std::string redirctUrl = CommonNapi::GetStringArgument(env, args[INDEX_C]);
    jsRequest->request_->RespondHeader(uuid, header, redirctUrl);
    MEDIA_LOGI("JsRespondHeader redirctUrl %{private}s", redirctUrl.c_str());
    return result;
}

napi_value MediaSourceLoadingRequestNapi::JsFinishLoading(napi_env env, napi_callback_info info)
{
    MediaTrace trace("MediaSourceLoadingRequestNapi::JsFinishLoading");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsFinishLoading In");

    size_t argCount = ARRAY_ARG_COUNTS_TWO; // args[0]:uuid, args[1]:state
    napi_value args[ARRAY_ARG_COUNTS_TWO] = { nullptr };
    MediaSourceLoadingRequestNapi* jsRequest =
        MediaSourceLoadingRequestNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(jsRequest != nullptr, result, "failed to GetJsInstance");
    
    int64_t uuid = 0;
    int32_t requestError = 0;
    CHECK_AND_RETURN_RET_LOG(napi_get_value_int64(env, args[INDEX_A], &uuid) == napi_ok, result, "get uuid fail");
    CHECK_AND_RETURN_RET_LOG(napi_get_value_int32(env, args[INDEX_B], &requestError) == napi_ok,
        result, "get requestError fail");
    jsRequest->request_->FinishLoading(uuid, requestError);
    return result;
}

napi_value MediaSourceLoadingRequestNapi::JsGetUrl(napi_env env, napi_callback_info info)
{
    MediaTrace trace("MediaSourceLoadingRequestNapi::JsGetUrl");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsGetUrl In");

    MediaSourceLoadingRequestNapi* jsRequest = MediaSourceLoadingRequestNapi::GetJsInstance(env, info);
    CHECK_AND_RETURN_RET_LOG(jsRequest != nullptr, result, "failed to GetJsInstance");

    (void)napi_create_string_utf8(env, jsRequest->request_->GetUrl().c_str(), NAPI_AUTO_LENGTH, &result);
    return result;
}

napi_value MediaSourceLoadingRequestNapi::JsGetHeader(napi_env env, napi_callback_info info)
{
    MediaTrace trace("MediaSourceLoadingRequestNapi::JsGetHeader");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsGetHeader In");

    MediaSourceLoadingRequestNapi* jsRequest = MediaSourceLoadingRequestNapi::GetJsInstance(env, info);
    CHECK_AND_RETURN_RET_LOG(jsRequest != nullptr, result, "failed to GetJsInstance");

    std::map<std::string, std::string> header = jsRequest->request_->GetHeader();
    (void)napi_create_object(env, &result);
    for (auto &[key, value] : header) {
        CommonNapi::SetPropertyString(env, result, key, value);
    }
    return result;
}

MediaSourceLoadingRequestNapi* MediaSourceLoadingRequestNapi::GetJsInstance(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argc, nullptr, &jsThis, nullptr);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && jsThis != nullptr, nullptr, "failed to napi_get_cb_info");

    MediaSourceLoadingRequestNapi *jsRequest = nullptr;
    status = napi_unwrap(env, jsThis, reinterpret_cast<void **>(&jsRequest));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && jsRequest != nullptr, nullptr, "failed to napi_unwrap");

    return jsRequest;
}

MediaSourceLoadingRequestNapi* MediaSourceLoadingRequestNapi::GetJsInstanceWithParameter(napi_env env,
    napi_callback_info info, size_t &argc, napi_value *argv)
{
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &jsThis, nullptr);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && jsThis != nullptr, nullptr, "failed to napi_get_cb_info");

    MediaSourceLoadingRequestNapi *jsRequest = nullptr;
    status = napi_unwrap(env, jsThis, reinterpret_cast<void **>(&jsRequest));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && jsRequest != nullptr, nullptr, "failed to napi_unwrap");

    return jsRequest;
}
} // namespace Media
} // namespace OHOS