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

#include "avimagegenerator_napi.h"
#include "media_log.h"
#include "media_errors.h"
#include "common_napi.h"
#include "pixel_map_napi.h"
#include "string_ex.h"
#include "player_xcollie.h"
#include "media_dfx.h"
#ifdef SUPPORT_JSSTACK
#include "xpower_event_js.h"
#endif
#include "av_common.h"
#if !defined(CROSS_PLATFORM)
#include "ipc_skeleton.h"
#include "tokenid_kit.h"
#endif

using namespace OHOS::AudioStandard;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_METADATA, "AVImageGeneratorNapi" };
constexpr uint8_t ARG_ZERO = 0;
constexpr uint8_t ARG_ONE = 1;
constexpr uint8_t ARG_TWO = 2;
constexpr uint8_t ARG_THREE = 3;
constexpr uint8_t ARG_FOUR = 4;
}

namespace OHOS {
namespace Media {
thread_local napi_ref AVImageGeneratorNapi::constructor_ = nullptr;
const std::string CLASS_NAME = "AVImageGenerator";

AVImageGeneratorNapi::AVImageGeneratorNapi()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

AVImageGeneratorNapi::~AVImageGeneratorNapi()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

napi_value AVImageGeneratorNapi::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor staticProperty[] = {
        DECLARE_NAPI_STATIC_FUNCTION("createAVImageGenerator", JsCreateAVImageGenerator),
    };

    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("fetchFrameByTime", JsFetchFrameAtTime),
        DECLARE_NAPI_FUNCTION("fetchScaledFrameByTime", JsFetchScaledFrameAtTime),
        DECLARE_NAPI_FUNCTION("release", JsRelease),

        DECLARE_NAPI_GETTER_SETTER("fdSrc", JsGetAVFileDescriptor, JsSetAVFileDescriptor),
    };

    napi_value constructor = nullptr;
    CHECK_AND_RETURN_RET_LOG(sizeof(properties[0]) != 0, nullptr, "Failed to define calss");

    napi_status status = napi_define_class(env, CLASS_NAME.c_str(), NAPI_AUTO_LENGTH, Constructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &constructor);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "Failed to define AVImageGenerator class");

    status = napi_create_reference(env, constructor, 1, &constructor_);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "Failed to create reference of constructor");

    status = napi_set_named_property(env, exports, CLASS_NAME.c_str(), constructor);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "Failed to set constructor");

    status = napi_define_properties(env, exports, sizeof(staticProperty) / sizeof(staticProperty[0]), staticProperty);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "Failed to define static function");

    MEDIA_LOGD("AVImageGeneratorNapi Init success");
    return exports;
}

napi_value AVImageGeneratorNapi::Constructor(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    size_t argCount = 0;
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argCount, nullptr, &jsThis, nullptr);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, result, "failed to napi_get_cb_info");

    AVImageGeneratorNapi *generator = new(std::nothrow) AVImageGeneratorNapi();
    CHECK_AND_RETURN_RET_LOG(generator != nullptr, result, "failed to new AVImageGeneratorNapi");

    generator->env_ = env;
    generator->helper_ = AVMetadataHelperFactory::CreateAVMetadataHelper();
    if (generator->helper_ == nullptr) {
        delete generator;
        MEDIA_LOGE("failed to CreateMetadataHelper");
        return result;
    }

    status = napi_wrap(env, jsThis, reinterpret_cast<void *>(generator),
        AVImageGeneratorNapi::Destructor, nullptr, nullptr);
    if (status != napi_ok) {
        delete generator;
        MEDIA_LOGE("Failed to wrap native instance");
        return result;
    }

    MEDIA_LOGI("Constructor success");
    return jsThis;
}

void AVImageGeneratorNapi::Destructor(napi_env env, void *nativeObject, void *finalize)
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Destructor", FAKE_POINTER(nativeObject));
    (void)finalize;
    CHECK_AND_RETURN(nativeObject != nullptr);
    AVImageGeneratorNapi *napi = reinterpret_cast<AVImageGeneratorNapi *>(nativeObject);
    std::thread([napi]() -> void {
        MEDIA_LOGD("Destructor Release enter");
        if (napi != nullptr && napi->helper_ != nullptr) {
            napi->helper_->Release();
        }
        delete napi;
    }).detach();
    MEDIA_LOGD("Destructor success");
}

napi_value AVImageGeneratorNapi::JsCreateAVImageGenerator(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVImageGeneratorNapi::JsCreateAVImageGenerator");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsCreateAVImageGenerator In");

    std::unique_ptr<MediaAsyncContext> asyncContext = std::make_unique<MediaAsyncContext>(env);

    // get args
    napi_value jsThis = nullptr;
    napi_value args[1] = { nullptr };
    size_t argCount = 1;
    napi_status status = napi_get_cb_info(env, info, &argCount, args, &jsThis, nullptr);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && jsThis != nullptr, nullptr, "failed to napi_get_cb_info");

    asyncContext->callbackRef = CommonNapi::CreateReference(env, args[0]);
    asyncContext->deferred = CommonNapi::CreatePromise(env, asyncContext->callbackRef, result);
    asyncContext->JsResult = std::make_unique<MediaJsResultInstance>(constructor_);
    asyncContext->ctorFlag = true;

    auto ret = MediaAsyncContext::SendCompleteEvent(env, asyncContext.get(), napi_eprio_high);
    if (ret != napi_status::napi_ok) {
        MEDIA_LOGE("failed to SendEvent, ret = %{public}d", ret);
    } else {
        asyncContext.release();
    }
    MEDIA_LOGI("JsCreateAVImageGenerator Out");
    return result;
}

int32_t AVImageGeneratorNapi::GetFetchFrameArgs(std::unique_ptr<AVImageGeneratorAsyncContext> &asyncCtx, napi_env env,
    napi_value timeUs, napi_value option, napi_value params)
{
    napi_status ret = napi_get_value_int64(env, timeUs, &asyncCtx->timeUs_);
    if (ret != napi_ok) {
        asyncCtx->SignError(MSERR_INVALID_VAL, "failed to get timeUs");
        return MSERR_INVALID_VAL;
    }
    ret = napi_get_value_int32(env, option, &asyncCtx->option_);
    if (ret != napi_ok) {
        asyncCtx->SignError(MSERR_INVALID_VAL, "failed to get option");
        return MSERR_INVALID_VAL;
    }

    int32_t width = -1;
    if (!CommonNapi::GetPropertyInt32(env, params, "width", width)) {
        MEDIA_LOGW("failed to get width");
    }

    int32_t height = -1;
    if (!CommonNapi::GetPropertyInt32(env, params, "height", height)) {
        MEDIA_LOGW("failed to get height");
    }

    PixelFormat colorFormat = PixelFormat::RGBA_8888;
    int32_t formatVal = 3;
    CommonNapi::GetPropertyInt32(env, params, "colorFormat", formatVal);
    colorFormat = static_cast<PixelFormat>(formatVal);
    if (colorFormat != PixelFormat::RGB_565 && colorFormat != PixelFormat::RGB_888 &&
        colorFormat != PixelFormat::RGBA_8888) {
        asyncCtx->SignError(MSERR_INVALID_VAL, "formatVal is invalid");
        return MSERR_INVALID_VAL;
    }

    asyncCtx->param_.dstWidth = width;
    asyncCtx->param_.dstHeight = height;
    asyncCtx->param_.colorFormat = colorFormat;
    return MSERR_OK;
}

napi_value AVImageGeneratorNapi::JsFetchFrameAtTime(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVImageGeneratorNapi::JsFetchFrameAtTime");
    MEDIA_LOGI("JsFetchFrameAtTime  in");
    const int32_t maxArgs = ARG_FOUR;  // args + callback
    const int32_t argCallback = ARG_THREE;  // index three, the 4th param if exist
    const int32_t argPixelParam = ARG_TWO;  // index 2, the 3rd param
    size_t argCount = maxArgs;
    napi_value args[maxArgs] = { nullptr };
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    AVImageGeneratorNapi *napi = AVImageGeneratorNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(napi != nullptr, result, "failed to GetJsInstance");

    auto asyncCtx = std::make_unique<AVImageGeneratorAsyncContext>(env);
    asyncCtx->innerHelper_ = napi->helper_;
    asyncCtx->callbackRef = CommonNapi::CreateReference(env, args[argCallback]);
    asyncCtx->deferred = CommonNapi::CreatePromise(env, asyncCtx->callbackRef, result);
    napi_valuetype valueType = napi_undefined;
    bool notParamValid = argCount < argCallback || napi_typeof(env, args[argPixelParam], &valueType) != napi_ok ||
        valueType != napi_object ||
        napi->GetFetchFrameArgs(asyncCtx, env, args[ARG_ZERO], args[ARG_ONE], args[ARG_TWO]) != MSERR_OK;
    if (notParamValid) {
        asyncCtx->SignError(MSERR_EXT_API9_INVALID_PARAMETER, "JsFetchFrameAtTime");
    }

    if (napi->state_ != HelperState::HELPER_STATE_RUNNABLE && !asyncCtx->errFlag) {
        asyncCtx->SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "Current state is not runnable, can't fetchFrame.");
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "JsFetchFrameAtTime", NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, [](napi_env env, void *data) {
        auto asyncCtx = reinterpret_cast<AVImageGeneratorAsyncContext *>(data);
        CHECK_AND_RETURN_LOG(asyncCtx && !asyncCtx->errFlag && asyncCtx->innerHelper_, "Invalid context.");
        auto pixelMap = asyncCtx->innerHelper_->
            FetchFrameYuv(asyncCtx->timeUs_, asyncCtx->option_, asyncCtx->param_);
        asyncCtx->pixel_ = pixelMap;
        CHECK_AND_RETURN(asyncCtx->pixel_ == nullptr);
        asyncCtx->SignError(MSERR_EXT_API9_UNSUPPORT_FORMAT, "FetchFrameByTime failed.");
    }, CreatePixelMapComplete, static_cast<void *>(asyncCtx.get()), &asyncCtx->work));
    NAPI_CALL(env, napi_queue_async_work(env, asyncCtx->work));
    asyncCtx.release();
    MEDIA_LOGI("JsFetchFrameAtTime Out");
    return result;
}

int32_t AVImageGeneratorNapi::GetFetchScaledFrameArgs(std::unique_ptr<AVImageGeneratorAsyncContext> &asyncCtx,
                                                      napi_env env, napi_value timeUs, napi_value option,
                                                      napi_value outputSize)
{
    napi_status ret = napi_get_value_int64(env, timeUs, &asyncCtx->timeUs_);
    if (ret != napi_ok) {
        asyncCtx->SignError(MSERR_INVALID_VAL, "failed to get timeUs");
        return MSERR_INVALID_VAL;
    }
    ret = napi_get_value_int32(env, option, &asyncCtx->option_);
    if (ret != napi_ok) {
        asyncCtx->SignError(MSERR_INVALID_VAL, "failed to get option");
        return MSERR_INVALID_VAL;
    }

    int32_t width = 0;
    int32_t height = 0;
    if (outputSize == nullptr) {
        MEDIA_LOGI("User has not set outputSize");
    } else {
        if (!CommonNapi::GetPropertyInt32(env, outputSize, "width", width)) {
            MEDIA_LOGW("User has not set width");
        }
        if (!CommonNapi::GetPropertyInt32(env, outputSize, "height", height)) {
            MEDIA_LOGW("User has not set height");
        }
    }

    asyncCtx->param_.dstWidth = width;
    asyncCtx->param_.dstHeight = height;
    asyncCtx->param_.colorFormat = PixelFormat::UNKNOWN;
    MEDIA_LOGI("searchMode=%{public}d width=%{public}d height=%{public}d GetFetchScaledFrameArgs",
        asyncCtx->option_, width, height);
    return MSERR_OK;
}

napi_value AVImageGeneratorNapi::VerifyTheParameters(napi_env env, napi_callback_info info,
                                                     std::unique_ptr<AVImageGeneratorAsyncContext> &promiseCtx)
{
    size_t argCount = ARG_THREE;
    const int32_t maxArgs = ARG_THREE;  // timeUs: number, options: AVImageQueryOptions, param: PixelMapParams
    const int32_t argOutputSizeIndex = ARG_TWO;
    napi_value args[maxArgs] = { nullptr };
    napi_value result = nullptr;
    CHECK_AND_RETURN_RET_LOG(env != nullptr, result, "env is null");
    napi_get_undefined(env, &result);

    AVImageGeneratorNapi *napi = AVImageGeneratorNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(napi != nullptr, result, "failed to GetJsInstance");

    promiseCtx = std::make_unique<AVImageGeneratorAsyncContext>(env);
    CHECK_AND_RETURN_RET_LOG(promiseCtx != nullptr, nullptr, "promiseCtx is null");
    promiseCtx->napi = napi;
    promiseCtx->deferred = CommonNapi::CreatePromise(env, promiseCtx->callbackRef, result);

    napi_valuetype valueType = napi_undefined;
    bool notParamValid = argCount < argOutputSizeIndex;
    if (notParamValid) {
        promiseCtx->SignError(MSERR_EXT_API9_INVALID_PARAMETER, "JsFetchScaledFrameAtTime");
        return nullptr;
    }
    if (argCount == maxArgs) {
        notParamValid = napi_typeof(env, args[argOutputSizeIndex], &valueType) != napi_ok ||
            valueType != napi_object || promiseCtx->napi->GetFetchScaledFrameArgs(promiseCtx, env, args[ARG_ZERO],
            args[ARG_ONE], args[ARG_TWO]) != MSERR_OK;
    } else {
        notParamValid = promiseCtx->napi->GetFetchScaledFrameArgs(
            promiseCtx, env, args[ARG_ZERO], args[ARG_ONE], nullptr) != MSERR_OK;
    }
    if (notParamValid) {
        promiseCtx->SignError(MSERR_EXT_API9_INVALID_PARAMETER, "JsFetchScaledFrameAtTime");
        return nullptr;
    }

    if (napi->state_ != HelperState::HELPER_STATE_RUNNABLE) {
        promiseCtx->SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "Current state is not runnable, can't fetchScaledFrame.");
        return nullptr;
    }

    return result;
}

napi_value AVImageGeneratorNapi::JsFetchScaledFrameAtTime(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVImageGeneratorNapi::JsFetchScaledFrameAtTime");
    MEDIA_LOGI("JsFetchScaledFrameAtTime in");
    std::unique_ptr<AVImageGeneratorAsyncContext> promiseCtx = nullptr;
    napi_value result = VerifyTheParameters(env, info, promiseCtx);
    CHECK_AND_RETURN_RET_LOG(result != nullptr, result, "failed to VerifyTheParameters");

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "JsFetchScaledFrameAtTime", NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, [](napi_env env, void *data) {
        auto asyncCtx = reinterpret_cast<AVImageGeneratorAsyncContext *>(data);
        CHECK_AND_RETURN_LOG(asyncCtx && asyncCtx->napi && !asyncCtx->errFlag,
            "Invalid AVImageGeneratorAsyncContext.");
        CHECK_AND_RETURN_LOG(asyncCtx->napi->helper_ != nullptr, "Invalid AVImageGeneratorNapi.");
        auto pixelMap = asyncCtx->napi->helper_->
            FetchScaledFrameYuv(asyncCtx->timeUs_, asyncCtx->option_, asyncCtx->param_);
        asyncCtx->pixel_ = pixelMap;
        if (asyncCtx->pixel_ == nullptr) {
            asyncCtx->SignError(MSERR_EXT_API9_UNSUPPORT_FORMAT, "JsFetchScaledFrameAtTime failed.");
        }
    }, CreatePixelMapComplete, static_cast<void *>(promiseCtx.get()), &promiseCtx->work));
    NAPI_CALL(env, napi_queue_async_work(env, promiseCtx->work));
    promiseCtx.release();
    return result;
}

void AVImageGeneratorNapi::CreatePixelMapComplete(napi_env env, napi_status status, void *data)
{
    napi_value result = nullptr;

    MEDIA_LOGI("CreatePixelMapComplete In");
    auto context = static_cast<AVImageGeneratorAsyncContext*>(data);

    if (status == napi_ok && context->errCode == napi_ok) {
        MEDIA_LOGI("set pixel map success");
        context->status = MSERR_OK;
        result = Media::PixelMapNapi::CreatePixelMap(env, context->pixel_);
    } else {
        context->status = context->errCode == napi_ok ? MSERR_INVALID_VAL : context->errCode;
        MEDIA_LOGW("set pixel map failed");
        napi_get_undefined(env, &result);
    }

    CommonCallbackRoutine(env, context, result);
}

void AVImageGeneratorNapi::CommonCallbackRoutine(napi_env env, AVImageGeneratorAsyncContext* &asyncContext,
    const napi_value &valueParam)
{
    napi_value result[2] = {0};
    napi_value retVal;
    napi_value callback = nullptr;

    napi_get_undefined(env, &result[0]);
    napi_get_undefined(env, &result[1]);

    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(env, &scope);
    CHECK_AND_RETURN(scope != nullptr && asyncContext != nullptr);
    if (asyncContext->status == ERR_OK) {
        result[1] = valueParam;
    }
    napi_create_uint32(env, asyncContext->status, &result[0]);

    if (asyncContext->errFlag) {
        (void)CommonNapi::CreateError(env, asyncContext->errCode, asyncContext->errMessage, callback);
        result[0] = callback;
    }
    if (asyncContext->deferred && asyncContext->status == ERR_OK) {
        napi_resolve_deferred(env, asyncContext->deferred, result[1]);
    } else if (asyncContext->deferred) {
        napi_reject_deferred(env, asyncContext->deferred, result[0]);
    } else {
        napi_get_reference_value(env, asyncContext->callbackRef, &callback);
        napi_call_function(env, nullptr, callback, ARG_TWO, result, &retVal);
        napi_delete_reference(env, asyncContext->callbackRef);
    }

    napi_delete_async_work(env, asyncContext->work);
    napi_close_handle_scope(env, scope);

    delete asyncContext;
    asyncContext = nullptr;
}

napi_value AVImageGeneratorNapi::JsRelease(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVImageGeneratorNapi::release");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsRelease In");

    auto promiseCtx = std::make_unique<AVImageGeneratorAsyncContext>(env);
    napi_value args[1] = { nullptr };
    size_t argCount = 1;
    AVImageGeneratorNapi *generator = AVImageGeneratorNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(generator != nullptr, result, "failed to GetJsInstance");
    promiseCtx->innerHelper_ = generator->helper_;
    promiseCtx->callbackRef = CommonNapi::CreateReference(env, args[0]);
    promiseCtx->deferred = CommonNapi::CreatePromise(env, promiseCtx->callbackRef, result);

    if (generator->state_ == HelperState::HELPER_STATE_RELEASED) {
        promiseCtx->SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "Has released once, can't release again.");
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "JsRelease", NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, [](napi_env env, void *data) {
        auto promiseCtx = reinterpret_cast<AVImageGeneratorAsyncContext *>(data);
        CHECK_AND_RETURN_LOG(promiseCtx && promiseCtx->innerHelper_, "Invalid promiseCtx.");
        promiseCtx->innerHelper_->Release();
    }, MediaAsyncContext::CompleteCallback, static_cast<void *>(promiseCtx.get()), &promiseCtx->work));
    napi_queue_async_work_with_qos(env, promiseCtx->work, napi_qos_user_initiated);
    promiseCtx.release();
    MEDIA_LOGI("JsRelease Out");
    return result;
}

napi_value AVImageGeneratorNapi::JsSetAVFileDescriptor(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVImageGeneratorNapi::set fd");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsSetAVFileDescriptor In");

    napi_value args[1] = { nullptr };
    size_t argCount = 1; // url: string
    AVImageGeneratorNapi *generator = AVImageGeneratorNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(generator != nullptr, result, "failed to GetJsInstanceWithParameter");

    CHECK_AND_RETURN_RET_LOG(
        generator->state_ == HelperState::HELPER_STATE_IDLE, result, "Has set source once, unsupport set again");

    napi_valuetype valueType = napi_undefined;
    bool notValidParam = argCount < 1 || napi_typeof(env, args[0], &valueType) != napi_ok || valueType != napi_object ||
        !CommonNapi::GetFdArgument(env, args[0], generator->fileDescriptor_);
    CHECK_AND_RETURN_RET_LOG(!notValidParam, result, "Invalid file descriptor, return");
    CHECK_AND_RETURN_RET_LOG(generator->helper_, result, "Invalid AVImageGeneratorNapi.");

    auto fileDescriptor = generator->fileDescriptor_;
    auto res = generator->helper_->SetSource(fileDescriptor.fd, fileDescriptor.offset, fileDescriptor.length);
    generator->state_ = res == MSERR_OK ? HelperState::HELPER_STATE_RUNNABLE : HelperState::HELPER_ERROR;
    return result;
}

napi_value AVImageGeneratorNapi::JsGetAVFileDescriptor(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVImageGeneratorNapi::get fd");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsGetAVFileDescriptor In");

    AVImageGeneratorNapi *generator = AVImageGeneratorNapi::GetJsInstance(env, info);
    CHECK_AND_RETURN_RET_LOG(generator != nullptr, result, "failed to GetJsInstance");

    napi_value value = nullptr;
    (void)napi_create_object(env, &value);
    (void)CommonNapi::AddNumberPropInt32(env, value, "fd", generator->fileDescriptor_.fd);
    (void)CommonNapi::AddNumberPropInt64(env, value, "offset", generator->fileDescriptor_.offset);
    (void)CommonNapi::AddNumberPropInt64(env, value, "length", generator->fileDescriptor_.length);

    MEDIA_LOGI("JsGetAVFileDescriptor Out");
    return value;
}

AVImageGeneratorNapi* AVImageGeneratorNapi::GetJsInstance(napi_env env, napi_callback_info info)
{
    size_t argCount = 0;
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argCount, nullptr, &jsThis, nullptr);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && jsThis != nullptr, nullptr, "failed to napi_get_cb_info");

    AVImageGeneratorNapi *generator = nullptr;
    status = napi_unwrap(env, jsThis, reinterpret_cast<void **>(&generator));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && generator != nullptr, nullptr, "failed to napi_unwrap");

    return generator;
}

AVImageGeneratorNapi* AVImageGeneratorNapi::GetJsInstanceWithParameter(napi_env env, napi_callback_info info,
    size_t &argc, napi_value *argv)
{
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &jsThis, nullptr);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && jsThis != nullptr, nullptr, "failed to napi_get_cb_info");

    AVImageGeneratorNapi *generator = nullptr;
    status = napi_unwrap(env, jsThis, reinterpret_cast<void **>(&generator));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && generator != nullptr, nullptr, "failed to napi_unwrap");

    return generator;
}
} // namespace Media
} // namespace OHOS