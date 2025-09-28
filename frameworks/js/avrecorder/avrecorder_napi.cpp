/*
 * Copyright (C) 2022-2025 Huawei Device Co., Ltd.
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

#include <climits>
#include "avrecorder_callback.h"
#include "media_dfx.h"
#include "media_log.h"
#include "media_errors.h"
#include "scope_guard.h"
#include "common_napi.h"
#include "surface_utils.h"
#include "string_ex.h"
#include "avcodec_info.h"
#include "av_common.h"
#ifndef CROSS_PLATFORM
#include "tokenid_kit.h"
#include "ipc_skeleton.h"
#endif
#ifdef SUPPORT_JSSTACK
#include "xpower_event_js.h"
#endif
#include "avrecorder_napi.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_RECORDER, "AVRecorderNapi"};
}

namespace OHOS {
namespace Media {
using namespace MediaAVCodec;

thread_local napi_ref AVRecorderNapi::constructor_ = nullptr;
const std::string CLASS_NAME = "AVRecorder";
std::map<std::string, AVRecorderNapi::AvRecorderTaskqFunc> AVRecorderNapi::taskQFuncs_ = {
    {AVRecordergOpt::GETINPUTSURFACE, &AVRecorderNapi::GetInputSurface},
    {AVRecordergOpt::START, &AVRecorderNapi::Start},
    {AVRecordergOpt::PAUSE, &AVRecorderNapi::Pause},
    {AVRecordergOpt::RESUME, &AVRecorderNapi::Resume},
    {AVRecordergOpt::STOP, &AVRecorderNapi::Stop},
    {AVRecordergOpt::RESET, &AVRecorderNapi::Reset},
    {AVRecordergOpt::RELEASE, &AVRecorderNapi::Release},
};

AVRecorderNapi::AVRecorderNapi()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR "Instances create", FAKE_POINTER(this));
}

AVRecorderNapi::~AVRecorderNapi()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR "Instances destroy", FAKE_POINTER(this));
}

napi_value AVRecorderNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_LOGI("JS Init Start");
    napi_property_descriptor staticProperty[] = {
        DECLARE_NAPI_STATIC_FUNCTION("createAVRecorder", JsCreateAVRecorder),
    };

    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("prepare", JsPrepare),
        DECLARE_NAPI_FUNCTION("SetOrientationHint", JsSetOrientationHint),
        DECLARE_NAPI_FUNCTION("updateRotation", JsSetOrientationHint),
        DECLARE_NAPI_FUNCTION("getInputSurface", JsGetInputSurface),
        DECLARE_NAPI_FUNCTION("getInputMetaSurface", JsGetInputMetaSurface),
        DECLARE_NAPI_FUNCTION("start", JsStart),
        DECLARE_NAPI_FUNCTION("pause", JsPause),
        DECLARE_NAPI_FUNCTION("resume", JsResume),
        DECLARE_NAPI_FUNCTION("stop", JsStop),
        DECLARE_NAPI_FUNCTION("reset", JsReset),
        DECLARE_NAPI_FUNCTION("release", JsRelease),
        DECLARE_NAPI_FUNCTION("on", JsSetEventCallback),
        DECLARE_NAPI_FUNCTION("off", JsCancelEventCallback),
        DECLARE_NAPI_FUNCTION("getAVRecorderProfile", JsGetAVRecorderProfile),
        DECLARE_NAPI_FUNCTION("setAVRecorderConfig", JsSetAVRecorderConfig),
        DECLARE_NAPI_FUNCTION("getAVRecorderConfig", JsGetAVRecorderConfig),
        DECLARE_NAPI_FUNCTION("getCurrentAudioCapturerInfo", JsGetCurrentAudioCapturerInfo),
        DECLARE_NAPI_FUNCTION("getAudioCapturerMaxAmplitude", JsGetAudioCapturerMaxAmplitude),
        DECLARE_NAPI_FUNCTION("getAvailableEncoder", JsGetAvailableEncoder),
        DECLARE_NAPI_FUNCTION("setWatermark", JsSetWatermark),
        DECLARE_NAPI_FUNCTION("setMetadata", JsSetMetadata),
        DECLARE_NAPI_FUNCTION("isWatermarkSupported", JsIsWatermarkSupported),
        DECLARE_NAPI_FUNCTION("setWillMuteWhenInterrupted", JsSetWillMuteWhenInterrupted),

        DECLARE_NAPI_GETTER("state", JsGetState),
    };

    napi_value constructor = nullptr;
    napi_status status = napi_define_class(env, CLASS_NAME.c_str(), NAPI_AUTO_LENGTH, Constructor, nullptr,
                                           sizeof(properties) / sizeof(properties[0]), properties, &constructor);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "Failed to define AVRecorder class");

    status = napi_create_reference(env, constructor, 1, &constructor_);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "Failed to create reference of constructor");

    status = napi_set_named_property(env, exports, CLASS_NAME.c_str(), constructor);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "Failed to set constructor");

    status = napi_define_properties(env, exports, sizeof(staticProperty) / sizeof(staticProperty[0]), staticProperty);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "Failed to define static function");

    MEDIA_LOGI("Js Init End");
    return exports;
}

napi_value AVRecorderNapi::Constructor(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVRecorder::Constructor");
    MEDIA_LOGI("Js Constructor Start");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    size_t argCount = 0;
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argCount, nullptr, &jsThis, nullptr);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, result, "failed to napi_get_cb_info");

    AVRecorderNapi *jsRecorder = new(std::nothrow) AVRecorderNapi();
    CHECK_AND_RETURN_RET_LOG(jsRecorder != nullptr, result, "failed to new AVRecorderNapi");

    jsRecorder->env_ = env;
    jsRecorder->recorder_ = RecorderFactory::CreateRecorder();
    if (jsRecorder->recorder_ == nullptr) {
        delete jsRecorder;
        MEDIA_LOGE("failed to CreateRecorder");
        return result;
    }

    jsRecorder->taskQue_ = std::make_unique<TaskQueue>("OS_AVRecordNapi");
    (void)jsRecorder->taskQue_->Start();

    jsRecorder->recorderCb_ = std::make_shared<AVRecorderCallback>(env);
    if (jsRecorder->recorderCb_ == nullptr) {
        delete jsRecorder;
        MEDIA_LOGE("failed to CreateRecorderCb");
        return result;
    }
    (void)jsRecorder->recorder_->SetRecorderCallback(jsRecorder->recorderCb_);

    status = napi_wrap(env, jsThis, reinterpret_cast<void *>(jsRecorder),
                       AVRecorderNapi::Destructor, nullptr, nullptr);
    if (status != napi_ok) {
        delete jsRecorder;
        MEDIA_LOGE("Failed to wrap native instance");
        return result;
    }

    MEDIA_LOGI("Js Constructor End");
    return jsThis;
}

void AVRecorderNapi::Destructor(napi_env env, void *nativeObject, void *finalize)
{
    MediaTrace trace("AVRecorder::Destructor");
    MEDIA_LOGI("Js Destructor Start");
    (void)finalize;
    if (nativeObject != nullptr) {
        AVRecorderNapi *napi = reinterpret_cast<AVRecorderNapi *>(nativeObject);
        if (napi->taskQue_ != nullptr) {
            (void)napi->taskQue_->Stop();
        }

        napi->RemoveSurface();
        napi->recorderCb_ = nullptr;

        if (napi->recorder_) {
            napi->recorder_->Release();
            napi->recorder_ = nullptr;
        }

        delete napi;
    }
    MEDIA_LOGI("Js Destructor End");
}

napi_value AVRecorderNapi::JsCreateAVRecorder(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVRecorder::JsCreateAVRecorder");
    MEDIA_LOGI("Js CreateAVRecorder Start");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    // get args
    napi_value jsThis = nullptr;
    napi_value args[1] = { nullptr };
    size_t argCount = 1;
    napi_status status = napi_get_cb_info(env, info, &argCount, args, &jsThis, nullptr);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, result, "failed to napi_get_cb_info");

    std::unique_ptr<AVRecorderAsyncContext> asyncCtx = std::make_unique<AVRecorderAsyncContext>(env);
    CHECK_AND_RETURN_RET_LOG(asyncCtx != nullptr, result, "failed to get AsyncContext");

    asyncCtx->callbackRef = CommonNapi::CreateReference(env, args[0]);
    asyncCtx->deferred = CommonNapi::CreatePromise(env, asyncCtx->callbackRef, result);
    asyncCtx->JsResult = std::make_unique<MediaJsResultInstance>(constructor_);
    asyncCtx->ctorFlag = true;

    auto ret = MediaAsyncContext::SendCompleteEvent(env, asyncCtx.get(), napi_eprio_immediate);
    if (ret != napi_status::napi_ok) {
        MEDIA_LOGE("failed to SendEvent, ret = %{public}d", ret);
    }
    asyncCtx.release();

    MEDIA_LOGI("Js CreateAVRecorder End");
    
    return result;
}

RetInfo GetRetInfo(int32_t errCode, const std::string &operate, const std::string &param, const std::string &add = "")
{
    MEDIA_LOGE("failed to %{public}s, param %{public}s, errCode = %{public}d", operate.c_str(), param.c_str(), errCode);
    MediaServiceExtErrCodeAPI9 err = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(errCode));
    if (errCode == MSERR_UNSUPPORT_VID_PARAMS) {
        return RetInfo(err, "The video parameter is not supported. Please check the type and range.");
    }
    
    if (errCode == MSERR_UNSUPPORT_AUD_PARAMS) {
        return RetInfo(err, "The audio parameter is not supported. Please check the type and range.");
    }
    
    std::string message;
    if (err == MSERR_EXT_API9_INVALID_PARAMETER) {
        message = MSExtErrorAPI9ToString(err, param, "") + add;
    } else {
        message = MSExtErrorAPI9ToString(err, operate, "") + add;
    }

    MEDIA_LOGE("errCode: %{public}d, errMsg: %{public}s", err, message.c_str());
    return RetInfo(err, message);
}

napi_value AVRecorderNapi::JsPrepare(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVRecorder::JsPrepare");
    const std::string &opt = AVRecordergOpt::PREPARE;
    MEDIA_LOGI("Js %{public}s Start", opt.c_str());

    const int32_t maxParam = 2; // config + callbackRef
    size_t argCount = maxParam;
    napi_value args[maxParam] = { nullptr };

    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    auto asyncCtx = std::make_unique<AVRecorderAsyncContext>(env);
    CHECK_AND_RETURN_RET_LOG(asyncCtx != nullptr, result, "failed to get AsyncContext");
    asyncCtx->napi = AVRecorderNapi::GetJsInstanceAndArgs(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(asyncCtx->napi != nullptr, result, "failed to GetJsInstanceAndArgs");
    CHECK_AND_RETURN_RET_LOG(asyncCtx->napi->taskQue_ != nullptr, result, "taskQue is nullptr!");

    asyncCtx->callbackRef = CommonNapi::CreateReference(env, args[1]);
    asyncCtx->deferred = CommonNapi::CreatePromise(env, asyncCtx->callbackRef, result);

    if (asyncCtx->napi->CheckStateMachine(opt) == MSERR_OK) {
        if (asyncCtx->napi->GetConfig(asyncCtx, env, args[0]) == MSERR_OK) {
            QOS::QosLevel level;
            GetThreadQos(level);
            MEDIA_LOGI("GetThreadQos %{public}d", static_cast<int32_t>(level));
            if (level == QOS::QosLevel::QOS_USER_INTERACTIVE) {
                asyncCtx->napi->taskQue_->SetQos(level);
            }
            asyncCtx->task_ = AVRecorderNapi::GetPrepareTask(asyncCtx);
            (void)asyncCtx->napi->taskQue_->EnqueueTask(asyncCtx->task_);
        }
    } else {
        asyncCtx->AVRecorderSignError(MSERR_INVALID_OPERATION, opt, "");
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, opt.c_str(), NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, [](napi_env env, void* data) {
        AVRecorderAsyncContext* asyncCtx = reinterpret_cast<AVRecorderAsyncContext *>(data);
        CHECK_AND_RETURN_LOG(asyncCtx != nullptr, "asyncCtx is nullptr!");

        if (asyncCtx->task_) {
            auto result = asyncCtx->task_->GetResult();
            if (result.Value().first != MSERR_EXT_API9_OK) {
                asyncCtx->SignError(result.Value().first, result.Value().second);
            }
        }
        asyncCtx->napi->taskQue_->ResetQos();
        MEDIA_LOGI("The js thread of prepare finishes execution and returns");
    }, MediaAsyncContext::CompleteCallback, static_cast<void *>(asyncCtx.get()), &asyncCtx->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCtx->work, napi_qos_user_initiated));
    asyncCtx.release();

    MEDIA_LOGI("Js %{public}s End", opt.c_str());
    return result;
}

napi_value AVRecorderNapi::JsSetOrientationHint(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVRecorder::JsSetOrientationHint");
    const std::string &opt = AVRecordergOpt::SET_ORIENTATION_HINT;
    MEDIA_LOGI("Js %{public}s Start", opt.c_str());

    const int32_t maxParam = 2; // config + callbackRef
    size_t argCount = maxParam;
    napi_value args[maxParam] = { nullptr };

    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    auto asyncCtx = std::make_unique<AVRecorderAsyncContext>(env);
    CHECK_AND_RETURN_RET_LOG(asyncCtx != nullptr, result, "failed to get AsyncContext");
    asyncCtx->napi = AVRecorderNapi::GetJsInstanceAndArgs(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(asyncCtx->napi != nullptr, result, "failed to GetJsInstanceAndArgs");
    CHECK_AND_RETURN_RET_LOG(asyncCtx->napi->taskQue_ != nullptr, result, "taskQue is nullptr!");

    asyncCtx->callbackRef = CommonNapi::CreateReference(env, args[1]);
    asyncCtx->deferred = CommonNapi::CreatePromise(env, asyncCtx->callbackRef, result);

    if (asyncCtx->napi->CheckStateMachine(opt) == MSERR_OK) {
        if (asyncCtx->napi->GetRotation(asyncCtx, env, args[0]) == MSERR_OK) {
            asyncCtx->task_ = AVRecorderNapi::GetSetOrientationHintTask(asyncCtx);
            (void)asyncCtx->napi->taskQue_->EnqueueTask(asyncCtx->task_);
        }
    } else {
        asyncCtx->AVRecorderSignError(MSERR_INVALID_OPERATION, opt, "");
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, opt.c_str(), NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, [](napi_env env, void* data) {
        AVRecorderAsyncContext* asyncCtx = reinterpret_cast<AVRecorderAsyncContext *>(data);
        CHECK_AND_RETURN_LOG(asyncCtx != nullptr, "asyncCtx is nullptr!");

        if (asyncCtx->task_) {
            auto result = asyncCtx->task_->GetResult();
            if (result.Value().first != MSERR_EXT_API9_OK) {
                asyncCtx->SignError(result.Value().first, result.Value().second);
            }
        }
        MEDIA_LOGI("The js thread of prepare finishes execution and returns");
    }, MediaAsyncContext::CompleteCallback, static_cast<void *>(asyncCtx.get()), &asyncCtx->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCtx->work, napi_qos_user_initiated));
    asyncCtx.release();

    MEDIA_LOGI("Js %{public}s End", opt.c_str());
    return result;
}

napi_value AVRecorderNapi::JsSetWatermark(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVRecorder::JsSetWatermark");
    const std::string &opt = AVRecordergOpt::SET_WATERMARK;
    MEDIA_LOGI("Js %{public}s Start", opt.c_str());

    const int32_t maxParam = 2; // pixelMap + WatermarkConfig
    size_t argCount = maxParam;
    napi_value args[maxParam] = { nullptr };

    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    auto asyncCtx = std::make_unique<AVRecorderAsyncContext>(env);
    CHECK_AND_RETURN_RET_LOG(asyncCtx != nullptr, result, "failed to get AsyncContext");
    asyncCtx->napi = AVRecorderNapi::GetJsInstanceAndArgs(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(asyncCtx->napi != nullptr, result, "failed to GetJsInstanceAndArgs");
    CHECK_AND_RETURN_RET_LOG(asyncCtx->napi->taskQue_ != nullptr, result, "taskQue is nullptr!");

    asyncCtx->deferred = CommonNapi::CreatePromise(env, nullptr, result);

    if (asyncCtx->napi->CheckStateMachine(opt) == MSERR_OK) {
        if (asyncCtx->napi->GetWatermarkParameter(asyncCtx, env, args[0], args[1]) == MSERR_OK) {
            asyncCtx->task_ = AVRecorderNapi::SetWatermarkTask(asyncCtx);
            (void)asyncCtx->napi->taskQue_->EnqueueTask(asyncCtx->task_);
        }
    } else {
        asyncCtx->AVRecorderSignError(MSERR_INVALID_OPERATION, opt, "");
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, opt.c_str(), NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, [](napi_env env, void* data) {
        AVRecorderAsyncContext* asyncCtx = reinterpret_cast<AVRecorderAsyncContext *>(data);
        CHECK_AND_RETURN_LOG(asyncCtx != nullptr, "asyncCtx is nullptr!");

        if (asyncCtx->task_) {
            auto result = asyncCtx->task_->GetResult();
            if (result.Value().first != MSERR_EXT_API9_OK) {
                asyncCtx->SignError(result.Value().first, result.Value().second);
            }
        }
        MEDIA_LOGI("The js thread of setWatermark finishes execution and returns");
    }, MediaAsyncContext::CompleteCallback, static_cast<void *>(asyncCtx.get()), &asyncCtx->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCtx->work, napi_qos_user_initiated));
    asyncCtx.release();

    MEDIA_LOGI("Js %{public}s End", opt.c_str());
    return result;
}

napi_value AVRecorderNapi::JsSetMetadata(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVRecorder::JsSetMetadata");
    const std::string &opt = AVRecordergOpt::SET_METADATA;
    MEDIA_LOGI("Js %{public}s Start", opt.c_str());

    const int32_t maxParam = 1; // metadata: Record<string, string>
    size_t argCount = maxParam;
    napi_value args[maxParam] = { nullptr };

    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    AVRecorderNapi *jsRecorder = AVRecorderNapi::GetJsInstanceAndArgs(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(jsRecorder != nullptr, result, "failed to GetJsInstanceAndArgs");
#ifndef CROSS_PLATFORM
    uint64_t accessTokenIDEx = IPCSkeleton::GetCallingFullTokenID();
    bool isSystemApp = Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(accessTokenIDEx);
    if (!isSystemApp) {
        jsRecorder->ErrorCallback(MSERR_EXT_API9_PERMISSION_DENIED, "JsSetMetadata", "not system app");
        return result;
    }
#endif
    CHECK_AND_RETURN_RET_LOG(jsRecorder->taskQue_ != nullptr, result, "taskQue is nullptr!");
    CHECK_AND_RETURN_RET_LOG(jsRecorder->CheckStateMachine(opt) == MSERR_OK, result, "on error state");
    CHECK_AND_RETURN_RET_LOG(jsRecorder->CheckRepeatOperation(opt) == MSERR_OK, result, "on error Operation");

    std::map<std::string, std::string> recordMeta;
    CommonNapi::GetPropertyMap(env, args[0], recordMeta);
    CHECK_AND_RETURN_RET_LOG(recordMeta.size() != 0, result, "recordMeta has no data");

    auto task = std::make_shared<TaskHandler<void>>([jsRecorder, recordMeta]() {
        if (jsRecorder != nullptr) {
            (void)jsRecorder->SetMetadata(recordMeta);
        }
    });
    (void)jsRecorder->taskQue_->EnqueueTask(task);

    MEDIA_LOGI("Js %{public}s End", opt.c_str());
    return result;
}

std::shared_ptr<TaskHandler<RetInfo>> AVRecorderNapi::GetPrepareTask(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx)
{
    return std::make_shared<TaskHandler<RetInfo>>([napi = asyncCtx->napi, config = asyncCtx->config_]() {
        const std::string &option = AVRecordergOpt::PREPARE;
        MEDIA_LOGI("%{public}s Start", option.c_str());
        CHECK_AND_RETURN_RET(napi != nullptr && napi->recorder_ != nullptr && config != nullptr,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));

        CHECK_AND_RETURN_RET(napi->CheckStateMachine(option) == MSERR_OK,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));

        RetInfo retinfo = napi->Configure(config);
        CHECK_AND_RETURN_RET(retinfo.first == MSERR_OK, ((void)napi->recorder_->Reset(), retinfo));

        int32_t ret = napi->recorder_->Prepare();
        CHECK_AND_RETURN_RET(ret == MSERR_OK, ((void)napi->recorder_->Reset(), GetRetInfo(ret, "Prepare", "")));

        napi->RemoveSurface();
        napi->StateCallback(AVRecorderState::STATE_PREPARED);
        napi->getVideoInputSurface_ = false;
        napi->withVideo_ = config->withVideo;
        MEDIA_LOGI("%{public}s End", option.c_str());
        return RetInfo(MSERR_EXT_API9_OK, "");
    });
}

std::shared_ptr<TaskHandler<RetInfo>> AVRecorderNapi::GetSetOrientationHintTask(
    const std::unique_ptr<AVRecorderAsyncContext> &asyncCtx)
{
    return std::make_shared<TaskHandler<RetInfo>>([napi = asyncCtx->napi, config = asyncCtx->config_]() {
        const std::string &option = AVRecordergOpt::SET_ORIENTATION_HINT;
        MEDIA_LOGI("%{public}s Start", option.c_str());
        CHECK_AND_RETURN_RET(napi != nullptr && napi->recorder_ != nullptr && config != nullptr,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));

        CHECK_AND_RETURN_RET(napi->CheckStateMachine(option) == MSERR_OK,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));
        
        napi->recorder_->SetOrientationHint(config->rotation);
        
        MEDIA_LOGI("%{public}s End", option.c_str());
        return RetInfo(MSERR_EXT_API9_OK, "");
    });
}

napi_value AVRecorderNapi::JsGetInputSurface(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVRecorder::JsGetInputSurface");
    MEDIA_LOGI("Js GetInputSurface Enter");
    return ExecuteByPromise(env, info, AVRecordergOpt::GETINPUTSURFACE);
}

napi_value AVRecorderNapi::JsGetInputMetaSurface(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVRecorder::JsGetInputMetaSurface");
    const std::string &opt = AVRecordergOpt::GETINPUTMETASURFACE;
    MEDIA_LOGI("Js %{public}s Start", opt.c_str());

    napi_value args[1] = { nullptr };
    size_t argCount = 1;

    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    auto asyncCtx = std::make_unique<AVRecorderAsyncContext>(env);
    CHECK_AND_RETURN_RET_LOG(asyncCtx != nullptr, result, "failed to get AsyncContext");
    asyncCtx->napi = AVRecorderNapi::GetJsInstanceAndArgs(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(asyncCtx->napi != nullptr, result, "failed to GetJsInstanceAndArgs");
    CHECK_AND_RETURN_RET_LOG(asyncCtx->napi->taskQue_ != nullptr, result, "taskQue is nullptr!");

    asyncCtx->callbackRef = CommonNapi::CreateReference(env, args[0]);
    asyncCtx->deferred = CommonNapi::CreatePromise(env, asyncCtx->callbackRef, result);

    if (asyncCtx->napi->CheckStateMachine(opt) == MSERR_OK) {
        if (asyncCtx->napi->GetMetaType(asyncCtx, env, args[0]) == MSERR_OK) {
            asyncCtx->task_ = AVRecorderNapi::GetInputMetaSurface(asyncCtx);
            (void)asyncCtx->napi->taskQue_->EnqueueTask(asyncCtx->task_);
        }
    } else {
        asyncCtx->AVRecorderSignError(MSERR_INVALID_OPERATION, opt, "");
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, opt.c_str(), NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, [](napi_env env, void* data) {
        AVRecorderAsyncContext* asyncCtx = reinterpret_cast<AVRecorderAsyncContext *>(data);
        CHECK_AND_RETURN_LOG(asyncCtx != nullptr, "asyncCtx is nullptr!");

        if (asyncCtx->task_) {
            auto result = asyncCtx->task_->GetResult();
            if (result.Value().first != MSERR_EXT_API9_OK) {
                asyncCtx->SignError(result.Value().first, result.Value().second);
            } else {
                asyncCtx->JsResult = std::make_unique<MediaJsResultString>(result.Value().second);
            }
        }
        MEDIA_LOGI("The js thread of getInputMetaSurface finishes execution and returns");
    }, MediaAsyncContext::CompleteCallback, static_cast<void *>(asyncCtx.get()), &asyncCtx->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCtx->work, napi_qos_user_initiated));
    asyncCtx.release();

    MEDIA_LOGI("Js %{public}s End", opt.c_str());
    return result;
}

napi_value AVRecorderNapi::JsStart(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVRecorder::JsStart");
    MEDIA_LOGI("Js Start Enter");
#ifdef SUPPORT_JSSTACK
    HiviewDFX::ReportXPowerJsStackSysEvent(env, "STREAM_CHANGE", "SRC=Media");
#endif
    return ExecuteByPromise(env, info, AVRecordergOpt::START);
}

napi_value AVRecorderNapi::JsPause(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVRecorder::JsPause");
    MEDIA_LOGI("Js Pause Enter");
    return ExecuteByPromise(env, info, AVRecordergOpt::PAUSE);
}

napi_value AVRecorderNapi::JsResume(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVRecorder::JsResume");
    MEDIA_LOGI("Js Resume Enter");
#ifdef SUPPORT_JSSTACK
    HiviewDFX::ReportXPowerJsStackSysEvent(env, "STREAM_CHANGE", "SRC=Media");
#endif
    return ExecuteByPromise(env, info, AVRecordergOpt::RESUME);
}

napi_value AVRecorderNapi::JsStop(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVRecorder::JsStop");
    MEDIA_LOGI("Js Stop Enter");
    return ExecuteByPromise(env, info, AVRecordergOpt::STOP);
}

napi_value AVRecorderNapi::JsReset(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVRecorder::JsReset");
    MEDIA_LOGI("Js Reset Enter");
    return ExecuteByPromise(env, info, AVRecordergOpt::RESET);
}

napi_value AVRecorderNapi::JsRelease(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVRecorder::JsRelease");
    MEDIA_LOGI("Js Release Enter");
    return ExecuteByPromise(env, info, AVRecordergOpt::RELEASE);
}

napi_value AVRecorderNapi::JsGetAVRecorderProfile(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVRecorder::JsGetAVRecorderProfile");
    MEDIA_LOGI("AVRecorder::JsGetAVRecorderProfile");
    const std::string &opt = AVRecordergOpt::GET_AV_RECORDER_PROFILE;
    MEDIA_LOGI("Js %{public}s Start", opt.c_str());

    const int32_t maxParam = 3; // config + callbackRef
    const int32_t callbackParam = 2; // callback
    size_t argCount = maxParam;
    napi_value args[maxParam] = { nullptr };
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    auto asyncCtx = std::make_unique<AVRecorderAsyncContext>(env);
    CHECK_AND_RETURN_RET_LOG(asyncCtx != nullptr, result, "failed to get AsyncContext");
    asyncCtx->napi = AVRecorderNapi::GetJsInstanceAndArgs(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(asyncCtx->napi != nullptr, result, "failed to GetJsInstanceAndArgs");
    CHECK_AND_RETURN_RET_LOG(asyncCtx->napi->taskQue_ != nullptr, result, "taskQue is nullptr!");

    asyncCtx->callbackRef = CommonNapi::CreateReference(env, args[callbackParam]);
    asyncCtx->deferred = CommonNapi::CreatePromise(env, asyncCtx->callbackRef, result);

    if (asyncCtx->napi->GetSourceIdAndQuality(asyncCtx, env, args[0], args[1], opt) == MSERR_OK) {
        asyncCtx->task_ = AVRecorderNapi::GetAVRecorderProfileTask(asyncCtx);
        (void)asyncCtx->napi->taskQue_->EnqueueTask(asyncCtx->task_);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, opt.c_str(), NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, [](napi_env env, void* data) {
        AVRecorderAsyncContext* asyncCtx = reinterpret_cast<AVRecorderAsyncContext *>(data);
        CHECK_AND_RETURN_LOG(asyncCtx != nullptr, "asyncCtx is nullptr!");
        if (asyncCtx->task_) {
            auto result = asyncCtx->task_->GetResult();
            if (result.Value().first != MSERR_EXT_API9_OK) {
                asyncCtx->SignError(result.Value().first, result.Value().second);
            } else {
                asyncCtx->JsResult = std::make_unique<MediaJsAVRecorderProfile>(asyncCtx->profile_);
            }
        }
        MEDIA_LOGI("The js thread of prepare finishes execution and returns");
    }, MediaAsyncContext::CompleteCallback, static_cast<void *>(asyncCtx.get()), &asyncCtx->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCtx->work, napi_qos_user_initiated));
    asyncCtx.release();

    MEDIA_LOGI("Js %{public}s End", opt.c_str());
    return result;
}

std::shared_ptr<TaskHandler<RetInfo>> AVRecorderNapi::GetAVRecorderProfileTask(
    const std::unique_ptr<AVRecorderAsyncContext> &asyncCtx)
{
    return std::make_shared<TaskHandler<RetInfo>>([napi = asyncCtx->napi, &profile = asyncCtx->profile_]() {
        const std::string &option = AVRecordergOpt::GET_AV_RECORDER_PROFILE;
        MEDIA_LOGI("%{public}s Start", option.c_str());
        profile = std::make_shared<AVRecorderProfile>();

        CHECK_AND_RETURN_RET(napi != nullptr && profile != nullptr,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));

        CHECK_AND_RETURN_RET(napi->CheckStateMachine(option) == MSERR_OK,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));

        CHECK_AND_RETURN_RET_LOG(napi->sourceId_ >= 0 && ((napi->qualityLevel_ >= RECORDER_QUALITY_LOW &&
            napi->qualityLevel_ <= RECORDER_QUALITY_2160P) ||
            (napi->qualityLevel_ >= RECORDER_QUALITY_TIME_LAPSE_LOW &&
            napi->qualityLevel_ <= RECORDER_QUALITY_TIME_LAPSE_2160P) ||
            (napi->qualityLevel_ >= RECORDER_QUALITY_HIGH_SPEED_LOW &&
            napi->qualityLevel_ <= RECORDER_QUALITY_HIGH_SPEED_1080P)),
            GetRetInfo(MSERR_INVALID_VAL, "GetAVRecorderProfileTask", ""), "sourceId or qualityLevel is null");

        int32_t ret = AVRecorderNapi::GetAVRecorderProfile(profile, napi->sourceId_, napi->qualityLevel_);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, GetRetInfo(MSERR_INVALID_VAL, "GetAVRecorderProfileTask", ""),
            "get AVRecorderProfile failed");

        MEDIA_LOGI("%{public}s End", option.c_str());
        return RetInfo(MSERR_EXT_API9_OK, "");
    });
}

std::shared_ptr<TaskHandler<RetInfo>> AVRecorderNapi::SetAVRecorderConfigTask(
    std::unique_ptr<AVRecorderAsyncContext> &asyncCtx)
{
    return std::make_shared<TaskHandler<RetInfo>>([napi = asyncCtx->napi, config = asyncCtx->config_]() {
        const std::string &option = AVRecordergOpt::SET_AV_RECORDER_CONFIG;
        MEDIA_LOGI("%{public}s Start", option.c_str());
        CHECK_AND_RETURN_RET(napi != nullptr && napi->recorder_ != nullptr && config != nullptr,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));

        CHECK_AND_RETURN_RET(napi->CheckStateMachine(option) == MSERR_OK,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));

        RetInfo retinfo = napi->Configure(config);
        CHECK_AND_RETURN_RET(retinfo.first == MSERR_OK, ((void)napi->recorder_->Reset(), retinfo));

        napi->withVideo_ = config->withVideo;
        MEDIA_LOGI("%{public}s End", option.c_str());
        return RetInfo(MSERR_EXT_API9_OK, "");
    });
}

napi_value AVRecorderNapi::JsSetAVRecorderConfig(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVRecorder::JsSetAVRecorderConfig");
    const std::string &opt = AVRecordergOpt::SET_AV_RECORDER_CONFIG;
    MEDIA_LOGI("Js %{public}s Start", opt.c_str());

    const int32_t maxParam = 2; // config + callbackRef
    size_t argCount = maxParam;
    napi_value args[maxParam] = { nullptr };
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    auto asyncCtx = std::make_unique<AVRecorderAsyncContext>(env);
    CHECK_AND_RETURN_RET_LOG(asyncCtx != nullptr, result, "failed to get AsyncContext");
    asyncCtx->napi = AVRecorderNapi::GetJsInstanceAndArgs(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(asyncCtx->napi != nullptr, result, "failed to GetJsInstanceAndArgs");
    CHECK_AND_RETURN_RET_LOG(asyncCtx->napi->taskQue_ != nullptr, result, "taskQue is nullptr!");

    asyncCtx->callbackRef = CommonNapi::CreateReference(env, args[1]);
    asyncCtx->deferred = CommonNapi::CreatePromise(env, asyncCtx->callbackRef, result);

    if (asyncCtx->napi->CheckStateMachine(opt) == MSERR_OK) {
        if (asyncCtx->napi->GetConfig(asyncCtx, env, args[0]) == MSERR_OK) {
            asyncCtx->task_ = AVRecorderNapi::SetAVRecorderConfigTask(asyncCtx);
            (void)asyncCtx->napi->taskQue_->EnqueueTask(asyncCtx->task_);
        }
    } else {
        asyncCtx->AVRecorderSignError(MSERR_INVALID_OPERATION, opt, "");
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, opt.c_str(), NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, [](napi_env env, void* data) {
        AVRecorderAsyncContext* asyncCtx = reinterpret_cast<AVRecorderAsyncContext *>(data);
        CHECK_AND_RETURN_LOG(asyncCtx != nullptr, "asyncCtx is nullptr!");
        if (asyncCtx->task_) {
            auto result = asyncCtx->task_->GetResult();
            if (result.Value().first != MSERR_EXT_API9_OK) {
                asyncCtx->SignError(result.Value().first, result.Value().second);
            }
        }
        MEDIA_LOGI("The js thread of prepare finishes execution and returns");
    }, MediaAsyncContext::CompleteCallback, static_cast<void *>(asyncCtx.get()), &asyncCtx->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCtx->work, napi_qos_user_initiated));
    asyncCtx.release();

    MEDIA_LOGI("Js %{public}s End", opt.c_str());
    return result;
}

napi_value AVRecorderNapi::JsGetAVRecorderConfig(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVRecorder::JsGetAVRecorderConfig");
    const std::string &opt = AVRecordergOpt::GET_AV_RECORDER_CONFIG;
    MEDIA_LOGI("Js %{public}s Start", opt.c_str());

    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    size_t argCount = 1;
    napi_value args[1] = { nullptr };

    auto asyncCtx = std::make_unique<AVRecorderAsyncContext>(env);
    CHECK_AND_RETURN_RET_LOG(asyncCtx != nullptr, result, "failed to get AsyncContext");
    asyncCtx->napi = AVRecorderNapi::GetJsInstanceAndArgs(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(asyncCtx->napi != nullptr, result, "failed to GetJsInstanceAndArgs");
    CHECK_AND_RETURN_RET_LOG(asyncCtx->napi->taskQue_ != nullptr, result, "taskQue is nullptr!");

    asyncCtx->callbackRef = CommonNapi::CreateReference(env, args[0]);
    asyncCtx->deferred = CommonNapi::CreatePromise(env, asyncCtx->callbackRef, result);

    if (asyncCtx->napi->CheckStateMachine(opt) == MSERR_OK) {
        asyncCtx->task_ = AVRecorderNapi::GetAVRecorderConfigTask(asyncCtx);
        (void)asyncCtx->napi->taskQue_->EnqueueTask(asyncCtx->task_);
        asyncCtx->opt_ = opt;
    } else {
        asyncCtx->AVRecorderSignError(MSERR_INVALID_OPERATION, opt, "");
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, opt.c_str(), NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, [](napi_env env, void* data) {
        AVRecorderAsyncContext* asyncCtx = reinterpret_cast<AVRecorderAsyncContext *>(data);
        CHECK_AND_RETURN_LOG(asyncCtx != nullptr, "asyncCtx is nullptr!");
        if (asyncCtx->task_) {
            auto result = asyncCtx->task_->GetResult();
            if (result.Value().first != MSERR_EXT_API9_OK) {
                asyncCtx->SignError(result.Value().first, result.Value().second);
            }

            if ((result.Value().first == MSERR_EXT_API9_OK) &&
                (asyncCtx->opt_ == AVRecordergOpt::GET_AV_RECORDER_CONFIG)) {
                asyncCtx->JsResult = std::make_unique<MediaJsAVRecorderConfig>(asyncCtx->config_);
            }
        }
        MEDIA_LOGI("The js thread of prepare finishes execution and returns");
    }, MediaAsyncContext::CompleteCallback, static_cast<void *>(asyncCtx.get()), &asyncCtx->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCtx->work, napi_qos_user_initiated));
    asyncCtx.release();

    MEDIA_LOGI("Js %{public}s End", opt.c_str());
    return result;
}

napi_value AVRecorderNapi::JsGetCurrentAudioCapturerInfo(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVRecorder::JsGetCurrentAudioCapturerInfo");
    const std::string &opt = AVRecordergOpt::GET_CURRENT_AUDIO_CAPTURER_INFO;
    MEDIA_LOGI("Js %{public}s Start", opt.c_str());

    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    size_t argCount = 1;
    napi_value args[1] = { nullptr };

    auto asyncCtx = std::make_unique<AVRecorderAsyncContext>(env);
    CHECK_AND_RETURN_RET_LOG(asyncCtx != nullptr, result, "failed to get AsyncContext");
    asyncCtx->napi = AVRecorderNapi::GetJsInstanceAndArgs(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(asyncCtx->napi != nullptr, result, "failed to GetJsInstanceAndArgs");
    CHECK_AND_RETURN_RET_LOG(asyncCtx->napi->taskQue_ != nullptr, result, "taskQue is nullptr!");

    asyncCtx->callbackRef = CommonNapi::CreateReference(env, args[0]);
    asyncCtx->deferred = CommonNapi::CreatePromise(env, asyncCtx->callbackRef, result);
    if (asyncCtx->napi->CheckStateMachine(opt) == MSERR_OK) {
        asyncCtx->task_ = AVRecorderNapi::GetCurrentCapturerChangeInfoTask(asyncCtx);
        (void)asyncCtx->napi->taskQue_->EnqueueTask(asyncCtx->task_);
        asyncCtx->opt_ = opt;
    } else {
        asyncCtx->AVRecorderSignError(MSERR_INVALID_OPERATION, opt, "");
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, opt.c_str(), NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, [](napi_env env, void* data) {
        AVRecorderAsyncContext* asyncCtx = reinterpret_cast<AVRecorderAsyncContext *>(data);
        CHECK_AND_RETURN_LOG(asyncCtx != nullptr, "asyncCtx is nullptr!");
        if (asyncCtx->task_) {
            auto result = asyncCtx->task_->GetResult();
            if (result.Value().first != MSERR_EXT_API9_OK) {
                asyncCtx->SignError(result.Value().first, result.Value().second);
            }

            if ((result.Value().first == MSERR_EXT_API9_OK) &&
                (asyncCtx->opt_ == AVRecordergOpt::GET_CURRENT_AUDIO_CAPTURER_INFO)) {
                asyncCtx->JsResult = std::make_unique<AudioCaptureChangeInfoJsCallback>(asyncCtx->changeInfo_);
            }
        }
        MEDIA_LOGI("The js thread of prepare finishes execution and returns");
    }, MediaAsyncContext::CompleteCallback, static_cast<void *>(asyncCtx.get()), &asyncCtx->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCtx->work, napi_qos_user_initiated));
    asyncCtx.release();

    MEDIA_LOGI("Js %{public}s End", opt.c_str());
    return result;
}

napi_value AVRecorderNapi::JsGetAudioCapturerMaxAmplitude(napi_env env,  napi_callback_info info)
{
    MediaTrace trace("AVRecorder::JsGetAudioCapturerMaxAmplitude");
    const std::string &opt = AVRecordergOpt::GET_MAX_AMPLITUDE;
    MEDIA_LOGD("Js %{public}s Start", opt.c_str());
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    size_t argCount = 1;
    napi_value args[1] = { nullptr };

    auto asyncCtx = std::make_unique<AVRecorderAsyncContext>(env);
    CHECK_AND_RETURN_RET_LOG(asyncCtx != nullptr, result, "failed to get AsyncContext");
    asyncCtx->napi = AVRecorderNapi::GetJsInstanceAndArgs(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(asyncCtx->napi != nullptr, result, "failed to GetJsInstanceAndArgs");
    CHECK_AND_RETURN_RET_LOG(asyncCtx->napi->taskQue_ != nullptr, result, "taskQue is nullptr!");

    asyncCtx->callbackRef = CommonNapi::CreateReference(env, args[0]);
    asyncCtx->deferred = CommonNapi::CreatePromise(env, asyncCtx->callbackRef, result);
    if (asyncCtx->napi->CheckStateMachine(opt) == MSERR_OK) {
        asyncCtx->task_ = AVRecorderNapi::GetMaxAmplitudeTask(asyncCtx);
        (void)asyncCtx->napi->taskQue_->EnqueueTask(asyncCtx->task_);
        asyncCtx->opt_ = opt;
    } else {
        asyncCtx->AVRecorderSignError(MSERR_INVALID_OPERATION, opt, "");
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, opt.c_str(), NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, [](napi_env env, void* data) {
        AVRecorderAsyncContext* asyncCtx = reinterpret_cast<AVRecorderAsyncContext *>(data);
        CHECK_AND_RETURN_LOG(asyncCtx != nullptr, "asyncCtx is nullptr!");
        if (asyncCtx->task_) {
            auto result = asyncCtx->task_->GetResult();
            if (result.Value().first != MSERR_EXT_API9_OK) {
                asyncCtx->SignError(result.Value().first, result.Value().second);
            }

            if ((result.Value().first == MSERR_EXT_API9_OK) &&
                (asyncCtx->opt_ == AVRecordergOpt::GET_MAX_AMPLITUDE)) {
                asyncCtx->JsResult = std::make_unique<MediaJsResultInt>(asyncCtx->maxAmplitude_);
            }
        }
        MEDIA_LOGI("The js thread of prepare finishes execution and returns");
    }, MediaAsyncContext::CompleteCallback, static_cast<void *>(asyncCtx.get()), &asyncCtx->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCtx->work, napi_qos_user_initiated));
    asyncCtx.release();

    MEDIA_LOGD("Js %{public}s End", opt.c_str());
    return result;
}

napi_value AVRecorderNapi::JsGetAvailableEncoder(napi_env env,  napi_callback_info info)
{
    MediaTrace trace("AVRecorder::JsGetAvailableEncoder");
    const std::string &opt = AVRecordergOpt::GET_ENCODER_INFO;
    MEDIA_LOGI("Js %{public}s Start", opt.c_str());
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    size_t argCount = 1;
    napi_value args[1] = { nullptr };

    auto asyncCtx = std::make_unique<AVRecorderAsyncContext>(env);
    CHECK_AND_RETURN_RET_LOG(asyncCtx != nullptr, result, "failed to get AsyncContext");
    asyncCtx->napi = AVRecorderNapi::GetJsInstanceAndArgs(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(asyncCtx->napi != nullptr, result, "failed to GetJsInstanceAndArgs");
    CHECK_AND_RETURN_RET_LOG(asyncCtx->napi->taskQue_ != nullptr, result, "taskQue is nullptr!");

    asyncCtx->callbackRef = CommonNapi::CreateReference(env, args[0]);
    asyncCtx->deferred = CommonNapi::CreatePromise(env, asyncCtx->callbackRef, result);
    if (asyncCtx->napi->CheckStateMachine(opt) == MSERR_OK) {
        asyncCtx->task_ = AVRecorderNapi::GetEncoderInfoTask(asyncCtx);
        (void)asyncCtx->napi->taskQue_->EnqueueTask(asyncCtx->task_);
        asyncCtx->opt_ = opt;
    } else {
        asyncCtx->AVRecorderSignError(MSERR_INVALID_OPERATION, opt, "");
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, opt.c_str(), NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, [](napi_env env, void* data) {
        AVRecorderAsyncContext* asyncCtx = reinterpret_cast<AVRecorderAsyncContext *>(data);
        CHECK_AND_RETURN_LOG(asyncCtx != nullptr, "asyncCtx is nullptr!");
        if (asyncCtx->task_) {
            auto result = asyncCtx->task_->GetResult();
            if (result.Value().first != MSERR_EXT_API9_OK) {
                asyncCtx->SignError(result.Value().first, result.Value().second);
            }

            if ((result.Value().first == MSERR_EXT_API9_OK) &&
                (asyncCtx->opt_ == AVRecordergOpt::GET_ENCODER_INFO)) {
                asyncCtx->JsResult = std::make_unique<MediaJsEncoderInfo>(asyncCtx->encoderInfo_);
            }
        }
        MEDIA_LOGI("The js thread of prepare finishes execution and returns");
    }, MediaAsyncContext::CompleteCallback, static_cast<void *>(asyncCtx.get()), &asyncCtx->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCtx->work, napi_qos_user_initiated));
    asyncCtx.release();

    MEDIA_LOGI("Js %{public}s End", opt.c_str());
    return result;
}

napi_value AVRecorderNapi::JsSetEventCallback(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVRecorder::JsSetEventCallback");
    MEDIA_LOGI("JsSetEventCallback Start");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    
    size_t argCount = 2;
    constexpr size_t requireArgc = 1;
    napi_value args[2] = { nullptr, nullptr };
    AVRecorderNapi *recorderNapi = AVRecorderNapi::GetJsInstanceAndArgs(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(recorderNapi != nullptr, result, "Failed to retrieve instance");

    napi_valuetype valueType0 = napi_undefined;
    napi_valuetype valueType1 = napi_undefined;

    if (argCount < requireArgc) {
        recorderNapi->ErrorCallback(MSERR_MANDATORY_PARAMETER_UNSPECIFIED, "SetEventCallback",
            "Mandatory parameters are left unspecified.");
        return result;
    }

    if (napi_typeof(env, args[0], &valueType0) != napi_ok || valueType0 != napi_string) {
        recorderNapi->ErrorCallback(MSERR_INCORRECT_PARAMETER_TYPE, "SetEventCallback",
            "type should be string");
        return result;
    }

    if (napi_typeof(env, args[1], &valueType1) != napi_ok || valueType1 != napi_function) {
        recorderNapi->ErrorCallback(MSERR_INCORRECT_PARAMETER_TYPE, "SetEventCallback",
            "callback type should be Callback or function.");
        return result;
    }

    std::string callbackName = CommonNapi::GetStringArgument(env, args[0]);
    if (callbackName != AVRecorderEvent::EVENT_ERROR && callbackName != AVRecorderEvent::EVENT_STATE_CHANGE
        && callbackName != AVRecorderEvent::EVENT_AUDIO_CAPTURE_CHANGE
        && callbackName != AVRecorderEvent::EVENT_PHOTO_ASSET_AVAILABLE) {
        recorderNapi->ErrorCallback(MSERR_PARAMETER_VERIFICATION_FAILED, "SetEventCallback",
            "type must be error, stateChange or audioCapturerChange or photoAssetAvailable.");
        return result;
    }

    napi_ref ref = nullptr;
    napi_status status = napi_create_reference(env, args[1], 1, &ref);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && ref != nullptr, result, "failed to create reference!");

    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, ref);
    recorderNapi->SetCallbackReference(callbackName, autoRef);

    MEDIA_LOGI("JsSetEventCallback End");
    return result;
}

napi_value AVRecorderNapi::JsCancelEventCallback(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVRecorder::JsCancelEventCallback");
    MEDIA_LOGI("JsCancelEventCallback Start");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    constexpr size_t requireArgc = 1;
    size_t argCount = 1;

    napi_value args[1] = { nullptr };
    AVRecorderNapi *recorderNapi = AVRecorderNapi::GetJsInstanceAndArgs(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(recorderNapi != nullptr, result, "Failed to retrieve instance");

    napi_valuetype valueType0 = napi_undefined;

    if (argCount < requireArgc) {
        recorderNapi->ErrorCallback(MSERR_MANDATORY_PARAMETER_UNSPECIFIED, "CancelEventCallback",
            "Mandatory parameters are left unspecified.");
        return result;
    }

    if (napi_typeof(env, args[0], &valueType0) != napi_ok || valueType0 != napi_string) {
        recorderNapi->ErrorCallback(MSERR_INCORRECT_PARAMETER_TYPE, "CancelEventCallback",
            "type should be string.");
        return result;
    }

    std::string callbackName = CommonNapi::GetStringArgument(env, args[0]);
    if (callbackName != AVRecorderEvent::EVENT_ERROR && callbackName != AVRecorderEvent::EVENT_STATE_CHANGE
        && callbackName != AVRecorderEvent::EVENT_AUDIO_CAPTURE_CHANGE) {
        recorderNapi->ErrorCallback(MSERR_PARAMETER_VERIFICATION_FAILED, "CancelEventCallback",
            "type must be error, stateChange or audioCapturerChange.");
        return result;
    }

    recorderNapi->CancelCallbackReference(callbackName);

    MEDIA_LOGI("JsCancelEventCallback End");
    return result;
}

napi_value AVRecorderNapi::JsGetState(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVRecorder::JsGetState");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    size_t argCount = 0;
    AVRecorderNapi *recorderNapi = AVRecorderNapi::GetJsInstanceAndArgs(env, info, argCount, nullptr);
    CHECK_AND_RETURN_RET_LOG(recorderNapi != nullptr, result, "failed to GetJsInstance");

    auto napiCb = std::static_pointer_cast<AVRecorderCallback>(recorderNapi->recorderCb_);
    CHECK_AND_RETURN_RET_LOG(napiCb != nullptr, result, "napiCb is nullptr!");
    std::string curState = napiCb->GetState();
    MEDIA_LOGD("GetState success, State: %{public}s", curState.c_str());

    napi_value jsResult = nullptr;
    napi_status status = napi_create_string_utf8(env, curState.c_str(), NAPI_AUTO_LENGTH, &jsResult);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, result, "napi_create_string_utf8 error");
    return jsResult;
}

napi_value AVRecorderNapi::JsIsWatermarkSupported(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVRecorderNapi::JsIsWatermarkSupported");
    const std::string &opt = AVRecordergOpt::IS_WATERMARK_SUPPORTED;
    MEDIA_LOGI("Js %{public}s Start", opt.c_str());
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    size_t argCount = 1;
    napi_value args[1] = { nullptr };

    auto asyncCtx = std::make_unique<AVRecorderAsyncContext>(env);
    CHECK_AND_RETURN_RET_LOG(asyncCtx != nullptr, result, "failed to get AsyncContext");
    asyncCtx->napi = AVRecorderNapi::GetJsInstanceAndArgs(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(asyncCtx->napi != nullptr, result, "failed to GetJsInstanceAndArgs");
    CHECK_AND_RETURN_RET_LOG(asyncCtx->napi->taskQue_ != nullptr, result, "taskQue is nullptr!");

    asyncCtx->deferred = CommonNapi::CreatePromise(env, nullptr, result);

    if (asyncCtx->napi->CheckStateMachine(opt) == MSERR_OK) {
        asyncCtx->task_ = AVRecorderNapi::IsWatermarkSupportedTask(asyncCtx);
        (void)asyncCtx->napi->taskQue_->EnqueueTask(asyncCtx->task_);
        asyncCtx->opt_ = opt;
    } else {
        asyncCtx->AVRecorderSignError(MSERR_INVALID_OPERATION, opt, "");
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, opt.c_str(), NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, [](napi_env env, void* data) {
        AVRecorderAsyncContext* asyncCtx = reinterpret_cast<AVRecorderAsyncContext *>(data);
        CHECK_AND_RETURN_LOG(asyncCtx != nullptr, "asyncCtx is nullptr!");
        if (asyncCtx->task_) {
            auto result = asyncCtx->task_->GetResult();
            if (result.Value().first != MSERR_EXT_API9_OK) {
                asyncCtx->SignError(result.Value().first, result.Value().second);
            }

            if ((result.Value().first == MSERR_EXT_API9_OK) &&
                (asyncCtx->opt_ == AVRecordergOpt::IS_WATERMARK_SUPPORTED)) {
                asyncCtx->JsResult = std::make_unique<MediaJsResultBoolean>(asyncCtx->isWatermarkSupported_);
            }
        }
        MEDIA_LOGI("The js thread of prepare finishes execution and returns");
    }, MediaAsyncContext::CompleteCallback, static_cast<void *>(asyncCtx.get()), &asyncCtx->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCtx->work, napi_qos_user_initiated));
    asyncCtx.release();

    MEDIA_LOGI("Js %{public}s End", opt.c_str());
    return result;
}

napi_value AVRecorderNapi::JsSetWillMuteWhenInterrupted(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVRecorder::JsSetWillMuteWhenInterrupted");
    const std::string &opt = AVRecordergOpt::SET_WILL_MUTE_WHEN_INTERRUPTED;
    MEDIA_LOGI("Js %{public}s Start", opt.c_str());

    const int32_t maxParam = 1;
    size_t argCount = maxParam;
    napi_value args[maxParam] = { nullptr };

    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    auto asyncCtx = std::make_unique<AVRecorderAsyncContext>(env);
    CHECK_AND_RETURN_RET_LOG(asyncCtx != nullptr, result, "failed to get AsyncContext");
    asyncCtx->napi = AVRecorderNapi::GetJsInstanceAndArgs(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(asyncCtx->napi != nullptr, result, "failed to GetJsInstanceAndArgs");
    CHECK_AND_RETURN_RET_LOG(asyncCtx->napi->taskQue_ != nullptr, result, "taskQue is nullptr!");
    asyncCtx->deferred = CommonNapi::CreatePromise(env, nullptr, result);

    bool enabled = false;
    napi_status status = napi_get_value_bool(env, args[0], &enabled);
    if (status != napi_ok) {
        asyncCtx->SignError(MSERR_EXT_API9_INVALID_PARAMETER,
            "invalid parameters, please check the input");
    } else {
        asyncCtx->task_ = AVRecorderNapi::SetWillMuteWhenInterruptedTask(asyncCtx, enabled);
        (void)asyncCtx->napi->taskQue_->EnqueueTask(asyncCtx->task_);
        asyncCtx->opt_ = opt;
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, opt.c_str(), NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, [](napi_env env, void* data) {
        AVRecorderAsyncContext* asyncCtx = reinterpret_cast<AVRecorderAsyncContext *>(data);
        CHECK_AND_RETURN_LOG(asyncCtx != nullptr, "asyncCtx is nullptr!");

        if (asyncCtx->task_) {
            auto result = asyncCtx->task_->GetResult();
            if (result.Value().first != MSERR_EXT_API9_OK) {
                asyncCtx->SignError(result.Value().first, result.Value().second);
            }
        }
        MEDIA_LOGI("The js thread of setWillMuteWhenInterrupted finishes execution and returns");
    }, MediaAsyncContext::CompleteCallback, static_cast<void *>(asyncCtx.get()), &asyncCtx->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCtx->work, napi_qos_user_initiated));
    asyncCtx.release();

    MEDIA_LOGI("Js %{public}s End", opt.c_str());
    return result;
}

AVRecorderNapi *AVRecorderNapi::GetJsInstanceAndArgs(
    napi_env env, napi_callback_info info, size_t &argCount, napi_value *args)
{
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argCount, args, &jsThis, nullptr);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && jsThis != nullptr, nullptr, "failed to napi_get_cb_info");
    MEDIA_LOGD("argCount:%{public}zu", argCount);

    AVRecorderNapi *recorderNapi = nullptr;
    status = napi_unwrap(env, jsThis, reinterpret_cast<void **>(&recorderNapi));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && recorderNapi != nullptr, nullptr, "failed to retrieve instance");

    return recorderNapi;
}

std::shared_ptr<TaskHandler<RetInfo>> AVRecorderNapi::GetPromiseTask(AVRecorderNapi *avnapi, const std::string &opt)
{
    return std::make_shared<TaskHandler<RetInfo>>([napi = avnapi, option = opt]() {
        MEDIA_LOGI("%{public}s Start", option.c_str());
        CHECK_AND_RETURN_RET(napi != nullptr && napi->recorder_ != nullptr,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));

        CHECK_AND_RETURN_RET(napi->CheckStateMachine(option) == MSERR_OK,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));
        
        CHECK_AND_RETURN_RET(napi->CheckRepeatOperation(option) == MSERR_OK,
            RetInfo(MSERR_EXT_API9_OK, ""));

        RetInfo ret(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "");
        auto itFunc = taskQFuncs_.find(option);
        CHECK_AND_RETURN_RET_LOG(itFunc != taskQFuncs_.end(), ret, "%{public}s not found in map!", option.c_str());
        auto memberFunc = itFunc->second;
        CHECK_AND_RETURN_RET_LOG(memberFunc != nullptr, ret, "memberFunc is nullptr!");
        ret = (napi->*memberFunc)();
        
        MEDIA_LOGI("%{public}s End", option.c_str());
        return ret;
    });
}

napi_value AVRecorderNapi::ExecuteByPromise(napi_env env, napi_callback_info info, const std::string &opt)
{
    MEDIA_LOGI("Js %{public}s Start", opt.c_str());
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    size_t argCount = 1; // Only callbackRef parameter
    napi_value args[1] = { nullptr }; // Only callbackRef parameter

    auto asyncCtx = std::make_unique<AVRecorderAsyncContext>(env);
    CHECK_AND_RETURN_RET_LOG(asyncCtx != nullptr, result, "failed to get AsyncContext");
    asyncCtx->napi = AVRecorderNapi::GetJsInstanceAndArgs(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(asyncCtx->napi != nullptr, result, "failed to GetJsInstanceAndArgs");
    CHECK_AND_RETURN_RET_LOG(asyncCtx->napi->taskQue_ != nullptr, result, "taskQue is nullptr!");

    asyncCtx->callbackRef = CommonNapi::CreateReference(env, args[0]);
    asyncCtx->deferred = CommonNapi::CreatePromise(env, asyncCtx->callbackRef, result);

    if (asyncCtx->napi->CheckStateMachine(opt) == MSERR_OK) {
        asyncCtx->task_ = AVRecorderNapi::GetPromiseTask(asyncCtx->napi, opt);
        (void)asyncCtx->napi->taskQue_->EnqueueTask(asyncCtx->task_);
        asyncCtx->opt_ = opt;
    } else {
        asyncCtx->AVRecorderSignError(MSERR_INVALID_OPERATION, opt, "");
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, opt.c_str(), NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, [](napi_env env, void* data) {
        AVRecorderAsyncContext* asyncCtx = reinterpret_cast<AVRecorderAsyncContext *>(data);
        CHECK_AND_RETURN_LOG(asyncCtx != nullptr, "asyncCtx is nullptr!");

        if (asyncCtx->task_) {
            auto result = asyncCtx->task_->GetResult();
            if (result.Value().first != MSERR_EXT_API9_OK) {
                asyncCtx->SignError(result.Value().first, result.Value().second);
            }

            if ((result.Value().first == MSERR_EXT_API9_OK) && (asyncCtx->opt_ == AVRecordergOpt::GETINPUTSURFACE)) {
                asyncCtx->JsResult = std::make_unique<MediaJsResultString>(result.Value().second);
            }
        }
        MEDIA_LOGI("The js thread of %{public}s finishes execution and returns", asyncCtx->opt_.c_str());
    }, MediaAsyncContext::CompleteCallback, static_cast<void *>(asyncCtx.get()), &asyncCtx->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCtx->work, napi_qos_user_initiated));
    asyncCtx.release();

    MEDIA_LOGI("Js %{public}s End", opt.c_str());
    return result;
}

std::shared_ptr<TaskHandler<RetInfo>> AVRecorderNapi::GetAVRecorderConfigTask(
    const std::unique_ptr<AVRecorderAsyncContext> &asyncCtx)
{
    return std::make_shared<TaskHandler<RetInfo>>([napi = asyncCtx->napi, &config = asyncCtx->config_]() {
        const std::string &option = AVRecordergOpt::GET_AV_RECORDER_CONFIG;
        MEDIA_LOGI("%{public}s Start", option.c_str());
        config = std::make_shared<AVRecorderConfig>();

        CHECK_AND_RETURN_RET(napi != nullptr && config != nullptr,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));

        CHECK_AND_RETURN_RET(napi->CheckStateMachine(option) == MSERR_OK,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));
        
        CHECK_AND_RETURN_RET(napi->CheckRepeatOperation(option) == MSERR_OK,
            RetInfo(MSERR_EXT_API9_OK, ""));

        int32_t ret = napi->GetAVRecorderConfig(config);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, GetRetInfo(MSERR_INVALID_VAL, "GetAVRecorderConfigTask", ""),
            "get AVRecorderConfigTask failed");

        MEDIA_LOGI("%{public}s End", option.c_str());
        return RetInfo(MSERR_EXT_API9_OK, "");
    });
}

std::shared_ptr<TaskHandler<RetInfo>> AVRecorderNapi::GetCurrentCapturerChangeInfoTask(
    const std::unique_ptr<AVRecorderAsyncContext> &asyncCtx)
{
    return std::make_shared<TaskHandler<RetInfo>>([napi = asyncCtx->napi, &changeInfo = asyncCtx->changeInfo_]() {
        const std::string &option = AVRecordergOpt::GET_CURRENT_AUDIO_CAPTURER_INFO;
        MEDIA_LOGI("%{public}s Start", option.c_str());

        CHECK_AND_RETURN_RET(napi != nullptr,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));

        CHECK_AND_RETURN_RET(napi->CheckStateMachine(option) == MSERR_OK,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));
        
        CHECK_AND_RETURN_RET(napi->CheckRepeatOperation(option) == MSERR_OK,
            RetInfo(MSERR_EXT_API9_OK, ""));

        int32_t ret = napi->GetCurrentCapturerChangeInfo(changeInfo);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, GetRetInfo(MSERR_INVALID_VAL, "GetCurrentCapturerChangeInfoTask", ""),
            "get GetCurrentCapturerChangeInfoTask failed");

        MEDIA_LOGI("%{public}s End", option.c_str());
        return RetInfo(MSERR_EXT_API9_OK, "");
    });
}

std::shared_ptr<TaskHandler<RetInfo>> AVRecorderNapi::GetMaxAmplitudeTask(
    const std::unique_ptr<AVRecorderAsyncContext> &asyncCtx)
{
    return std::make_shared<TaskHandler<RetInfo>>([napi = asyncCtx->napi, &maxAmplitude = asyncCtx->maxAmplitude_]() {
        const std::string &option = AVRecordergOpt::GET_MAX_AMPLITUDE;
        MEDIA_LOGD("%{public}s Start", option.c_str());

        CHECK_AND_RETURN_RET(napi != nullptr,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));

        CHECK_AND_RETURN_RET(napi->CheckStateMachine(option) == MSERR_OK,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));
        
        CHECK_AND_RETURN_RET(napi->CheckRepeatOperation(option) == MSERR_OK,
            RetInfo(MSERR_EXT_API9_OK, ""));

        int32_t ret = napi->GetMaxAmplitude(maxAmplitude);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, GetRetInfo(MSERR_INVALID_VAL, "GetMaxAmplitudeTask", ""),
            "get GetMaxAmplitudeTask failed");

        MEDIA_LOGD("%{public}s End", option.c_str());
        return RetInfo(MSERR_EXT_API9_OK, "");
    });
}

std::shared_ptr<TaskHandler<RetInfo>> AVRecorderNapi::GetEncoderInfoTask(
    const std::unique_ptr<AVRecorderAsyncContext> &asyncCtx)
{
    return std::make_shared<TaskHandler<RetInfo>>([napi = asyncCtx->napi, &encoderInfo = asyncCtx->encoderInfo_]() {
        const std::string &option = AVRecordergOpt::GET_ENCODER_INFO;
        MEDIA_LOGI("%{public}s Start", option.c_str());

        CHECK_AND_RETURN_RET(napi != nullptr,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));

        CHECK_AND_RETURN_RET(napi->CheckStateMachine(option) == MSERR_OK,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));
        
        CHECK_AND_RETURN_RET(napi->CheckRepeatOperation(option) == MSERR_OK,
            RetInfo(MSERR_EXT_API9_OK, ""));

        int32_t ret = napi->GetEncoderInfo(encoderInfo);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, GetRetInfo(MSERR_INVALID_VAL, "GetEncoderInfoTask", ""),
            "get GetEncoderInfoTask failed");

        MEDIA_LOGI("%{public}s End", option.c_str());
        return RetInfo(MSERR_EXT_API9_OK, "");
    });
}

std::shared_ptr<TaskHandler<RetInfo>> AVRecorderNapi::IsWatermarkSupportedTask(
    const std::unique_ptr<AVRecorderAsyncContext> &asyncCtx)
{
    return std::make_shared<TaskHandler<RetInfo>>([napi = asyncCtx->napi,
        &isWatermarkSupported = asyncCtx->isWatermarkSupported_]() {
        const std::string &option = AVRecordergOpt::IS_WATERMARK_SUPPORTED;
        MEDIA_LOGI("%{public}s Start", option.c_str());

        CHECK_AND_RETURN_RET(napi != nullptr,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));

        CHECK_AND_RETURN_RET(napi->CheckStateMachine(option) == MSERR_OK,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));
        
        CHECK_AND_RETURN_RET(napi->CheckRepeatOperation(option) == MSERR_OK,
            RetInfo(MSERR_EXT_API9_OK, ""));

        int32_t ret = napi->IsWatermarkSupported(isWatermarkSupported);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, GetRetInfo(MSERR_INVALID_VAL, "IsWatermarkSupportedTask", ""),
            "IsWatermarkSupportedTask failed");

        MEDIA_LOGI("%{public}s End", option.c_str());
        return RetInfo(MSERR_EXT_API9_OK, "");
    });
}

std::shared_ptr<TaskHandler<RetInfo>> AVRecorderNapi::SetWillMuteWhenInterruptedTask(
    const std::unique_ptr<AVRecorderAsyncContext> &asyncCtx, bool enable)
{
    return std::make_shared<TaskHandler<RetInfo>>([napi = asyncCtx->napi, enable]() {
        const std::string &option = AVRecordergOpt::SET_WILL_MUTE_WHEN_INTERRUPTED;
        MEDIA_LOGI("%{public}s Start", option.c_str());

        CHECK_AND_RETURN_RET(napi != nullptr,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));

        CHECK_AND_RETURN_RET(napi->CheckStateMachine(option) == MSERR_OK,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));

        CHECK_AND_RETURN_RET(napi->CheckRepeatOperation(option) == MSERR_OK,
            RetInfo(MSERR_EXT_API9_OK, ""));
        int32_t ret = napi->SetWillMuteWhenInterrupted(enable);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, GetRetInfo(MSERR_UNKNOWN, "SetWillMuteWhenInterruptedTask", ""),
            "SetWillMuteWhenInterruptedTask fail");
        MEDIA_LOGI("%{public}s End", option.c_str());
        return RetInfo(MSERR_EXT_API9_OK, "");
    });
}

std::shared_ptr<TaskHandler<RetInfo>> AVRecorderNapi::SetWatermarkTask(
    const std::unique_ptr<AVRecorderAsyncContext> &asyncCtx)
{
    return std::make_shared<TaskHandler<RetInfo>>([napi = asyncCtx->napi, &pixelMap = asyncCtx->pixelMap_,
        &watermarkConfig = asyncCtx->watermarkConfig_]() {
        const std::string &option = AVRecordergOpt::SET_WATERMARK;
        MEDIA_LOGI("%{public}s Start", option.c_str());

        CHECK_AND_RETURN_RET(napi != nullptr,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));

        CHECK_AND_RETURN_RET(napi->CheckStateMachine(option) == MSERR_OK,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));

        CHECK_AND_RETURN_RET(napi->CheckRepeatOperation(option) == MSERR_OK,
            RetInfo(MSERR_EXT_API9_OK, ""));
        bool isWatermarkSupported = false;
        int32_t ret = napi->IsWatermarkSupported(isWatermarkSupported);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, GetRetInfo(MSERR_UNKNOWN, "SetWatermarkTask", ""),
            "IsWatermarkSupported fail");
        CHECK_AND_RETURN_RET_LOG(isWatermarkSupported, GetRetInfo(MSERR_UNSUPPORT_WATER_MARK, "SetWatermarkTask", ""),
            "capability not supported");

        ret = napi->SetWatermark(pixelMap, watermarkConfig);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, GetRetInfo(ret, "SetWatermarkTask", ""),
            "SetWatermarkTask failed");

        MEDIA_LOGI("%{public}s End", option.c_str());
        return RetInfo(MSERR_EXT_API9_OK, "");
    });
}

RetInfo AVRecorderNapi::GetInputSurface()
{
    CHECK_AND_RETURN_RET_LOG(withVideo_, GetRetInfo(MSERR_INVALID_OPERATION, "GetInputSurface", "",
        "The VideoSourceType is not configured. Please do not call getInputSurface"), "No video recording");

    if (surface_ == nullptr) {
        surface_ = recorder_->GetSurface(videoSourceID_);
        CHECK_AND_RETURN_RET_LOG(surface_ != nullptr,
            GetRetInfo(MSERR_INVALID_OPERATION, "GetInputSurface", ""), "failed to GetSurface");

        SurfaceError error = SurfaceUtils::GetInstance()->Add(surface_->GetUniqueId(), surface_);
        CHECK_AND_RETURN_RET_LOG(error == SURFACE_ERROR_OK,
            GetRetInfo(MSERR_INVALID_OPERATION, "GetInputSurface", ""), "failed to AddSurface");
    }

    auto surfaceId = std::to_string(surface_->GetUniqueId());
    getVideoInputSurface_ = true;
    return RetInfo(MSERR_EXT_API9_OK, surfaceId);
}

std::shared_ptr<TaskHandler<RetInfo>> AVRecorderNapi::GetInputMetaSurface(
    const std::unique_ptr<AVRecorderAsyncContext> &asyncCtx)
{
    return std::make_shared<TaskHandler<RetInfo>>(
        [napi = asyncCtx->napi, config = asyncCtx->config_, type = asyncCtx->metaType_]() {
        const std::string &option = AVRecordergOpt::GETINPUTMETASURFACE;
        MEDIA_LOGI("%{public}s Start", option.c_str());
        CHECK_AND_RETURN_RET(napi != nullptr && napi->recorder_ != nullptr && config != nullptr,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));

        CHECK_AND_RETURN_RET(napi->CheckStateMachine(option) == MSERR_OK,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));
        CHECK_AND_RETURN_RET_LOG(napi->metaSourceIDMap_.find(type) != napi->metaSourceIDMap_.end(),
            GetRetInfo(MSERR_INVALID_OPERATION, "GetInputMetaSurface", "no meta source type"),
            "failed to find meta type");
        if (napi->metaSurface_ == nullptr) {
            MEDIA_LOGI("The meta source type is %{public}d", static_cast<int32_t>(type));
            napi->metaSurface_ = napi->recorder_->GetMetaSurface(napi->metaSourceIDMap_.at(type));
            CHECK_AND_RETURN_RET_LOG(napi->metaSurface_ != nullptr,
                GetRetInfo(MSERR_INVALID_OPERATION, "GetInputMetaSurface", ""), "failed to GetInputMetaSurface");
 
            SurfaceError error =
                SurfaceUtils::GetInstance()->Add(napi->metaSurface_->GetUniqueId(), napi->metaSurface_);
            CHECK_AND_RETURN_RET_LOG(error == SURFACE_ERROR_OK,
                GetRetInfo(MSERR_INVALID_OPERATION, "GetInputMetaSurface", "add surface failed"),
                "failed to AddSurface");
        }

        auto surfaceId = std::to_string(napi->metaSurface_->GetUniqueId());
        MEDIA_LOGI("surfaceId:%{public}s", surfaceId.c_str());
        MEDIA_LOGI("%{public}s End", option.c_str());
        return RetInfo(MSERR_EXT_API9_OK, surfaceId);
    });
}

RetInfo AVRecorderNapi::Start()
{
    if (withVideo_ && !getVideoInputSurface_) {
        return GetRetInfo(MSERR_INVALID_OPERATION, "Start", "",
            " Please get the video input surface through GetInputSurface first!");
    }

    int32_t ret = recorder_->Start();
    if (ret != MSERR_OK) {
        StateCallback(AVRecorderState::STATE_ERROR);
    }
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "Start", ""));
    StateCallback(AVRecorderState::STATE_STARTED);
    return RetInfo(MSERR_EXT_API9_OK, "");
}

RetInfo AVRecorderNapi::Pause()
{
    int32_t ret = recorder_->Pause();
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "Pause", ""));
    StateCallback(AVRecorderState::STATE_PAUSED);
    return RetInfo(MSERR_EXT_API9_OK, "");
}

RetInfo AVRecorderNapi::Resume()
{
    int32_t ret = recorder_->Resume();
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "Resume", ""));
    StateCallback(AVRecorderState::STATE_STARTED);
    return RetInfo(MSERR_EXT_API9_OK, "");
}

RetInfo AVRecorderNapi::Stop()
{
    int32_t ret = recorder_->Stop(false);
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "Stop", ""));
    StateCallback(AVRecorderState::STATE_STOPPED);
    hasConfiged_ = false;
    return RetInfo(MSERR_EXT_API9_OK, "");
}

RetInfo AVRecorderNapi::Reset()
{
    RemoveSurface();
    int32_t ret = recorder_->Reset();
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "Reset", ""));

    StateCallback(AVRecorderState::STATE_IDLE);
    hasConfiged_ = false;
    return RetInfo(MSERR_EXT_API9_OK, "");
}

RetInfo AVRecorderNapi::Release()
{
    RemoveSurface();
    int32_t ret = recorder_->Release();
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "Release", ""));

    StateCallback(AVRecorderState::STATE_RELEASED);
    CancelCallback();
    hasConfiged_ = false;
    return RetInfo(MSERR_EXT_API9_OK, "");
}

int32_t AVRecorderNapi::GetAVRecorderConfig(std::shared_ptr<AVRecorderConfig> &config)
{
    ConfigMap configMap;
    recorder_->GetAVRecorderConfig(configMap);
    Location location;
    recorder_->GetLocation(location);

    config->profile.audioBitrate = configMap["audioBitrate"];
    config->profile.audioChannels = configMap["audioChannels"];
    config->profile.audioCodecFormat = static_cast<AudioCodecFormat>(configMap["audioCodec"]);
    config->profile.audioSampleRate = configMap["audioSampleRate"];
    config->profile.fileFormat = static_cast<OutputFormatType>(configMap["fileFormat"]);
    config->profile.videoBitrate = configMap["videoBitrate"];
    config->profile.videoCodecFormat = static_cast<VideoCodecFormat>(configMap["videoCodec"]);
    config->profile.videoFrameHeight = configMap["videoFrameHeight"];
    config->profile.videoFrameWidth = configMap["videoFrameWidth"];
    config->profile.videoFrameRate = configMap["videoFrameRate"];

    config->audioSourceType = static_cast<AudioSourceType>(configMap["audioSourceType"]);
    config->videoSourceType = static_cast<VideoSourceType>(configMap["videoSourceType"]);
    const std::string fdHead = "fd://";
    config->url = fdHead + std::to_string(configMap["url"]);
    config->rotation = configMap["rotation"];
    config->maxDuration = configMap["maxDuration"];
    config->withVideo = configMap["withVideo"];
    config->withAudio = configMap["withAudio"];
    config->withLocation = configMap["withLocation"];
    config->location.latitude = location.latitude;
    config->location.longitude = location.longitude;
    return MSERR_OK;
}

int32_t AVRecorderNapi::GetCurrentCapturerChangeInfo(AudioRecorderChangeInfo &changeInfo)
{
    int32_t ret = recorder_->GetCurrentCapturerChangeInfo(changeInfo);
    return ret;
}

int32_t AVRecorderNapi::GetMaxAmplitude(int32_t &maxAmplitude)
{
    maxAmplitude = recorder_->GetMaxAmplitude();
    return MSERR_OK;
}

int32_t AVRecorderNapi::GetEncoderInfo(std::vector<EncoderCapabilityData> &encoderInfo)
{
    int32_t ret = recorder_->GetAvailableEncoder(encoderInfo);
    return ret;
}

int32_t AVRecorderNapi::IsWatermarkSupported(bool &isWatermarkSupported)
{
    return recorder_->IsWatermarkSupported(isWatermarkSupported);
}

int32_t AVRecorderNapi::SetWillMuteWhenInterrupted(bool muteWhenInterrupted)
{
    CHECK_AND_RETURN_RET_LOG(recorder_ != nullptr, MSERR_INVALID_OPERATION, "recorder_ is nullptr!");
    return recorder_->SetWillMuteWhenInterrupted(muteWhenInterrupted);
}

int32_t AVRecorderNapi::SetWatermark(std::shared_ptr<PixelMap> &pixelMap,
    std::shared_ptr<WatermarkConfig> &watermarkConfig)
{
#ifndef CROSS_PLATFORM
    MEDIA_LOGD("pixelMap Width %{public}d, height %{public}d, pixelformat %{public}d, RowStride %{public}d",
        pixelMap->GetWidth(), pixelMap->GetHeight(), pixelMap->GetPixelFormat(), pixelMap->GetRowStride());
    CHECK_AND_RETURN_RET_LOG(pixelMap->GetPixelFormat() == PixelFormat::RGBA_8888, MSERR_INVALID_VAL,
        "Invalid pixel format");
    std::shared_ptr<Meta> avBufferConfig = std::make_shared<Meta>();
    int32_t ret = ConfigAVBufferMeta(pixelMap, watermarkConfig, avBufferConfig);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_INVALID_VAL, "ConfigAVBufferMeta is failed");
    sptr<SurfaceBuffer> surfaceBuffer = SurfaceBuffer::Create();
    BufferRequestConfig bufferConfig = {
        .width = pixelMap->GetWidth(),
        .height = pixelMap->GetHeight(),
        .strideAlignment = 0x8,
        .format = GraphicPixelFormat::GRAPHIC_PIXEL_FMT_RGBA_8888,
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA,
        .timeout = 0,
    };
    surfaceBuffer->Alloc(bufferConfig);

    MEDIA_LOGD("surface size %{public}d, surface stride %{public}d",
        surfaceBuffer->GetSize(), surfaceBuffer->GetStride());

    for (int i = 0; i < pixelMap->GetHeight(); i++) {
        ret = memcpy_s(static_cast<uint8_t *>(surfaceBuffer->GetVirAddr()) + i * surfaceBuffer->GetStride(),
            pixelMap->GetRowStride(), pixelMap->GetPixels() + i * pixelMap->GetRowStride(), pixelMap->GetRowStride());
        CHECK_AND_RETURN_RET_LOG(ret == 0, MSERR_INVALID_VAL, "memcpy failed");
    }
    std::shared_ptr<AVBuffer> waterMarkBuffer = AVBuffer::CreateAVBuffer(surfaceBuffer);
    CHECK_AND_RETURN_RET_LOG(waterMarkBuffer != nullptr, MSERR_NO_MEMORY, "surfaceBuffer is nullptr");
    waterMarkBuffer->meta_ = avBufferConfig;
    return recorder_->SetWatermark(waterMarkBuffer);
#endif
    return MSERR_OK;
}

int32_t AVRecorderNapi::SetMetadata(const std::map<std::string, std::string> &recordMeta)
{
    std::shared_ptr<Meta> userMeta = std::make_shared<Meta>();
    for (auto &meta : recordMeta) {
        MEDIA_LOGI("recordMeta tag: %{public}s, value: %{public}s", meta.first.c_str(), meta.second.c_str());
        userMeta->SetData(meta.first, meta.second);
    }
    return recorder_->SetUserMeta(userMeta);
}

int32_t AVRecorderNapi::ConfigAVBufferMeta(std::shared_ptr<PixelMap> &pixelMap,
    std::shared_ptr<WatermarkConfig> &watermarkConfig, std::shared_ptr<Meta> &meta)
{
    int32_t top = watermarkConfig->top;
    int32_t left = watermarkConfig->left;
    int32_t watermarkWidth = pixelMap->GetWidth();
    int32_t watermarkHeight = pixelMap->GetHeight();
    meta->Set<Tag::VIDEO_ENCODER_ENABLE_WATERMARK>(true);
    switch (rotation_) {
        case VIDEO_ROTATION_0:
            meta->Set<Tag::VIDEO_COORDINATE_X>(left);
            meta->Set<Tag::VIDEO_COORDINATE_Y>(top);
            meta->Set<Tag::VIDEO_COORDINATE_W>(watermarkWidth);
            meta->Set<Tag::VIDEO_COORDINATE_H>(watermarkHeight);
            break;
        case VIDEO_ROTATION_90:
            MEDIA_LOGI("rotation %{public}d", VIDEO_ROTATION_90);
            CHECK_AND_RETURN_RET_LOG(videoFrameHeight_ - left - watermarkWidth >= 0,
                MSERR_INVALID_VAL, "invalid watermark");
            pixelMap->rotate(VIDEO_ROTATION_270);
            meta->Set<Tag::VIDEO_COORDINATE_X>(top);
            meta->Set<Tag::VIDEO_COORDINATE_Y>(videoFrameHeight_ - left - watermarkWidth);
            meta->Set<Tag::VIDEO_COORDINATE_W>(watermarkHeight);
            meta->Set<Tag::VIDEO_COORDINATE_H>(watermarkWidth);
            break;
        case VIDEO_ROTATION_180:
            MEDIA_LOGI("rotation %{public}d", VIDEO_ROTATION_180);
            CHECK_AND_RETURN_RET_LOG(videoFrameWidth_-left-watermarkWidth >= 0,
                MSERR_INVALID_VAL, "invalid watermark");
            CHECK_AND_RETURN_RET_LOG(videoFrameHeight_-top-watermarkHeight >= 0,
                MSERR_INVALID_VAL, "invalid watermark");
            pixelMap->rotate(VIDEO_ROTATION_180);
            meta->Set<Tag::VIDEO_COORDINATE_X>(videoFrameWidth_-left-watermarkWidth);
            meta->Set<Tag::VIDEO_COORDINATE_Y>(videoFrameHeight_-top-watermarkHeight);
            meta->Set<Tag::VIDEO_COORDINATE_W>(watermarkWidth);
            meta->Set<Tag::VIDEO_COORDINATE_H>(watermarkHeight);
            break;
        case VIDEO_ROTATION_270:
            MEDIA_LOGI("rotation %{public}d", VIDEO_ROTATION_270);
            CHECK_AND_RETURN_RET_LOG(videoFrameHeight_ - left - watermarkWidth >= 0,
                MSERR_INVALID_VAL, "invalid watermark");
            pixelMap->rotate(VIDEO_ROTATION_90);
            meta->Set<Tag::VIDEO_COORDINATE_X>(videoFrameWidth_ - top - watermarkHeight);
            meta->Set<Tag::VIDEO_COORDINATE_Y>(left);
            meta->Set<Tag::VIDEO_COORDINATE_W>(watermarkHeight);
            meta->Set<Tag::VIDEO_COORDINATE_H>(watermarkWidth);
            break;
        default:
            break;
    }
    return MSERR_OK;
}

int32_t AVRecorderNapi::CheckStateMachine(const std::string &opt)
{
    auto napiCb = std::static_pointer_cast<AVRecorderCallback>(recorderCb_);
    CHECK_AND_RETURN_RET_LOG(napiCb != nullptr, MSERR_INVALID_OPERATION, "napiCb is nullptr!");

    std::string curState = napiCb->GetState();
    std::vector<std::string> allowedOpt = stateCtrlList.at(curState);
    if (find(allowedOpt.begin(), allowedOpt.end(), opt) == allowedOpt.end()) {
        MEDIA_LOGE("The %{public}s operation is not allowed in the %{public}s state!", opt.c_str(), curState.c_str());
        return MSERR_INVALID_OPERATION;
    }

    return MSERR_OK;
}

int32_t AVRecorderNapi::CheckRepeatOperation(const std::string &opt)
{
    const std::map<std::string, std::vector<std::string>> stateCtrl = {
        {AVRecorderState::STATE_IDLE, {
            AVRecordergOpt::RESET,
            AVRecordergOpt::GET_AV_RECORDER_PROFILE,
            AVRecordergOpt::SET_AV_RECORDER_CONFIG,
            AVRecordergOpt::GET_AV_RECORDER_CONFIG,
        }},
        {AVRecorderState::STATE_PREPARED, {}},
        {AVRecorderState::STATE_STARTED, {
            AVRecordergOpt::START,
            AVRecordergOpt::RESUME
        }},
        {AVRecorderState::STATE_PAUSED, {
            AVRecordergOpt::PAUSE
        }},
        {AVRecorderState::STATE_STOPPED, {
            AVRecordergOpt::STOP
        }},
        {AVRecorderState::STATE_RELEASED, {
            AVRecordergOpt::RELEASE
        }},
        {AVRecorderState::STATE_ERROR, {}},
    };

    auto napiCb = std::static_pointer_cast<AVRecorderCallback>(recorderCb_);
    CHECK_AND_RETURN_RET_LOG(napiCb != nullptr, MSERR_INVALID_OPERATION, "napiCb is nullptr!");

    std::string curState = napiCb->GetState();
    std::vector<std::string> repeatOpt = stateCtrl.at(curState);
    if (find(repeatOpt.begin(), repeatOpt.end(), opt) != repeatOpt.end()) {
        MEDIA_LOGI("Current state is %{public}s. Please do not call %{public}s again!", curState.c_str(), opt.c_str());
        return MSERR_INVALID_OPERATION;
    }

    return MSERR_OK;
}

int32_t AVRecorderNapi::GetAudioAacProfile(const int32_t &mime, AacProfile &aacProfile)
{
    if (mime >= static_cast<int32_t>(AacProfile::AAC_LC) &&
        mime <= static_cast<int32_t>(AacProfile::AAC_H2_V2)) {
        aacProfile = static_cast<AacProfile>(mime);
    } else {
        aacProfile = AacProfile::AAC_LC;
    }

    return MSERR_OK;
}

int32_t AVRecorderNapi::GetAudioCodecFormat(const std::string &mime, AudioCodecFormat &codecFormat)
{
    MEDIA_LOGI("mime %{public}s", mime.c_str());
    const std::map<std::string_view, AudioCodecFormat> mimeStrToCodecFormat = {
        { CodecMimeType::AUDIO_AAC, AudioCodecFormat::AAC_LC },
        { CodecMimeType::AUDIO_MPEG, AudioCodecFormat::AUDIO_MPEG },
        { CodecMimeType::AUDIO_G711MU, AudioCodecFormat::AUDIO_G711MU },
        { CodecMimeType::AUDIO_AMR_NB, AudioCodecFormat::AUDIO_AMR_NB },
        { CodecMimeType::AUDIO_AMR_WB, AudioCodecFormat::AUDIO_AMR_WB },
        { "", AudioCodecFormat::AUDIO_DEFAULT },
    };

    auto iter = mimeStrToCodecFormat.find(mime);
    if (iter != mimeStrToCodecFormat.end()) {
        codecFormat = iter->second;
        return MSERR_OK;
    }
    return MSERR_INVALID_VAL;
}

int32_t AVRecorderNapi::GetVideoCodecFormat(const std::string &mime, VideoCodecFormat &codecFormat)
{
    MEDIA_LOGI("mime %{public}s", mime.c_str());
    const std::map<std::string_view, VideoCodecFormat> mimeStrToCodecFormat = {
        { CodecMimeType::VIDEO_AVC, VideoCodecFormat::H264 },
        { CodecMimeType::VIDEO_MPEG4, VideoCodecFormat::MPEG4 },
        { CodecMimeType::VIDEO_HEVC, VideoCodecFormat::H265 },
        { "", VideoCodecFormat::VIDEO_DEFAULT },
    };

    auto iter = mimeStrToCodecFormat.find(mime);
    if (iter != mimeStrToCodecFormat.end()) {
        codecFormat = iter->second;
        return MSERR_OK;
    }
    return MSERR_INVALID_VAL;
}

int32_t AVRecorderNapi::GetOutputFormat(const std::string &extension, OutputFormatType &type)
{
    MEDIA_LOGI("mime %{public}s", extension.c_str());
    const std::map<std::string, OutputFormatType> extensionToOutputFormat = {
        { "mp4", OutputFormatType::FORMAT_MPEG_4 },
        { "m4a", OutputFormatType::FORMAT_M4A },
        { "mp3", OutputFormatType::FORMAT_MP3 },
        { "wav", OutputFormatType::FORMAT_WAV },
        { "amr", OutputFormatType::FORMAT_AMR },
        { "aac", OutputFormatType::FORMAT_AAC },
        { "", OutputFormatType::FORMAT_DEFAULT },
    };

    auto iter = extensionToOutputFormat.find(extension);
    if (iter != extensionToOutputFormat.end()) {
        type = iter->second;
        return MSERR_OK;
    }
    return MSERR_INVALID_VAL;
}

int32_t AVRecorderNapi::GetSourceType(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx, napi_env env, napi_value args)
{
    std::shared_ptr<AVRecorderConfig> config = asyncCtx->config_;
    int32_t audioSource = AUDIO_SOURCE_INVALID;
    int32_t videoSource = VIDEO_SOURCE_BUTT;
    std::vector<int32_t> metaSource {};

    bool getValue = false;
    int32_t ret = AVRecorderNapi::GetPropertyInt32(env, args, "audioSourceType", audioSource, getValue);
    CHECK_AND_RETURN_RET(ret == MSERR_OK,
        (asyncCtx->AVRecorderSignError(ret, "getaudioSourceType", "audioSourceType"), ret));
    if (getValue) {
        config->audioSourceType = static_cast<AudioSourceType>(audioSource);
        config->withAudio = true;
        MEDIA_LOGI("audioSource Type %{public}d!", audioSource);
    }

    ret = AVRecorderNapi::GetPropertyInt32(env, args, "videoSourceType", videoSource, getValue);
    CHECK_AND_RETURN_RET(ret == MSERR_OK,
        (asyncCtx->AVRecorderSignError(ret, "getvideoSourceType", "videoSourceType"), ret));
    if (getValue) {
        config->videoSourceType = static_cast<VideoSourceType>(videoSource);
        config->withVideo = true;
        MEDIA_LOGI("videoSource Type %{public}d!", videoSource);
    }

    ret = AVRecorderNapi::GetPropertyInt32Vec(env, args, "metaSourceTypes", metaSource, getValue);
    CHECK_AND_RETURN_RET(ret == MSERR_OK,
        (asyncCtx->AVRecorderSignError(ret, "getMetaSourceTypes", "metaSourceTypes"), ret));
    if (getValue) {
        for (auto item : metaSource) {
            config->metaSourceTypeVec.push_back(static_cast<MetaSourceType>(item));
        }
    }

    CHECK_AND_RETURN_RET(config->withAudio || config->withVideo,
        (asyncCtx->AVRecorderSignError(MSERR_INVALID_VAL, "getsourcetype", "SourceType"), MSERR_INVALID_VAL));

    return MSERR_OK;
}

int32_t AVRecorderNapi::GetAudioProfile(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx, napi_env env,
    napi_value item, AVRecorderProfile &profile)
{
    int32_t ret = MSERR_OK;
    std::string audioCodec = CommonNapi::GetPropertyString(env, item, "audioCodec");
    ret = AVRecorderNapi::GetAudioCodecFormat(audioCodec, profile.audioCodecFormat);
    CHECK_AND_RETURN_RET(ret == MSERR_OK,
        (asyncCtx->AVRecorderSignError(ret, "GetAudioCodecFormat", "audioCodecFormat"), ret));
    ret = MSERR_INVALID_VAL;
    CHECK_AND_RETURN_RET(CommonNapi::GetPropertyInt32(env, item, "audioBitrate", profile.audioBitrate),
        (asyncCtx->AVRecorderSignError(ret, "GetaudioBitrate", "audioBitrate"), ret));
    CHECK_AND_RETURN_RET(CommonNapi::GetPropertyInt32(env, item, "audioChannels", profile.audioChannels),
        (asyncCtx->AVRecorderSignError(ret, "GetaudioChannels", "audioChannels"), ret));
    CHECK_AND_RETURN_RET(CommonNapi::GetPropertyInt32(env, item, "audioSampleRate", profile.audioSampleRate),
        (asyncCtx->AVRecorderSignError(ret, "GetaudioSampleRate", "audioSampleRate"), ret));
    ret = MSERR_OK;
    int aacProfile = 0;
    CommonNapi::GetPropertyInt32(env, item, "aacProfile", aacProfile);
    ret = AVRecorderNapi::GetAudioAacProfile(aacProfile, profile.aacProfile);
    CHECK_AND_RETURN_RET(ret == MSERR_OK,
        (asyncCtx->AVRecorderSignError(ret, "GetAudioCodecFormat", "aacProfile"), ret));
    MediaProfileLog(false, profile);
    return ret;
}

int32_t AVRecorderNapi::GetVideoProfile(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx, napi_env env,
    napi_value item, AVRecorderProfile &profile)
{
    int32_t ret = MSERR_OK;
    std::string videoCodec = CommonNapi::GetPropertyString(env, item, "videoCodec");
    ret = AVRecorderNapi::GetVideoCodecFormat(videoCodec, profile.videoCodecFormat);
    CHECK_AND_RETURN_RET(ret == MSERR_OK,
        (asyncCtx->AVRecorderSignError(ret, "GetVideoCodecFormat", "videoCodecFormat"), ret));
    ret = MSERR_INVALID_VAL;
    CHECK_AND_RETURN_RET(CommonNapi::GetPropertyInt32(env, item, "videoBitrate", profile.videoBitrate),
        (asyncCtx->AVRecorderSignError(ret, "GetvideoBitrate", "videoBitrate"), ret));
    CHECK_AND_RETURN_RET(CommonNapi::GetPropertyInt32(env, item, "videoFrameWidth", profile.videoFrameWidth),
        (asyncCtx->AVRecorderSignError(ret, "GetvideoFrameWidth", "videoFrameWidth"), ret));
    videoFrameWidth_ = profile.videoFrameWidth;
    CHECK_AND_RETURN_RET(CommonNapi::GetPropertyInt32(env, item, "videoFrameHeight", profile.videoFrameHeight),
        (asyncCtx->AVRecorderSignError(ret, "GetvideoFrameHeight", "videoFrameHeight"), ret));
    videoFrameHeight_ = profile.videoFrameHeight;
    CHECK_AND_RETURN_RET(CommonNapi::GetPropertyInt32(env, item, "videoFrameRate", profile.videoFrameRate),
        (asyncCtx->AVRecorderSignError(ret, "GetvideoFrameRate", "videoFrameRate"), ret));
    if (CommonNapi::GetPropertyBool(env, item, "isHdr", profile.isHdr)) {
        CHECK_AND_RETURN_RET(!(profile.isHdr && (profile.videoCodecFormat != VideoCodecFormat::H265)),
            (asyncCtx->AVRecorderSignError(MSERR_UNSUPPORT_VID_PARAMS, "isHdr needs to match video/hevc", ""),
            MSERR_UNSUPPORT_VID_PARAMS));
    } else {
        profile.isHdr = false;
    }
    if (!CommonNapi::GetPropertyBool(env, item, "enableTemporalScale", profile.enableTemporalScale)) {
        MEDIA_LOGI("avRecorderProfile enableTemporalScale is not set.");
        profile.enableTemporalScale = false;
    }
    if (!CommonNapi::GetPropertyBool(env, item, "enableStableQualityMode", profile.enableStableQualityMode)) {
        MEDIA_LOGI("avRecorderProfile enableStableQualityMode is not set.");
        profile.enableStableQualityMode = false;
    }
    if (!CommonNapi::GetPropertyBool(env, item, "enableBFrame", profile.enableBFrame)) {
        MEDIA_LOGI("avRecorderProfile enableBFrame is not set.");
        profile.enableBFrame = false;
    }
    MediaProfileLog(true, profile);
    return ret;
}

int32_t AVRecorderNapi::GetProfile(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx, napi_env env, napi_value args)
{
    napi_value item = nullptr;
    napi_get_named_property(env, args, "profile", &item);
    CHECK_AND_RETURN_RET_LOG(item != nullptr, MSERR_INVALID_VAL, "get profile error");
    AVRecorderProfile &profile = asyncCtx->config_->profile;
    int32_t ret = MSERR_OK;
    if (asyncCtx->config_->withAudio) {
        ret = GetAudioProfile(asyncCtx, env, item, profile);
    }
    if (asyncCtx->config_->withVideo) {
        ret = GetVideoProfile(asyncCtx, env, item, profile);
    }

    std::string outputFile = CommonNapi::GetPropertyString(env, item, "fileFormat");
    ret = AVRecorderNapi::GetOutputFormat(outputFile, profile.fileFormat);
    CHECK_AND_RETURN_RET(ret == MSERR_OK, (asyncCtx->AVRecorderSignError(ret, "GetOutputFormat", "fileFormat"), ret));
    MEDIA_LOGI("fileFormat %{public}d", profile.fileFormat);
    return MSERR_OK;
}

int32_t AVRecorderNapi::GetModeAndUrl(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx, napi_env env, napi_value args)
{
    if (CommonNapi::CheckhasNamedProperty(env, args, "fileGenerationMode")) {
        int32_t mode = 0;
        CHECK_AND_RETURN_RET(CommonNapi::GetPropertyInt32(env, args, "fileGenerationMode", mode),
            (asyncCtx->AVRecorderSignError(MSERR_INVALID_VAL, "GetFileGenerationMode", "fileGenerationMode",
                "failed to GetFileGenerationMode"), MSERR_INVALID_VAL));
        CHECK_AND_RETURN_RET(mode >= FileGenerationMode::APP_CREATE
            && mode <= FileGenerationMode::AUTO_CREATE_CAMERA_SCENE,
            (asyncCtx->AVRecorderSignError(MSERR_INVALID_VAL, "fileGenerationMode", "fileGenerationMode",
                "invalide fileGenerationMode"), MSERR_INVALID_VAL));
        asyncCtx->config_->fileGenerationMode = static_cast<FileGenerationMode>(mode);
        MEDIA_LOGI("FileGenerationMode %{public}d!", mode);
    }

    asyncCtx->config_->url = CommonNapi::GetPropertyString(env, args, "url");
    MEDIA_LOGI("url %{public}s!", asyncCtx->config_->url.c_str());
    if (asyncCtx->config_->fileGenerationMode == FileGenerationMode::APP_CREATE) {
        CHECK_AND_RETURN_RET(asyncCtx->config_->url != "",
            (asyncCtx->AVRecorderSignError(MSERR_PARAMETER_VERIFICATION_FAILED, "geturl", "url",
                "config->url cannot be null"), MSERR_PARAMETER_VERIFICATION_FAILED));
    }
    return MSERR_OK;
}

void AVRecorderNapi::MediaProfileLog(bool isVideo, AVRecorderProfile &profile)
{
    if (isVideo) {
        MEDIA_LOGI("videoBitrate %{public}d, videoCodecFormat %{public}d, videoFrameWidth %{public}d,"
            " videoFrameHeight %{public}d, videoFrameRate %{public}d, isHdr %{public}d, enableTemporalScale %{public}d",
            profile.videoBitrate, profile.videoCodecFormat, profile.videoFrameWidth,
            profile.videoFrameHeight, profile.videoFrameRate, profile.isHdr, profile.enableTemporalScale);
        return;
    }
    MEDIA_LOGI("audioBitrate %{public}d, audioChannels %{public}d, audioCodecFormat %{public}d,"
        " audioSampleRate %{public}d, audioaac %{public}d!", profile.audioBitrate, profile.audioChannels,
        profile.audioCodecFormat, profile.audioSampleRate, profile.aacProfile);
}

int32_t AVRecorderNapi::GetConfig(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx, napi_env env, napi_value args)
{
    CHECK_AND_RETURN_RET(CommonNapi::CheckValueType(env, args, napi_object),
        (asyncCtx->AVRecorderSignError(MSERR_INCORRECT_PARAMETER_TYPE, "GetConfig", "AVRecorderConfig",
            "config type should be AVRecorderConfig."), MSERR_INCORRECT_PARAMETER_TYPE));

    asyncCtx->config_ = std::make_shared<AVRecorderConfig>();
    CHECK_AND_RETURN_RET(asyncCtx->config_,
        (asyncCtx->AVRecorderSignError(MSERR_NO_MEMORY, "AVRecorderConfig", "AVRecorderConfig"), MSERR_NO_MEMORY));

    std::shared_ptr<AVRecorderConfig> config = asyncCtx->config_;

    int32_t ret = GetSourceType(asyncCtx, env, args);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "failed to GetSourceType");

    ret = GetProfile(asyncCtx, env, args);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "failed to GetProfile");

    ret = GetModeAndUrl(asyncCtx, env, args);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "failed to GetModeAndUrl");

    bool getValue = false;
    ret = AVRecorderNapi::GetPropertyInt32(env, args, "rotation", config->rotation, getValue);
    CHECK_AND_RETURN_RET(ret == MSERR_OK,
        (asyncCtx->AVRecorderSignError(ret, "getrotation", "rotation"), ret));
    MEDIA_LOGI("rotation %{public}d!", config->rotation);
    CHECK_AND_RETURN_RET((config->rotation == VIDEO_ROTATION_0 || config->rotation == VIDEO_ROTATION_90 ||
        config->rotation == VIDEO_ROTATION_180 || config->rotation == VIDEO_ROTATION_270),
        (asyncCtx->AVRecorderSignError(MSERR_PARAMETER_VERIFICATION_FAILED, "getrotation", "rotation",
            "rotation angle must be 0, 90, 180 or 270!"), MSERR_PARAMETER_VERIFICATION_FAILED));
    rotation_ = config->rotation;
    if (CommonNapi::CheckhasNamedProperty(env, args, "location")) {
        CHECK_AND_RETURN_RET(GetLocation(asyncCtx, env, args),
            (asyncCtx->AVRecorderSignError(MSERR_INCORRECT_PARAMETER_TYPE, "GetLocation", "Location",
                "location type should be Location."), MSERR_INCORRECT_PARAMETER_TYPE));
    }

    ret = AVRecorderNapi::GetPropertyInt32(env, args, "maxDuration", config->maxDuration, getValue);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "failed to GetMaxDuration");

    if (CommonNapi::CheckhasNamedProperty(env, args, "metadata")) {
        CHECK_AND_RETURN_RET_LOG(AVRecorderNapi::GetAVMetaData(asyncCtx, env, args) == MSERR_OK,
            MSERR_INVALID_VAL, "failed to GetAVMetaData");
    }
    return MSERR_OK;
}

int32_t AVRecorderNapi::GetRotation(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx, napi_env env, napi_value args)
{
    napi_valuetype valueType = napi_undefined;
    if (args == nullptr || napi_typeof(env, args, &valueType) != napi_ok ||
        (valueType != napi_object && valueType != napi_number)) {
        asyncCtx->AVRecorderSignError(MSERR_INCORRECT_PARAMETER_TYPE, "GetConfig", "AVRecorderConfig",
            "rotation type should be number.");
        return MSERR_INCORRECT_PARAMETER_TYPE;
    }

    asyncCtx->config_ = std::make_shared<AVRecorderConfig>();
    CHECK_AND_RETURN_RET(asyncCtx->config_,
        (asyncCtx->AVRecorderSignError(MSERR_NO_MEMORY, "AVRecorderConfig", "AVRecorderConfig"), MSERR_NO_MEMORY));

    std::shared_ptr<AVRecorderConfig> config = asyncCtx->config_;

    if (napi_get_value_int32(env, args, &(config->rotation)) == napi_ok) {
        CHECK_AND_RETURN_RET((config->rotation == VIDEO_ROTATION_0 || config->rotation == VIDEO_ROTATION_90 ||
                                 config->rotation == VIDEO_ROTATION_180 || config->rotation == VIDEO_ROTATION_270),
            (asyncCtx->AVRecorderSignError(MSERR_INVALID_VAL, "getrotation", "rotation"), MSERR_INVALID_VAL));
        MEDIA_LOGI("GetRecordRotation success %{public}d", config->rotation);
        rotation_ = config->rotation;
        return MSERR_OK;
    }

    bool getValue = false;
    int32_t ret = AVRecorderNapi::GetPropertyInt32(env, args, "rotation", config->rotation, getValue);
    CHECK_AND_RETURN_RET(ret == MSERR_OK,
        (asyncCtx->AVRecorderSignError(ret, "getrotation", "rotation"), ret));
    MEDIA_LOGI("rotation %{public}d!", config->rotation);
    CHECK_AND_RETURN_RET((config->rotation == VIDEO_ROTATION_0 || config->rotation == VIDEO_ROTATION_90 ||
        config->rotation == VIDEO_ROTATION_180 || config->rotation == VIDEO_ROTATION_270),
        (asyncCtx->AVRecorderSignError(MSERR_INVALID_VAL, "getrotation", "rotation"), MSERR_INVALID_VAL));
    rotation_ = config->rotation;
    return MSERR_OK;
}

int32_t AVRecorderNapi::GetMetaType(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx, napi_env env, napi_value args)
{
    napi_valuetype valueType = napi_undefined;
    if (args == nullptr || napi_typeof(env, args, &valueType) != napi_ok ||
        (valueType != napi_object && valueType != napi_number)) {
        asyncCtx->AVRecorderSignError(MSERR_INCORRECT_PARAMETER_TYPE, "GetConfig", "AVRecorderConfig",
            "meta type should be number.");
        return MSERR_INCORRECT_PARAMETER_TYPE;
    }

    asyncCtx->config_ = std::make_shared<AVRecorderConfig>();
    CHECK_AND_RETURN_RET(asyncCtx->config_,
        (asyncCtx->AVRecorderSignError(MSERR_NO_MEMORY, "AVRecorderConfig", "AVRecorderConfig"), MSERR_NO_MEMORY));

    int32_t metaSourceType = VIDEO_META_SOURCE_INVALID;
    if (napi_get_value_int32(env, args, &metaSourceType) != napi_ok) {
        std::string string = CommonNapi::GetStringArgument(env, args);
        CHECK_AND_RETURN_RET(string == "",
            (asyncCtx->AVRecorderSignError(MSERR_INVALID_VAL, "getMetaType", "metaSourceType"), MSERR_INVALID_VAL));
    }
    asyncCtx->metaType_ = static_cast<MetaSourceType>(metaSourceType);
    MEDIA_LOGI("metaSource Type %{public}d!", metaSourceType);
    return MSERR_OK;
}

int32_t AVRecorderNapi::GetAVMetaData(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx, napi_env env,
    napi_value args)
{
    napi_value metadata = nullptr;
    if (napi_get_named_property(env, args, "metadata", &metadata) != napi_ok) {
        return (asyncCtx->AVRecorderSignError(MSERR_INVALID_VAL, "GetAVMetaData", "metadata"), MSERR_INVALID_VAL);
    }
    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, metadata, &valueType) != napi_ok || valueType != napi_object) {
        if (valueType == napi_undefined) {
            return MSERR_OK;
        }
        return (asyncCtx->AVRecorderSignError(MSERR_INVALID_VAL, "GetAVMetaData", "metadata"), MSERR_INVALID_VAL);
    }

    AVMetadata &avMetadata = asyncCtx->config_->metadata;

    if (CommonNapi::CheckhasNamedProperty(env, metadata, "location")) {
        CHECK_AND_RETURN_RET(GetLocation(asyncCtx, env, metadata),
            (asyncCtx->AVRecorderSignError(MSERR_INVALID_VAL, "GetLocation", "Location"), MSERR_INVALID_VAL));
    }
    if (CommonNapi::CheckhasNamedProperty(env, metadata, "genre")) {
        napi_value item = nullptr;
        CHECK_AND_RETURN_RET_LOG(napi_get_named_property(env, metadata, "genre", &item) == napi_ok,
            MSERR_INVALID_VAL, "get genre property fail");
        avMetadata.genre = CommonNapi::GetStringArgument(env, item, CUSTOM_MAX_LENGTH);
        CHECK_AND_RETURN_RET(avMetadata.genre != "",
            (asyncCtx->AVRecorderSignError(MSERR_INVALID_VAL, "getgenre", "genre"), MSERR_INVALID_VAL));
    }
    std::string strRotation = CommonNapi::GetPropertyString(env, metadata, "videoOrientation");
    if (strRotation == "0" || strRotation == "90" || strRotation == "180" || strRotation == "270") {
        asyncCtx->config_->rotation = std::stoi(strRotation);
        rotation_ = asyncCtx->config_->rotation;
        MEDIA_LOGI("rotation: %{public}d", asyncCtx->config_->rotation);
    } else if (strRotation != "") {
        asyncCtx->AVRecorderSignError(MSERR_INVALID_VAL, "not support rotation", "videoOrientation");
        return MSERR_INVALID_VAL;
    }
    // get customInfo
    if (CommonNapi::CheckhasNamedProperty(env, metadata, "customInfo")) {
        CHECK_AND_RETURN_RET(
            CommonNapi::GetPropertyRecord(env, metadata, avMetadata.customInfo, "customInfo") == napi_ok,
            (asyncCtx->AVRecorderSignError(MSERR_INVALID_VAL, "GetCustomInfo", "customInfo"), MSERR_INVALID_VAL));
    }
    return MSERR_OK;
}

int32_t AVRecorderNapi::GetWatermarkParameter(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx,
    napi_env env, napi_value watermark, napi_value watermarkConfig)
{
    int32_t ret = GetWatermark(asyncCtx, env, watermark);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "failed to GetWatermark");
    ret = GetWatermarkConfig(asyncCtx, env, watermarkConfig);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "failed to GetWatermarkConfig");
    return MSERR_OK;
}

int32_t AVRecorderNapi::GetWatermark(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx,
    napi_env env, napi_value args)
{
    CHECK_AND_RETURN_RET(CommonNapi::CheckValueType(env, args, napi_object),
        (asyncCtx->AVRecorderSignError(MSERR_INVALID_VAL, "GetPixelMap", "PixelMap"), MSERR_INVALID_VAL));
    asyncCtx->pixelMap_ = Media::PixelMapNapi::GetPixelMap(env, args);
    CHECK_AND_RETURN_RET(asyncCtx->pixelMap_ != nullptr,
        (asyncCtx->AVRecorderSignError(MSERR_INVALID_VAL, "GetPixelMap", "PixelMap"), MSERR_INVALID_VAL));
    return MSERR_OK;
}

int32_t AVRecorderNapi::GetWatermarkConfig(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx,
    napi_env env, napi_value args)
{
    CHECK_AND_RETURN_RET(CommonNapi::CheckValueType(env, args, napi_object),
        (asyncCtx->AVRecorderSignError(MSERR_INVALID_VAL, "GetWatermarkConfig", "WatermarkConfig"), MSERR_INVALID_VAL));
    asyncCtx->watermarkConfig_ = std::make_shared<WatermarkConfig>();

    bool ret = CommonNapi::GetPropertyInt32(env, args, "top", asyncCtx->watermarkConfig_->top);
    CHECK_AND_RETURN_RET(ret && asyncCtx->watermarkConfig_->top >= 0,
        (asyncCtx->AVRecorderSignError(MSERR_PARAMETER_VERIFICATION_FAILED, "GetWatermarkConfig", "top",
            "config top cannot be null or less than zero"), MSERR_PARAMETER_VERIFICATION_FAILED));

    ret = CommonNapi::GetPropertyInt32(env, args, "left", asyncCtx->watermarkConfig_->left);
    CHECK_AND_RETURN_RET(ret && asyncCtx->watermarkConfig_->left >= 0,
        (asyncCtx->AVRecorderSignError(MSERR_PARAMETER_VERIFICATION_FAILED, "GetWatermarkConfig", "left",
            "config left cannot be null or less than zero"), MSERR_PARAMETER_VERIFICATION_FAILED));
    return MSERR_OK;
}

bool AVRecorderNapi::GetLocation(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx, napi_env env, napi_value args)
{
    napi_value geoLocation = nullptr;
    napi_valuetype valueType = napi_undefined;
    CHECK_AND_RETURN_RET(napi_get_named_property(env, args, "location", &geoLocation) == napi_ok, false);
    napi_status status = napi_typeof(env, geoLocation, &valueType);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "get valueType failed");
    CHECK_AND_RETURN_RET_LOG(valueType != napi_undefined, true, "location undefined");
    userLocation &location = asyncCtx->config_->metadata.location;

    double tempLatitude = 0;
    double tempLongitude = 0;
    CHECK_AND_RETURN_RET(CommonNapi::GetPropertyDouble(env, geoLocation, "latitude", tempLatitude), false);
    CHECK_AND_RETURN_RET(CommonNapi::GetPropertyDouble(env, geoLocation, "longitude", tempLongitude), false);
    location.latitude = static_cast<float>(tempLatitude);
    location.longitude = static_cast<float>(tempLongitude);
    asyncCtx->config_->withLocation = true;
    return true;
}

RetInfo AVRecorderNapi::SetProfile(std::shared_ptr<AVRecorderConfig> config)
{
    int32_t ret;
    AVRecorderProfile &profile = config->profile;

    ret = recorder_->SetOutputFormat(profile.fileFormat);
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetOutputFormat", "fileFormat"));

    if (config->withAudio) {
        ret = recorder_->SetAudioEncoder(audioSourceID_, profile.audioCodecFormat);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetAudioEncoder", "audioCodecFormat"));

        ret = recorder_->SetAudioSampleRate(audioSourceID_, profile.audioSampleRate);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetAudioSampleRate", "audioSampleRate"));

        ret = recorder_->SetAudioChannels(audioSourceID_, profile.audioChannels);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetAudioChannels", "audioChannels"));

        ret = recorder_->SetAudioEncodingBitRate(audioSourceID_, profile.audioBitrate);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetAudioEncodingBitRate", "audioBitrate"));

        if (profile.audioCodecFormat == AudioCodecFormat::AUDIO_DEFAULT ||
            profile.audioCodecFormat == AudioCodecFormat::AAC_LC) {
            ret = recorder_->SetAudioAacProfile(audioSourceID_, profile.aacProfile);
            CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetAudioAacProfile", "audioAacProfile"));
        }
    }

    if (config->withVideo) {
        ret = recorder_->SetVideoEncoder(videoSourceID_, profile.videoCodecFormat);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetVideoEncoder", "videoCodecFormat"));

        ret = recorder_->SetVideoSize(videoSourceID_, profile.videoFrameWidth, profile.videoFrameHeight);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetVideoSize", "VideoSize"));

        ret = recorder_->SetVideoFrameRate(videoSourceID_, profile.videoFrameRate);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetVideoFrameRate", "videoFrameRate"));

        ret = recorder_->SetVideoEncodingBitRate(videoSourceID_, profile.videoBitrate);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetVideoEncodingBitRate", "videoBitrate"));

        ret = recorder_->SetVideoIsHdr(videoSourceID_, profile.isHdr);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetVideoIsHdr", "isHdr"));

        ret = recorder_->SetVideoEnableTemporalScale(videoSourceID_, profile.enableTemporalScale);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetVideoEnableTemporalScale", "enableTemporalScale"));

        ret = recorder_->SetVideoEnableStableQualityMode(videoSourceID_, profile.enableStableQualityMode);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetVideoEnableStableQualityMode",
            "enableStableQualityMode"));
        
        ret = recorder_->SetVideoEnableBFrame(videoSourceID_, profile.enableBFrame);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetVideoEnableBFrame", "enableBFrame"));
    }

    if (config->metaSourceTypeVec.size() != 0 &&
        std::find(config->metaSourceTypeVec.cbegin(), config->metaSourceTypeVec.cend(),
        MetaSourceType::VIDEO_META_MAKER_INFO) != config->metaSourceTypeVec.cend()) {
        ret = recorder_->SetMetaConfigs(metaSourceID_);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetMetaConfigs", "metaSourceType"));
    }

    return RetInfo(MSERR_EXT_API9_OK, "");
}

RetInfo AVRecorderNapi::Configure(std::shared_ptr<AVRecorderConfig> config)
{
    CHECK_AND_RETURN_RET(recorder_ != nullptr, GetRetInfo(MSERR_INVALID_OPERATION, "Configure", ""));
    CHECK_AND_RETURN_RET(config != nullptr, GetRetInfo(MSERR_MANDATORY_PARAMETER_UNSPECIFIED, "Configure", "config"));

    if (hasConfiged_) {
        MEDIA_LOGE("AVRecorderConfig has been configured and will not be configured again");
        return RetInfo(MSERR_EXT_API9_OK, "");
    }

    int32_t ret;
    if (config->withAudio) {
        ret = recorder_->SetAudioSource(config->audioSourceType, audioSourceID_);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetAudioSource", "audioSourceType"));
    }

    if (config->withVideo) {
        ret = recorder_->SetVideoSource(config->videoSourceType, videoSourceID_);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetVideoSource", "videoSourceType"));
    }

    if (config->metaSourceTypeVec.size() != 0 &&
        std::find(config->metaSourceTypeVec.cbegin(), config->metaSourceTypeVec.cend(),
        MetaSourceType::VIDEO_META_MAKER_INFO) != config->metaSourceTypeVec.cend()) {
        ret = recorder_->SetMetaSource(MetaSourceType::VIDEO_META_MAKER_INFO, metaSourceID_);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetMetaSource", "metaSourceType"));
        metaSourceIDMap_.emplace(std::make_pair(MetaSourceType::VIDEO_META_MAKER_INFO, metaSourceID_));
    }

    RetInfo retInfo = SetProfile(config);
    CHECK_AND_RETURN_RET_LOG(retInfo.first == MSERR_OK, retInfo, "Fail to set videoBitrate");

    if (config->maxDuration < 1) {
        config->maxDuration = INT32_MAX;
        MEDIA_LOGI("AVRecorderNapi::Configure maxDuration = %{public}d is invalid, set to default",
            config->maxDuration);
    }
    recorder_->SetMaxDuration(config->maxDuration);
    MEDIA_LOGI("AVRecorderNapi::Configure SetMaxDuration = %{public}d", config->maxDuration);

    if (config->withLocation) {
        recorder_->SetLocation(config->metadata.location.latitude, config->metadata.location.longitude);
    }

    if (config->withVideo) {
        recorder_->SetOrientationHint(config->rotation);
    }

    if (!config->metadata.genre.empty()) {
        ret = recorder_->SetGenre(config->metadata.genre);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetGenre", "Genre"));
    }
    if (!config->metadata.customInfo.Empty()) {
        ret = recorder_->SetUserCustomInfo(config->metadata.customInfo);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetUserCustomInfo", "customInfo"));
    }
    return ConfigureUrl(config);
}

RetInfo AVRecorderNapi::ConfigureUrl(std::shared_ptr<AVRecorderConfig> config)
{
    int32_t ret;
    if (config->fileGenerationMode == FileGenerationMode::AUTO_CREATE_CAMERA_SCENE) {
        ret = recorder_->SetFileGenerationMode(config->fileGenerationMode);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetFileGenerationMode", "fileGenerationMode"));
    } else {
        ret = MSERR_PARAMETER_VERIFICATION_FAILED;
        const std::string fdHead = "fd://";
        CHECK_AND_RETURN_RET(config->url.find(fdHead) != std::string::npos, GetRetInfo(ret, "Getfd", "uri"));
        int32_t fd = -1;
        std::string inputFd = config->url.substr(fdHead.size());
        CHECK_AND_RETURN_RET(StrToInt(inputFd, fd) == true && fd >= 0, GetRetInfo(ret, "Getfd", "uri"));

        ret = recorder_->SetOutputFile(fd);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, GetRetInfo(ret, "SetOutputFile", "uri"));
    }
    hasConfiged_ = true;
    return RetInfo(MSERR_EXT_API9_OK, "");
}

int32_t AVRecorderNapi::GetSourceIdAndQuality(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx,
    napi_env env, napi_value sourceIdArgs, napi_value qualityArgs, const std::string &opt)
{
    if (asyncCtx->napi->CheckStateMachine(opt) == MSERR_OK) {
        napi_status ret = napi_get_value_int32(env, sourceIdArgs, &asyncCtx->napi->sourceId_);
        if (ret != napi_ok) {
            asyncCtx->AVRecorderSignError(MSERR_INVALID_VAL, "failed to get sourceId", "");
            return MSERR_INVALID_VAL;
        }
        ret = napi_get_value_int32(env, qualityArgs, &asyncCtx->napi->qualityLevel_);
        if (ret != napi_ok) {
            asyncCtx->AVRecorderSignError(MSERR_INVALID_VAL, "failed to get qualityLevel", "");
            return MSERR_INVALID_VAL;
        }
    } else {
        asyncCtx->AVRecorderSignError(MSERR_INVALID_OPERATION, opt, "");
        return MSERR_INVALID_OPERATION;
    }
    return MSERR_OK;
}

int32_t AVRecorderNapi::GetAVRecorderProfile(std::shared_ptr<AVRecorderProfile> &profile,
    const int32_t sourceId, const int32_t qualityLevel)
{
    MediaTrace trace("AVRecorder::GetAVRecorderProfile");
    std::shared_ptr<VideoRecorderProfile> videoRecorderProfile =
        OHOS::Media::RecorderProfilesFactory::CreateRecorderProfiles().GetVideoRecorderProfile(sourceId, qualityLevel);
    CHECK_AND_RETURN_RET_LOG(videoRecorderProfile != nullptr, MSERR_INVALID_VAL, "failed to get videoRecorderProfile");

    int32_t ret = MSERR_OK;
    ret = AVRecorderNapi::GetOutputFormat(videoRecorderProfile->containerFormatType, profile ->fileFormat);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_INVALID_VAL, "get outputFormat error");

    ret = AVRecorderNapi::GetAudioCodecFormat(videoRecorderProfile->audioCodec, profile ->audioCodecFormat);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_INVALID_VAL, "get audioCodec error");

    ret = AVRecorderNapi::GetVideoCodecFormat(videoRecorderProfile->videoCodec, profile ->videoCodecFormat);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_INVALID_VAL, "get videoCodec error");

    profile->audioBitrate = videoRecorderProfile->audioBitrate;
    profile->audioChannels = videoRecorderProfile->audioChannels;
    profile->audioSampleRate = videoRecorderProfile->audioSampleRate;
    profile->videoBitrate = videoRecorderProfile->videoBitrate;
    profile->videoFrameWidth = videoRecorderProfile->videoFrameWidth;
    profile->videoFrameHeight = videoRecorderProfile->videoFrameHeight;
    profile->videoFrameRate = videoRecorderProfile->videoFrameRate;

    return MSERR_OK;
}

void AVRecorderNapi::ErrorCallback(int32_t errCode, const std::string &operate, const std::string &add)
{
    MEDIA_LOGE("failed to %{public}s, errCode = %{public}d", operate.c_str(), errCode);
    CHECK_AND_RETURN_LOG(recorderCb_ != nullptr, "recorderCb_ is nullptr!");
    auto napiCb = std::static_pointer_cast<AVRecorderCallback>(recorderCb_);

    MediaServiceExtErrCodeAPI9 err = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(errCode));
    std::string msg = MSExtErrorAPI9ToString(err, operate, "") + add;
    napiCb->SendErrorCallback(errCode, msg);
}

void AVRecorderNapi::StateCallback(const std::string &state)
{
    MEDIA_LOGI("Change state to %{public}s", state.c_str());
    CHECK_AND_RETURN_LOG(recorderCb_ != nullptr, "recorderCb_ is nullptr!");
    auto napiCb = std::static_pointer_cast<AVRecorderCallback>(recorderCb_);
    napiCb->SendStateCallback(state, StateChangeReason::USER);
}

void AVRecorderNapi::SetCallbackReference(const std::string &callbackName, std::shared_ptr<AutoRef> ref)
{
    eventCbMap_[callbackName] = ref;
    CHECK_AND_RETURN_LOG(recorderCb_ != nullptr, "recorderCb_ is nullptr!");
    auto napiCb = std::static_pointer_cast<AVRecorderCallback>(recorderCb_);
    napiCb->SaveCallbackReference(callbackName, ref);
}

void AVRecorderNapi::CancelCallbackReference(const std::string &callbackName)
{
    CHECK_AND_RETURN_LOG(recorderCb_ != nullptr, "recorderCb_ is nullptr!");
    auto napiCb = std::static_pointer_cast<AVRecorderCallback>(recorderCb_);
    napiCb->CancelCallbackReference(callbackName);
    eventCbMap_[callbackName] = nullptr;
}

void AVRecorderNapi::CancelCallback()
{
    CHECK_AND_RETURN_LOG(recorderCb_ != nullptr, "recorderCb_ is nullptr!");
    auto napiCb = std::static_pointer_cast<AVRecorderCallback>(recorderCb_);
    napiCb->ClearCallbackReference();
}

void AVRecorderNapi::RemoveSurface()
{
    if (surface_ != nullptr) {
        auto id = surface_->GetUniqueId();
        auto surface = SurfaceUtils::GetInstance()->GetSurface(id);
        if (surface) {
            (void)SurfaceUtils::GetInstance()->Remove(id);
        }
        surface_ = nullptr;
    }
}

int32_t AVRecorderNapi::GetPropertyInt32(napi_env env, napi_value configObj, const std::string &type, int32_t &result,
    bool &getValue)
{
    napi_value item = nullptr;
    bool exist = false;
    getValue = false;
    napi_status status = napi_has_named_property(env, configObj, type.c_str(), &exist);
    if (status != napi_ok || !exist) {
        MEDIA_LOGI("can not find %{public}s property", type.c_str());
        return MSERR_OK;
    }

    if (napi_get_named_property(env, configObj, type.c_str(), &item) != napi_ok) {
        MEDIA_LOGI("get %{public}s property fail", type.c_str());
        return MSERR_UNKNOWN;
    }

    if (napi_get_value_int32(env, item, &result) != napi_ok) {
        std::string string = CommonNapi::GetStringArgument(env, item);
        if (string == "") {
            // This attribute has not been assigned
            return MSERR_OK;
        } else {
            MEDIA_LOGE("get %{public}s property value fail", type.c_str());
            return MSERR_INVALID_VAL;
        }
    }

    MEDIA_LOGI("get %{public}s : %{public}d!", type.c_str(), result);
    getValue = true;
    return MSERR_OK;
}

int32_t AVRecorderNapi::GetPropertyInt32Vec(napi_env env, napi_value configObj, const std::string &type,
    std::vector<int32_t> &result, bool &getValue)
{
    napi_value item = nullptr;
    bool exist = false;
    getValue = false;
    napi_status status = napi_has_named_property(env, configObj, type.c_str(), &exist);
    if (status != napi_ok || !exist) {
        MEDIA_LOGI("can not find %{public}s property", type.c_str());
        return MSERR_OK;
    }

    if (napi_get_named_property(env, configObj, type.c_str(), &item) != napi_ok) {
        MEDIA_LOGI("get %{public}s property fail", type.c_str());
        return MSERR_UNKNOWN;
    }
    bool isArray = false;
    status = napi_is_array(env, item, &isArray);
    if (status != napi_ok || !isArray) {
        MEDIA_LOGE("get property fail: not array");
    }
    uint32_t arrayLen = 0;
    napi_get_array_length(env, item, &arrayLen);
    for (uint32_t i = 0; i < arrayLen; i++) {
        napi_value element = nullptr;
        napi_get_element(env, item, i, &element);

        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, element, &valueType);
        if (valueType != napi_number) {
            MEDIA_LOGE("get int32 vector failed, not number!");
            return MSERR_UNKNOWN;
        }

        int32_t int32Value = 0;
        napi_get_value_int32(env, element, &int32Value);
        result.push_back(int32Value);
    }

    getValue = true;
    return MSERR_OK;
}

napi_status MediaJsAVRecorderProfile::GetJsResult(napi_env env, napi_value &result)
{
    napi_status ret = napi_ok;
    bool setRet = true;
    int32_t setState = MSERR_OK;
    CHECK_AND_RETURN_RET(value_ != nullptr, napi_generic_failure);
    CHECK_AND_RETURN_RET((ret = napi_create_object(env, &result)) == napi_ok, ret);

    setRet = CommonNapi::SetPropertyInt32(env, result, "audioBitrate", value_->audioBitrate);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);
    setRet = CommonNapi::SetPropertyInt32(env, result, "audioChannels", value_->audioChannels);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);

    std::string audioCodec;
    setState = MediaJsResultExtensionMethod::SetAudioCodecFormat(value_->audioCodecFormat, audioCodec);
    CHECK_AND_RETURN_RET(setState == MSERR_OK, napi_generic_failure);
    setRet = CommonNapi::SetPropertyString(env, result, "audioCodec", audioCodec);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);

    setRet = CommonNapi::SetPropertyInt32(env, result, "audioSampleRate", value_->audioSampleRate);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);

    std::string fileFormat;
    setState = MediaJsResultExtensionMethod::SetFileFormat(value_->fileFormat, fileFormat);
    CHECK_AND_RETURN_RET(setState == MSERR_OK, napi_generic_failure);
    setRet = CommonNapi::SetPropertyString(env, result, "fileFormat", fileFormat);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);

    setRet = CommonNapi::SetPropertyInt32(env, result, "videoBitrate", value_->videoBitrate);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);

    std::string videoCodec;
    setState = MediaJsResultExtensionMethod::SetVideoCodecFormat(value_->videoCodecFormat, videoCodec);
    CHECK_AND_RETURN_RET(setState == MSERR_OK, napi_generic_failure);
    setRet = CommonNapi::SetPropertyString(env, result, "videoCodec", videoCodec);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);

    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);
    setRet = CommonNapi::SetPropertyInt32(env, result, "videoFrameWidth", value_->videoFrameWidth);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);
    setRet = CommonNapi::SetPropertyInt32(env, result, "videoFrameHeight", value_->videoFrameHeight);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);
    setRet = CommonNapi::SetPropertyInt32(env, result, "videoFrameRate", value_->videoFrameRate);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);

    return ret;
}

int32_t MediaJsResultExtensionMethod::SetAudioCodecFormat(AudioCodecFormat &codecFormat, std::string &mime)
{
    MEDIA_LOGI("audioCodecFormat %{public}d", codecFormat);
    const std::map<AudioCodecFormat, std::string_view> codecFormatToMimeStr = {
        { AudioCodecFormat::AAC_LC, CodecMimeType::AUDIO_AAC },
        { AudioCodecFormat::AUDIO_MPEG, CodecMimeType::AUDIO_MPEG },
        { AudioCodecFormat::AUDIO_G711MU, CodecMimeType::AUDIO_G711MU },
        { AudioCodecFormat::AUDIO_AMR_NB, CodecMimeType::AUDIO_AMR_NB },
        { AudioCodecFormat::AUDIO_AMR_WB, CodecMimeType::AUDIO_AMR_WB },
        { AudioCodecFormat::AUDIO_DEFAULT, "" },
    };

    auto iter = codecFormatToMimeStr.find(codecFormat);
    if (iter != codecFormatToMimeStr.end()) {
        mime = iter->second;
        return MSERR_OK;
    }
    return MSERR_INVALID_VAL;
}

int32_t MediaJsResultExtensionMethod::SetVideoCodecFormat(VideoCodecFormat &codecFormat, std::string &mime)
{
    MEDIA_LOGI("VideoCodecFormat %{public}d", codecFormat);
    const std::map<VideoCodecFormat, std::string_view> codecFormatTomimeStr = {
        { VideoCodecFormat::H264, CodecMimeType::VIDEO_AVC },
        { VideoCodecFormat::MPEG4, CodecMimeType::VIDEO_MPEG4 },
        { VideoCodecFormat::H265, CodecMimeType::VIDEO_HEVC },
        { VideoCodecFormat::VIDEO_DEFAULT, ""},
    };

    auto iter = codecFormatTomimeStr.find(codecFormat);
    if (iter != codecFormatTomimeStr.end()) {
        mime = iter->second;
        return MSERR_OK;
    }
    return MSERR_INVALID_VAL;
}

int32_t MediaJsResultExtensionMethod::SetFileFormat(OutputFormatType &type, std::string &extension)
{
    MEDIA_LOGI("OutputFormatType %{public}d", type);
    const std::map<OutputFormatType, std::string> outputFormatToextension = {
        { OutputFormatType::FORMAT_MPEG_4, "mp4" },
        { OutputFormatType::FORMAT_M4A, "m4a" },
        { OutputFormatType::FORMAT_MP3, "mp3" },
        { OutputFormatType::FORMAT_WAV, "wav" },
        { OutputFormatType::FORMAT_AMR, "amr" },
        { OutputFormatType::FORMAT_AAC, "aac" },
        { OutputFormatType::FORMAT_DEFAULT, "" },
    };

    auto iter = outputFormatToextension.find(type);
    if (iter != outputFormatToextension.end()) {
        extension = iter->second;
        return MSERR_OK;
    }
    return MSERR_INVALID_VAL;
}

void AVRecorderAsyncContext::AVRecorderSignError(int32_t errCode, const std::string &operate,
    const std::string &param, const std::string &add)
{
    RetInfo retInfo = GetRetInfo(errCode, operate, param, add);
    SignError(retInfo.first, retInfo.second);
}

napi_status MediaJsAVRecorderConfig::GetJsResult(napi_env env, napi_value &result)
{
    napi_status ret = napi_ok;
    int32_t setState = MSERR_OK;
    CHECK_AND_RETURN_RET(value_ != nullptr, napi_generic_failure);
    CHECK_AND_RETURN_RET((ret = napi_create_object(env, &result)) == napi_ok, ret);

    napi_value profile;
    napi_value location;
    CHECK_AND_RETURN_RET((ret = napi_create_object(env, &profile)) == napi_ok, ret);
    CHECK_AND_RETURN_RET((ret = napi_create_object(env, &location)) == napi_ok, ret);
    CHECK_AND_RETURN_RET((ret = audioToSet(env, profile, result)) == napi_ok, ret);
    CHECK_AND_RETURN_RET((ret = videoToSet(env, profile, result)) == napi_ok, ret);
    CHECK_AND_RETURN_RET((ret = locationToSet(env, location, result)) == napi_ok, ret);

    if (value_->withAudio || value_->withVideo) {
        bool setRet = true;
        setRet = CommonNapi::SetPropertyString(env, result, "url", value_->url);
        CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);

        std::string fileFormat;
        setState = MediaJsResultExtensionMethod::SetFileFormat(value_->profile.fileFormat, fileFormat);
        CHECK_AND_RETURN_RET(setState == MSERR_OK, napi_generic_failure);
        setRet = CommonNapi::SetPropertyString(env, profile, "fileFormat", fileFormat);
        CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);
    }
    napi_set_named_property(env, result, "profile", profile);
    return ret;
}

napi_status MediaJsAVRecorderConfig::audioToSet(napi_env env, napi_value &profile, napi_value &result)
{
    bool setRet = true;
    int32_t setState = MSERR_OK;
    CHECK_AND_RETURN_RET(value_->withAudio == true, napi_ok);
    setRet = CommonNapi::SetPropertyInt32(env, result, "audioSourceType", value_->audioSourceType);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);
    setRet = CommonNapi::SetPropertyInt32(env, profile, "audioBitrate", value_->profile.audioBitrate);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);
    setRet = CommonNapi::SetPropertyInt32(env, profile, "audioChannels", value_->profile.audioChannels);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);
    setRet = CommonNapi::SetPropertyInt32(env, profile, "audioSampleRate", value_->profile.audioSampleRate);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);

    std::string audioCodec;
    setState = MediaJsResultExtensionMethod::SetAudioCodecFormat(value_->profile.audioCodecFormat, audioCodec);
    CHECK_AND_RETURN_RET(setState == MSERR_OK, napi_generic_failure);
    setRet = CommonNapi::SetPropertyString(env, profile, "audioCodec", audioCodec);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);
    return napi_ok;
}

napi_status MediaJsAVRecorderConfig::videoToSet(napi_env env, napi_value &profile, napi_value &result)
{
    bool setRet = true;
    int32_t setState = MSERR_OK;
    CHECK_AND_RETURN_RET(value_->withVideo == true, napi_ok);
    setRet = CommonNapi::SetPropertyInt32(env, result, "videoSourceType", value_->videoSourceType);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);
    setRet = CommonNapi::SetPropertyInt32(env, result, "rotation", value_->rotation);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);
    setRet = CommonNapi::SetPropertyInt32(env, profile, "videoBitrate", value_->profile.videoBitrate);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);
    setRet = CommonNapi::SetPropertyInt32(env, profile, "videoFrameWidth", value_->profile.videoFrameWidth);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);
    setRet = CommonNapi::SetPropertyInt32(env, profile, "videoFrameHeight", value_->profile.videoFrameHeight);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);
    setRet = CommonNapi::SetPropertyInt32(env, profile, "videoFrameRate", value_->profile.videoFrameRate);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);

    std::string videoCodec;
    setState = MediaJsResultExtensionMethod::SetVideoCodecFormat(value_->profile.videoCodecFormat, videoCodec);
    CHECK_AND_RETURN_RET(setState == MSERR_OK, napi_generic_failure);
    setRet = CommonNapi::SetPropertyString(env, profile, "videoCodec", videoCodec);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);
    return napi_ok;
}

napi_status MediaJsAVRecorderConfig::locationToSet(napi_env env, napi_value &location, napi_value &result)
{
    bool setRet = true;
    setRet = CommonNapi::SetPropertyDouble(env, location, "latitude", value_->location.latitude);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);
    setRet = CommonNapi::SetPropertyDouble(env, location, "longitude", value_->location.longitude);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);
    napi_set_named_property(env, result, "location", location);
    return napi_ok;
}

napi_status MediaJsEncoderInfo::GetJsResult(napi_env env, napi_value &result)
{
    napi_status ret = napi_ok;

    size_t size = encoderInfo_.size();
    napi_create_array_with_length(env, size, &result);

    CHECK_AND_RETURN_RET((ret = napi_create_array(env, &result)) == napi_ok, ret);

    napi_value audioEncoder;
    napi_value vidoeEncoder;
    napi_value encoderInfoArray;
    CHECK_AND_RETURN_RET((ret = napi_create_object(env, &audioEncoder)) == napi_ok, ret);
    CHECK_AND_RETURN_RET((ret = napi_create_object(env, &vidoeEncoder)) == napi_ok, ret);
    CHECK_AND_RETURN_RET((ret = napi_create_array(env, &encoderInfoArray)) == napi_ok, ret);

    for (uint32_t i = 0; i < encoderInfo_.size(); i++) {
        if (encoderInfo_[i].type == "audio") {
            ret = GetAudioEncoderInfo(env, encoderInfo_[i], result, i);
            CHECK_AND_RETURN_RET(ret == napi_ok, ret);
        } else {
            ret = GetVideoEncoderInfo(env, encoderInfo_[i], result, i);
            CHECK_AND_RETURN_RET(ret == napi_ok, ret);
        }
    }
    return napi_ok;
}

napi_status MediaJsEncoderInfo::GetAudioEncoderInfo(
    napi_env env, EncoderCapabilityData encoderCapData, napi_value &result, uint32_t position)
{
    bool setRet = true;
    napi_value encoderInfo;
    napi_status ret;
    CHECK_AND_RETURN_RET((ret = napi_create_object(env, &encoderInfo)) == napi_ok, ret);

    setRet = CommonNapi::SetPropertyString(env, encoderInfo, "mimeType", encoderCapData.mimeType);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);

    setRet = CommonNapi::SetPropertyString(env, encoderInfo, "type", encoderCapData.type);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);

    setRet = CommonNapi::AddRangeProperty(env, encoderInfo, "bitRate",
        encoderCapData.bitrate.minVal, encoderCapData.bitrate.maxVal);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);

    setRet = CommonNapi::AddRangeProperty(env, encoderInfo, "channels",
        encoderCapData.channels.minVal, encoderCapData.channels.maxVal);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);

    setRet = CommonNapi::AddArrayProperty(env, encoderInfo, "sampleRate", encoderCapData.sampleRate);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);

    napi_status status = napi_set_element(env, result, position, encoderInfo);
    CHECK_AND_RETURN_RET(status == napi_ok, napi_generic_failure);
    return napi_ok;
}

napi_status MediaJsEncoderInfo::GetVideoEncoderInfo(
    napi_env env, EncoderCapabilityData encoderCapData, napi_value &result, uint32_t position)
{
    bool setRet = true;
    napi_value encoderInfo;
    napi_status ret;
    CHECK_AND_RETURN_RET((ret = napi_create_object(env, &encoderInfo)) == napi_ok, ret);

    setRet = CommonNapi::SetPropertyString(env, encoderInfo, "mimeType", encoderCapData.mimeType);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);

    setRet = CommonNapi::SetPropertyString(env, encoderInfo, "type", encoderCapData.type);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);

    setRet = CommonNapi::AddRangeProperty(env, encoderInfo, "bitRate",
        encoderCapData.bitrate.minVal, encoderCapData.bitrate.maxVal);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);

    setRet = CommonNapi::AddRangeProperty(env, encoderInfo, "frameRate",
        encoderCapData.frameRate.minVal, encoderCapData.frameRate.maxVal);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);

    setRet = CommonNapi::AddRangeProperty(env, encoderInfo, "width",
        encoderCapData.width.minVal, encoderCapData.width.maxVal);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);

    setRet = CommonNapi::AddRangeProperty(env, encoderInfo, "height",
        encoderCapData.height.minVal, encoderCapData.height.maxVal);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);

    napi_status status = napi_set_element(env, result, position, encoderInfo);
    CHECK_AND_RETURN_RET(status == napi_ok, napi_generic_failure);
    return napi_ok;
}
} // namespace Media
} // namespace OHOS