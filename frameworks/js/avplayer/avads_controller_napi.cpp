/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "avads_controller_napi.h"
#include "avplayer_napi.h"
#include "media_source_napi.h"
#include "media_log.h"
#include "common_napi.h"
#include "media_dfx.h"

namespace OHOS {
namespace Media {

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_PLAYER, "AVAdsControllerNapi" };
    const std::string CLASS_NAME = "AVAdsController";
    constexpr int32_t MIN_REQUIRED_ARGS = 2;
    constexpr int32_t ERR_ADS_PARAM_INVALID = 5400108;

    void RejectPromise(napi_env env, napi_deferred deferred, int32_t code, const std::string &msg)
    {
        napi_value error = nullptr;
        CommonNapi::CreateError(env, code, msg, error);
        napi_reject_deferred(env, deferred, error);
    }
}

thread_local napi_ref AVAdsControllerNapi::constructor_ = nullptr;

AVAdsControllerNapi::AVAdsControllerNapi()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " ctor", FAKE_POINTER(this));
}

AVAdsControllerNapi::~AVAdsControllerNapi()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " dtor", FAKE_POINTER(this));
}

void AVAdsControllerNapi::SetPlayer(AVPlayerNapi *player)
{
    std::lock_guard<std::mutex> lock(mutex_);
    player_ = player;
}

AVPlayerNapi *AVAdsControllerNapi::GetPlayer() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return player_;
}

napi_value AVAdsControllerNapi::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor staticProperty[] = {
        DECLARE_NAPI_STATIC_FUNCTION("createAVAdsController", JsCreateAVAdsController),
    };

    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("addAdsMediaSource", JsAddAdsMediaSource),
        DECLARE_NAPI_FUNCTION("removeAdsMediaSource", JsRemoveAdsMediaSource),
        DECLARE_NAPI_FUNCTION("skipCurrentAdsMediaSource", JsSkipCurrentAdsMediaSource),
        DECLARE_NAPI_FUNCTION("disableAllAdsMediaSource", JsDisableAllAdsMediaSource),
        DECLARE_NAPI_FUNCTION("release", JsRelease),
        DECLARE_NAPI_FUNCTION("onAdsEventListenerLoadingError", JsOnAdsEventListenerLoadingError),
        DECLARE_NAPI_FUNCTION("offAdsEventListenerLoadingError", JsOffAdsEventListenerLoadingError),
        DECLARE_NAPI_FUNCTION("onAdsListenerAdsStarted", JsOnAdsListenerAdsStarted),
        DECLARE_NAPI_FUNCTION("offAdsListenerAdsStarted", JsOffAdsListenerAdsStarted),
        DECLARE_NAPI_FUNCTION("onAdsListenerAdsSkipped", JsOnAdsListenerAdsSkipped),
        DECLARE_NAPI_FUNCTION("offAdsListenerAdsSkipped", JsOffAdsListenerAdsSkipped),
        DECLARE_NAPI_FUNCTION("onAdsListenerAdsCompleted", JsOnAdsListenerAdsCompleted),
        DECLARE_NAPI_FUNCTION("offAdsListenerAdsCompleted", JsOffAdsListenerAdsCompleted),
    };

    napi_value constructor = nullptr;
    napi_status status = napi_define_class(env, CLASS_NAME.c_str(), NAPI_AUTO_LENGTH, Constructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &constructor);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "Failed to define AVAdsController class");

    status = napi_create_reference(env, constructor, 1, &constructor_);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "Failed to create reference of constructor");

    status = napi_define_properties(env, exports, sizeof(staticProperty) / sizeof(staticProperty[0]), staticProperty);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "Failed to define static function createAVAdsController");

    return exports;
}

napi_value AVAdsControllerNapi::CreateInstance(napi_env env, AVPlayerNapi *player)
{
    napi_value constructor = nullptr;
    napi_status status = napi_get_reference_value(env, constructor_, &constructor);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "Failed to get constructor reference");

    napi_value instance = nullptr;
    status = napi_new_instance(env, constructor, 0, nullptr, &instance);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "Failed to create AVAdsController instance");

    AVAdsControllerNapi *controller = nullptr;
    status = napi_unwrap(env, instance, reinterpret_cast<void **>(&controller));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && controller != nullptr, nullptr, "Failed to unwrap controller");

    controller->SetPlayer(player);
    return instance;
}

napi_value AVAdsControllerNapi::JsCreateAVAdsController(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVAdsControllerNapi::createAVAdsController");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsCreateAVAdsController In");

    napi_value args[1] = { nullptr };
    size_t argCount = 1;
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argCount, args, &jsThis, nullptr);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, result, "failed to napi_get_cb_info");

    if (argCount < 1) {
        napi_throw_error(env, nullptr, "Invalid arguments, expected 1 (AVPlayer)");
        return result;
    }

    napi_valuetype type;
    napi_typeof(env, args[0], &type);
    if (type != napi_object) {
        napi_throw_error(env, nullptr, "First argument must be AVPlayer");
        return result;
    }

    AVPlayerNapi *jsPlayer = nullptr;
    status = napi_unwrap(env, args[0], reinterpret_cast<void **>(&jsPlayer));
    if (status != napi_ok || jsPlayer == nullptr) {
        napi_throw_error(env, nullptr, "Failed to unwrap AVPlayer");
        return result;
    }

    if (jsPlayer->GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        napi_throw_error(env, nullptr, "Player is released, cannot create ads controller");
        return result;
    }

    return CreateInstance(env, jsPlayer);
}

napi_value AVAdsControllerNapi::Constructor(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_value thisArg = nullptr;
    void *data = nullptr;
    napi_status status = napi_get_cb_info(env, info, nullptr, nullptr, &thisArg, &data);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, result, "Failed to get callback info");

    AVAdsControllerNapi *controller = new (std::nothrow) AVAdsControllerNapi();
    CHECK_AND_RETURN_RET_LOG(controller != nullptr, result, "Failed to allocate AVAdsControllerNapi");

    status = napi_wrap(env, thisArg, controller, Destructor, nullptr, nullptr);
    if (status != napi_ok) {
        delete controller;
        MEDIA_LOGE("Failed to wrap AVAdsControllerNapi");
        return result;
    }

    return thisArg;
}

void AVAdsControllerNapi::Destructor(napi_env env, void *nativeObject, void *finalize)
{
    (void)env;
    (void)finalize;
    auto *controller = reinterpret_cast<AVAdsControllerNapi *>(nativeObject);
    if (controller != nullptr) {
        delete controller;
    }
}

void AVAdsControllerNapi::ExecuteAdsTask(napi_env env, void *data)
{
    (void)env;
    auto ctx = reinterpret_cast<AdsAsyncContext *>(data);
    CHECK_AND_RETURN_LOG(ctx != nullptr, "context is nullptr");

    if (ctx->errFlag) {
        return;
    }

    auto player = ctx->player;
    if (player == nullptr) {
        ctx->SignError(MSERR_INVALID_OPERATION, "player is nullptr");
        return;
    }

    int32_t ret = MSERR_OK;
    switch (ctx->opType) {
        case AdsAsyncContext::OpType::ADD:
            ret = player->AddAdsMediaSource(ctx->mediaSource, ctx->startMs, ctx->outId);
            if (ret != MSERR_OK) {
                ctx->SignError(ERR_ADS_PARAM_INVALID, "addAdsMediaSource failed");
            }
            break;
        case AdsAsyncContext::OpType::REMOVE:
            ret = player->RemoveAdsMediaSource(ctx->adId);
            if (ret != MSERR_OK) {
                ctx->SignError(ERR_ADS_PARAM_INVALID, "removeAdsMediaSource failed");
            }
            break;
        case AdsAsyncContext::OpType::SKIP:
            ret = player->SkipCurrentAdsMediaSource();
            if (ret != MSERR_OK) {
                ctx->SignError(ERR_ADS_PARAM_INVALID, "skipCurrentAdsMediaSource failed");
            }
            break;
        case AdsAsyncContext::OpType::DISABLE_ALL:
            ret = player->DisableAllAdsMediaSource();
            if (ret != MSERR_OK) {
                ctx->SignError(ERR_ADS_PARAM_INVALID, "disableAllAdsMediaSource failed");
            }
            break;
        default:
            ctx->SignError(ERR_ADS_PARAM_INVALID, "unknown opType");
            break;
    }
}

void AVAdsControllerNapi::CompleteAdsTask(napi_env env, napi_status status, void *data)
{
    auto ctx = reinterpret_cast<AdsAsyncContext *>(data);
    CHECK_AND_RETURN_LOG(ctx != nullptr, "context is nullptr");

    if (status != napi_ok) {
        ctx->SignError(MSERR_EXT_UNKNOWN, "async work status != napi_ok");
    }

    if (!ctx->errFlag) {
        napi_value result = nullptr;
        if (ctx->opType == AdsAsyncContext::OpType::ADD) {
            napi_create_string_utf8(env, ctx->outId.c_str(), ctx->outId.length(), &result);
        } else {
            napi_get_undefined(env, &result);
        }
        napi_resolve_deferred(env, ctx->deferred, result);
    } else {
        RejectPromise(env, ctx->deferred, ctx->errCode, ctx->errMessage);
    }
    ctx->deferred = nullptr;

    napi_delete_async_work(env, ctx->work);
    delete ctx;
}

napi_value AVAdsControllerNapi::JsAddAdsMediaSource(napi_env env, napi_callback_info info)
{
    MEDIA_LOGI("JsAddAdsMediaSource enter");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    size_t argc = 2;
    napi_value argv[2] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisArg, &data);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, result, "Failed to get callback info");

    AVAdsControllerNapi *controller = nullptr;
    status = napi_unwrap(env, thisArg, reinterpret_cast<void **>(&controller));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && controller != nullptr, result, "Failed to unwrap controller");

    AVPlayerNapi *player = controller->GetPlayer();
    CHECK_AND_RETURN_RET_LOG(player != nullptr, result, "Player is null");

    auto ctx = new (std::nothrow) AdsAsyncContext(env);
    CHECK_AND_RETURN_RET_LOG(ctx != nullptr, result, "Failed to allocate AdsAsyncContext");
    ctx->deferred = CommonNapi::CreatePromise(env, nullptr, result);
    ctx->player = player->GetPlayerInstance();
    ctx->opType = AdsAsyncContext::OpType::ADD;

    napi_valuetype type;
    napi_typeof(env, argv[1], &type);
    if (argc < MIN_REQUIRED_ARGS || ctx->player == nullptr || type != napi_number) {
        RejectPromise(env, ctx->deferred, ERR_ADS_PARAM_INVALID, "Invalid arguments");
        delete ctx;
        return result;
    }

    napi_get_value_int64(env, argv[1], &ctx->startMs);
    std::shared_ptr<AVMediaSourceTmp> srcTmp = MediaSourceNapi::GetMediaSource(env, argv[0]);
    if (srcTmp == nullptr) {
        RejectPromise(env, ctx->deferred, ERR_ADS_PARAM_INVALID, "Failed to get MediaSource");
        delete ctx;
        return result;
    }
    ctx->mediaSource = AVPlayerNapi::GetAVMediaSource(env, argv[0], srcTmp);
    if (ctx->mediaSource == nullptr) {
        RejectPromise(env, ctx->deferred, ERR_ADS_PARAM_INVALID, "Failed to convert MediaSource");
        delete ctx;
        return result;
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "JsAddAdsMediaSource", NAPI_AUTO_LENGTH, &resource);
    napi_create_async_work(env, nullptr, resource, ExecuteAdsTask, CompleteAdsTask,
        static_cast<void *>(ctx), &ctx->work);
    napi_queue_async_work_with_qos(env, ctx->work, napi_qos_user_initiated);
    return result;
}

napi_value AVAdsControllerNapi::JsRemoveAdsMediaSource(napi_env env, napi_callback_info info)
{
    MEDIA_LOGI("JsRemoveAdsMediaSource enter");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisArg, &data);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, result, "Failed to get callback info");

    AVAdsControllerNapi *controller = nullptr;
    status = napi_unwrap(env, thisArg, reinterpret_cast<void **>(&controller));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && controller != nullptr, result, "Failed to unwrap controller");

    AVPlayerNapi *player = controller->GetPlayer();
    CHECK_AND_RETURN_RET_LOG(player != nullptr, result, "Player is null");

    auto ctx = new (std::nothrow) AdsAsyncContext(env);
    CHECK_AND_RETURN_RET_LOG(ctx != nullptr, result, "Failed to allocate AdsAsyncContext");
    ctx->deferred = CommonNapi::CreatePromise(env, nullptr, result);
    ctx->player = player->GetPlayerInstance();
    ctx->opType = AdsAsyncContext::OpType::REMOVE;

    if (argc < 1 || ctx->player == nullptr) {
        RejectPromise(env, ctx->deferred, ERR_ADS_PARAM_INVALID, "Invalid arguments");
        delete ctx;
        return result;
    }

    napi_valuetype type;
    napi_typeof(env, argv[0], &type);
    if (type != napi_string) {
        RejectPromise(env, ctx->deferred, ERR_ADS_PARAM_INVALID, "Argument must be string");
        delete ctx;
        return result;
    }

    ctx->adId = CommonNapi::GetStringArgument(env, argv[0]);

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "JsRemoveAdsMediaSource", NAPI_AUTO_LENGTH, &resource);
    napi_create_async_work(env, nullptr, resource, ExecuteAdsTask, CompleteAdsTask,
        static_cast<void *>(ctx), &ctx->work);
    napi_queue_async_work_with_qos(env, ctx->work, napi_qos_user_initiated);
    return result;
}

napi_value AVAdsControllerNapi::JsSkipCurrentAdsMediaSource(napi_env env, napi_callback_info info)
{
    MEDIA_LOGI("JsSkipCurrentAdsMediaSource enter");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_value thisArg = nullptr;
    void *data = nullptr;
    napi_status status = napi_get_cb_info(env, info, nullptr, nullptr, &thisArg, &data);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, result, "Failed to get callback info");

    AVAdsControllerNapi *controller = nullptr;
    status = napi_unwrap(env, thisArg, reinterpret_cast<void **>(&controller));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && controller != nullptr, result, "Failed to unwrap controller");

    AVPlayerNapi *player = controller->GetPlayer();
    CHECK_AND_RETURN_RET_LOG(player != nullptr, result, "Player is null");

    auto ctx = new (std::nothrow) AdsAsyncContext(env);
    CHECK_AND_RETURN_RET_LOG(ctx != nullptr, result, "Failed to allocate AdsAsyncContext");
    ctx->deferred = CommonNapi::CreatePromise(env, nullptr, result);
    ctx->player = player->GetPlayerInstance();
    ctx->opType = AdsAsyncContext::OpType::SKIP;

    if (ctx->player == nullptr) {
        RejectPromise(env, ctx->deferred, ERR_ADS_PARAM_INVALID, "Player instance is null");
        delete ctx;
        return result;
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "JsSkipCurrentAdsMediaSource", NAPI_AUTO_LENGTH, &resource);
    napi_create_async_work(env, nullptr, resource, ExecuteAdsTask, CompleteAdsTask,
        static_cast<void *>(ctx), &ctx->work);
    napi_queue_async_work_with_qos(env, ctx->work, napi_qos_user_initiated);
    return result;
}

napi_value AVAdsControllerNapi::JsDisableAllAdsMediaSource(napi_env env, napi_callback_info info)
{
    MEDIA_LOGI("JsDisableAllAdsMediaSource enter");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_value thisArg = nullptr;
    void *data = nullptr;
    napi_status status = napi_get_cb_info(env, info, nullptr, nullptr, &thisArg, &data);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, result, "Failed to get callback info");

    AVAdsControllerNapi *controller = nullptr;
    status = napi_unwrap(env, thisArg, reinterpret_cast<void **>(&controller));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && controller != nullptr, result, "Failed to unwrap controller");

    AVPlayerNapi *player = controller->GetPlayer();
    CHECK_AND_RETURN_RET_LOG(player != nullptr, result, "Player is null");

    auto ctx = new (std::nothrow) AdsAsyncContext(env);
    CHECK_AND_RETURN_RET_LOG(ctx != nullptr, result, "Failed to allocate AdsAsyncContext");
    ctx->deferred = CommonNapi::CreatePromise(env, nullptr, result);
    ctx->player = player->GetPlayerInstance();
    ctx->opType = AdsAsyncContext::OpType::DISABLE_ALL;

    if (ctx->player == nullptr) {
        RejectPromise(env, ctx->deferred, ERR_ADS_PARAM_INVALID, "Player instance is null");
        delete ctx;
        return result;
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "JsDisableAllAdsMediaSource", NAPI_AUTO_LENGTH, &resource);
    napi_create_async_work(env, nullptr, resource, ExecuteAdsTask, CompleteAdsTask,
        static_cast<void *>(ctx), &ctx->work);
    napi_queue_async_work_with_qos(env, ctx->work, napi_qos_user_initiated);
    return result;
}

napi_value AVAdsControllerNapi::JsRelease(napi_env env, napi_callback_info info)
{
    MEDIA_LOGI("JsRelease enter");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_value thisArg = nullptr;
    void *data = nullptr;
    napi_status status = napi_get_cb_info(env, info, nullptr, nullptr, &thisArg, &data);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, result, "Failed to get callback info");

    AVAdsControllerNapi *controller = nullptr;
    status = napi_unwrap(env, thisArg, reinterpret_cast<void **>(&controller));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && controller != nullptr, result, "Failed to unwrap controller");

    AVPlayerNapi *player = controller->GetPlayer();
    if (player != nullptr && player->GetPlayerInstance() != nullptr) {
        player->GetPlayerInstance()->DisableAllAdsMediaSource();
        player->ClearCallbackReference(AVPlayerEvent::EVENT_ADS_LOADING_ERROR);
        player->ClearCallbackReference(AVPlayerEvent::EVENT_ADS_STARTED);
        player->ClearCallbackReference(AVPlayerEvent::EVENT_ADS_SKIPPED);
        player->ClearCallbackReference(AVPlayerEvent::EVENT_ADS_COMPLETED);
    }

    {
        std::lock_guard<std::mutex> lock(controller->mutex_);
        controller->player_ = nullptr;
    }

    return result;
}

napi_value AVAdsControllerNapi::JsOnAdsEventListenerLoadingError(napi_env env, napi_callback_info info)
{
    MEDIA_LOGI("JsOnAdsEventListenerLoadingError enter");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisArg, &data);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, result, "Failed to get callback info");

    AVAdsControllerNapi *controller = nullptr;
    status = napi_unwrap(env, thisArg, reinterpret_cast<void **>(&controller));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && controller != nullptr, result, "Failed to unwrap controller");

    if (argc < 1) {
        napi_throw_error(env, nullptr, "Invalid arguments, expected 1");
        return result;
    }

    napi_valuetype type;
    napi_typeof(env, argv[0], &type);
    CHECK_AND_RETURN_RET_LOG(type == napi_function, result, "Argument must be function");

    napi_ref ref = nullptr;
    status = napi_create_reference(env, argv[0], 1, &ref);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && ref != nullptr, result, "failed to create reference!");

    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, ref);
    AVPlayerNapi *player = controller->GetPlayer();
    CHECK_AND_RETURN_RET_LOG(player != nullptr, result, "Player is null");
    player->SaveCallbackReference(AVPlayerEvent::EVENT_ADS_LOADING_ERROR, autoRef);

    MEDIA_LOGI("JsOnAdsEventListenerLoadingError registered successfully");
    return result;
}

napi_value AVAdsControllerNapi::JsOffAdsEventListenerLoadingError(napi_env env, napi_callback_info info)
{
    MEDIA_LOGI("JsOffAdsEventListenerLoadingError enter");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_value thisArg = nullptr;
    void *data = nullptr;
    napi_status status = napi_get_cb_info(env, info, nullptr, nullptr, &thisArg, &data);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, result, "Failed to get callback info");

    AVAdsControllerNapi *controller = nullptr;
    status = napi_unwrap(env, thisArg, reinterpret_cast<void **>(&controller));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && controller != nullptr, result, "Failed to unwrap controller");

    AVPlayerNapi *player = controller->GetPlayer();
    CHECK_AND_RETURN_RET_LOG(player != nullptr, result, "Player is null");
    player->ClearCallbackReference(AVPlayerEvent::EVENT_ADS_LOADING_ERROR);

    MEDIA_LOGI("JsOffAdsEventListenerLoadingError success");
    return result;
}

napi_value AVAdsControllerNapi::JsOnAdsListenerAdsStarted(napi_env env, napi_callback_info info)
{
    MEDIA_LOGI("JsOnAdsListenerAdsStarted enter");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisArg, &data);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, result, "Failed to get callback info");

    AVAdsControllerNapi *controller = nullptr;
    status = napi_unwrap(env, thisArg, reinterpret_cast<void **>(&controller));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && controller != nullptr, result, "Failed to unwrap controller");

    if (argc < 1) {
        napi_throw_error(env, nullptr, "Invalid arguments, expected 1");
        return result;
    }

    napi_valuetype type;
    napi_typeof(env, argv[0], &type);
    CHECK_AND_RETURN_RET_LOG(type == napi_function, result, "Argument must be function");

    napi_ref ref = nullptr;
    status = napi_create_reference(env, argv[0], 1, &ref);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && ref != nullptr, result, "failed to create reference!");

    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, ref);
    AVPlayerNapi *player = controller->GetPlayer();
    CHECK_AND_RETURN_RET_LOG(player != nullptr, result, "Player is null");
    player->SaveCallbackReference(AVPlayerEvent::EVENT_ADS_STARTED, autoRef);

    MEDIA_LOGI("JsOnAdsListenerAdsStarted registered successfully");
    return result;
}

napi_value AVAdsControllerNapi::JsOffAdsListenerAdsStarted(napi_env env, napi_callback_info info)
{
    MEDIA_LOGI("JsOffAdsListenerAdsStarted enter");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_value thisArg = nullptr;
    void *data = nullptr;
    napi_status status = napi_get_cb_info(env, info, nullptr, nullptr, &thisArg, &data);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, result, "Failed to get callback info");

    AVAdsControllerNapi *controller = nullptr;
    status = napi_unwrap(env, thisArg, reinterpret_cast<void **>(&controller));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && controller != nullptr, result, "Failed to unwrap controller");

    AVPlayerNapi *player = controller->GetPlayer();
    CHECK_AND_RETURN_RET_LOG(player != nullptr, result, "Player is null");
    player->ClearCallbackReference(AVPlayerEvent::EVENT_ADS_STARTED);

    MEDIA_LOGI("JsOffAdsListenerAdsStarted success");
    return result;
}

napi_value AVAdsControllerNapi::JsOnAdsListenerAdsSkipped(napi_env env, napi_callback_info info)
{
    MEDIA_LOGI("JsOnAdsListenerAdsSkipped enter");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisArg, &data);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, result, "Failed to get callback info");

    AVAdsControllerNapi *controller = nullptr;
    status = napi_unwrap(env, thisArg, reinterpret_cast<void **>(&controller));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && controller != nullptr, result, "Failed to unwrap controller");

    if (argc < 1) {
        napi_throw_error(env, nullptr, "Invalid arguments, expected 1");
        return result;
    }

    napi_valuetype type;
    napi_typeof(env, argv[0], &type);
    CHECK_AND_RETURN_RET_LOG(type == napi_function, result, "Argument must be function");

    napi_ref ref = nullptr;
    status = napi_create_reference(env, argv[0], 1, &ref);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && ref != nullptr, result, "failed to create reference!");

    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, ref);
    AVPlayerNapi *player = controller->GetPlayer();
    CHECK_AND_RETURN_RET_LOG(player != nullptr, result, "Player is null");
    player->SaveCallbackReference(AVPlayerEvent::EVENT_ADS_SKIPPED, autoRef);

    MEDIA_LOGI("JsOnAdsListenerAdsSkipped registered successfully");
    return result;
}

napi_value AVAdsControllerNapi::JsOffAdsListenerAdsSkipped(napi_env env, napi_callback_info info)
{
    MEDIA_LOGI("JsOffAdsListenerAdsSkipped enter");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_value thisArg = nullptr;
    void *data = nullptr;
    napi_status status = napi_get_cb_info(env, info, nullptr, nullptr, &thisArg, &data);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, result, "Failed to get callback info");

    AVAdsControllerNapi *controller = nullptr;
    status = napi_unwrap(env, thisArg, reinterpret_cast<void **>(&controller));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && controller != nullptr, result, "Failed to unwrap controller");

    AVPlayerNapi *player = controller->GetPlayer();
    CHECK_AND_RETURN_RET_LOG(player != nullptr, result, "Player is null");
    player->ClearCallbackReference(AVPlayerEvent::EVENT_ADS_SKIPPED);

    MEDIA_LOGI("JsOffAdsListenerAdsSkipped success");
    return result;
}

napi_value AVAdsControllerNapi::JsOnAdsListenerAdsCompleted(napi_env env, napi_callback_info info)
{
    MEDIA_LOGI("JsOnAdsListenerAdsCompleted enter");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisArg, &data);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, result, "Failed to get callback info");

    AVAdsControllerNapi *controller = nullptr;
    status = napi_unwrap(env, thisArg, reinterpret_cast<void **>(&controller));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && controller != nullptr, result, "Failed to unwrap controller");

    if (argc < 1) {
        napi_throw_error(env, nullptr, "Invalid arguments, expected 1");
        return result;
    }

    napi_valuetype type;
    napi_typeof(env, argv[0], &type);
    CHECK_AND_RETURN_RET_LOG(type == napi_function, result, "Argument must be function");

    napi_ref ref = nullptr;
    status = napi_create_reference(env, argv[0], 1, &ref);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && ref != nullptr, result, "failed to create reference!");

    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, ref);
    AVPlayerNapi *player = controller->GetPlayer();
    CHECK_AND_RETURN_RET_LOG(player != nullptr, result, "Player is null");
    player->SaveCallbackReference(AVPlayerEvent::EVENT_ADS_COMPLETED, autoRef);

    MEDIA_LOGI("JsOnAdsListenerAdsCompleted registered successfully");
    return result;
}

napi_value AVAdsControllerNapi::JsOffAdsListenerAdsCompleted(napi_env env, napi_callback_info info)
{
    MEDIA_LOGI("JsOffAdsListenerAdsCompleted enter");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_value thisArg = nullptr;
    void *data = nullptr;
    napi_status status = napi_get_cb_info(env, info, nullptr, nullptr, &thisArg, &data);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, result, "Failed to get callback info");

    AVAdsControllerNapi *controller = nullptr;
    status = napi_unwrap(env, thisArg, reinterpret_cast<void **>(&controller));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && controller != nullptr, result, "Failed to unwrap controller");

    AVPlayerNapi *player = controller->GetPlayer();
    CHECK_AND_RETURN_RET_LOG(player != nullptr, result, "Player is null");
    player->ClearCallbackReference(AVPlayerEvent::EVENT_ADS_COMPLETED);

    MEDIA_LOGI("JsOffAdsListenerAdsCompleted success");
    return result;
}

} // namespace Media
} // namespace OHOS
