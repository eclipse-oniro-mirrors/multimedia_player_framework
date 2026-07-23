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
#include "scope_guard.h"

namespace OHOS {
namespace Media {

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_PLAYER, "AVAdsControllerNapi" };
    const std::string CLASS_NAME = "AVAdsController";
    constexpr int32_t MIN_REQUIRED_ARGS = 2;
    constexpr int32_t ERR_ADS_PARAM_INVALID = 5400108;

    void RejectPromise(napi_env env, napi_deferred deferred, int32_t code, const std::string &msg)
    {
        CHECK_AND_RETURN_LOG(deferred != nullptr, "deferred is nullptr, cannot reject promise");
        napi_value error = nullptr;
        napi_status status = CommonNapi::CreateError(env, code, msg, error);
        if (status != napi_ok || error == nullptr) {
            napi_get_undefined(env, &error);
        }
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

void AVAdsControllerNapi::SetPlayer(napi_env env, napi_value playerObj)
{
    AVPlayerNapi *player = nullptr;
    napi_status status = napi_unwrap(env, playerObj, reinterpret_cast<void **>(&player));
    CHECK_AND_RETURN_LOG(status == napi_ok && player != nullptr, "Failed to unwrap player object");
    playerInstance_ = player->GetPlayerInstance();
    if (playerRef_ != nullptr) {
        napi_delete_reference(env, playerRef_);
        playerRef_ = nullptr;
    }
    status = napi_create_reference(env, playerObj, 1, &playerRef_);
    if (status != napi_ok) {
        MEDIA_LOGE("Failed to create player reference");
        playerInstance_ = nullptr;
    }
}

std::shared_ptr<Player> AVAdsControllerNapi::GetPlayerInstance() const
{
    return playerInstance_;
}

AVPlayerNapi *AVAdsControllerNapi::GetPlayerNapi(napi_env env) const
{
    CHECK_AND_RETURN_RET_LOG(playerRef_ != nullptr, nullptr, "playerRef_ is nullptr");
    napi_value playerObj = nullptr;
    napi_status status = napi_get_reference_value(env, playerRef_, &playerObj);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && playerObj != nullptr, nullptr, "napi_get_reference_value failed");
    AVPlayerNapi *player = nullptr;
    status = napi_unwrap(env, playerObj, reinterpret_cast<void **>(&player));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "napi_unwrap failed");
    return player;
}

void AVAdsControllerNapi::ReleasePlayer(napi_env env)
{
    if (playerInstance_ != nullptr) {
        playerInstance_->DisableAllAdsMediaSource();
    }
    AVPlayerNapi *player = nullptr;
    if (playerRef_ != nullptr) {
        napi_value playerObj = nullptr;
        napi_status status = napi_get_reference_value(env, playerRef_, &playerObj);
        if (status == napi_ok && playerObj != nullptr) {
            status = napi_unwrap(env, playerObj, reinterpret_cast<void **>(&player));
        }
    }
    if (player != nullptr) {
        player->ClearCallbackReference(AVPlayerEvent::EVENT_ADS_LOADING_ERROR);
        player->ClearCallbackReference(AVPlayerEvent::EVENT_ADS_STARTED);
        player->ClearCallbackReference(AVPlayerEvent::EVENT_ADS_SKIPPED);
        player->ClearCallbackReference(AVPlayerEvent::EVENT_ADS_COMPLETED);
    }
    if (playerRef_ != nullptr) {
        napi_delete_reference(env, playerRef_);
        playerRef_ = nullptr;
    }
    playerInstance_ = nullptr;
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
    if (status != napi_ok) {
        napi_delete_reference(env, constructor_);
        constructor_ = nullptr;
        MEDIA_LOGE("Failed to define static function createAVAdsController");
        return nullptr;
    }

    return exports;
}

napi_value AVAdsControllerNapi::CreateInstance(napi_env env, napi_value playerObj)
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

    controller->SetPlayer(env, playerObj);
    return instance;
}

napi_value AVAdsControllerNapi::JsCreateAVAdsController(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVAdsControllerNapi::createAVAdsController");
    MEDIA_LOGI("JsCreateAVAdsController In");

    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_status status = napi_create_promise(env, &deferred, &promise);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && deferred != nullptr, nullptr, "Failed to create promise");

    napi_value args[1] = { nullptr };
    size_t argCount = 1;
    napi_value jsThis = nullptr;
    status = napi_get_cb_info(env, info, &argCount, args, &jsThis, nullptr);
    if (status != napi_ok) {
        MEDIA_LOGE("failed to napi_get_cb_info");
        RejectPromise(env, deferred, ERR_ADS_PARAM_INVALID, "failed to napi_get_cb_info");
        return promise;
    }

    if (argCount < 1) {
        RejectPromise(env, deferred, ERR_ADS_PARAM_INVALID, "Invalid arguments, expected 1 (AVPlayer)");
        return promise;
    }

    napi_valuetype type = napi_undefined;
    status = napi_typeof(env, args[0], &type);
    if (status != napi_ok || type != napi_object) {
        RejectPromise(env, deferred, ERR_ADS_PARAM_INVALID, "First argument must be AVPlayer");
        return promise;
    }

    AVPlayerNapi *jsPlayer = nullptr;
    status = napi_unwrap(env, args[0], reinterpret_cast<void **>(&jsPlayer));
    if (status != napi_ok || jsPlayer == nullptr) {
        RejectPromise(env, deferred, ERR_ADS_PARAM_INVALID,
            "The player object corresponding to player does not exist or is invalid");
        return promise;
    }

    if (jsPlayer->GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        RejectPromise(env, deferred, ERR_ADS_PARAM_INVALID,
            "The player object corresponding to player does not exist or is invalid");
        return promise;
    }

    napi_value instance = CreateInstance(env, args[0]);
    if (instance == nullptr) {
        RejectPromise(env, deferred, ERR_ADS_PARAM_INVALID, "Failed to create AVAdsController");
        return promise;
    }

    napi_resolve_deferred(env, deferred, instance);
    return promise;
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
    (void)finalize;
    auto *controller = reinterpret_cast<AVAdsControllerNapi *>(nativeObject);
    if (controller != nullptr) {
        controller->ReleasePlayer(env);
        delete controller;
    }
}

void AVAdsControllerNapi::ExecuteAdsTask(napi_env env, void *data)
{
    (void)env;
    auto ctx = reinterpret_cast<AdsAsyncContext *>(data);
    CHECK_AND_RETURN_LOG(ctx != nullptr, "context is nullptr");
    CHECK_AND_RETURN_LOG(!ctx->errFlag, "errFlag is error");
    auto player = ctx->player;
    if (player == nullptr) {
        ctx->SignError(ERR_ADS_PARAM_INVALID, "player is nullptr");
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
        ctx->SignError(ERR_ADS_PARAM_INVALID, "async work status != napi_ok");
    }

    if (ctx->deferred == nullptr) {
        napi_delete_async_work(env, ctx->work);
        delete ctx;
        return;
    }

    if (ctx->errFlag) {
        RejectPromise(env, ctx->deferred, ctx->errCode, ctx->errMessage);
    } else {
        napi_value result = nullptr;
        napi_status strStatus = napi_create_string_utf8(env, ctx->outId.c_str(), ctx->outId.length(), &result);
        if (strStatus != napi_ok) {
            RejectPromise(env, ctx->deferred, ERR_ADS_PARAM_INVALID, "Failed to create result string");
        } else {
            napi_resolve_deferred(env, ctx->deferred, result);
        }
    }
    ctx->deferred = nullptr;
    napi_delete_async_work(env, ctx->work);
    delete ctx;
}

bool AVAdsControllerNapi::QueueAdsAsyncWork(napi_env env, AdsAsyncContext *ctx, const std::string &name)
{
    napi_value resource = nullptr;
    napi_status status = napi_create_string_utf8(env, name.c_str(), NAPI_AUTO_LENGTH, &resource);
    if (status != napi_ok) {
        MEDIA_LOGE("Failed to create async work resource string");
        RejectPromise(env, ctx->deferred, ERR_ADS_PARAM_INVALID, "Failed to create async work resource string");
        return false;
    }
    status = napi_create_async_work(env, nullptr, resource, ExecuteAdsTask, CompleteAdsTask,
        static_cast<void *>(ctx), &ctx->work);
    if (status != napi_ok) {
        MEDIA_LOGE("Failed to create async work");
        RejectPromise(env, ctx->deferred, ERR_ADS_PARAM_INVALID, "Failed to create async work");
        return false;
    }
    status = napi_queue_async_work_with_qos(env, ctx->work, napi_qos_user_initiated);
    if (status != napi_ok) {
        MEDIA_LOGE("Failed to queue async work");
        napi_delete_async_work(env, ctx->work);
        RejectPromise(env, ctx->deferred, ERR_ADS_PARAM_INVALID, "Failed to queue async work");
        return false;
    }
    return true;
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

    auto ctx = new (std::nothrow) AdsAsyncContext(env);
    CHECK_AND_RETURN_RET_LOG(ctx != nullptr, result, "Failed to allocate AdsAsyncContext");
    ON_SCOPE_EXIT(0) { delete ctx; };
    ctx->deferred = CommonNapi::CreatePromise(env, nullptr, result);
    CHECK_AND_RETURN_RET_LOG(ctx->deferred != nullptr, result, "Failed to create promise");

    ctx->player = controller->GetPlayerInstance();
    if (ctx->player == nullptr) {
        RejectPromise(env, ctx->deferred, ERR_ADS_PARAM_INVALID, "Player is null");
        return result;
    }
    ctx->opType = AdsAsyncContext::OpType::ADD;

    napi_valuetype type = napi_undefined;
    status = napi_typeof(env, argv[1], &type);
    if (argc < MIN_REQUIRED_ARGS || ctx->player == nullptr || status != napi_ok || type != napi_number) {
        RejectPromise(env, ctx->deferred, ERR_ADS_PARAM_INVALID, "Invalid arguments");
        return result;
    }
    napi_get_value_int64(env, argv[1], &ctx->startMs);
    auto srcTmp = MediaSourceNapi::GetMediaSource(env, argv[0]);
    if (srcTmp == nullptr) {
        RejectPromise(env, ctx->deferred, ERR_ADS_PARAM_INVALID, "Failed to get MediaSource");
        return result;
    }
    ctx->mediaSource = AVPlayerNapi::GetAVMediaSource(env, argv[0], srcTmp);
    if (ctx->mediaSource == nullptr) {
        RejectPromise(env, ctx->deferred, ERR_ADS_PARAM_INVALID, "Failed to convert MediaSource");
        return result;
    }

    if (!QueueAdsAsyncWork(env, ctx, "JsAddAdsMediaSource")) {
        return result;
    }
    CANCEL_SCOPE_EXIT_GUARD(0);
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

    std::shared_ptr<Player> playerInstance = controller->GetPlayerInstance();
    if (playerInstance == nullptr) {
        CommonNapi::ThrowError(env, ERR_ADS_PARAM_INVALID, "controller is released");
        return result;
    }

    if (argc < 1) {
        CommonNapi::ThrowError(env, ERR_ADS_PARAM_INVALID, "Invalid arguments");
        return result;
    }

    napi_valuetype type = napi_undefined;
    status = napi_typeof(env, argv[0], &type);
    if (status != napi_ok || type != napi_string) {
        CommonNapi::ThrowError(env, ERR_ADS_PARAM_INVALID, "Argument must be string");
        return result;
    }

    std::string adId = CommonNapi::GetStringArgument(env, argv[0]);
    int32_t ret = playerInstance->RemoveAdsMediaSource(adId);
    if (ret != MSERR_OK) {
        CommonNapi::ThrowError(env, ERR_ADS_PARAM_INVALID, "removeAdsMediaSource failed");
    }

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

    AVPlayerNapi *player = controller->GetPlayerNapi(env);
    std::shared_ptr<Player> playerInstance = controller->GetPlayerInstance();
    if (player == nullptr || playerInstance == nullptr) {
        MEDIA_LOGE("controller is released");
        return result;
    }

    if (player->GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        MEDIA_LOGE("current state is released, unsupport to skip");
        return result;
    }

    playerInstance->SkipCurrentAdsMediaSource();
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

    std::shared_ptr<Player> playerInstance = controller->GetPlayerInstance();
    if (playerInstance == nullptr) {
        MEDIA_LOGE("controller is released");
        return result;
    }

    playerInstance->DisableAllAdsMediaSource();
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

    controller->ReleasePlayer(env);

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

    AVPlayerNapi *player = controller->GetPlayerNapi(env);
    if (argc < 1) {
        MEDIA_LOGE("Invalid arguments, expected 1");
        return result;
    }

    napi_valuetype type = napi_undefined;
    status = napi_typeof(env, argv[0], &type);
    if (status != napi_ok || type != napi_function) {
        MEDIA_LOGE("Argument must be function");
        return result;
    }

    CHECK_AND_RETURN_RET_LOG(player != nullptr, result, "Player is null");
    if (player->GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        MEDIA_LOGE("current state is released");
        return result;
    }

    napi_ref ref = nullptr;
    status = napi_create_reference(env, argv[0], 1, &ref);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && ref != nullptr, result, "failed to create reference!");

    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, ref);
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

    AVPlayerNapi *player = controller->GetPlayerNapi(env);
    if (player != nullptr) {
        player->ClearCallbackReference(AVPlayerEvent::EVENT_ADS_LOADING_ERROR);
    }

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

    AVPlayerNapi *player = controller->GetPlayerNapi(env);
    if (argc < 1) {
        MEDIA_LOGE("Invalid arguments, expected 1");
        return result;
    }

    napi_valuetype type = napi_undefined;
    status = napi_typeof(env, argv[0], &type);
    if (status != napi_ok || type != napi_function) {
        MEDIA_LOGE("Argument must be function");
        return result;
    }

    CHECK_AND_RETURN_RET_LOG(player != nullptr, result, "Player is null");
    if (player->GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        MEDIA_LOGE("current state is released");
        return result;
    }

    napi_ref ref = nullptr;
    status = napi_create_reference(env, argv[0], 1, &ref);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && ref != nullptr, result, "failed to create reference!");

    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, ref);
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

    AVPlayerNapi *player = controller->GetPlayerNapi(env);
    if (player != nullptr) {
        player->ClearCallbackReference(AVPlayerEvent::EVENT_ADS_STARTED);
    }

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

    AVPlayerNapi *player = controller->GetPlayerNapi(env);
    if (argc < 1) {
        MEDIA_LOGE("Invalid arguments, expected 1");
        return result;
    }

    napi_valuetype type = napi_undefined;
    status = napi_typeof(env, argv[0], &type);
    if (status != napi_ok || type != napi_function) {
        MEDIA_LOGE("Argument must be function");
        return result;
    }

    CHECK_AND_RETURN_RET_LOG(player != nullptr, result, "Player is null");
    if (player->GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        MEDIA_LOGE("current state is released");
        return result;
    }

    napi_ref ref = nullptr;
    status = napi_create_reference(env, argv[0], 1, &ref);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && ref != nullptr, result, "failed to create reference!");

    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, ref);
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

    AVPlayerNapi *player = controller->GetPlayerNapi(env);
    if (player != nullptr) {
        player->ClearCallbackReference(AVPlayerEvent::EVENT_ADS_SKIPPED);
    }

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

    AVPlayerNapi *player = controller->GetPlayerNapi(env);
    if (argc < 1) {
        MEDIA_LOGE("Invalid arguments, expected 1");
        return result;
    }

    napi_valuetype type = napi_undefined;
    status = napi_typeof(env, argv[0], &type);
    if (status != napi_ok || type != napi_function) {
        MEDIA_LOGE("Argument must be function");
        return result;
    }

    CHECK_AND_RETURN_RET_LOG(player != nullptr, result, "Player is null");
    if (player->GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        MEDIA_LOGE("current state is released");
        return result;
    }

    napi_ref ref = nullptr;
    status = napi_create_reference(env, argv[0], 1, &ref);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && ref != nullptr, result, "failed to create reference!");

    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, ref);
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

    AVPlayerNapi *player = controller->GetPlayerNapi(env);
    if (player != nullptr) {
        player->ClearCallbackReference(AVPlayerEvent::EVENT_ADS_COMPLETED);
    }

    MEDIA_LOGI("JsOffAdsListenerAdsCompleted success");
    return result;
}

} // namespace Media
} // namespace OHOS
