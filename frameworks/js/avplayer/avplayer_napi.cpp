/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "avplayer_napi.h"
#include "avplayer_callback.h"
#include "media_errors.h"
#include "common_napi.h"
#include "js_common_utils.h"
#ifdef SUPPORT_AVPLAYER_DRM
#include "key_session_impl.h"
#endif
#ifdef SUPPORT_VIDEO
#include "surface_utils.h"
#endif
#include "string_ex.h"
#include "player_xcollie.h"
#include "media_dfx.h"
#ifdef SUPPORT_JSSTACK
#include "xpower_event_js.h"
#endif
#include "av_common.h"
#include "meta/video_types.h"
#include "media_source_napi.h"
#include "media_log.h"
#ifndef CROSS_PLATFORM
#include "ipc_skeleton.h"
#include "tokenid_kit.h"
#endif

using namespace OHOS::AudioStandard;

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_PLAYER, "AVPlayerNapi" };
    constexpr uint32_t MIN_ARG_COUNTS = 1;
    constexpr uint32_t MAX_ARG_COUNTS = 2;
    constexpr size_t ARRAY_ARG_COUNTS_TWO = 2;
    constexpr size_t ARRAY_ARG_COUNTS_THREE = 3;
    constexpr int32_t PLAY_RANGE_DEFAULT_VALUE = -1;
    constexpr int32_t SEEK_MODE_CLOSEST = 2;
    constexpr int32_t INDEX_A = 0;
    constexpr int32_t INDEX_B = 1;
    constexpr int32_t INDEX_C = 2;
    constexpr uint32_t TASK_TIME_LIMIT_MS = 2000; // ms
    constexpr size_t PARAM_COUNT_SINGLE = 1;
    constexpr int32_t API_VERSION_17 = 17;
    static int32_t g_apiVersion = -1;
    constexpr int32_t ARGS_TWO = 2;
    constexpr int32_t ARGS_THREE = 3;
    constexpr int32_t SEEK_CONTINUOUS_TS_ENUM_NUM = 3;
    constexpr int32_t SEI_MSG_PAYLOAD_TYPE_SUPPORT = 5;
    constexpr double RATE_DEFAULT_VALUE = 1.0;
}

namespace OHOS {
namespace Media {
thread_local napi_ref AVPlayerNapi::constructor_ = nullptr;
const std::string CLASS_NAME = "AVPlayer";

AVPlayerNapi::AVPlayerNapi()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " ctor", FAKE_POINTER(this));
}

AVPlayerNapi::~AVPlayerNapi()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " dtor", FAKE_POINTER(this));
}

napi_value AVPlayerNapi::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor staticProperty[] = {
        DECLARE_NAPI_STATIC_FUNCTION("createAVPlayer", JsCreateAVPlayer),
    };

    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("play", JsPlay),
        DECLARE_NAPI_FUNCTION("pause", JsPause),
        DECLARE_NAPI_FUNCTION("stop", JsStop),
        DECLARE_NAPI_FUNCTION("reset", JsReset),
        DECLARE_NAPI_FUNCTION("release", JsRelease),
        DECLARE_NAPI_FUNCTION("seek", JsSeek),
        DECLARE_NAPI_FUNCTION("setPlaybackRange", JsSetPlaybackRange),
        DECLARE_NAPI_FUNCTION("setSuperResolution", JsSetSuperResolution),
        DECLARE_NAPI_FUNCTION("setVideoWindowSize", JsSetVideoWindowSize),
        DECLARE_NAPI_FUNCTION("enableCameraPostprocessing", JsEnableCameraPostprocessing),
        DECLARE_NAPI_FUNCTION("on", JsSetOnCallback),
        DECLARE_NAPI_FUNCTION("off", JsClearOnCallback),
        DECLARE_NAPI_FUNCTION("setVolume", JsSetVolume),
        DECLARE_NAPI_FUNCTION("setLoudnessGain", JsSetLoudnessGain),
        DECLARE_NAPI_FUNCTION("setSpeed", JsSetSpeed),
        DECLARE_NAPI_FUNCTION("setPlaybackRate", JsSetPlaybackRate),
        DECLARE_NAPI_FUNCTION("getPlaybackRate", JsGetPlaybackRate),
        DECLARE_NAPI_FUNCTION("setMediaSource", JsSetMediaSource),
        DECLARE_NAPI_FUNCTION("setBitrate", JsSelectBitrate),
        DECLARE_NAPI_FUNCTION("getTrackDescription", JsGetTrackDescription),
        DECLARE_NAPI_FUNCTION("getSelectedTracks", JsGetSelectedTracks),
        DECLARE_NAPI_FUNCTION("selectTrack", JsSelectTrack),
        DECLARE_NAPI_FUNCTION("deselectTrack", JsDeselectTrack),
        DECLARE_NAPI_FUNCTION("getCurrentTrack", JsGetCurrentTrack),
        DECLARE_NAPI_FUNCTION("addSubtitleUrl", JsAddSubtitleUrl),
        DECLARE_NAPI_FUNCTION("addSubtitleFdSrc", JsAddSubtitleAVFileDescriptor),
        DECLARE_NAPI_FUNCTION("addSubtitleFromFd", JsAddSubtitleAVFileDescriptor),
        DECLARE_NAPI_FUNCTION("setDecryptionConfig", JsSetDecryptConfig),
        DECLARE_NAPI_FUNCTION("getMediaKeySystemInfos", JsGetMediaKeySystemInfos),
        DECLARE_NAPI_FUNCTION("setPlaybackStrategy", JsSetPlaybackStrategy),
        DECLARE_NAPI_FUNCTION("setMediaMuted", JsSetMediaMuted),
        DECLARE_NAPI_FUNCTION("getPlaybackInfo", JsGetPlaybackInfo),
        DECLARE_NAPI_FUNCTION("getPlaybackStatisticMetrics", JsGetPlaybackStatisticMetrics),
        DECLARE_NAPI_FUNCTION("isSeekContinuousSupported", JsIsSeekContinuousSupported),
        DECLARE_NAPI_FUNCTION("getPlaybackPosition", JsGetPlaybackPosition),
        DECLARE_NAPI_FUNCTION("forceLoadVideo", JsForceLoadVideo),
        DECLARE_NAPI_FUNCTION("getCurrentPresentationTimestamp", JsGetCurrentPresentationTimestamp),
        DECLARE_NAPI_FUNCTION("onMetricsEvent", JsSetOnMetricsEventCallback),
        DECLARE_NAPI_FUNCTION("offMetricsEvent", JsClearOnMetricsEventCallback),

        DECLARE_NAPI_WRITABLE_FUNCTION("prepare", JsPrepare),
        DECLARE_NAPI_WRITABLE_FUNCTION("addSubtitleFromUrl", JsAddSubtitleUrl),

        DECLARE_NAPI_GETTER_SETTER("url", JsGetUrl, JsSetUrl),
        DECLARE_NAPI_GETTER_SETTER("fdSrc", JsGetAVFileDescriptor, JsSetAVFileDescriptor),
        DECLARE_NAPI_GETTER_SETTER("dataSrc", JsGetDataSrc, JsSetDataSrc),
        DECLARE_NAPI_GETTER_SETTER("surfaceId", JsGetSurfaceID, JsSetSurfaceID),
        DECLARE_NAPI_GETTER_SETTER("loop", JsGetLoop, JsSetLoop),
        DECLARE_NAPI_GETTER_SETTER("videoScaleType", JsGetVideoScaleType, JsSetVideoScaleType),
        DECLARE_NAPI_GETTER_SETTER("audioInterruptMode", JsGetAudioInterruptMode, JsSetAudioInterruptMode),
        DECLARE_NAPI_GETTER_SETTER("audioRendererInfo", JsGetAudioRendererInfo, JsSetAudioRendererInfo),
        DECLARE_NAPI_GETTER_SETTER("privacyType", JsGetPrivacyType, JsSetPrivacyType),
        DECLARE_NAPI_GETTER_SETTER("audioEffectMode", JsGetAudioEffectMode, JsSetAudioEffectMode),

        DECLARE_NAPI_SETTER("enableStartFrameRateOpt", JsSetStartFrameRateOptEnabled),
        DECLARE_NAPI_GETTER("state", JsGetState),
        DECLARE_NAPI_GETTER("currentTime", JsGetCurrentTime),
        DECLARE_NAPI_GETTER("duration", JsGetDuration),
        DECLARE_NAPI_GETTER("width", JsGetWidth),
        DECLARE_NAPI_GETTER("height", JsGetHeight),
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

napi_value AVPlayerNapi::Constructor(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    size_t argCount = 0;
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argCount, nullptr, &jsThis, nullptr);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, result, "failed to napi_get_cb_info");

    AVPlayerNapi *jsPlayer = new(std::nothrow) AVPlayerNapi();
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to new AVPlayerNapi");

    jsPlayer->env_ = env;
    jsPlayer->player_ = PlayerFactory::CreatePlayer(PlayerProducer::NAPI);
    if (jsPlayer->player_ == nullptr) {
        delete jsPlayer;
        MEDIA_LOGE("failed to CreatePlayer");
        return result;
    }

    jsPlayer->taskQue_ = std::make_unique<TaskQueue>("OS_AVPlayerNapi");
    (void)jsPlayer->taskQue_->Start();

    jsPlayer->playerCb_ = std::make_shared<AVPlayerCallback>(env, jsPlayer);
    (void)jsPlayer->player_->SetPlayerCallback(jsPlayer->playerCb_);

    status = napi_wrap(env, jsThis, reinterpret_cast<void *>(jsPlayer),
        AVPlayerNapi::Destructor, nullptr, nullptr);
    if (status != napi_ok) {
        delete jsPlayer;
        MEDIA_LOGE("Failed to wrap native instance");
        return result;
    }

    MEDIA_LOGI("0x%{public}06" PRIXPTR " Constructor success", FAKE_POINTER(jsPlayer));
    return jsThis;
}

void AVPlayerNapi::Destructor(napi_env env, void *nativeObject, void *finalize)
{
    (void)env;
    (void)finalize;
    if (nativeObject != nullptr) {
        AVPlayerNapi *jsPlayer = reinterpret_cast<AVPlayerNapi *>(nativeObject);
        jsPlayer->ClearCallbackReference();
        std::thread([jsPlayer]() -> void {
            auto task = jsPlayer->ReleaseTask();
            if (task != nullptr) {
                MEDIA_LOGI("0x%{public}06" PRIXPTR " Destructor wait >>", FAKE_POINTER(jsPlayer));
                task->GetResult(); // sync release
                MEDIA_LOGI("0x%{public}06" PRIXPTR " Destructor wait <<", FAKE_POINTER(jsPlayer));
            }
            jsPlayer->WaitTaskQueStop();
            delete jsPlayer;
        }).detach();
    }
    MEDIA_LOGD("Destructor success");
}

bool AVPlayerNapi::IsSystemApp()
{
    static bool isSystemApp = false;
#ifndef CROSS_PLATFORM
    static std::once_flag once;
    std::call_once(once, [] {
        uint64_t tokenId = IPCSkeleton::GetSelfTokenID();
        isSystemApp = Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(tokenId);
    });
#endif
    return isSystemApp;
}

napi_value AVPlayerNapi::JsCreateAVPlayer(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::createAVPlayer");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGD("JsCreateAVPlayer In");

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

    auto ret = MediaAsyncContext::SendCompleteEvent(env, asyncContext.get(), napi_eprio_immediate);
    if (ret != napi_status::napi_ok) {
        MEDIA_LOGE("failed to SendEvent, ret = %{public}d", ret);
    } else {
        asyncContext.release();
    }
    MEDIA_LOGD("0x%{public}06" PRIXPTR " JsCreateAVPlayer Out", FAKE_POINTER(jsThis));
    return result;
}

std::shared_ptr<TaskHandler<TaskRet>> AVPlayerNapi::PrepareTask()
{
    auto task = std::make_shared<TaskHandler<TaskRet>>([this]() {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " Prepare Task In", FAKE_POINTER(this));
        std::unique_lock<std::mutex> lock(taskMutex_);
        auto state = GetCurrentState();
        if (state == AVPlayerState::STATE_INITIALIZED ||
            state == AVPlayerState::STATE_STOPPED) {
            int32_t ret = player_->PrepareAsync();
            if (ret != MSERR_OK) {
                auto errCode = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(ret));
                return TaskRet(errCode, "failed to prepare");
            }
            stopWait_ = false;
            stateChangeCond_.wait(lock, [this]() {
                return stopWait_.load() || isInterrupted_.load() || avplayerExit_;
            });

            if (GetCurrentState() == AVPlayerState::STATE_ERROR) {
                return TaskRet(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                    "failed to prepare, avplayer enter error status, please check error callback messages!");
            }
        } else if (state == AVPlayerState::STATE_PREPARED) {
            MEDIA_LOGI("current state is prepared, invalid operation");
        } else {
            return TaskRet(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                "current state is not stopped or initialized, unsupport prepare operation");
        }

        MEDIA_LOGI("0x%{public}06" PRIXPTR " Prepare Task Out", FAKE_POINTER(this));
        return TaskRet(MSERR_EXT_API9_OK, "Success");
    });

    (void)taskQue_->EnqueueTask(task);
    return task;
}

napi_value AVPlayerNapi::JsPrepare(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::prepare");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsPrepare In");

    auto promiseCtx = std::make_unique<AVPlayerContext>(env);
    napi_value args[1] = { nullptr };
    size_t argCount = 1;
    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstance");

    promiseCtx->callbackRef = CommonNapi::CreateReference(env, args[0]);
    promiseCtx->deferred = CommonNapi::CreatePromise(env, promiseCtx->callbackRef, result);
    auto state = jsPlayer->GetCurrentState();
    if (state != AVPlayerState::STATE_INITIALIZED &&
        state != AVPlayerState::STATE_STOPPED &&
        state != AVPlayerState::STATE_PREPARED) {
        promiseCtx->SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not stopped or initialized, unsupport prepare operation");
    } else {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " JsPrepare EnqueueTask In", FAKE_POINTER(jsPlayer));
        promiseCtx->asyncTask = jsPlayer->PrepareTask();
        MEDIA_LOGI("0x%{public}06" PRIXPTR " JsPrepare EnqueueTask out", FAKE_POINTER(jsPlayer));
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "JsPrepare", NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource,
        [](napi_env env, void *data) {
            MEDIA_LOGI("Wait Prepare Task Start");
            auto promiseCtx = reinterpret_cast<AVPlayerContext *>(data);
            CHECK_AND_RETURN_LOG(promiseCtx != nullptr, "promiseCtx is nullptr!");
            promiseCtx->CheckTaskResult(true, TASK_TIME_LIMIT_MS);
            MEDIA_LOGI("Wait Prepare Task End");
        },
        MediaAsyncContext::CompleteCallback, static_cast<void *>(promiseCtx.get()), &promiseCtx->work));
    napi_queue_async_work_with_qos(env, promiseCtx->work, napi_qos_user_initiated);
    promiseCtx.release();
    MEDIA_LOGI("0x%{public}06" PRIXPTR " JsPrepare Out", FAKE_POINTER(jsPlayer));
    return result;
}

std::shared_ptr<TaskHandler<TaskRet>> AVPlayerNapi::PlayTask()
{
    auto task = std::make_shared<TaskHandler<TaskRet>>([this]() {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " Play Task In", FAKE_POINTER(this));
        std::unique_lock<std::mutex> lock(taskMutex_);
        auto state = GetCurrentState();
        if (state == AVPlayerState::STATE_PREPARED ||
            state == AVPlayerState::STATE_PAUSED ||
            state == AVPlayerState::STATE_COMPLETED) {
            int32_t ret = player_->Play();
            if (ret != MSERR_OK) {
                auto errCode = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(ret));
                return TaskRet(errCode, "failed to Play");
            }
            stopWait_ = false;
            stateChangeCond_.wait(lock, [this]() {
                return stopWait_.load() || isInterrupted_.load() || avplayerExit_;
            });

            if (GetCurrentState() == AVPlayerState::STATE_ERROR) {
                return TaskRet(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                    "failed to play, avplayer enter error status, please check error callback messages!");
            }
        } else if (state == AVPlayerState::STATE_PLAYING) {
            if (IsSystemApp()) {
                player_->Seek(-1, SEEK_CONTINOUS);
            }
            MEDIA_LOGI("current state is playing, invalid operation");
        } else {
            return TaskRet(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                "current state is not prepared/paused/completed, unsupport play operation");
        }

        MEDIA_LOGI("0x%{public}06" PRIXPTR " Play Task Out", FAKE_POINTER(this));
        return TaskRet(MSERR_EXT_API9_OK, "Success");
    });
    (void)taskQue_->EnqueueTask(task);
    return task;
}

napi_value AVPlayerNapi::JsPlay(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::play");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsPlay In");

    auto promiseCtx = std::make_unique<AVPlayerContext>(env);
    napi_value args[1] = { nullptr };
    size_t argCount = 1;
    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstance");

    promiseCtx->callbackRef = CommonNapi::CreateReference(env, args[0]);
    promiseCtx->deferred = CommonNapi::CreatePromise(env, promiseCtx->callbackRef, result);
    auto state = jsPlayer->GetCurrentState();
    if (state != AVPlayerState::STATE_PREPARED &&
        state != AVPlayerState::STATE_PAUSED &&
        state != AVPlayerState::STATE_COMPLETED &&
        state != AVPlayerState::STATE_PLAYING) {
        promiseCtx->SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/paused/completed, unsupport play operation");
    } else if (state == AVPlayerState::STATE_COMPLETED && jsPlayer->IsLiveSource()) {
        promiseCtx->SignError(MSERR_EXT_API9_UNSUPPORT_CAPABILITY,
            "In live mode, replay not be allowed.");
    } else {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " JsPlay EnqueueTask In", FAKE_POINTER(jsPlayer));
        promiseCtx->asyncTask = jsPlayer->PlayTask();
        MEDIA_LOGI("0x%{public}06" PRIXPTR " JsPlay EnqueueTask Out", FAKE_POINTER(jsPlayer));
    }
#ifdef SUPPORT_JSSTACK
    HiviewDFX::ReportXPowerJsStackSysEvent(env, "STREAM_CHANGE", "SRC=Media");
#endif
    napi_value resource = nullptr;
    napi_create_string_utf8(env, "JsPlay", NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource,
        [](napi_env env, void *data) {
            MEDIA_LOGI("Wait JsPlay Task Start");
            auto promiseCtx = reinterpret_cast<AVPlayerContext *>(data);
            CHECK_AND_RETURN_LOG(promiseCtx != nullptr, "promiseCtx is nullptr!");
            promiseCtx->CheckTaskResult(true, TASK_TIME_LIMIT_MS);
            MEDIA_LOGI("Wait JsPlay Task End");
        },
        MediaAsyncContext::CompleteCallback, static_cast<void *>(promiseCtx.get()), &promiseCtx->work));
    napi_queue_async_work_with_qos(env, promiseCtx->work, napi_qos_user_initiated);
    promiseCtx.release();
    MEDIA_LOGI("0x%{public}06" PRIXPTR " JsPlay Out", FAKE_POINTER(jsPlayer));
    return result;
}

std::shared_ptr<TaskHandler<TaskRet>> AVPlayerNapi::PauseTask()
{
    auto task = std::make_shared<TaskHandler<TaskRet>>([this]() {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " Pause Task In", FAKE_POINTER(this));
        std::unique_lock<std::mutex> lock(taskMutex_);
        auto state = GetCurrentState();
        if (state == AVPlayerState::STATE_PLAYING) {
            int32_t ret = player_->Pause();
            if (ret != MSERR_OK) {
                auto errCode = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(ret));
                return TaskRet(errCode, "failed to Pause");
            }
            stopWait_ = false;
            stateChangeCond_.wait(lock, [this]() { return stopWait_.load() || avplayerExit_; });
        } else if (state == AVPlayerState::STATE_PAUSED) {
            MEDIA_LOGI("current state is paused, invalid operation");
        } else {
            return TaskRet(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                "current state is not playing, unsupport pause operation");
        }

        MEDIA_LOGI("0x%{public}06" PRIXPTR " Pause Task Out", FAKE_POINTER(this));
        return TaskRet(MSERR_EXT_API9_OK, "Success");
    });
    (void)taskQue_->EnqueueTask(task);
    return task;
}

napi_value AVPlayerNapi::JsPause(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::pause");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsPause In");

    auto promiseCtx = std::make_unique<AVPlayerContext>(env);
    napi_value args[1] = { nullptr };
    size_t argCount = 1;
    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstance");

    promiseCtx->callbackRef = CommonNapi::CreateReference(env, args[0]);
    promiseCtx->deferred = CommonNapi::CreatePromise(env, promiseCtx->callbackRef, result);
    auto state = jsPlayer->GetCurrentState();
    if (state != AVPlayerState::STATE_PLAYING &&
        state != AVPlayerState::STATE_PAUSED) {
        promiseCtx->SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not playing, unsupport pause operation");
    } else {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " JsPause EnqueueTask In", FAKE_POINTER(jsPlayer));
        promiseCtx->asyncTask = jsPlayer->PauseTask();
        MEDIA_LOGI("0x%{public}06" PRIXPTR " JsPause EnqueueTask Out", FAKE_POINTER(jsPlayer));
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "JsPause", NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource,
        [](napi_env env, void *data) {
            MEDIA_LOGI("Wait JsPause Task Start");
            auto promiseCtx = reinterpret_cast<AVPlayerContext *>(data);
            CHECK_AND_RETURN_LOG(promiseCtx != nullptr, "promiseCtx is nullptr!");
            promiseCtx->CheckTaskResult();
            MEDIA_LOGI("Wait JsPause Task End");
        },
        MediaAsyncContext::CompleteCallback, static_cast<void *>(promiseCtx.get()), &promiseCtx->work));
    napi_queue_async_work_with_qos(env, promiseCtx->work, napi_qos_user_initiated);
    promiseCtx.release();
    MEDIA_LOGI("0x%{public}06" PRIXPTR " JsPause Out", FAKE_POINTER(jsPlayer));
    return result;
}

std::shared_ptr<TaskHandler<TaskRet>> AVPlayerNapi::StopTask()
{
    auto task = std::make_shared<TaskHandler<TaskRet>>([this]() {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " Stop Task In", FAKE_POINTER(this));
        std::unique_lock<std::mutex> lock(taskMutex_);
        if (IsControllable()) {
            int32_t ret = player_->Stop();
            if (ret != MSERR_OK) {
                auto errCode = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(ret));
                return TaskRet(errCode, "failed to Stop");
            }
            stopWait_ = false;
            stateChangeCond_.wait(lock, [this]() { return stopWait_.load() || avplayerExit_; });
        } else if (GetCurrentState() == AVPlayerState::STATE_STOPPED) {
            MEDIA_LOGI("current state is stopped, invalid operation");
        }  else {
            return TaskRet(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                "current state is not prepared/playing/paused/completed, unsupport stop operation");
        }

        MEDIA_LOGI("0x%{public}06" PRIXPTR " Stop Task Out", FAKE_POINTER(this));
        return TaskRet(MSERR_EXT_API9_OK, "Success");
    });
    (void)taskQue_->EnqueueTask(task);
    return task;
}

napi_value AVPlayerNapi::JsStop(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::stop");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsStop In");

    auto promiseCtx = std::make_unique<AVPlayerContext>(env);
    napi_value args[1] = { nullptr };
    size_t argCount = 1;
    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstance");

    promiseCtx->callbackRef = CommonNapi::CreateReference(env, args[0]);
    promiseCtx->deferred = CommonNapi::CreatePromise(env, promiseCtx->callbackRef, result);
    auto state = jsPlayer->GetCurrentState();
    if (state == AVPlayerState::STATE_IDLE ||
        state == AVPlayerState::STATE_INITIALIZED ||
        state == AVPlayerState::STATE_RELEASED ||
        state == AVPlayerState::STATE_ERROR) {
        promiseCtx->SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, unsupport stop operation");
    } else {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " JsStop EnqueueTask In", FAKE_POINTER(jsPlayer));
        promiseCtx->asyncTask = jsPlayer->StopTask();
        MEDIA_LOGI("0x%{public}06" PRIXPTR " JsStop EnqueueTask Out", FAKE_POINTER(jsPlayer));
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "JsStop", NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource,
        [](napi_env env, void *data) {
            MEDIA_LOGI("Wait JsStop Task Start");
            auto promiseCtx = reinterpret_cast<AVPlayerContext *>(data);
            CHECK_AND_RETURN_LOG(promiseCtx != nullptr, "promiseCtx is nullptr!");
            promiseCtx->CheckTaskResult();
            MEDIA_LOGI("Wait JsStop Task End");
        },
        MediaAsyncContext::CompleteCallback, static_cast<void *>(promiseCtx.get()), &promiseCtx->work));
    napi_queue_async_work_with_qos(env, promiseCtx->work, napi_qos_user_initiated);
    promiseCtx.release();
    MEDIA_LOGI("0x%{public}06" PRIXPTR " JsStop Out", FAKE_POINTER(jsPlayer));
    return result;
}

std::shared_ptr<TaskHandler<TaskRet>> AVPlayerNapi::ResetTask()
{
    auto task = std::make_shared<TaskHandler<TaskRet>>([this]() {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " Reset Task In", FAKE_POINTER(this));
        PauseListenCurrentResource(); // Pause event listening for the current resource
        ResetUserParameters();
        {
            isInterrupted_.store(false);
            std::unique_lock<std::mutex> lock(taskMutex_);
            if (GetCurrentState() == AVPlayerState::STATE_RELEASED) {
                return TaskRet(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                    "current state is not playing, unsupport pause operation");
            } else if (GetCurrentState() == AVPlayerState::STATE_IDLE) {
                MEDIA_LOGI("current state is idle, invalid operation");
            } else {
                int32_t ret = player_->Reset();
                if (ret != MSERR_OK) {
                    auto errCode = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(ret));
                    return TaskRet(errCode, "failed to Reset");
                }
                stopWait_ = false;
                stateChangeCond_.wait(lock, [this]() { return stopWait_.load() || avplayerExit_; });
            }
        }
        MEDIA_LOGI("0x%{public}06" PRIXPTR " Reset Task Out", FAKE_POINTER(this));
        return TaskRet(MSERR_EXT_API9_OK, "Success");
    });
    (void)taskQue_->EnqueueTask(task, true); // CancelNotExecutedTask
    isInterrupted_.store(true);
    stateChangeCond_.notify_all();
    return task;
}

napi_value AVPlayerNapi::JsReset(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::reset");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsReset In");

    auto promiseCtx = std::make_unique<AVPlayerContext>(env);
    napi_value args[1] = { nullptr };
    size_t argCount = 1;
    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstance");
    promiseCtx->callbackRef = CommonNapi::CreateReference(env, args[0]);
    promiseCtx->deferred = CommonNapi::CreatePromise(env, promiseCtx->callbackRef, result);
    if (jsPlayer->GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        promiseCtx->SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is released, unsupport reset operation");
    } else {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " JsReset EnqueueTask In", FAKE_POINTER(jsPlayer));
        promiseCtx->asyncTask = jsPlayer->ResetTask();
        MEDIA_LOGI("0x%{public}06" PRIXPTR " JsReset EnqueueTask Out", FAKE_POINTER(jsPlayer));
        if (jsPlayer->dataSrcCb_ != nullptr) {
            jsPlayer->dataSrcCb_->ClearCallbackReference();
            jsPlayer->dataSrcCb_ = nullptr;
        }
        jsPlayer->isLiveStream_ = false;
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "JsReset", NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource,
        [](napi_env env, void *data) {
            auto promiseCtx = reinterpret_cast<AVPlayerContext *>(data);
            CHECK_AND_RETURN_LOG(promiseCtx != nullptr, "promiseCtx is nullptr!");
            if (promiseCtx->asyncTask != nullptr) {
                MEDIA_LOGI("Wait Reset Task Start");
                promiseCtx->CheckTaskResult();
                MEDIA_LOGI("Wait Reset Task Stop");
            }
        },
        MediaAsyncContext::CompleteCallback, static_cast<void *>(promiseCtx.get()), &promiseCtx->work));
    napi_queue_async_work_with_qos(env, promiseCtx->work, napi_qos_user_initiated);
    promiseCtx.release();
    MEDIA_LOGI("0x%{public}06" PRIXPTR " JsReset Out", FAKE_POINTER(jsPlayer));
    return result;
}

void AVPlayerNapi::WaitTaskQueStop()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " WaitTaskQueStop In", FAKE_POINTER(this));
    std::unique_lock<std::mutex> lock(mutex_);
    stopTaskQueCond_.wait(lock, [this]() { return taskQueStoped_; });
    MEDIA_LOGI("0x%{public}06" PRIXPTR " WaitTaskQueStop Out", FAKE_POINTER(this));
}

void AVPlayerNapi::StopTaskQue()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " StopTaskQue In", FAKE_POINTER(this));
    {
        std::unique_lock<std::mutex> lock(taskMutex_);
        avplayerExit_ = true;
    }
    stateChangeCond_.notify_all();
    taskQue_->Stop();
    std::unique_lock<std::mutex> lock(mutex_);
    taskQueStoped_ = true;
    stopTaskQueCond_.notify_all();
    MEDIA_LOGI("0x%{public}06" PRIXPTR " StopTaskQue Out", FAKE_POINTER(this));
}

std::shared_ptr<TaskHandler<TaskRet>> AVPlayerNapi::ReleaseTask()
{
    std::shared_ptr<TaskHandler<TaskRet>> task = nullptr;
    if (!isReleased_.load()) {
        task = std::make_shared<TaskHandler<TaskRet>>([this]() {
            MEDIA_LOGI("0x%{public}06" PRIXPTR " Release Task In", FAKE_POINTER(this));
            PauseListenCurrentResource(); // Pause event listening for the current resource
            ResetUserParameters();

            {
                std::lock_guard<std::mutex> lock(syncMutex_);
                if (player_ != nullptr) {
                    (void)player_->ReleaseSync();
                    player_ = nullptr;
                }
            }

            if (playerCb_ != nullptr) {
                playerCb_->Release();
            }
            MEDIA_LOGI("0x%{public}06" PRIXPTR " Release Task Out", FAKE_POINTER(this));
            std::thread([this] () -> void { this->StopTaskQue(); }).detach();
            return TaskRet(MSERR_EXT_API9_OK, "Success");
        });

        isReleased_.store(true);
        (void)taskQue_->EnqueueTask(task, true); // CancelNotExecutedTask
        if (taskQue_->IsTaskExecuting()) {
            MEDIA_LOGW("0x%{public}06" PRIXPTR " Cancel Executing Task, ReleaseTask Report Error", FAKE_POINTER(this));
            NotifyState(PlayerStates::PLAYER_STATE_ERROR);
        }
    }
    return task;
}

napi_value AVPlayerNapi::JsRelease(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::release");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsRelease In");

    auto promiseCtx = std::make_unique<AVPlayerContext>(env);
    napi_value args[1] = { nullptr };
    size_t argCount = 1;
    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstance");
    jsPlayer->isReadyReleased_.store(true);
    promiseCtx->callbackRef = CommonNapi::CreateReference(env, args[0]);
    promiseCtx->deferred = CommonNapi::CreatePromise(env, promiseCtx->callbackRef, result);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " JsRelease EnqueueTask In", FAKE_POINTER(jsPlayer));
    promiseCtx->asyncTask = jsPlayer->ReleaseTask();
    MEDIA_LOGI("0x%{public}06" PRIXPTR " JsRelease EnqueueTask Out", FAKE_POINTER(jsPlayer));
    if (jsPlayer->dataSrcCb_ != nullptr) {
        jsPlayer->dataSrcCb_->ClearCallbackReference();
        jsPlayer->dataSrcCb_ = nullptr;
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "JsRelease", NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource,
        [](napi_env env, void *data) {
            auto promiseCtx = reinterpret_cast<AVPlayerContext *>(data);
            CHECK_AND_RETURN_LOG(promiseCtx != nullptr, "promiseCtx is nullptr!");
            if (promiseCtx->asyncTask != nullptr) {
                MEDIA_LOGI("Wait Release Task Start");
                promiseCtx->CheckTaskResult();
                MEDIA_LOGI("Wait Release Task Stop");
            }
        },
        MediaAsyncContext::CompleteCallback, static_cast<void *>(promiseCtx.get()), &promiseCtx->work));
    napi_queue_async_work_with_qos(env, promiseCtx->work, napi_qos_user_initiated);
    promiseCtx.release();
    MEDIA_LOGI("0x%{public}06" PRIXPTR " JsRelease Out", FAKE_POINTER(jsPlayer));
    return result;
}

napi_value AVPlayerNapi::JsSeek(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::seek");
    MEDIA_LOGI("JsSeek in");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_value args[ARRAY_ARG_COUNTS_TWO] = { nullptr }; // args[0]:timeMs, args[1]:SeekMode
    size_t argCount = 2; // args[0]:timeMs, args[1]:SeekMode
    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstanceWithParameter");
    if (jsPlayer->IsLiveSource()) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_UNSUPPORT_CAPABILITY, "The stream is live stream, not support seek");
        return result;
    }
    napi_valuetype valueType = napi_undefined;
    if (argCount < 1 || napi_typeof(env, args[0], &valueType) != napi_ok || valueType != napi_number) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "seek time is not number");
        return result;
    }
    int32_t time = -1;
    napi_status status = napi_get_value_int32(env, args[0], &time);
    if (status != napi_ok || (time < 0 && argCount == 1)) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, please check seek time");
        return result;
    }
    int32_t mode = SEEK_PREVIOUS_SYNC;
    if (argCount > 1) {
        if (napi_typeof(env, args[1], &valueType) != napi_ok || valueType != napi_number) {
            jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "seek mode is not number");
            return result;
        }
        status = napi_get_value_int32(env, args[1], &mode);
        if (status != napi_ok || mode < SEEK_NEXT_SYNC || mode > SEEK_CONTINUOUS_TS_ENUM_NUM) {
            jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, please check seek mode");
            return result;
        }
        bool isNegativeTime = time < 0;
        bool isExitSeekContinuous = time == -1 && mode == SEEK_CONTINUOUS_TS_ENUM_NUM;
        if (isNegativeTime && !isExitSeekContinuous) {
            jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, please check seek time");
            return result;
        }
    }
    if (!jsPlayer->IsControllable()) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, unsupport seek operation");
        return result;
    }
    SeekEnqueueTask(jsPlayer, time, mode);
    return result;
}

PlayerSeekMode AVPlayerNapi::TransferSeekMode(int32_t mode)
{
    MEDIA_LOGI("Seek Task TransferSeekMode, mode: %{public}d", mode);
    PlayerSeekMode seekMode = PlayerSeekMode::SEEK_PREVIOUS_SYNC;
    switch (mode) {
        case 0: // Seek to the next sync frame of the given timestamp.
            seekMode = PlayerSeekMode::SEEK_NEXT_SYNC;
            break;
        case 1: // Seek to the previous sync frame of the given timestamp.
            seekMode = PlayerSeekMode::SEEK_PREVIOUS_SYNC;
            break;
        case 2: // Seek to the closest frame of the given timestamp. 2 refers SeekMode in @ohos.multimedia.media.d.ts
            seekMode = PlayerSeekMode::SEEK_CLOSEST;
            break;
        case 3: // Seek continous of the given timestamp. 3 refers SeekMode in @ohos.multimedia.media.d.ts
            seekMode = PlayerSeekMode::SEEK_CONTINOUS;
            break;
        default:
            seekMode = PlayerSeekMode::SEEK_PREVIOUS_SYNC;
            break;
    }
    return seekMode;
}

napi_value AVPlayerNapi::JsSetPlaybackRange(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::setPlaybackRange");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsSetPlaybackRange In");

    auto promiseCtx = std::make_unique<AVPlayerContext>(env);
    napi_value args[ARRAY_ARG_COUNTS_THREE] = { nullptr };
    size_t argCount = ARRAY_ARG_COUNTS_THREE; // args[0]:startTimeMs, args[1]:endTimeMs, args[2]:SeekMode
    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstance");

    promiseCtx->deferred = CommonNapi::CreatePromise(env, nullptr, result);
    napi_valuetype valueType = napi_undefined;
    int32_t startTimeMs = PLAY_RANGE_DEFAULT_VALUE;
    int32_t endTimeMs = PLAY_RANGE_DEFAULT_VALUE;
    int32_t mode = SEEK_PREVIOUS_SYNC;
    if (!jsPlayer->CanSetPlayRange()) {
        promiseCtx->SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not initialized/prepared/paused/stopped/completed, unsupport setPlaybackRange operation");
    } else if (argCount < ARRAY_ARG_COUNTS_TWO || napi_typeof(env, args[INDEX_A], &valueType) != napi_ok ||
        valueType != napi_number || napi_typeof(env, args[INDEX_B], &valueType) != napi_ok || valueType != napi_number
        || napi_get_value_int32(env, args[INDEX_A], &startTimeMs) != napi_ok ||
        napi_get_value_int32(env, args[INDEX_B], &endTimeMs) != napi_ok ||
        startTimeMs < PLAY_RANGE_DEFAULT_VALUE || endTimeMs < PLAY_RANGE_DEFAULT_VALUE) {
        promiseCtx->SignError(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, please check start or end time");
    } else if (argCount > ARRAY_ARG_COUNTS_TWO && (napi_typeof(env, args[INDEX_C], &valueType) != napi_ok ||
        valueType != napi_number || napi_get_value_int32(env, args[INDEX_C], &mode) != napi_ok ||
        mode < SEEK_PREVIOUS_SYNC || mode > SEEK_MODE_CLOSEST)) {
        promiseCtx->SignError(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, please check seek mode");
    } else {
        promiseCtx->asyncTask = jsPlayer->EqueueSetPlayRangeTask(startTimeMs, endTimeMs, mode);
        MEDIA_LOGI("0x%{public}06" PRIXPTR " JsSetPlaybackRange EnqueueTask Out", FAKE_POINTER(jsPlayer));
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "JsSetPlaybackRange", NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource,
        [](napi_env env, void *data) {
            MEDIA_LOGI("Wait JsSetPlaybackRange Task Start");
            auto promiseCtx = reinterpret_cast<AVPlayerContext *>(data);
            CHECK_AND_RETURN_LOG(promiseCtx != nullptr, "promiseCtx is nullptr!");
            promiseCtx->CheckTaskResult();
            MEDIA_LOGI("Wait JsSetPlaybackRange Task End");
        },
        MediaAsyncContext::CompleteCallback, static_cast<void *>(promiseCtx.get()), &promiseCtx->work));
    napi_queue_async_work_with_qos(env, promiseCtx->work, napi_qos_user_initiated);
    promiseCtx.release();
    MEDIA_LOGI("0x%{public}06" PRIXPTR " JsSetPlaybackRange Out", FAKE_POINTER(jsPlayer));
    return result;
}

std::shared_ptr<TaskHandler<TaskRet>> AVPlayerNapi::EqueueSetPlayRangeTask(int32_t start, int32_t end, int32_t mode)
{
    auto task = std::make_shared<TaskHandler<TaskRet>>([this, start, end, mode]() {
        std::unique_lock<std::mutex> lock(taskMutex_);
        MEDIA_LOGI("0x%{public}06" PRIXPTR " JsSetPlaybackRange Task In", FAKE_POINTER(this));
        if (player_ != nullptr) {
            auto ret = player_->SetPlayRangeWithMode(start, end, TransferSeekMode(mode));
            if (ret != MSERR_OK) {
                auto errCode = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(ret));
                return TaskRet(errCode, "failed to setPlaybackRange");
            }
        }
        MEDIA_LOGI("0x%{public}06" PRIXPTR " JsSetPlaybackRange Task Out", FAKE_POINTER(this));
        return TaskRet(MSERR_EXT_API9_OK, "Success");
    });
    (void)taskQue_->EnqueueTask(task);
    return task;
}

PlayerSwitchMode AVPlayerNapi::TransferSwitchMode(int32_t mode)
{
    MEDIA_LOGI("Seek Task TransferSeekMode, mode: %{public}d", mode);
    PlayerSwitchMode switchMode = PlayerSwitchMode::SWITCH_CLOSEST;
    switch (mode) {
        case 0:
            switchMode = PlayerSwitchMode::SWITCH_SMOOTH;
            break;
        case 1:
            switchMode = PlayerSwitchMode::SWITCH_SEGMENT;
            break;
        default:
            break;
    }
    return switchMode;
}

napi_value AVPlayerNapi::JsSetSpeed(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::setSpeed");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsSetSpeed In");

    napi_value args[1] = { nullptr };
    size_t argCount = 1; // setSpeed(speed: number)
    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstanceWithParameter");

    if (jsPlayer->IsLiveSource()) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_UNSUPPORT_CAPABILITY, "The stream is live stream, not support speed");
        return result;
    }

    napi_valuetype valueType = napi_undefined;
    if (argCount < 1 || napi_typeof(env, args[0], &valueType) != napi_ok || valueType != napi_number) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "speed mode is not number");
        return result;
    }

    int32_t mode = SPEED_FORWARD_1_00_X;
    napi_status status = napi_get_value_int32(env, args[0], &mode);
    if (status != napi_ok || mode < SPEED_FORWARD_0_75_X || mode > SPEED_FORWARD_4_00_X ||
        (mode == SPEED_FORWARD_4_00_X && !IsSystemApp())) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER,
            "invalid parameters, please check the speed mode");
        return result;
    }

    if (!jsPlayer->IsControllable()) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, unsupport speed operation");
        return result;
    }

    auto task = std::make_shared<TaskHandler<void>>([jsPlayer, mode]() {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " Speed Task In", FAKE_POINTER(jsPlayer));
        if (jsPlayer->player_ != nullptr) {
            (void)jsPlayer->player_->SetPlaybackSpeed(static_cast<PlaybackRateMode>(mode));
        }
        MEDIA_LOGI("0x%{public}06" PRIXPTR " Speed Task Out", FAKE_POINTER(jsPlayer));
    });
    MEDIA_LOGI("0x%{public}06" PRIXPTR " JsSetSpeed EnqueueTask In", FAKE_POINTER(jsPlayer));
    (void)jsPlayer->taskQue_->EnqueueTask(task);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " JsSetSpeed Out", FAKE_POINTER(jsPlayer));
    return result;
}

napi_value AVPlayerNapi::JsSetPlaybackRate(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::setRate");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsSetRate In");

    napi_value args[1] = { nullptr };
    size_t argCount = 1;
    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstanceWithParameter");

    if (jsPlayer->IsLiveSource()) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "The stream is live stream, not support rate");
        return result;
    }

    napi_valuetype valueType = napi_undefined;
    if (argCount < 1 || napi_typeof(env, args[0], &valueType) != napi_ok || valueType != napi_number) {
        jsPlayer->OnErrorCb(MSERR_EXT_API20_PARAM_ERROR_OUT_OF_RANGE, "rate is not number");
        return result;
    }

    double rate = RATE_DEFAULT_VALUE;
    napi_status status = napi_get_value_double(env, args[0], &rate);
    if (status != napi_ok || !jsPlayer->IsRateValid(rate)) {
        jsPlayer->OnErrorCb(MSERR_EXT_API20_PARAM_ERROR_OUT_OF_RANGE,
            "invalid parameters, please check the rate");
        return result;
    }

    if (!jsPlayer->IsControllable()) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, unsupport rate operation");
        return result;
    }

    auto task = std::make_shared<TaskHandler<void>>([jsPlayer, rate]() {
        if (jsPlayer->player_ != nullptr) {
            (void)jsPlayer->player_->SetPlaybackRate(static_cast<float>(rate));
        }
    });
    MEDIA_LOGD("0x%{public}06" PRIXPTR " JsSetRate EnqueueTask In", FAKE_POINTER(jsPlayer));
    if (jsPlayer->player_ != nullptr) {
        (void)jsPlayer->taskQue_->EnqueueTask(task);
    }
    MEDIA_LOGD("0x%{public}06" PRIXPTR " JsSetRate Out", FAKE_POINTER(jsPlayer));
    return result;
}

napi_value AVPlayerNapi::JsGetPlaybackRate(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::getRate");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsGetRate In");

    auto promiseCtx = std::make_unique<AVPlayerContext>(env);
    napi_value args[1] = { nullptr };
    size_t argCount = 1;
    promiseCtx->napi = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    promiseCtx->callbackRef = CommonNapi::CreateReference(env, args[0]);
    promiseCtx->deferred = CommonNapi::CreatePromise(env, promiseCtx->callbackRef, result);

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "JsGetPlaybackRate", NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource,
        [](napi_env env, void *data) {
            auto promiseCtx = reinterpret_cast<AVPlayerContext *>(data);
            CHECK_AND_RETURN_LOG(promiseCtx != nullptr, "promiseCtx is nullptr!");
            auto jsPlayer = promiseCtx->napi;
            float rate = RATE_DEFAULT_VALUE;
            jsPlayer->player_->GetPlaybackRate(rate);
            promiseCtx->JsResult = std::make_unique<MediaJsResultDouble>(rate);
        },
        MediaAsyncContext::CompleteCallback, static_cast<void *>(promiseCtx.get()), &promiseCtx->work));
    napi_queue_async_work_with_qos(env, promiseCtx->work, napi_qos_user_initiated);
    promiseCtx.release();
    MEDIA_LOGD("JsGetRate Out");
    return result;
}

napi_value AVPlayerNapi::JsSetVolume(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::setVolume");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsSetVolume In");

    napi_value args[1] = { nullptr };
    size_t argCount = 1; // setVolume(vol: number)
    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstanceWithParameter");

    if (jsPlayer->playerCb_->isSetVolume_) {
        MEDIA_LOGI("SetVolume is processing, skip this task until onVolumeChangedCb");
    }
    jsPlayer->playerCb_->isSetVolume_ = true;
    
    napi_valuetype valueType = napi_undefined;
    if (argCount < 1 || napi_typeof(env, args[0], &valueType) != napi_ok || valueType != napi_number) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "setVolume level is not number");
        return result;
    }

    double volumeLevel = 1.0f;
    napi_status status = napi_get_value_double(env, args[0], &volumeLevel);
    if (status != napi_ok || volumeLevel < 0.0f || volumeLevel > 1.0f) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, check volume level");
        return result;
    }

    if (!jsPlayer->IsControllable()) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, unsupport volume operation");
        return result;
    }
#ifdef SUPPORT_JSSTACK
    HiviewDFX::ReportXPowerJsStackSysEvent(env, "VOLUME_CHANGE", "SRC=Media");
#endif
    auto task = std::make_shared<TaskHandler<void>>([jsPlayer, volumeLevel]() {
        MEDIA_LOGD("SetVolume Task");
        if (jsPlayer->player_ != nullptr) {
            (void)jsPlayer->player_->SetVolume(volumeLevel, volumeLevel);
        }
    });
    (void)jsPlayer->taskQue_->EnqueueTask(task);
    MEDIA_LOGI("JsSetVolume Out");
    return result;
}

napi_value AVPlayerNapi::JsSelectBitrate(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::setBitrate");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsSelectBitrate In");

    napi_value args[1] = { nullptr };
    size_t argCount = 1; // selectBitrate(bitRate: number)
    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstanceWithParameter");

    napi_valuetype valueType = napi_undefined;
    if (argCount < 1 || napi_typeof(env, args[0], &valueType) != napi_ok || valueType != napi_number) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "selectBitrate is not number");
        return result;
    }

    int32_t bitrate = 0;
    napi_status status = napi_get_value_int32(env, args[0], &bitrate);
    if (status != napi_ok || bitrate < 0) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, please check the input bitrate");
        return result;
    }

    if (!jsPlayer->IsControllable()) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, unsupport select bitrate operation");
        return result;
    }

    auto task = std::make_shared<TaskHandler<void>>([jsPlayer, bitrate]() {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " JsSelectBitrate Task In", FAKE_POINTER(jsPlayer));
        if (jsPlayer->player_ != nullptr) {
            (void)jsPlayer->player_->SelectBitRate(static_cast<uint32_t>(bitrate));
        }
        MEDIA_LOGI("0x%{public}06" PRIXPTR " JsSelectBitrate Task Out", FAKE_POINTER(jsPlayer));
    });
    MEDIA_LOGI("0x%{public}06" PRIXPTR " JsSelectBitrate EnqueueTask In", FAKE_POINTER(jsPlayer));
    (void)jsPlayer->taskQue_->EnqueueTask(task);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " JsSelectBitrate Out", FAKE_POINTER(jsPlayer));
    return result;
}

void AVPlayerNapi::AddSubSource(std::string url)
{
    MEDIA_LOGI("input url is %{private}s!", url.c_str());
    bool isFd = (url.find("fd://") != std::string::npos) ? true : false;
    bool isNetwork = (url.find("http") != std::string::npos) ? true : false;
    if (isNetwork) {
        auto task = std::make_shared<TaskHandler<void>>([this, url]() {
            MEDIA_LOGI("AddSubtitleNetworkSource Task");
            if (player_ != nullptr) {
                if (player_->AddSubSource(url) != MSERR_OK) {
                    OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "failed to AddSubtitleNetworkSource");
                }
            }
        });
        (void)taskQue_->EnqueueTask(task);
    } else if (isFd) {
        const std::string fdHead = "fd://";
        std::string inputFd = url.substr(fdHead.size());
        int32_t fd = -1;
        if (!StrToInt(inputFd, fd) || fd < 0) {
            OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER,
                "invalid parameters, The input parameter is not a fd://+numeric string");
            return;
        }

        auto task = std::make_shared<TaskHandler<void>>([this, fd]() {
            MEDIA_LOGI("AddSubtitleFdSource Task");
            if (player_ != nullptr) {
                if (player_->AddSubSource(fd, 0, -1) != MSERR_OK) {
                    OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "failed to AddSubtitleFdSource");
                }
            }
        });
        (void)taskQue_->EnqueueTask(task);
    } else {
        OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER,
            "invalid parameters, The input parameter is not fd:// or network address");
    }
}

napi_value AVPlayerNapi::JsAddSubtitleUrl(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::addSubtitleUrl");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsAddSubtitleUrl In");

    napi_value args[1] = { nullptr };
    size_t argCount = 1; // addSubtitleUrl(url: string)
    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstanceWithParameter");

    napi_valuetype valueType = napi_undefined;
    if (argCount < 1 || napi_typeof(env, args[0], &valueType) != napi_ok || valueType != napi_string) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "url is not string");
        return result;
    }

    // get subUrl from js
    std::string subUrl = CommonNapi::GetStringArgument(env, args[0]);
    jsPlayer->AddSubSource(subUrl);

    MEDIA_LOGI("JsAddSubtitleUrl Out");
    return result;
}

napi_value AVPlayerNapi::JsAddSubtitleAVFileDescriptor(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_value args[3] = { nullptr };
    size_t argCount = 3; // url: string
    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstanceWithParameter");
    int32_t subtitleFd = -1;
    napi_status status = napi_get_value_int32(env, args[0], &subtitleFd);
    if (status != napi_ok) {
        MEDIA_LOGE("JsAddSubtitleAVFileDescriptor status != napi_ok");
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER,
            "invalid parameters, please check JsAddSubtitleAVFileDescriptor");
        return result;
    }
    int64_t offset = -1;
    napi_status status_offset = napi_get_value_int64(env, args[1], &offset);
    if (status_offset != napi_ok) {
        MEDIA_LOGI("JsAddSubtitleAVFileDescriptor status_offset != napi_ok");
        offset = 0;
    }
    int64_t length = -1;
    napi_status status_length = napi_get_value_int64(env, args[2], &length);
    if (status_length != napi_ok) {
        MEDIA_LOGI("JsAddSubtitleAVFileDescriptor status_length != napi_ok");
        length = 0;
    }
    auto task = std::make_shared<TaskHandler<void>>([jsPlayer, subtitleFd, offset, length]() {
        if (jsPlayer->player_ != nullptr) {
            if (jsPlayer->player_->AddSubSource(subtitleFd, offset, length) != MSERR_OK) {
                jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "failed to AddSubtitleAVFileDescriptor");
            }
        }
    });
    (void)jsPlayer->taskQue_->EnqueueTask(task);
    MEDIA_LOGI("JsAddSubtitleAVFileDescriptor Out");
    return result;
}

void AVPlayerNapi::SetSource(std::string url)
{
    bool isFd = (url.find("fd://") != std::string::npos) ? true : false;
    bool isNetwork = (url.find("http") != std::string::npos) ? true : false;
    if (isNetwork) {
        EnqueueNetworkTask(url);
    } else if (isFd) {
        std::string inputFd = url.substr(sizeof("fd://") - 1);
        int32_t fd = -1;
        if (!StrToInt(inputFd, fd) || fd < 0) {
            OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER,
                      "invalid parameters, The input parameter is not a fd://+numeric string");
            return;
        }
        EnqueueFdTask(fd);
    } else {
        OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER,
            "invalid parameters, The input parameter is not fd:// or network address");
    }
}

void AVPlayerNapi::EnqueueNetworkTask(const std::string url)
{
    auto task = std::make_shared<TaskHandler<void>>([this, url]() {
        std::unique_lock<std::mutex> lock(taskMutex_);
        auto state = GetCurrentState();
        if (state != AVPlayerState::STATE_IDLE) {
            QueueOnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is not idle, unsupport set url");
            return;
        }
        if (player_ != nullptr) {
            if (player_->SetSource(url) != MSERR_OK) {
                QueueOnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "failed to SetSourceNetWork");
                return;
            }
            stopWait_ = false;
            stateChangeCond_.wait(lock, [this]() { return stopWait_.load() || avplayerExit_; });
            MEDIA_LOGI("0x%{public}06" PRIXPTR " Set source network out", FAKE_POINTER(this));
        }
    });
    (void)taskQue_->EnqueueTask(task);
}

void AVPlayerNapi::EnqueueFdTask(const int32_t fd)
{
    auto task = std::make_shared<TaskHandler<void>>([this, fd]() {
        std::unique_lock<std::mutex> lock(taskMutex_);
        auto state = GetCurrentState();
        if (state != AVPlayerState::STATE_IDLE) {
            QueueOnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is not idle, unsupport set source fd");
            return;
        }
        if (player_ != nullptr) {
            if (player_->SetSource(fd, 0, -1) != MSERR_OK) {
                QueueOnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "failed to SetSourceFd");
                return;
            }
            stopWait_ = false;
            stateChangeCond_.wait(lock, [this]() { return stopWait_.load() || avplayerExit_; });
            MEDIA_LOGI("Set source fd out");
        }
    });
    (void)taskQue_->EnqueueTask(task);
}

void AVPlayerNapi::QueueOnErrorCb(MediaServiceExtErrCodeAPI9 errorCode, const std::string &errorMsg)
{
    CHECK_AND_RETURN(!isReleased_.load());
    auto task = std::make_shared<TaskHandler<void>>([this, errorCode, errorMsg] {
        OnErrorCb(errorCode, errorMsg);
    });
    (void)taskQue_->EnqueueTask(task);
}

napi_value AVPlayerNapi::JsSetUrl(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::set url");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGD("JsSetUrl In");

    napi_value args[1] = { nullptr };
    size_t argCount = 1; // url: string
    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstanceWithParameter");

    if (jsPlayer->GetCurrentState() != AVPlayerState::STATE_IDLE) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is not idle, unsupport set url");
        return result;
    }

    jsPlayer->StartListenCurrentResource(); // Listen to the events of the current resource
    napi_valuetype valueType = napi_undefined;
    if (argCount < 1 || napi_typeof(env, args[0], &valueType) != napi_ok || valueType != napi_string) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "url is not string");
        return result;
    }

    // get url from js
    jsPlayer->url_ = CommonNapi::GetStringArgument(env, args[0]);
    MEDIA_LOGD("JsSetUrl url: %{private}s", jsPlayer->url_.c_str());
    jsPlayer->SetSource(jsPlayer->url_);

    MEDIA_LOGI("0x%{public}06" PRIXPTR " JsSetUrl Out", FAKE_POINTER(jsPlayer));
    return result;
}

napi_value AVPlayerNapi::JsSetStartFrameRateOptEnabled(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::SetStartFrameRateOptEnabled");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGD("JsSetStartFrameRateOptEnabled");

    napi_value args[1] = { nullptr };
    size_t argCount = 1; // enable: bool
    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstanceWithParameter");

    napi_valuetype valueType = napi_undefined;
    if (argCount < 1 || napi_typeof(env, args[0], &valueType) != napi_ok || valueType != napi_boolean) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "enableStartFrameRateOpt is not napi_boolean");
        return result;
    }

    napi_status status = napi_get_value_bool(env, args[0], &jsPlayer->enabled_);
    if (status != napi_ok) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER,
            "invalid parameters, please check the input enableStartFrameRateOpt");
        return result;
    }

    if (!IsSystemApp()) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER,
            "invalid parameters, please dont't set");
        return result;
    }

    auto task = std::make_shared<TaskHandler<void>>([jsPlayer]() {
        MEDIA_LOGD("SetStartFrameRateOptEnabled Task");
        if (jsPlayer->player_ != nullptr) {
            (void)jsPlayer->player_->SetStartFrameRateOptEnabled(jsPlayer->enabled_);
        }
    });
    (void)jsPlayer->taskQue_->EnqueueTask(task);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " SetStartFrameRateOptEnabled Out", FAKE_POINTER(jsPlayer));
    return result;
}

#ifdef SUPPORT_AVPLAYER_DRM
napi_value AVPlayerNapi::JsSetDecryptConfig(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::JsSetDecryptConfig");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsSetDecryptConfig In");
    napi_value args[ARRAY_ARG_COUNTS_TWO] = { nullptr }; // args[0]:MediaKeySession, args[1]:svp
    size_t argCount = 2; // args[0]:int64, args[1]:bool
    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstanceWithParameter");
    bool svp = 0;
    napi_status status = napi_get_value_bool(env, args[1], &svp);
    if (status != napi_ok) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "secureVideoPath type should be boolean.");
        return result;
    }
    napi_value sessionObj;
    status = napi_coerce_to_object(env, args[0], &sessionObj);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, result, "JsSetDecryptConfig get sessionObj failure!");

    napi_valuetype valueType;
    if (argCount < 1 || napi_typeof(env, sessionObj, &valueType) != napi_ok || valueType != napi_object) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "mediaKeySession should be drm.MediaKeySession.");
        return result;
    }
    napi_value nativePointer = nullptr;
    std::string type = "MediaKeySessionNative";
    bool exist = false;
    status = napi_has_named_property(env, sessionObj, type.c_str(), &exist);

    CHECK_AND_RETURN_RET_LOG(status == napi_ok && exist, result, "can not find %{public}s property", type.c_str());
    CHECK_AND_RETURN_RET_LOG(napi_get_named_property(env, sessionObj, type.c_str(), &nativePointer) == napi_ok,
        result, "get %{public}s property fail", type.c_str());

    int64_t nativePointerInt;
    CHECK_AND_RETURN_RET_LOG(napi_get_value_int64(env, nativePointer, &nativePointerInt) == napi_ok, result,
        "get %{public}s property value fail", type.c_str());
    DrmStandard::MediaKeySessionImpl* keySessionImpl =
        reinterpret_cast<DrmStandard::MediaKeySessionImpl*>(nativePointerInt);
    if (keySessionImpl != nullptr) {
        sptr<DrmStandard::IMediaKeySessionService> keySessionServiceProxy =
            keySessionImpl->GetMediaKeySessionServiceProxy();
        MEDIA_LOGD("And it's count is: %{public}d", keySessionServiceProxy->GetSptrRefCount());
        {
            std::lock_guard<std::mutex> lock(jsPlayer->syncMutex_);
            CHECK_AND_RETURN_RET_LOG((jsPlayer->player_ != nullptr), result, "JsSetDecryptConfig player_ nullptr");
            (void)jsPlayer->player_->SetDecryptConfig(keySessionServiceProxy, svp);
        }
    } else {
        MEDIA_LOGE("SetDecryptConfig keySessionImpl is nullptr!");
    }
    return result;
}
#else
napi_value AVPlayerNapi::JsSetDecryptConfig(napi_env env, napi_callback_info info)
{
    MEDIA_LOGI("JsSetDecryptConfig is not surpport.");
    (void)env;
    (void)info;
    return nullptr;
}
#endif

napi_value AVPlayerNapi::JsGetMediaKeySystemInfos(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::JsGetMediaKeySystemInfos");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsGetMediaKeySystemInfos In");

    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstance(env, info);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstance");
    CHECK_AND_RETURN_RET_LOG(!jsPlayer->localDrmInfos_.empty(), result, "localDrmInfo is empty");

    uint32_t index = 0;
    napi_value napiMap;
    napi_status status = napi_create_array_with_length(env, jsPlayer->localDrmInfos_.size(), &napiMap);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, result, "create napi array failed");

    for (auto item : jsPlayer->localDrmInfos_) {
        napi_value jsObject;
        napi_value jsUuid;
        napi_value jsPssh;
        napi_create_object(env, &jsObject);
        napi_create_string_utf8(env, item.first.c_str(), NAPI_AUTO_LENGTH, &jsUuid);
        napi_set_named_property(env, jsObject, "uuid", jsUuid);

        status = napi_create_array_with_length(env, item.second.size(), &jsPssh);
        CHECK_AND_RETURN_RET_LOG(status == napi_ok, result, "create napi array failed");
        for (uint32_t i = 0; i < item.second.size(); i++) {
            napi_value number = nullptr;
            (void)napi_create_uint32(env, item.second[i], &number);
            (void)napi_set_element(env, jsPssh, i, number);
        }
        napi_set_named_property(env, jsObject, "pssh", jsPssh);
        napi_set_element(env, napiMap, index, jsObject);
        index++;
    }

    return napiMap;
}

napi_value AVPlayerNapi::JsGetPlaybackStatisticMetrics(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::JsGetPlaybackStatisticMetrics");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsGetPlaybackStatisticMetrics In");

    auto promiseCtx = std::make_unique<AVPlayerContext>(env);
    promiseCtx->napi = AVPlayerNapi::GetJsInstance(env, info);
    CHECK_AND_RETURN_RET_LOG(promiseCtx->napi != nullptr, result, "failed to GetJsInstance");
    promiseCtx->deferred = CommonNapi::CreatePromise(env, nullptr, result);
    // async work
    napi_value resource = nullptr;
    napi_create_string_utf8(env, "JsGetPlaybackStatisticMetrics", NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resource,
        [](napi_env env, void *data) {
            MEDIA_LOGI("JsGetPlaybackStatisticMetrics Task");
            auto promiseCtx = reinterpret_cast<AVPlayerContext *>(data);
            CHECK_AND_RETURN_LOG(promiseCtx != nullptr, "promiseCtx is nullptr!");

            auto jsPlayer = promiseCtx->napi;
            if (jsPlayer == nullptr) {
                return promiseCtx->SignError(
                    MSERR_EXT_API9_OPERATE_NOT_PERMIT, "avplayer is deconstructed");
            }

            Format &playbackStatisticMetrics = jsPlayer->PlaybackStatisticMetrics_;
            if (jsPlayer->CanGetPlaybackStatisticMetrics() && jsPlayer->player_ != nullptr) {
                (void)jsPlayer->player_->GetPlaybackStatisticMetrics(playbackStatisticMetrics);
            } else {
                return promiseCtx->SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                    "current state is not prepared/playing/paused/completed/stopped, "
                    "unsupport get playback statistics metrics");
            }
            promiseCtx->JsResult = std::make_unique<AVCodecJsResultFormat>(playbackStatisticMetrics);
        },
        MediaAsyncContext::CompleteCallback, static_cast<void *>(promiseCtx.get()), &promiseCtx->work));
    napi_queue_async_work_with_qos(env, promiseCtx->work, napi_qos_user_initiated);
    promiseCtx.release();
    MEDIA_LOGI("JSGetPlaybackStatisticMetrics Out");
    return result;
}

napi_value AVPlayerNapi::JsGetPlaybackInfo(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::JsGetPlaybackInfo");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("GetPlaybackInfo In");

    auto promiseCtx = std::make_unique<AVPlayerContext>(env);
    promiseCtx->napi = AVPlayerNapi::GetJsInstance(env, info);
    CHECK_AND_RETURN_RET_LOG(promiseCtx->napi != nullptr, result, "failed to GetJsInstance");
    promiseCtx->deferred = CommonNapi::CreatePromise(env, nullptr, result);
    // async work
    napi_value resource = nullptr;
    napi_create_string_utf8(env, "JsGetPlaybackInfo", NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource,
        [](napi_env env, void *data) {
            MEDIA_LOGI("GetPlaybackInfo Task");
            auto promiseCtx = reinterpret_cast<AVPlayerContext *>(data);
            CHECK_AND_RETURN_LOG(promiseCtx != nullptr, "promiseCtx is nullptr!");

            auto jsPlayer = promiseCtx->napi;
            if (jsPlayer == nullptr) {
                return promiseCtx->SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "avplayer is deconstructed");
            }

            Format &playbackInfo = jsPlayer->playbackInfo_;
            if (jsPlayer->IsControllable() && jsPlayer->player_ != nullptr) {
                (void)jsPlayer->player_->GetPlaybackInfo(playbackInfo);
            } else {
                return promiseCtx->SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                    "current state unsupport get playback info");
            }
            promiseCtx->JsResult = std::make_unique<AVCodecJsResultFormat>(playbackInfo);
        },
        MediaAsyncContext::CompleteCallback, static_cast<void *>(promiseCtx.get()), &promiseCtx->work));
    napi_queue_async_work_with_qos(env, promiseCtx->work, napi_qos_user_initiated);
    promiseCtx.release();
    MEDIA_LOGI("GetPlaybackInfo Out");
    return result;
}

void AVPlayerNapi::GetAVPlayStrategyFromStrategyTmp(AVPlayStrategy &strategy, const AVPlayStrategyTmp &strategyTmp)
{
    strategy.preferredWidth = strategyTmp.preferredWidth;
    strategy.preferredHeight = strategyTmp.preferredHeight;
    strategy.preferredBufferDuration = strategyTmp.preferredBufferDuration;
    strategy.preferredHdr = strategyTmp.preferredHdr;
    strategy.showFirstFrameOnPrepare = strategyTmp.showFirstFrameOnPrepare;
    strategy.enableSuperResolution = strategyTmp.enableSuperResolution;
    strategy.enableCameraPostprocessing = strategyTmp.enableCameraPostprocessing;
    strategy.mutedMediaType = static_cast<MediaType>(strategyTmp.mutedMediaType);
    strategy.preferredAudioLanguage = strategyTmp.preferredAudioLanguage;
    strategy.preferredSubtitleLanguage = strategyTmp.preferredSubtitleLanguage;
    strategy.preferredBufferDurationForPlaying = strategyTmp.isSetBufferDurationForPlaying ?
        strategyTmp.preferredBufferDurationForPlaying : -1;
    strategy.thresholdForAutoQuickPlay = strategyTmp.isSetThresholdForAutoQuickPlay ?
        strategyTmp.thresholdForAutoQuickPlay : -1;
    strategy.keepDecodingOnMute = strategyTmp.keepDecodingOnMute;
}

bool AVPlayerNapi::IsPalyingDurationValid(const AVPlayStrategyTmp &strategyTmp)
{
    if ((strategyTmp.preferredBufferDuration > 0 && strategyTmp.preferredBufferDurationForPlaying > 0 &&
                   strategyTmp.preferredBufferDurationForPlaying > strategyTmp.preferredBufferDuration) ||
                   strategyTmp.preferredBufferDurationForPlaying < 0) {
        return false;
    }
    return true;
}

bool AVPlayerNapi::IsLivingMaxDelayTimeValid(const AVPlayStrategyTmp &strategyTmp)
{
    if (!strategyTmp.isSetThresholdForAutoQuickPlay) {
        return true;
    }
    if (strategyTmp.thresholdForAutoQuickPlay < AVPlayStrategyConstant::BUFFER_DURATION_FOR_PLAYING_SECONDS ||
        strategyTmp.thresholdForAutoQuickPlay < strategyTmp.preferredBufferDurationForPlaying) {
        return false;
    }
    return true;
}

bool AVPlayerNapi::IsRateValid(float rate)
{
    const double minRate = 0.125f;
    const double maxRate = 4.0f;
    const double eps = 1e-15;
    if ((rate < minRate - eps) || (rate > maxRate + eps)) {
        return false;
    }
    return true;
}

napi_value AVPlayerNapi::JsSetPlaybackStrategy(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::JsSetPlaybackStrategy");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsSetPlaybackStrategy");

    size_t paramCountSingle = PARAM_COUNT_SINGLE;
    napi_value args[PARAM_COUNT_SINGLE] = { nullptr };
    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstanceWithParameter(env, info, paramCountSingle, args);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstance");

    auto promiseCtx = std::make_unique<AVPlayerContext>(env);
    promiseCtx->deferred = CommonNapi::CreatePromise(env, nullptr, result);
    std::string currentState = jsPlayer->GetCurrentState();
    napi_valuetype valueType = napi_undefined;
    if (currentState != AVPlayerState::STATE_INITIALIZED && currentState != AVPlayerState::STATE_STOPPED) {
        promiseCtx->SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not initialized / stopped, unsupport set playback strategy");
    } else if (napi_typeof(env, args[0], &valueType) != napi_ok || valueType != napi_object) {
        promiseCtx->SignError(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, please check input parameter");
    } else {
        AVPlayStrategyTmp strategyTmp;
        (void)CommonNapi::GetPlayStrategy(env, args[0], strategyTmp);
        if ((jsPlayer->GetJsApiVersion() < API_VERSION_17) &&
            (strategyTmp.mutedMediaType != MediaType::MEDIA_TYPE_AUD)) {
            promiseCtx->SignError(MSERR_EXT_API9_INVALID_PARAMETER, "only support mute media type audio now");
        } else if (!jsPlayer->IsPalyingDurationValid(strategyTmp)) {
            promiseCtx->SignError(MSERR_EXT_API9_INVALID_PARAMETER,
                                  "playing duration is above buffer duration or below zero");
        } else if (!jsPlayer->IsLivingMaxDelayTimeValid(strategyTmp)) {
            promiseCtx->SignError(MSERR_EXT_API9_INVALID_PARAMETER,
                                  "thresholdForAutoQuickPlay is invalid");
        } else {
            AVPlayStrategy strategy;
            jsPlayer->GetAVPlayStrategyFromStrategyTmp(strategy, strategyTmp);
            promiseCtx->asyncTask = jsPlayer->SetPlaybackStrategyTask(strategy);
            jsPlayer->mutedMediaType_ = strategy.mutedMediaType;
        }
    }
    napi_value resource = nullptr;
    napi_create_string_utf8(env, "JsSetPlaybackStrategy", NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource,
        [](napi_env env, void *data) {
            auto promiseCtx = reinterpret_cast<AVPlayerContext *>(data);
            CHECK_AND_RETURN_LOG(promiseCtx != nullptr, "promiseCtx is nullptr!");
            promiseCtx->CheckTaskResult();
        },
        MediaAsyncContext::CompleteCallback, static_cast<void *>(promiseCtx.get()), &promiseCtx->work));
    napi_queue_async_work_with_qos(env, promiseCtx->work, napi_qos_user_initiated);
    promiseCtx.release();
    return result;
}

napi_value AVPlayerNapi::JsSetMediaMuted(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::JsSetPlaybackStrategy");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsSetMediaMuted");
    auto promiseCtx = std::make_unique<AVPlayerContext>(env);

    const int32_t maxParam = 3; // config + callbackRef
    size_t argCount = maxParam;
    napi_value args[maxParam] = { nullptr };
    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstance");

    if (!jsPlayer->IsControllable()) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, unsupport set media muted operation");
        return result;
    }

    int32_t mediaType = MediaType::MEDIA_TYPE_AUD;
    napi_get_value_int32(env, args[0], &mediaType);
    bool isMuted = false;
    napi_get_value_bool(env, args[1], &isMuted);

    promiseCtx->callbackRef = CommonNapi::CreateReference(env, args[maxParam - 1]);
    promiseCtx->deferred = CommonNapi::CreatePromise(env, promiseCtx->callbackRef, result);

    auto curState = jsPlayer->GetCurrentState();
    bool canSetMute = curState == AVPlayerState::STATE_PREPARED || curState == AVPlayerState::STATE_PLAYING ||
                      curState == AVPlayerState::STATE_PAUSED || curState == AVPlayerState::STATE_COMPLETED;
    if (!canSetMute) {
        promiseCtx->SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not initialized / stopped, unsupport set playback strategy operation");
    } else {
        promiseCtx->asyncTask = jsPlayer->SetMediaMutedTask(static_cast<MediaType>(mediaType), isMuted);
    }
    napi_value resource = nullptr;
    napi_create_string_utf8(env, "JsSetMediaMuted", NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource,
        [](napi_env env, void *data) {
            auto promiseCtx = reinterpret_cast<AVPlayerContext *>(data);
            CHECK_AND_RETURN_LOG(promiseCtx != nullptr, "promiseCtx is nullptr!");
            promiseCtx->CheckTaskResult();
        },
        MediaAsyncContext::CompleteCallback, static_cast<void *>(promiseCtx.get()), &promiseCtx->work));
    napi_queue_async_work_with_qos(env, promiseCtx->work, napi_qos_user_initiated);
    promiseCtx.release();
    return result;
}

std::shared_ptr<TaskHandler<TaskRet>> AVPlayerNapi::SetMediaMutedTask(MediaType type, bool isMuted)
{
    auto task = std::make_shared<TaskHandler<TaskRet>>([this, type, isMuted]() {
        std::unique_lock<std::mutex> lock(taskMutex_);
        auto state = GetCurrentState();
        if (state == AVPlayerState::STATE_INITIALIZED || IsControllable()) {
            int32_t ret = player_->SetMediaMuted(type, isMuted);
            if (ret != MSERR_OK) {
                auto errCode = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(ret));
                return TaskRet(errCode, "failed to set muted");
            }
        } else {
            return TaskRet(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                "current state is not stopped or initialized, unsupport prepare operation");
        }
        return TaskRet(MSERR_EXT_API9_OK, "Success");
    });
    (void)taskQue_->EnqueueTask(task);
    return task;
}

std::shared_ptr<TaskHandler<TaskRet>> AVPlayerNapi::SetPlaybackStrategyTask(AVPlayStrategy playStrategy)
{
    auto task = std::make_shared<TaskHandler<TaskRet>>([this, playStrategy]() {
        std::unique_lock<std::mutex> lock(taskMutex_);
        auto state = GetCurrentState();
        if (state == AVPlayerState::STATE_INITIALIZED || state == AVPlayerState::STATE_STOPPED) {
            int32_t ret = player_->SetPlaybackStrategy(playStrategy);
            if (ret != MSERR_OK) {
                auto errCode = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(ret));
                return TaskRet(errCode, "failed to set playback strategy");
            }
        } else {
            return TaskRet(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                "current state is not initialized or stopped, unsupport set playback strategy operation");
        }
        return TaskRet(MSERR_EXT_API9_OK, "Success");
    });
    (void)taskQue_->EnqueueTask(task);
    return task;
}

napi_value AVPlayerNapi::JsSetSuperResolution(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::setSuperResolution");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsSetSuperResolution In");

    napi_value args[PARAM_COUNT_SINGLE] = { nullptr };
    size_t argCount = PARAM_COUNT_SINGLE; // setSuperResolution(enabled: boolean)
    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstanceWithParameter");

    auto promiseCtx = std::make_unique<AVPlayerContext>(env);
    promiseCtx->deferred = CommonNapi::CreatePromise(env, nullptr, result);
    napi_valuetype valueType = napi_undefined;

    if (!jsPlayer->CanSetSuperResolution()) {
        promiseCtx->SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not initialized/prepared/playing/paused/completed/stopped, "
            "unsupport set super resolution operation");
    } else if (argCount < PARAM_COUNT_SINGLE
        || napi_typeof(env, args[0], &valueType) != napi_ok || valueType != napi_boolean) {
        promiseCtx->SignError(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, please check the input");
    } else {
        bool enabled = false;
        napi_status status = napi_get_value_bool(env, args[0], &enabled);
        if (status != napi_ok) {
            promiseCtx->SignError(MSERR_EXT_API9_INVALID_PARAMETER,
                "invalid parameters, please check the input");
        } else {
            promiseCtx->asyncTask = jsPlayer->SetSuperResolutionTask(enabled);
        }
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "JsSetSuperResolution", NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource,
        [](napi_env env, void *data) {
            auto promiseCtx = reinterpret_cast<AVPlayerContext *>(data);
            CHECK_AND_RETURN_LOG(promiseCtx != nullptr, "promiseCtx is nullptr!");
            promiseCtx->CheckTaskResult();
        },
        MediaAsyncContext::CompleteCallback, static_cast<void *>(promiseCtx.get()), &promiseCtx->work));
    napi_queue_async_work_with_qos(env, promiseCtx->work, napi_qos_user_initiated);
    promiseCtx.release();
    return result;
}

std::shared_ptr<TaskHandler<TaskRet>> AVPlayerNapi::SetSuperResolutionTask(bool enable)
{
    auto task = std::make_shared<TaskHandler<TaskRet>>([this, enable]() {
        std::unique_lock<std::mutex> lock(taskMutex_);
        if (CanSetSuperResolution()) {
            int32_t ret = player_->SetSuperResolution(enable);
            if (ret != MSERR_OK) {
                auto errCode = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(ret));
                return TaskRet(errCode, "failed to set super resolution");
            }
        } else {
            return TaskRet(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                "current state is not initialized/prepared/playing/paused/completed/stopped, "
                "unsupport set super resolution operation");
        }
        return TaskRet(MSERR_EXT_API9_OK, "Success");
    });
    (void)taskQue_->EnqueueTask(task);
    return task;
}

napi_value AVPlayerNapi::JsSetVideoWindowSize(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::setVideoWindowSize");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsSetVideoWindowSize In");

    napi_value args[ARRAY_ARG_COUNTS_TWO] = { nullptr };
    size_t argCount = ARRAY_ARG_COUNTS_TWO; // setVideoWindowSize(width: number, height: number)
    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstanceWithParameter");

    auto promiseCtx = std::make_unique<AVPlayerContext>(env);
    promiseCtx->deferred = CommonNapi::CreatePromise(env, nullptr, result);
    napi_valuetype valueType = napi_undefined;

    if (!jsPlayer->CanSetSuperResolution()) {
        promiseCtx->SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not initialized/prepared/playing/paused/completed/stopped, "
            "unsupport set video window size");
    } else if (argCount < ARRAY_ARG_COUNTS_TWO ||
                napi_typeof(env, args[0], &valueType) != napi_ok || valueType != napi_number ||
                napi_typeof(env, args[1], &valueType) != napi_ok || valueType != napi_number) {
        promiseCtx->SignError(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, please check the input");
    } else {
        int32_t width = 0;
        int32_t height = 0;
        napi_status status1 = napi_get_value_int32(env, args[0], &width);
        napi_status status2 = napi_get_value_int32(env, args[1], &height);
        if (status1 != napi_ok || status2 != napi_ok) {
            promiseCtx->SignError(MSERR_EXT_API9_INVALID_PARAMETER,
                "invalid parameters, please check the input");
        } else {
            promiseCtx->asyncTask = jsPlayer->SetVideoWindowSizeTask(width, height);
        }
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "JsSetVideoWindowSize", NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource,
        [](napi_env env, void *data) {
            auto promiseCtx = reinterpret_cast<AVPlayerContext *>(data);
            CHECK_AND_RETURN_LOG(promiseCtx != nullptr, "promiseCtx is nullptr!");
            promiseCtx->CheckTaskResult();
        },
        MediaAsyncContext::CompleteCallback, static_cast<void *>(promiseCtx.get()), &promiseCtx->work));
    napi_queue_async_work_with_qos(env, promiseCtx->work, napi_qos_user_initiated);
    promiseCtx.release();
    return result;
}

std::shared_ptr<TaskHandler<TaskRet>> AVPlayerNapi::SetVideoWindowSizeTask(int32_t width, int32_t height)
{
    auto task = std::make_shared<TaskHandler<TaskRet>>([this, width, height]() {
        std::unique_lock<std::mutex> lock(taskMutex_);
        auto state = GetCurrentState();
        if (CanSetSuperResolution()) {
            int32_t ret = player_->SetVideoWindowSize(width, height);
            if (ret != MSERR_OK) {
                auto errCode = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(ret));
                return TaskRet(errCode, "failed to set super resolution");
            }
        } else {
            return TaskRet(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                "current state is not initialized/prepared/playing/paused/completed/stopped, "
                "unsupport set super resolution operation");
        }
        return TaskRet(MSERR_EXT_API9_OK, "Success");
    });
    (void)taskQue_->EnqueueTask(task);
    return task;
}

napi_value AVPlayerNapi::JsEnableCameraPostprocessing(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::enableCameraPostprocessing");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGD("JsEnableCameraPostprocessing In");
 
    napi_value args[PARAM_COUNT_SINGLE] = { nullptr };
    size_t argCount = PARAM_COUNT_SINGLE; // enableCameraPostprocessing(enabled: boolean)
    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstanceWithParameter");
 
    auto promiseCtx = std::make_unique<AVPlayerContext>(env);
    CHECK_AND_RETURN_RET_LOG(promiseCtx != nullptr, result, "promiseCtx is null");
    promiseCtx->deferred = CommonNapi::CreatePromise(env, nullptr, result);
 
    if (!IsSystemApp()) {
        promiseCtx->SignError(MSERR_EXT_API9_PERMISSION_DENIED, "systemapi permission denied");
    }
    if (!jsPlayer->CanCameraPostprocessing()) {
        promiseCtx->SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not initialized, unsupport enable cameraPostProcessor");
    } else {
        promiseCtx->asyncTask = jsPlayer->EnableCameraPostprocessingTask();
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "JsEnableCameraPostprocessing", NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource,
        [](napi_env env, void *data) {
            auto promiseCtx = reinterpret_cast<AVPlayerContext *>(data);
            CHECK_AND_RETURN_LOG(promiseCtx != nullptr, "promiseCtx is nullptr!");
            promiseCtx->CheckTaskResult();
        },
        MediaAsyncContext::CompleteCallback, static_cast<void *>(promiseCtx.get()), &promiseCtx->work));
    napi_queue_async_work_with_qos(env, promiseCtx->work, napi_qos_user_initiated);
    promiseCtx.release();
    return result;
}
 
std::shared_ptr<TaskHandler<TaskRet>> AVPlayerNapi::EnableCameraPostprocessingTask()
{
    auto task = std::make_shared<TaskHandler<TaskRet>>([this]() {
        std::unique_lock<std::mutex> lock(taskMutex_);
        if (CanCameraPostprocessing()) {
            int32_t ret = player_->EnableCameraPostprocessing();
            if (ret != MSERR_OK) {
                auto errCode = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(ret));
                return TaskRet(errCode, "failed to enable cameraPostProcessor");
            }
        } else {
            return TaskRet(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                "current state is not initialized, unsupport enable cameraPostProcessor");
        }
        return TaskRet(MSERR_EXT_API9_OK, "Success");
    });
    (void)taskQue_->EnqueueTask(task);
    return task;
}

napi_value AVPlayerNapi::JsGetUrl(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::get url");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGD("JsGetUrl In");

    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstance(env, info);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstance");

    napi_value value = nullptr;
    (void)napi_create_string_utf8(env, jsPlayer->url_.c_str(), NAPI_AUTO_LENGTH, &value);

    MEDIA_LOGD("JsGetUrl Out Current Url: %{private}s", jsPlayer->url_.c_str());
    return value;
}

napi_value AVPlayerNapi::JsSetAVFileDescriptor(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::set fd");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsSetAVFileDescriptor In");

    napi_value args[1] = { nullptr };
    size_t argCount = 1; // url: string
    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstanceWithParameter");

    if (jsPlayer->GetCurrentState() != AVPlayerState::STATE_IDLE) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is not idle, unsupport set fd");
        return result;
    }

    jsPlayer->StartListenCurrentResource(); // Listen to the events of the current resource
    napi_valuetype valueType = napi_undefined;
    if (argCount < 1 || napi_typeof(env, args[0], &valueType) != napi_ok || valueType != napi_object) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "SetAVFileDescriptor is not napi_object");
        return result;
    }

    if (!CommonNapi::GetFdArgument(env, args[0], jsPlayer->fileDescriptor_)) {
        MEDIA_LOGE("get fileDescriptor argument failed!");
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER,
            "invalid parameters, please check the input parameters(fileDescriptor)");
        return result;
    }

    auto task = std::make_shared<TaskHandler<void>>([jsPlayer]() {
        MEDIA_LOGI("SetAVFileDescriptor Task");
        if (jsPlayer->player_ != nullptr) {
            auto playerFd = jsPlayer->fileDescriptor_;
            MEDIA_LOGI("JsSetAVFileDescriptor fd: %{public}d, offset: %{public}"
                PRId64 ", size: %{public}" PRId64, playerFd.fd, playerFd.offset, playerFd.length);
            if (jsPlayer->player_->SetSource(playerFd.fd, playerFd.offset, playerFd.length) != MSERR_OK) {
                jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "player SetSource FileDescriptor failed");
            }
        }
    });
    (void)jsPlayer->taskQue_->EnqueueTask(task);

    MEDIA_LOGI("JsSetAVFileDescriptor Out");
    return result;
}

napi_value AVPlayerNapi::JsGetAVFileDescriptor(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::get fd");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsGetAVFileDescriptor In");

    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstance(env, info);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstance");

    napi_value value = nullptr;
    (void)napi_create_object(env, &value);
    (void)CommonNapi::AddNumberPropInt32(env, value, "fd", jsPlayer->fileDescriptor_.fd);
    (void)CommonNapi::AddNumberPropInt64(env, value, "offset", jsPlayer->fileDescriptor_.offset);
    (void)CommonNapi::AddNumberPropInt64(env, value, "length", jsPlayer->fileDescriptor_.length);

    MEDIA_LOGI("JsGetAVFileDescriptor Out");
    return value;
}

napi_value AVPlayerNapi::JsSetMediaSource(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::JsSetMediaSource");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_value args[ARRAY_ARG_COUNTS_TWO] = { nullptr };
    size_t argCount = 2;
    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstanceWithParameter");

    if (jsPlayer->GetCurrentState() != AVPlayerState::STATE_IDLE) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is not idle, unsupport set mediaSource");
        return result;
    }
    jsPlayer->StartListenCurrentResource(); // Listen to the events of the current resource
    napi_valuetype valueType = napi_undefined;
    if (argCount < MIN_ARG_COUNTS || napi_typeof(env, args[0], &valueType) != napi_ok || valueType != napi_object) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "src type should be MediaSource.");
        return result;
    }
    if (argCount > MAX_ARG_COUNTS) { // api allow one param
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, please check");
        return result;
    }
    std::shared_ptr<AVMediaSourceTmp> srcTmp = MediaSourceNapi::GetMediaSource(env, args[0]);
    CHECK_AND_RETURN_RET_LOG(srcTmp != nullptr, result, "get GetMediaSource argument failed!");

    std::shared_ptr<AVMediaSource> mediaSource = GetAVMediaSource(env, args[0], srcTmp);
    CHECK_AND_RETURN_RET_LOG(mediaSource != nullptr, result, "create mediaSource failed!");
    jsPlayer->AddMediaStreamToAVMediaSource(srcTmp, mediaSource);

    struct AVPlayStrategyTmp strategyTmp;
    struct AVPlayStrategy strategy;
    if (!CommonNapi::GetPlayStrategy(env, args[1], strategyTmp)) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "strategy type should be PlaybackStrategy.");
        return result;
    } else if (!jsPlayer->IsPalyingDurationValid(strategyTmp)) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "playing duration is invalid");
        return result;
    } else if (!jsPlayer->IsLivingMaxDelayTimeValid(strategyTmp)) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "thresholdForAutoQuickPlay is invalid");
        return result;
    }
    jsPlayer->GetAVPlayStrategyFromStrategyTmp(strategy, strategyTmp);
    if (jsPlayer->GetJsApiVersion() < API_VERSION_17) {
        strategy.mutedMediaType = MediaType::MEDIA_TYPE_MAX_COUNT;
    }
    jsPlayer->EnqueueMediaSourceTask(jsPlayer, mediaSource, strategy);
    return result;
}

std::shared_ptr<AVMediaSource> AVPlayerNapi::GetAVMediaSource(napi_env env, napi_value value,
    std::shared_ptr<AVMediaSourceTmp> &srcTmp)
{
    std::shared_ptr<AVMediaSource> mediaSource = std::make_shared<AVMediaSource>(srcTmp->url, srcTmp->header);
    CHECK_AND_RETURN_RET_LOG(mediaSource != nullptr, nullptr, "create mediaSource failed!");
    mediaSource->SetMimeType(srcTmp->GetMimeType());
    mediaSource->enableOfflineCache(srcTmp->GetenableOfflineCache());
    mediaSource->mediaSourceLoaderCb_ = MediaSourceNapi::GetSourceLoader(env, value);
    if (mediaSource->mediaSourceLoaderCb_ == nullptr) {
        MEDIA_LOGI("mediaSourceLoaderCb_ nullptr");
    }
    return mediaSource;
}

void AVPlayerNapi::EnqueueMediaSourceTask(AVPlayerNapi *jsPlayer, const std::shared_ptr<AVMediaSource> &mediaSource,
                                          const struct AVPlayStrategy &strategy)
{
    auto task = std::make_shared<TaskHandler<void>>([jsPlayer, mediaSource, strategy]() {
        if (jsPlayer->player_ != nullptr) {
            (void)jsPlayer->player_->SetMediaSource(mediaSource, strategy);
        }
    });
    (void)jsPlayer->taskQue_->EnqueueTask(task);
}

napi_value AVPlayerNapi::JsSetDataSrc(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::set dataSrc");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsSetDataSrc In");

    napi_value args[1] = { nullptr };
    size_t argCount = 1;
    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstanceWithParameter");

    if (jsPlayer->GetCurrentState() != AVPlayerState::STATE_IDLE) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is not idle, unsupport set dataSrc");
        return result;
    }
    jsPlayer->StartListenCurrentResource(); // Listen to the events of the current resource

    napi_valuetype valueType = napi_undefined;
    if (argCount < 1 || napi_typeof(env, args[0], &valueType) != napi_ok || valueType != napi_object) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "args[0] is not napi_object");
        return result;
    }
    (void)CommonNapi::GetPropertyInt64(env, args[0], "fileSize", jsPlayer->dataSrcDescriptor_.fileSize);
    if (jsPlayer->dataSrcDescriptor_.fileSize < -1 || jsPlayer->dataSrcDescriptor_.fileSize == 0) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, please check parameter fileSize");
        return result;
    }
    MEDIA_LOGD("Recvive filesize is %{public}" PRId64 "", jsPlayer->dataSrcDescriptor_.fileSize);
    jsPlayer->dataSrcCb_ = std::make_shared<MediaDataSourceCallback>(env, jsPlayer->dataSrcDescriptor_.fileSize);

    napi_value callback = nullptr;
    napi_ref ref = nullptr;
    napi_get_named_property(env, args[0], "callback", &callback);
    jsPlayer->dataSrcDescriptor_.callback = callback;
    napi_status status = napi_create_reference(env, callback, 1, &ref);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && ref != nullptr, result, "failed to create reference!");
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, ref);
    jsPlayer->dataSrcCb_->SaveCallbackReference(READAT_CALLBACK_NAME, autoRef);
    jsPlayer->SetDataSource(jsPlayer);
    MEDIA_LOGI("JsSetDataSrc Out");
    return result;
}

void AVPlayerNapi::SetDataSource(AVPlayerNapi *jsPlayer)
{
    MEDIA_LOGI("SetDataSource while setStateChange_ %{public}d", jsPlayer->hasSetStateChangeCb_);
    if (jsPlayer->hasSetStateChangeCb_) {
        if (jsPlayer->player_ != nullptr) {
            if (jsPlayer->player_->SetSource(jsPlayer->dataSrcCb_) != MSERR_OK) {
                jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "player SetSource DataSrc failed");
            } else {
                jsPlayer->state_ = PlayerStates::PLAYER_INITIALIZED;
            }
            if (jsPlayer->dataSrcDescriptor_.fileSize == -1) {
                jsPlayer->isLiveStream_ = true;
            }
        }
        return;
    }

    auto task = std::make_shared<TaskHandler<void>>([jsPlayer]() {
        MEDIA_LOGI("SetDataSrc Task");
        if (jsPlayer->player_ != nullptr) {
            if (jsPlayer->player_->SetSource(jsPlayer->dataSrcCb_) != MSERR_OK) {
                jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "player SetSource DataSrc failed");
            }
            if (jsPlayer->dataSrcDescriptor_.fileSize == -1) {
                jsPlayer->isLiveStream_ = true;
            }
        }
    });
    (void)jsPlayer->taskQue_->EnqueueTask(task);
}

napi_value AVPlayerNapi::JsGetDataSrc(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::get dataSrc");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsGetDataSrc In");

    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstance(env, info);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstance");
    CHECK_AND_RETURN_RET_LOG(jsPlayer->dataSrcCb_ != nullptr, result, "failed to check dataSrcCb_");

    napi_value value = nullptr;
    int64_t fileSize;
    napi_value callback = nullptr;
    (void)napi_create_object(env, &value);
    (void)jsPlayer->dataSrcCb_->GetSize(fileSize);
    (void)CommonNapi::AddNumberPropInt64(env, value, "fileSize", fileSize);
    int32_t ret = jsPlayer->dataSrcCb_->GetCallback(READAT_CALLBACK_NAME, &callback);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, result, "failed to GetCallback");
    (void)MediaDataSourceCallback::AddNapiValueProp(env, value, "callback", callback);

    MEDIA_LOGI("JsGetDataSrc Out");
    return value;
}

#ifdef SUPPORT_VIDEO
void AVPlayerNapi::SetSurface(const std::string &surfaceStr)
{
    MEDIA_LOGI("get surface, surfaceStr = %{public}s", surfaceStr.c_str());
    uint64_t surfaceId = 0;
    if (surfaceStr.empty() || surfaceStr[0] < '0' || surfaceStr[0] > '9') {
        OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER,
            "Please obtain the surface from XComponentController.getXComponentSurfaceId");
        return;
    }
    if (!StrToULL(surfaceStr, surfaceId)) {
        OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER,
            "invalid parameters, failed to obtain surfaceId");
        return;
    }
    MEDIA_LOGI("get surface, surfaceId = (%{public}" PRIu64 ")", surfaceId);

    auto surface = SurfaceUtils::GetInstance()->GetSurface(surfaceId);
    if (surface == nullptr) {
        OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "SurfaceUtils cannot convert ID to Surface");
        return;
    }

    auto task = std::make_shared<TaskHandler<void>>([this, surface]() {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " SetSurface Task", FAKE_POINTER(this));
        if (player_ != nullptr) {
            (void)player_->SetVideoSurface(surface);
        }
    });
    (void)taskQue_->EnqueueTask(task);
}
#else
void AVPlayerNapi::SetSurface(const std::string &surfaceStr)
{
    (void)surfaceStr;
    OnErrorCb(MSERR_EXT_API9_UNSUPPORT_CAPABILITY, "The music player does not need to support (Surface)");
}
#endif

napi_value AVPlayerNapi::JsSetSurfaceID(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::set surface");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGD("JsSetSurfaceID In");

    napi_value args[1] = { nullptr };
    size_t argCount = 1; // surfaceId?: string
    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstanceWithParameter");

    napi_valuetype valueType = napi_undefined;
    if (argCount < 1 || napi_typeof(env, args[0], &valueType) != napi_ok || valueType != napi_string) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "the attribute(SurfaceID) input is not string");
        return result;
    }

    std::string curState = jsPlayer->GetCurrentState();
    bool setSurfaceFirst = curState == AVPlayerState::STATE_INITIALIZED;
    bool switchSurface = curState == AVPlayerState::STATE_PREPARED ||
        curState == AVPlayerState::STATE_PLAYING ||
        curState == AVPlayerState::STATE_PAUSED ||
        curState == AVPlayerState::STATE_STOPPED ||
        curState == AVPlayerState::STATE_COMPLETED;

    if (setSurfaceFirst) {
        MEDIA_LOGI("JsSetSurfaceID set surface first in %{public}s state", curState.c_str());
    } else if (switchSurface) {
        MEDIA_LOGI("JsSetSurfaceID switch surface in %{public}s state", curState.c_str());
        std::string oldSurface = jsPlayer->surface_;
        if (oldSurface.empty() && !jsPlayer->isForceLoadVideo_ &&
            jsPlayer->mutedMediaType_ != OHOS::Media::MediaType::MEDIA_TYPE_VID) {
            jsPlayer->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                "switch surface with no old surface");
            return result;
        }
    } else {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "the attribute(SurfaceID) can only be set in the initialized state");
        return result;
    }

    // get url from js
    jsPlayer->surface_ = CommonNapi::GetStringArgument(env, args[0]);
    jsPlayer->SetSurface(jsPlayer->surface_);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " JsSetSurfaceID Out", FAKE_POINTER(jsPlayer));
    return result;
}

napi_value AVPlayerNapi::JsGetSurfaceID(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::get surface");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGD("JsGetSurfaceID In");

    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstance(env, info);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstance");

    napi_value value = nullptr;
    (void)napi_create_string_utf8(env, jsPlayer->surface_.c_str(), NAPI_AUTO_LENGTH, &value);

    MEDIA_LOGI("JsGetSurfaceID Out Current SurfaceID: %{public}s", jsPlayer->surface_.c_str());
    return value;
}

napi_value AVPlayerNapi::JsSetLoop(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::set loop");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsSetLoop In");

    napi_value args[1] = { nullptr };
    size_t argCount = 1; // loop: boolenan
    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstanceWithParameter");

    if (jsPlayer->IsLiveSource()) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_UNSUPPORT_CAPABILITY, "The stream is live stream, not support loop");
        return result;
    }

    if (!jsPlayer->IsControllable()) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, unsupport loop operation");
        return result;
    }

    napi_valuetype valueType = napi_undefined;
    if (argCount < 1 || napi_typeof(env, args[0], &valueType) != napi_ok || valueType != napi_boolean) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "SetLoop is not napi_boolean");
        return result;
    }

    napi_status status = napi_get_value_bool(env, args[0], &jsPlayer->loop_);
    if (status != napi_ok) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER,
            "invalid parameters, please check the input loop");
        return result;
    }

    auto task = std::make_shared<TaskHandler<void>>([jsPlayer]() {
        MEDIA_LOGD("SetLooping Task");
        if (jsPlayer->player_ != nullptr) {
            (void)jsPlayer->player_->SetLooping(jsPlayer->loop_);
        }
    });
    (void)jsPlayer->taskQue_->EnqueueTask(task);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " JsSetLoop Out", FAKE_POINTER(jsPlayer));
    return result;
}

napi_value AVPlayerNapi::JsGetLoop(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::get loop");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsGetLoop In");

    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstance(env, info);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstance");

    napi_value value = nullptr;
    (void)napi_get_boolean(env, jsPlayer->loop_, &value);
    MEDIA_LOGI("JsGetLoop Out Current Loop: %{public}d", jsPlayer->loop_);
    return value;
}

napi_value AVPlayerNapi::JsSetVideoScaleType(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::set videoScaleType");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsSetVideoScaleType In");

    napi_value args[1] = { nullptr };
    size_t argCount = 1;
    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstanceWithParameter");

    if (!jsPlayer->IsControllable()) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, unsupport video scale operation");
        return result;
    }

    napi_valuetype valueType = napi_undefined;
    if (argCount < 1 || napi_typeof(env, args[0], &valueType) != napi_ok || valueType != napi_number) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "SetVideoScaleType is not napi_number");
        return result;
    }

    int32_t videoScaleType = 0;
    napi_status status = napi_get_value_int32(env, args[0], &videoScaleType);
    if (status != napi_ok || videoScaleType < static_cast<int32_t>(Plugins::VideoScaleType::VIDEO_SCALE_TYPE_FIT)
        || videoScaleType > static_cast<int32_t>(Plugins::VideoScaleType::VIDEO_SCALE_TYPE_SCALED_ASPECT)) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, please check the input scale type");
        return result;
    }
    jsPlayer->videoScaleType_ = videoScaleType;

    auto task = std::make_shared<TaskHandler<void>>([jsPlayer, videoScaleType]() {
        MEDIA_LOGI("SetVideoScaleType Task");
        if (jsPlayer->player_ != nullptr) {
            Format format;
            (void)format.PutIntValue(PlayerKeys::VIDEO_SCALE_TYPE, videoScaleType);
            (void)jsPlayer->player_->SetParameter(format);
        }
    });
    (void)jsPlayer->taskQue_->EnqueueTask(task);
    MEDIA_LOGI("JsSetVideoScaleType Out");
    return result;
}

napi_value AVPlayerNapi::JsGetVideoScaleType(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::get videoScaleType");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsGetVideoScaleType In");

    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstance(env, info);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstance");

    napi_value value = nullptr;
    (void)napi_create_int32(env, static_cast<int32_t>(jsPlayer->videoScaleType_), &value);
    MEDIA_LOGI("JsGetVideoScaleType Out Current VideoScale: %{public}d", jsPlayer->videoScaleType_);
    return value;
}

napi_value AVPlayerNapi::JsSetAudioInterruptMode(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::set audioInterruptMode");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsSetAudioInterruptMode In");

    napi_value args[1] = { nullptr };
    size_t argCount = 1;
    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstanceWithParameter");

    if (!jsPlayer->IsControllable()) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, unsupport audio interrupt operation");
        return result;
    }

    napi_valuetype valueType = napi_undefined;
    if (argCount < 1 || napi_typeof(env, args[0], &valueType) != napi_ok || valueType != napi_number) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "SetAudioInterruptMode is not napi_number");
        return result;
    }

    int32_t interruptMode = 0;
    napi_status status = napi_get_value_int32(env, args[0], &interruptMode);
    if (status != napi_ok ||
        interruptMode < AudioStandard::InterruptMode::SHARE_MODE ||
        interruptMode > AudioStandard::InterruptMode::INDEPENDENT_MODE) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER,
            "invalid parameters, please check the input interrupt Mode");
        return result;
    }
    jsPlayer->interruptMode_ = static_cast<AudioStandard::InterruptMode>(interruptMode);

    auto task = std::make_shared<TaskHandler<void>>([jsPlayer]() {
        MEDIA_LOGI("SetAudioInterruptMode Task");
        if (jsPlayer->player_ != nullptr) {
            Format format;
            (void)format.PutIntValue(PlayerKeys::AUDIO_INTERRUPT_MODE, jsPlayer->interruptMode_);
            (void)jsPlayer->player_->SetParameter(format);
        }
    });
    (void)jsPlayer->taskQue_->EnqueueTask(task);
    MEDIA_LOGI("JsSetAudioInterruptMode Out");
    return result;
}

napi_value AVPlayerNapi::JsGetAudioInterruptMode(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::get audioInterruptMode");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsGetAudioInterruptMode In");

    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstance(env, info);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstance");

    napi_value value = nullptr;
    (void)napi_create_int32(env, static_cast<int32_t>(jsPlayer->interruptMode_), &value);
    MEDIA_LOGI("JsGetAudioInterruptMode Out");
    return value;
}

napi_value AVPlayerNapi::JsSetAudioEffectMode(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::JsSetAudioEffectMode");
    MEDIA_LOGI("JsSetAudioEffectMode In");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    size_t argCount = 1; // 1param audioEffectMode
    napi_value args[1] = { nullptr };
    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstanceWithParameter");

    if (!jsPlayer->IsControllable()) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, unsupport audio effect mode operation");
        return result;
    }

    napi_valuetype valueType = napi_undefined;
    if (argCount < 1 || napi_typeof(env, args[0], &valueType) != napi_ok || valueType != napi_number) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "audioEffectMode is not number");
        return result;
    }

    int32_t effectMode = OHOS::AudioStandard::AudioEffectMode::EFFECT_DEFAULT;
    napi_status status = napi_get_value_int32(env, args[0], &effectMode);
    if (status != napi_ok || effectMode > OHOS::AudioStandard::AudioEffectMode::EFFECT_DEFAULT ||
        effectMode < OHOS::AudioStandard::AudioEffectMode::EFFECT_NONE) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER,
            "invalid audioEffectMode, please check the input audio effect Mode");
        return result;
    }

    if (jsPlayer->audioEffectMode_ == effectMode) {
        MEDIA_LOGI("Same effectMode parameter");
        return result;
    }

    jsPlayer->audioEffectMode_ = effectMode;

    auto task = std::make_shared<TaskHandler<void>>([jsPlayer, effectMode]() {
        MEDIA_LOGI("JsSetAudioEffectMode Task in");
        if (jsPlayer->player_ != nullptr) {
            Format format;
            (void)format.PutIntValue(PlayerKeys::AUDIO_EFFECT_MODE, effectMode);
            (void)jsPlayer->player_->SetParameter(format);
        }
        MEDIA_LOGI("JsSetAudioEffectMode Task out");
    });
    (void)jsPlayer->taskQue_->EnqueueTask(task);
    MEDIA_LOGI("JsSetAudioEffectMode Out");
    return result;
}

napi_value AVPlayerNapi::JsGetAudioEffectMode(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::JsGetAudioEffectMode");
    MEDIA_LOGI("JsGetAudioEffectMode In");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstance(env, info);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstance");

    napi_value value = nullptr;
    (void)napi_create_int32(env, static_cast<int32_t>(jsPlayer->audioEffectMode_), &value);
    MEDIA_LOGI("JsGetAudioEffectMode Out");
    return value;
}

bool AVPlayerNapi::JsHandleParameter(napi_env env, napi_value args, AVPlayerNapi *jsPlayer)
{
    int32_t content = CONTENT_TYPE_UNKNOWN;
    int32_t usage = -1;
    int32_t rendererFlags = -1;
    int32_t volumeMode = -1;
    (void)CommonNapi::GetPropertyInt32(env, args, "content", content);
    (void)CommonNapi::GetPropertyInt32(env, args, "usage", usage);
    (void)CommonNapi::GetPropertyInt32(env, args, "rendererFlags", rendererFlags);
    (void)CommonNapi::GetPropertyInt32(env, args, "volumeMode", volumeMode);
    MEDIA_LOGI("content = %{public}d, usage = %{public}d, rendererFlags = %{public}d, volumeMode = %{public}d",
        content, usage, rendererFlags, volumeMode);
    std::vector<int32_t> contents = {
        CONTENT_TYPE_UNKNOWN, CONTENT_TYPE_SPEECH,
        CONTENT_TYPE_MUSIC, CONTENT_TYPE_MOVIE,
        CONTENT_TYPE_SONIFICATION, CONTENT_TYPE_RINGTONE
    };
    std::vector<int32_t> usages = {
        STREAM_USAGE_UNKNOWN, STREAM_USAGE_MEDIA,
        STREAM_USAGE_MUSIC, STREAM_USAGE_VOICE_COMMUNICATION,
        STREAM_USAGE_VOICE_ASSISTANT, STREAM_USAGE_ALARM,
        STREAM_USAGE_VOICE_MESSAGE, STREAM_USAGE_NOTIFICATION_RINGTONE,
        STREAM_USAGE_RINGTONE, STREAM_USAGE_NOTIFICATION,
        STREAM_USAGE_ACCESSIBILITY, STREAM_USAGE_SYSTEM,
        STREAM_USAGE_MOVIE, STREAM_USAGE_GAME,
        STREAM_USAGE_AUDIOBOOK, STREAM_USAGE_NAVIGATION,
        STREAM_USAGE_DTMF, STREAM_USAGE_ENFORCED_TONE,
        STREAM_USAGE_ULTRASONIC, STREAM_USAGE_VIDEO_COMMUNICATION
    };
    std::vector<int32_t> systemUsages = { STREAM_USAGE_VOICE_CALL_ASSISTANT, STREAM_USAGE_VOICE_RINGTONE };
    usages.insert(usages.end(), systemUsages.begin(), systemUsages.end());
    if (std::find(systemUsages.begin(), systemUsages.end(), usage) != systemUsages.end() && !IsSystemApp()) {
        MEDIA_LOGI("The caller is not a system app, usage = %{public}d", usage);
        return false;
    }
    if (std::find(contents.begin(), contents.end(), content) == contents.end() ||
        std::find(usages.begin(), usages.end(), usage) == usages.end()) {
        return false;
    }

    if (jsPlayer->audioRendererInfo_.contentType != content ||
        jsPlayer->audioRendererInfo_.streamUsage != usage) {
        jsPlayer->audioEffectMode_ = OHOS::AudioStandard::AudioEffectMode::EFFECT_DEFAULT;
    }

    jsPlayer->audioRendererInfo_ = AudioStandard::AudioRendererInfo {
        static_cast<AudioStandard::ContentType>(content),
        static_cast<AudioStandard::StreamUsage>(usage),
        rendererFlags,
        static_cast<AudioStandard::AudioVolumeMode>(volumeMode)
    };
    return true;
}

void AVPlayerNapi::SeekEnqueueTask(AVPlayerNapi *jsPlayer, int32_t time, int32_t mode)
{
    auto task = std::make_shared<TaskHandler<void>>([jsPlayer, time, mode]() {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " JsSeek Task In", FAKE_POINTER(jsPlayer));
        if (jsPlayer->player_ != nullptr) {
            (void)jsPlayer->player_->Seek(time, jsPlayer->TransferSeekMode(mode));
        }
        MEDIA_LOGI("0x%{public}06" PRIXPTR " JsSeek Task Out", FAKE_POINTER(jsPlayer));
    });
    MEDIA_LOGI("0x%{public}06" PRIXPTR " JsSeek EnqueueTask In", FAKE_POINTER(jsPlayer));
    (void)jsPlayer->taskQue_->EnqueueTask(task);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " JsSeek Out", FAKE_POINTER(jsPlayer));
}

napi_value AVPlayerNapi::JsSetAudioRendererInfo(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::set audioRendererInfo");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsSetAudioRendererInfo In");

    napi_value args[1] = { nullptr };
    size_t argCount = 1;
    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstanceWithParameter");
    napi_valuetype valueType = napi_undefined;
    if (argCount < 1 || napi_typeof(env, args[0], &valueType) != napi_ok || valueType != napi_object) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, please check the input");
        return result;
    }
    if (jsPlayer->GetCurrentState() != AVPlayerState::STATE_INITIALIZED) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not initialized, unsupport to set audio renderer info");
        return result;
    }
    if (!AVPlayerNapi::JsHandleParameter(env, args[0], jsPlayer)) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER,
            "invalid parameters, please check the input audio renderer info");
        return result;
    }
    auto task = std::make_shared<TaskHandler<void>>([jsPlayer]() {
        MEDIA_LOGI("SetAudioRendererInfo Task");
        if (jsPlayer->player_ != nullptr) {
            Format format;
            (void)format.PutIntValue(PlayerKeys::CONTENT_TYPE, jsPlayer->audioRendererInfo_.contentType);
            (void)format.PutIntValue(PlayerKeys::STREAM_USAGE, jsPlayer->audioRendererInfo_.streamUsage);
            (void)format.PutIntValue(PlayerKeys::RENDERER_FLAG, jsPlayer->audioRendererInfo_.rendererFlags);
            (void)format.PutIntValue(PlayerKeys::VOLUME_MODE, jsPlayer->audioRendererInfo_.volumeMode);
            (void)jsPlayer->player_->SetParameter(format);
        }
    });
    (void)jsPlayer->taskQue_->EnqueueTask(task);
    MEDIA_LOGI("JsSetAudioRendererInfo Out");
    return result;
}

napi_value AVPlayerNapi::JsSetPrivacyType(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::set privacyType");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsSetPrivacyType In");

    napi_value args[1] = { nullptr };
    size_t argCount = 1;
    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstanceWithParameter");
    napi_valuetype valueType = napi_undefined;
    if (argCount < 1 || napi_typeof(env, args[0], &valueType) != napi_ok || valueType != napi_number) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, please check the input");
        return result;
    }
    if (jsPlayer->GetCurrentState() != AVPlayerState::STATE_INITIALIZED) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not initialized, unsupport to set audio renderer info");
        return result;
    }

    int32_t privacyType = 0;
    napi_status status = napi_get_value_int32(env, args[0], &privacyType);
    if (status != napi_ok || privacyType < 0) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, please check the input privacyType");
        return result;
    }
    jsPlayer->privacyType_ = privacyType;

    auto task = std::make_shared<TaskHandler<void>>([jsPlayer, privacyType]() {
        MEDIA_LOGI("SetPrivacyType Task");
        if (jsPlayer->player_ != nullptr) {
            Format format;
            (void)format.PutIntValue(PlayerKeys::PRIVACY_TYPE, privacyType);
            (void)jsPlayer->player_->SetParameter(format);
        }
    });
    (void)jsPlayer->taskQue_->EnqueueTask(task);
    MEDIA_LOGI("JsSetPrivacyType Out");
    return result;
}

napi_value AVPlayerNapi::JsGetAudioRendererInfo(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::get audioRendererInfo");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsGetAudioRendererInfo In");

    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstance(env, info);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstance");

    int32_t content = static_cast<int32_t>(jsPlayer->audioRendererInfo_.contentType);
    int32_t usage = static_cast<int32_t>(jsPlayer->audioRendererInfo_.streamUsage);
    int32_t rendererFlags = jsPlayer->audioRendererInfo_.rendererFlags;
    int32_t volumeMode = static_cast<int32_t>(jsPlayer->audioRendererInfo_.volumeMode);
    (void)napi_create_object(env, &result);
    CommonNapi::SetPropertyInt32(env, result, "content", content);
    CommonNapi::SetPropertyInt32(env, result, "usage", usage);
    CommonNapi::SetPropertyInt32(env, result, "rendererFlags", rendererFlags);
    CommonNapi::SetPropertyInt32(env, result, "volumeMode", volumeMode);
    MEDIA_LOGI("JsGetAudioRendererInfo Out");
    return result;
}

napi_value AVPlayerNapi::JsGetPrivacyType(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::get privacyType");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsGetPrivacyType In");

    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstance(env, info);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstance");
    napi_value value = nullptr;
    (void)napi_create_int32(env, static_cast<int32_t>(jsPlayer->privacyType_), &value);
    MEDIA_LOGI("JsGetPrivacyType Out");
    return value;
}

napi_value AVPlayerNapi::JsGetCurrentTime(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::get currentTime");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGD("JsGetCurrentTime In");

    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstance(env, info);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstance");

    int32_t currentTime = -1;
    if (jsPlayer->IsControllable()) {
        if (!jsPlayer->reportMediaProgressCallbackflag_ && jsPlayer->player_ != nullptr) {
            auto ret = jsPlayer->player_->GetCurrentTime(currentTime);
            currentTime = ret == MSERR_OK ? currentTime : -1;
            jsPlayer->HandleListenerStateChange("timeUpdate", true);
        } else {
            currentTime = jsPlayer->position_;
        }
    }

    if (jsPlayer->IsLiveSource() && jsPlayer->dataSrcCb_ == nullptr) {
        currentTime = -1;
    }
    napi_value value = nullptr;
    (void)napi_create_int32(env, currentTime, &value);
    std::string curState = jsPlayer->GetCurrentState();
    if (currentTime != -1) {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " JsGetCurrenTime Out, state %{public}s, time %{public}d",
            FAKE_POINTER(jsPlayer), curState.c_str(), currentTime);
    }
    return value;
}

napi_value AVPlayerNapi::JsGetPlaybackPosition(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::get playbackPosition");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGD("JsGetPlaybackPosition In");

    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstance(env, info);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstance");
    CHECK_AND_RETURN_RET_LOG(jsPlayer->player_ != nullptr, result, "failed to check player_");

    std::string curState = jsPlayer->GetCurrentState();
    if (curState == AVPlayerState::STATE_PLAYING &&
        curState == AVPlayerState::STATE_PAUSED &&
        curState == AVPlayerState::STATE_PREPARED &&
        curState == AVPlayerState::STATE_COMPLETED) {
        return CommonNapi::ThrowError(env, MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, not support get playback position");
    }

    int32_t playbackPosition = 0;
    (void)jsPlayer->player_->GetPlaybackPosition(playbackPosition);
    if (playbackPosition != 0) {
        MEDIA_LOGD("0x%{public}06" PRIXPTR " JsGetPlaybackPosition Out, state %{public}s, time: %{public}d",
            FAKE_POINTER(jsPlayer), curState.c_str(), playbackPosition);
    }

    napi_value value = nullptr;
    napi_status status = napi_create_int32(env, playbackPosition, &value);
    if (status != napi_ok) {
        MEDIA_LOGE("JsGetPlaybackPosition status != napi_ok");
    }
    return value;
}

napi_value AVPlayerNapi::JsGetCurrentPresentationTimestamp(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::getCurrentPresentationTimestamp");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGD("JsGetCurrentPresentationTimestamp In");

    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstance(env, info);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstance");
    CHECK_AND_RETURN_RET_LOG(jsPlayer->player_ != nullptr, result, "failed to check player_");

    std::string curState = jsPlayer->GetCurrentState();
    if (curState != AVPlayerState::STATE_PLAYING &&
        curState != AVPlayerState::STATE_PAUSED &&
        curState != AVPlayerState::STATE_COMPLETED) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not playing/paused/completed, not support getCurrentPresentationTimestamp");
        return result;
    }

    int64_t currentPresentation = 0;
    (void)jsPlayer->player_->GetCurrentPresentationTimestamp(currentPresentation);
    if (currentPresentation != 0) {
        MEDIA_LOGD("0x%{public}06" PRIXPTR " JsGetCurrentPresentationTimestamp Out, time: (%{public}" PRIu64 ")",
            FAKE_POINTER(jsPlayer), currentPresentation);
    }

    napi_value value = nullptr;
    napi_status status = napi_create_int64(env, currentPresentation, &value);
    if (status != napi_ok) {
        MEDIA_LOGE("JsGetCurrentPresentationTimestamp status != napi_ok");
        return CommonNapi::ThrowError(env, MSERR_EXT_API9_OPERATE_NOT_PERMIT, "faild to create int64 value");
    }
    return value;
}

napi_value AVPlayerNapi::JsForceLoadVideo(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::ForceLoadVideo");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    auto promiseCtx = std::make_unique<AVPlayerContext>(env);
    napi_value args[1] = { nullptr };
    size_t argCount = 1;

    promiseCtx->napi = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(promiseCtx->napi != nullptr, result, "failed to GetJsInstance");
    CHECK_AND_RETURN_RET_LOG(promiseCtx->napi->player_ != nullptr, result, "failed to check player_");
    promiseCtx->deferred = CommonNapi::CreatePromise(env, promiseCtx->callbackRef, result);

    bool isForceLoadVideo = false;
    if (!IsSystemApp()) {
        promiseCtx->SignError(MSERR_EXT_API9_PERMISSION_DENIED, "only system app support this function");
    } else if (napi_valuetype valueType = napi_undefined; napi_typeof(env, args[0], &valueType) != napi_ok
        || valueType != napi_boolean || napi_get_value_bool(env, args[0], &isForceLoadVideo) != napi_ok) {
        promiseCtx->SignError(MSERR_EXT_API9_INVALID_PARAMETER, "input param type is not boolean");
    }

    // only if no errors can exec task
    if (!promiseCtx->errFlag) {
        promiseCtx->asyncTask = promiseCtx->napi->ForceLoadVideoTask(isForceLoadVideo);
        promiseCtx->napi->isForceLoadVideo_ = isForceLoadVideo;
    }
    napi_value resource = nullptr;
    napi_create_string_utf8(env, "JsForceLoadVideo", NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, [](napi_env env, void *data) {
        auto promiseCtx = reinterpret_cast<AVPlayerContext *>(data);
        CHECK_AND_RETURN_LOG(promiseCtx != nullptr, "promiseCtx is nullptr!");
        promiseCtx->CheckTaskResult();
    }, MediaAsyncContext::CompleteCallback, static_cast<void *>(promiseCtx.get()), &promiseCtx->work));
    napi_queue_async_work_with_qos(env, promiseCtx->work, napi_qos_user_initiated);
    promiseCtx.release();
    return result;
}

std::shared_ptr<TaskHandler<TaskRet>> AVPlayerNapi::ForceLoadVideoTask(bool status)
{
    auto task = std::make_shared<TaskHandler<TaskRet>>([this, status] {
        std::unique_lock<std::mutex> lock(taskMutex_);
        auto state = GetCurrentState();
        CHECK_AND_RETURN_RET(state == AVPlayerState::STATE_INITIALIZED || state == AVPlayerState::STATE_STOPPED,
            TaskRet(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "state unsupport this operation"));
        auto ret = player_->ForceLoadVideo(status);
        CHECK_AND_RETURN_RET(ret == MSERR_OK,
            TaskRet(MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(ret)), "ForceLoadVideo failed"));
        return TaskRet(MSERR_EXT_API9_OK, "Success");
    });
    (void)taskQue_->EnqueueTask(task);
    return task;
}

napi_value AVPlayerNapi::JsGetDuration(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::get duration");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGD("JsGetDuration In");

    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstance(env, info);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstance");

    int32_t duration = -1;
    if (jsPlayer->IsControllable() && !jsPlayer->IsLiveSource()) {
        duration = jsPlayer->duration_;
    }

    napi_value value = nullptr;
    (void)napi_create_int32(env, duration, &value);
    std::string curState = jsPlayer->GetCurrentState();
    MEDIA_LOGD("JsGetDuration Out, state %{public}s, duration %{public}d", curState.c_str(), duration);
    return value;
}

bool AVPlayerNapi::IsControllable()
{
    auto state = GetCurrentState();
    if (state == AVPlayerState::STATE_PREPARED || state == AVPlayerState::STATE_PLAYING ||
        state == AVPlayerState::STATE_PAUSED || state == AVPlayerState::STATE_COMPLETED) {
        return true;
    } else {
        return false;
    }
}

bool AVPlayerNapi::CanGetPlaybackStatisticMetrics()
{
    auto state = GetCurrentState();
    if (state == AVPlayerState::STATE_PREPARED || state == AVPlayerState::STATE_PLAYING ||
        state == AVPlayerState::STATE_PAUSED || state == AVPlayerState::STATE_COMPLETED ||
        state == AVPlayerState::STATE_STOPPED) {
        return true;
    } else {
        return false;
    }
}

bool AVPlayerNapi::CanSetPlayRange()
{
    auto state = GetCurrentState();
    if (state == AVPlayerState::STATE_INITIALIZED || state == AVPlayerState::STATE_PREPARED ||
        state == AVPlayerState::STATE_PAUSED || state == AVPlayerState::STATE_STOPPED ||
        state == AVPlayerState::STATE_COMPLETED) {
        return true;
    }
    return false;
}

bool AVPlayerNapi::CanSetSuperResolution()
{
    auto state = GetCurrentState();
    if (state == AVPlayerState::STATE_INITIALIZED || state == AVPlayerState::STATE_PREPARED ||
        state == AVPlayerState::STATE_PLAYING || state == AVPlayerState::STATE_PAUSED ||
        state == AVPlayerState::STATE_STOPPED || state == AVPlayerState::STATE_COMPLETED) {
        return true;
    }
    return false;
}

bool AVPlayerNapi::CanCameraPostprocessing()
{
    auto state = GetCurrentState();
    if (state == AVPlayerState::STATE_INITIALIZED) {
        return true;
    }
    return false;
}

std::string AVPlayerNapi::GetCurrentState()
{
    if (isReleased_.load()) {
        return AVPlayerState::STATE_RELEASED;
    }

    std::string curState = AVPlayerState::STATE_ERROR;
    static const std::map<PlayerStates, std::string> stateMap = {
        {PLAYER_IDLE, AVPlayerState::STATE_IDLE},
        {PLAYER_INITIALIZED, AVPlayerState::STATE_INITIALIZED},
        {PLAYER_PREPARED, AVPlayerState::STATE_PREPARED},
        {PLAYER_STARTED, AVPlayerState::STATE_PLAYING},
        {PLAYER_PAUSED, AVPlayerState::STATE_PAUSED},
        {PLAYER_STOPPED, AVPlayerState::STATE_STOPPED},
        {PLAYER_PLAYBACK_COMPLETE, AVPlayerState::STATE_COMPLETED},
        {PLAYER_STATE_ERROR, AVPlayerState::STATE_ERROR},
    };

    if (stateMap.find(state_) != stateMap.end()) {
        curState = stateMap.at(state_);
    }
    return curState;
}

napi_value AVPlayerNapi::JsGetState(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::get state");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGD("JsGetState In");

    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstance(env, info);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstance");

    std::string curState = jsPlayer->GetCurrentState();
    MEDIA_LOGI("0x%{public}06" PRIXPTR " JsGetState curState: %{public}s ",
        FAKE_POINTER(jsPlayer), curState.c_str());
    napi_value value = nullptr;
    (void)napi_create_string_utf8(env, curState.c_str(), NAPI_AUTO_LENGTH, &value);
    MEDIA_LOGD("JsGetState Out");
    return value;
}

napi_value AVPlayerNapi::JsGetWidth(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::get width");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsGetWidth");

    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstance(env, info);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstance");

    int32_t width = 0;
    if (jsPlayer->IsControllable()) {
        width = jsPlayer->width_;
    }

    napi_value value = nullptr;
    (void)napi_create_int32(env, width, &value);
    return value;
}

napi_value AVPlayerNapi::JsGetHeight(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::get height");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsGetHeight");

    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstance(env, info);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstance");

    int32_t height = 0;
    if (jsPlayer->IsControllable()) {
        height = jsPlayer->height_;
    }

    napi_value value = nullptr;
    (void)napi_create_int32(env, height, &value);
    return value;
}

napi_value AVPlayerNapi::JsGetTrackDescription(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::get trackDescription");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("GetTrackDescription In");

    auto promiseCtx = std::make_unique<AVPlayerContext>(env);
    napi_value args[1] = { nullptr };
    size_t argCount = 1;
    promiseCtx->napi = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    promiseCtx->callbackRef = CommonNapi::CreateReference(env, args[0]);
    promiseCtx->deferred = CommonNapi::CreatePromise(env, promiseCtx->callbackRef, result);
    
    auto jsPlayer = promiseCtx->napi;
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstance");
    MEDIA_LOGD("0x%{public}06" PRIXPTR " JsGetTrackDescription EnqueueTask In", FAKE_POINTER(jsPlayer));
    promiseCtx->asyncTask = jsPlayer->GetTrackDescriptionTask(promiseCtx);
    MEDIA_LOGD("0x%{public}06" PRIXPTR " JsGetTrackDescription EnqueueTask Out", FAKE_POINTER(jsPlayer));

    // async work
    napi_value resource = nullptr;
    napi_create_string_utf8(env, "JsGetTrackDescription", NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource,
        [](napi_env env, void *data) {
            MEDIA_LOGI("Wait JsGetTrackDescription Task Start");
            auto promiseCtx = reinterpret_cast<AVPlayerContext *>(data);
            CHECK_AND_RETURN_LOG(promiseCtx != nullptr, "promiseCtx is nullptr!");
            if (promiseCtx->asyncTask) {
                auto result = promiseCtx->asyncTask->GetResult();
                if (!result.HasResult()) {
                    return promiseCtx->SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                                                 "task has been cleared");
                }
                if (result.Value().first != MSERR_EXT_API9_OK) {
                    return promiseCtx->SignError(result.Value().first, result.Value().second);
                }
                promiseCtx->JsResult = std::make_unique<MediaJsResultArray>(promiseCtx->trackInfoVec_);
            }
            MEDIA_LOGI("Wait JsGetTrackDescription Task End");
        },
        MediaAsyncContext::CompleteCallback, static_cast<void *>(promiseCtx.get()), &promiseCtx->work));
    napi_queue_async_work_with_qos(env, promiseCtx->work, napi_qos_user_initiated);
    promiseCtx.release();
    MEDIA_LOGI("GetTrackDescription Out");
    return result;
}

std::shared_ptr<TaskHandler<TaskRet>> AVPlayerNapi::GetTrackDescriptionTask(const std::unique_ptr<AVPlayerContext>
                                                                            &promiseCtx)
{
    auto task = std::make_shared<TaskHandler<TaskRet>>([this, &trackInfo = promiseCtx->trackInfoVec_]() {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " GetTrackDescription Task In", FAKE_POINTER(this));
        std::unique_lock<std::mutex> lock(taskMutex_);
        trackInfo.clear();
        if (IsControllable()) {
            (void)player_->GetVideoTrackInfo(trackInfo);
            (void)player_->GetAudioTrackInfo(trackInfo);
            (void)player_->GetSubtitleTrackInfo(trackInfo);
        } else {
            return TaskRet(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                           "current state unsupport get track description");
        }
        MEDIA_LOGI("0x%{public}06" PRIXPTR " GetTrackDescription Task Out", FAKE_POINTER(this));
        return TaskRet(MSERR_EXT_API9_OK, "Success");
    });
    (void)taskQue_->EnqueueTask(task);
    return task;
}

napi_value AVPlayerNapi::JsGetSelectedTracks(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::get selected tracks");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsGetSelectedTracks In");

    auto promiseCtx = std::make_unique<AVPlayerContext>(env);
    napi_value args[1] = { nullptr };
    size_t argCount = 1;
    promiseCtx->napi = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    promiseCtx->callbackRef = CommonNapi::CreateReference(env, args[0]);
    promiseCtx->deferred = CommonNapi::CreatePromise(env, promiseCtx->callbackRef, result);
    // async work
    napi_value resource = nullptr;
    napi_create_string_utf8(env, "JsGetSelectedTracks", NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, [](napi_env env, void *data) {
            MEDIA_LOGI("JsGetSelectedTracks Task");
            auto promiseCtx = reinterpret_cast<AVPlayerContext *>(data);
            CHECK_AND_RETURN_LOG(promiseCtx != nullptr, "promiseCtx is nullptr!");

            auto jsPlayer = promiseCtx->napi;
            if (jsPlayer == nullptr) {
                return promiseCtx->SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "avplayer is deconstructed");
            }

            std::vector<int32_t> trackIndex;
            if (jsPlayer->IsControllable()) {
                int32_t videoIndex = -1;
                (void)jsPlayer->player_->GetCurrentTrack(MediaType::MEDIA_TYPE_VID, videoIndex);
                if (videoIndex != -1) {
                    trackIndex.push_back(videoIndex);
                }

                int32_t audioIndex = -1;
                (void)jsPlayer->player_->GetCurrentTrack(MediaType::MEDIA_TYPE_AUD, audioIndex);
                if (audioIndex != -1) {
                    trackIndex.push_back(audioIndex);
                }

                int32_t subtitleIndex = -1;
                (void)jsPlayer->player_->GetCurrentTrack(MediaType::MEDIA_TYPE_SUBTITLE, subtitleIndex);
                if (subtitleIndex != -1) {
                    trackIndex.push_back(subtitleIndex);
                }
            } else {
                return promiseCtx->SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
                    "current state unsupport get current selections");
            }
            promiseCtx->JsResult = std::make_unique<MediaJsResultIntArray>(trackIndex);
        },
        MediaAsyncContext::CompleteCallback, static_cast<void *>(promiseCtx.get()), &promiseCtx->work));
    napi_queue_async_work_with_qos(env, promiseCtx->work, napi_qos_user_initiated);
    promiseCtx.release();
    MEDIA_LOGI("JsGetSelectedTracks Out");
    return result;
}

void AVPlayerNapi::HandleSelectTrack(std::unique_ptr<AVPlayerContext> &promiseCtx, napi_env env,
    napi_value args[], size_t argCount)
{
    napi_valuetype valueType = napi_undefined;
    if (argCount < 1 || napi_typeof(env, args[0], &valueType) != napi_ok || valueType != napi_number) {
        promiseCtx->SignError(MSERR_EXT_API9_INVALID_PARAMETER, "track index is not number");
        return;
    }

    auto jsPlayer = promiseCtx->napi;
    napi_status status = napi_get_value_int32(env, args[0], &jsPlayer->index_);
    if (status != napi_ok || jsPlayer->index_ < 0) {
        promiseCtx->SignError(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, please check the track index");
        return;
    }

    if (argCount > 1) {
        if (napi_typeof(env, args[1], &valueType) != napi_ok || valueType != napi_number) {
            promiseCtx->SignError(MSERR_EXT_API9_INVALID_PARAMETER, "switch mode is not number");
            return;
        }
        status = napi_get_value_int32(env, args[1], &jsPlayer->mode_);
        if (status != napi_ok || jsPlayer->mode_ < SWITCH_SMOOTH || jsPlayer->mode_ > SWITCH_CLOSEST) {
            promiseCtx->SignError(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, please switch seek mode");
            return;
        }
    }

    if (!jsPlayer->IsControllable()) {
        promiseCtx->SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, unsupport selectTrack operation");
        return;
    }
}

napi_value AVPlayerNapi::JsSelectTrack(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::selectTrack");
    MEDIA_LOGI("JsSelectTrack In");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    auto promiseCtx = std::make_unique<AVPlayerContext>(env);
    size_t argCount = 3; // 2 prarm, args[0]:index args[1]:SwitchMode callbackRef
    napi_value args[ARRAY_ARG_COUNTS_THREE] = { nullptr };
    promiseCtx->napi = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    promiseCtx->callbackRef = CommonNapi::CreateReference(env, args[argCount -1]);
    promiseCtx->deferred = CommonNapi::CreatePromise(env, promiseCtx->callbackRef, result);
    CHECK_AND_RETURN_RET_LOG(promiseCtx->napi != nullptr, result, "failed to GetJsInstanceWithParameter");

    promiseCtx->napi->HandleSelectTrack(promiseCtx, env, args, argCount);

    // async work
    napi_value resource = nullptr;
    napi_create_string_utf8(env, "JsSelectTrack ", NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, [](napi_env env, void *data) {
        MEDIA_LOGI("JsSelectTrack Task");
        auto promiseCtx = reinterpret_cast<AVPlayerContext *>(data);
        CHECK_AND_RETURN_LOG(promiseCtx != nullptr, "promiseCtx is nullptr!");

        CHECK_AND_RETURN(!promiseCtx->errFlag);

        auto jsPlayer = promiseCtx->napi;
        if (jsPlayer == nullptr) {
            return promiseCtx->SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "avplayer is deconstructed");
        }

        auto task = std::make_shared<TaskHandler<void>>([jsPlayer, index = jsPlayer->index_, mode = jsPlayer->mode_]() {
            MEDIA_LOGI("0x%{public}06" PRIXPTR " JsSelectTrack Task In", FAKE_POINTER(jsPlayer));
            if (jsPlayer->player_ != nullptr) {
                (void)jsPlayer->player_->SelectTrack(index, jsPlayer->TransferSwitchMode(mode));
            }
            MEDIA_LOGI("0x%{public}06" PRIXPTR " JsSelectTrack Task Out", FAKE_POINTER(jsPlayer));
        });
        MEDIA_LOGI("0x%{public}06" PRIXPTR " JsSelectTrack EnqueueTask In", FAKE_POINTER(jsPlayer));
        (void)jsPlayer->taskQue_->EnqueueTask(task);
        MEDIA_LOGI("0x%{public}06" PRIXPTR " JsSelectTrack Out", FAKE_POINTER(jsPlayer));
    },
    MediaAsyncContext::CompleteCallback, static_cast<void *>(promiseCtx.get()), &promiseCtx->work));
    napi_queue_async_work_with_qos(env, promiseCtx->work, napi_qos_user_initiated);
    promiseCtx.release();
    MEDIA_LOGI("JsSelectTrack Out");
    return result;
}

napi_value AVPlayerNapi::JsDeselectTrack(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::deselectTrack");
    MEDIA_LOGI("deselectTrack In");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    size_t argCount = 1;     // 1 prarm, args[0]:index
    napi_value args[1] = { nullptr };
    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstanceWithParameter");

    napi_valuetype valueType = napi_undefined;
    if (argCount < 1 || napi_typeof(env, args[0], &valueType) != napi_ok || valueType != napi_number) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "track index is not number");
        return result;
    }

    int32_t index = -1;
    napi_status status = napi_get_value_int32(env, args[0], &index);
    if (status != napi_ok || index < 0) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, please check the track index");
        return result;
    }

    if (!jsPlayer->IsControllable()) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, unsupport deselecttrack operation");
        return result;
    }

    auto task = std::make_shared<TaskHandler<void>>([jsPlayer, index]() {
        MEDIA_LOGI("deselectTrack Task");
        if (jsPlayer->player_ != nullptr) {
            (void)jsPlayer->player_->DeselectTrack(index);
        }
        MEDIA_LOGI("deselectTrack Task end");
    });
    (void)jsPlayer->taskQue_->EnqueueTask(task);
    return result;
}

napi_value AVPlayerNapi::JsGetCurrentTrack(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::JsGetCurrentTrack");
    MEDIA_LOGI("GetCurrentTrack In");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    size_t argCount = 2; // 2 param: trackType + callback
    napi_value args[ARRAY_ARG_COUNTS_TWO] = { nullptr };
    auto promiseCtx = std::make_unique<AVPlayerContext>(env);
    promiseCtx->napi = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(promiseCtx->napi != nullptr, result, "failed to GetJsInstanceWithParameter");
    promiseCtx->callbackRef = CommonNapi::CreateReference(env, args[1]);
    promiseCtx->deferred = CommonNapi::CreatePromise(env, promiseCtx->callbackRef, result);

    promiseCtx->napi->GetCurrentTrackTask(promiseCtx, env, args[0]);

    // async work
    napi_value resource = nullptr;
    napi_create_string_utf8(env, "JsGetCurrentTrack", NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource,
        [](napi_env env, void *data) {
            MEDIA_LOGI("GetCurrentTrack Task");
            auto promiseCtx = reinterpret_cast<AVPlayerContext *>(data);
            CHECK_AND_RETURN_LOG(promiseCtx != nullptr, "promiseCtx is nullptr!");
            CHECK_AND_RETURN_LOG(promiseCtx->asyncTask != nullptr, "asyncTask is nullptr!");
            auto result = promiseCtx->asyncTask->GetResult();
            if (result.HasResult() && result.Value().first != MSERR_EXT_API9_OK) {
                promiseCtx->SignError(result.Value().first, result.Value().second);
            } else {
                promiseCtx->JsResult = std::make_unique<MediaJsResultInt>(stoi(result.Value().second));
            }
            MEDIA_LOGI("GetCurrentTrack Task end");
        },
        MediaAsyncContext::CompleteCallback, static_cast<void *>(promiseCtx.get()), &promiseCtx->work));
    napi_queue_async_work_with_qos(env, promiseCtx->work, napi_qos_user_initiated);
    promiseCtx.release();
    return result;
}

void AVPlayerNapi::GetCurrentTrackTask(std::unique_ptr<AVPlayerContext> &promiseCtx, napi_env env, napi_value args)
{
    if (!promiseCtx->napi->IsControllable()) {
        promiseCtx->napi->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, unsupport getCurrentTrack operation");
        return;
    }

    napi_valuetype valueType = napi_undefined;
    if (args == nullptr || napi_typeof(env, args, &valueType) != napi_ok || valueType != napi_number) {
        promiseCtx->SignError(MSERR_EXT_API9_INVALID_PARAMETER, "track index is not number");
        return;
    }

    int32_t trackType = MediaType::MEDIA_TYPE_AUD;
    napi_status status = napi_get_value_int32(env, args, &trackType);
    if (status != napi_ok || trackType < MediaType::MEDIA_TYPE_AUD || trackType > MediaType::MEDIA_TYPE_VID) {
        promiseCtx->SignError(MSERR_EXT_API9_INVALID_PARAMETER, "invalid track Type");
        return;
    }

    auto task = std::make_shared<TaskHandler<TaskRet>>([this, trackType]() {
        MEDIA_LOGI("GetCurrentTrack Task In");
        std::unique_lock<std::mutex> lock(taskMutex_);
        CHECK_AND_RETURN_RET(IsControllable(), TaskRet(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, unsupport getCurrentTrack operation"));

        int32_t index = 0;
        int32_t ret = player_->GetCurrentTrack(trackType, index);
        if (ret != MSERR_OK) {
            auto errCode = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(ret));
            return TaskRet(errCode, "failed to GetCurrentTrack");
        }
        MEDIA_LOGI("GetCurrentTrack Task Out");
        return TaskRet(MSERR_EXT_API9_OK, std::to_string(index));
    });
    (void)taskQue_->EnqueueTask(task);
    promiseCtx->asyncTask = task;
    return;
}

void AVPlayerNapi::DeviceChangeCallbackOn(AVPlayerNapi *jsPlayer, std::string callbackName)
{
    if (jsPlayer == nullptr) {
        deviceChangeCallbackflag_ = false;
        return;
    }
    if (callbackName == "audioOutputDeviceChangeWithInfo") {
        deviceChangeCallbackflag_ = true;
    }
    if (jsPlayer->player_ != nullptr && deviceChangeCallbackflag_) {
        (void)jsPlayer->player_->SetDeviceChangeCbStatus(deviceChangeCallbackflag_);
    }
}

void AVPlayerNapi::DeviceChangeCallbackOff(AVPlayerNapi *jsPlayer, std::string callbackName)
{
    if (jsPlayer != nullptr && deviceChangeCallbackflag_ && callbackName == "audioOutputDeviceChangeWithInfo") {
        deviceChangeCallbackflag_ = false;
        if (jsPlayer->player_ != nullptr) {
            (void)jsPlayer->player_->SetDeviceChangeCbStatus(deviceChangeCallbackflag_);
        }
    }
}

void AVPlayerNapi::HandleListenerStateChange(std::string callbackName, bool state)
{
    CHECK_AND_RETURN_LOG(player_ != nullptr, "player is nullptr");
    
    if (callbackName == "amplitudeUpdate") {
        return (void)player_->SetMaxAmplitudeCbStatus(state);
    }

    if (callbackName == "timeUpdate") {
        reportMediaProgressCallbackflag_ = state;
        return (void)player_->EnableReportMediaProgress(state);
    }

    if (callbackName == "audioInterrupt") {
        return (void)player_->EnableReportAudioInterrupt(state);
    }
}

void AVPlayerNapi::SeiMessageCallbackOn(AVPlayerNapi *jsPlayer, std::string callbackName,
    const std::vector<int32_t> &payloadTypes)
{
    if (callbackName == "seiMessageReceived") {
        seiMessageCallbackflag_ = true;
    }

    if (jsPlayer->player_ != nullptr && seiMessageCallbackflag_) {
        MEDIA_LOGI("seiMessageCallbackflag_ = %{public}d", seiMessageCallbackflag_);
        (void)jsPlayer->player_->SetSeiMessageCbStatus(seiMessageCallbackflag_, payloadTypes);
    }
}

napi_value AVPlayerNapi::JsSetOnCallback(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::on");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGD("JsSetOnCallback In");

    napi_value args[ARRAY_ARG_COUNTS_THREE] = { nullptr }; // args[0]:type, args[1]: payloadTypes  args[2]:callback
    size_t argCount = ARRAY_ARG_COUNTS_THREE;
    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstanceWithParameter");
    if (argCount < ARRAY_ARG_COUNTS_TWO || argCount > ARRAY_ARG_COUNTS_THREE) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "Mandatory parameters are left unspecified.");
        return result;
    }

    if (jsPlayer->GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is released, unsupport to on event");
        return result;
    }

    CHECK_AND_RETURN_RET_NOLOG(
        VerifyExpectedType({ env, args[0], napi_string }, jsPlayer, "type should be string."), result);
    std::string callbackName = CommonNapi::GetStringArgument(env, args[0]);
    jsPlayer->hasSetStateChangeCb_ |= (callbackName == "stateChange");

    napi_ref ref = nullptr;
    if (argCount == ARGS_THREE) {
        CHECK_AND_RETURN_RET_NOLOG(
            VerifyExpectedType({ env, args[1], napi_object }, jsPlayer, "payloadTypes should be an Array."), result);
        CHECK_AND_RETURN_RET_NOLOG(
            VerifyExpectedType({ env, args[ARGS_TWO], napi_function }, jsPlayer, "param should be function."), result);
        std::vector<int32_t> payloadTypes = {};
        (void)CommonNapi::GetIntArrayArgument(env, args[1], payloadTypes);
        jsPlayer->SeiMessageCallbackOn(jsPlayer, callbackName, payloadTypes);
        napi_status status = napi_create_reference(env, args[ARGS_TWO], 1, &ref);
        CHECK_AND_RETURN_RET_LOG(status == napi_ok && ref != nullptr, result, "failed to create reference!");
    } else if (argCount == ARGS_TWO) {
        CHECK_AND_RETURN_RET_NOLOG(
            VerifyExpectedType({env, args[1], napi_function}, jsPlayer, "param should be function."), result);
        jsPlayer->HandleListenerStateChange(callbackName, true);
        napi_status status = napi_create_reference(env, args[1], 1, &ref);
        CHECK_AND_RETURN_RET_LOG(status == napi_ok && ref != nullptr, result, "failed to create reference!");
    }
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, ref);
        jsPlayer->SaveCallbackReference(callbackName, autoRef);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " JsSetOnCallback callbackName: %{public}s success",
        FAKE_POINTER(jsPlayer), callbackName.c_str());
    return result;
}

napi_value AVPlayerNapi::JsSetOnMetricsEventCallback(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::onMetricsEvent");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGD("JsSetOnMetricsEventCallback In");

    napi_value args[MIN_ARG_COUNTS] = { nullptr }; // args[0]: callback
    size_t argCount = MIN_ARG_COUNTS;
    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstanceWithParameter");
    if (argCount > MIN_ARG_COUNTS) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "Mandatory parameters are left unspecified.");
        return result;
    }

    if (jsPlayer->GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is released, unsupport to on event");
        return result;
    }

    std::string callbackName = AVPlayerEvent::EVENT_METRICS;
    napi_ref ref = nullptr;
    CHECK_AND_RETURN_RET_NOLOG(
        VerifyExpectedType({env, args[0], napi_function}, jsPlayer, "param should be function."), result);
    jsPlayer->HandleListenerStateChange(callbackName, true);
    napi_status status = napi_create_reference(env, args[0], 1, &ref);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && ref != nullptr, result, "failed to create reference!");

    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, ref);
        jsPlayer->SaveCallbackReference(callbackName, autoRef);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " JsSetOnMetricsEventCallback callbackName: %{public}s success",
        FAKE_POINTER(jsPlayer), callbackName.c_str());
    return result;
}

bool AVPlayerNapi::VerifyExpectedType(const NapiTypeCheckUnit &unit, AVPlayerNapi *jsPlayer, const std::string &msg)
{
    napi_valuetype tmpType;
    CHECK_AND_RETURN_RET_NOLOG(
        napi_typeof(unit.env, unit.param, &tmpType) != napi_ok || tmpType != unit.expectedType, true);
    jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, msg);
    return false;
}

void AVPlayerNapi::SeiMessageCallbackOff(AVPlayerNapi *jsPlayer, std::string &callbackName,
    const std::vector<int32_t> &payloadTypes)
{
    if (jsPlayer == nullptr || !seiMessageCallbackflag_ || callbackName != "seiMessageReceived") {
        return;
    }
    seiMessageCallbackflag_ = false;
    if (jsPlayer->player_ == nullptr) {
        return;
    }
    (void)jsPlayer->player_->SetSeiMessageCbStatus(seiMessageCallbackflag_, payloadTypes);
}

napi_value AVPlayerNapi::JsClearOnMetricsEventCallback(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::offMetricsEvent");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGD("JsClearOnMetricsEventCallback In");

    napi_value args[ARRAY_ARG_COUNTS_THREE] = { nullptr }; // args[0]:type, args[1]: payloadTypes  args[2]:callback
    size_t argCount = 3;
    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstanceWithParameter");

    if (jsPlayer->GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        return result;
    }

    if (argCount > 1) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "Mandatory parameters are left unspecified.");
        return result;
    }

    std::string callbackName = AVPlayerEvent::EVENT_METRICS;

    MEDIA_LOGI("0x%{public}06" PRIXPTR " set callbackName: %{public}s", FAKE_POINTER(jsPlayer), callbackName.c_str());
    jsPlayer->HandleListenerStateChange(callbackName, false);
    jsPlayer->ClearCallbackReference(callbackName);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " JsClearOnCallback success", FAKE_POINTER(jsPlayer));
    return result;
}


napi_value AVPlayerNapi::JsClearOnCallback(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::off");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGD("JsClearOnCallback In");

    napi_value args[ARRAY_ARG_COUNTS_THREE] = { nullptr }; // args[0]:type, args[1]: payloadTypes  args[2]:callback
    size_t argCount = 3;
    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstanceWithParameter");

    if (jsPlayer->GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        return result;
    }

    napi_valuetype valueType0 = napi_undefined;
    if (argCount < 1) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "Mandatory parameters are left unspecified.");
        return result;
    }

    if (napi_typeof(env, args[0], &valueType0) != napi_ok || valueType0 != napi_string) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "type should be string.");
        return result;
    }

    std::string callbackName = CommonNapi::GetStringArgument(env, args[0]);
    jsPlayer->hasSetStateChangeCb_ &= (callbackName != "stateChange");
    MEDIA_LOGI("0x%{public}06" PRIXPTR " set callbackName: %{public}s", FAKE_POINTER(jsPlayer), callbackName.c_str());
    if (callbackName != "seiMessageReceived") {
        jsPlayer->HandleListenerStateChange(callbackName, false);
        jsPlayer->ClearCallbackReference(callbackName);
        MEDIA_LOGI("0x%{public}06" PRIXPTR " JsClearOnCallback success", FAKE_POINTER(jsPlayer));
        return result;
    }
    
    napi_valuetype valueType1 = napi_undefined;
    if (napi_typeof(env, args[1], &valueType1) != napi_ok || valueType1 != napi_object) {
        jsPlayer->SeiMessageCallbackOff(jsPlayer, callbackName, {});
        jsPlayer->ClearCallbackReference(callbackName);
        MEDIA_LOGI("0x%{public}06" PRIXPTR " JsClearOnCallback success", FAKE_POINTER(jsPlayer));
        return result;
    }
    std::vector<int32_t> payloadTypes = {};
    if (CommonNapi::GetIntArrayArgument(env, args[1], payloadTypes)) {
        jsPlayer->SeiMessageCallbackOff(jsPlayer, callbackName, payloadTypes);
        if (!payloadTypes.empty() && payloadTypes[0] == SEI_MSG_PAYLOAD_TYPE_SUPPORT) {
            jsPlayer->ClearCallbackReference(callbackName);
            MEDIA_LOGI("SEI_MSG_PAYLOAD_TYPE_SUPPORT.");
        }
    } else {
        MEDIA_LOGD("The array is empty, no processing is performed.");
    }
    
    return result;
}

void AVPlayerNapi::SaveCallbackReference(const std::string &callbackName, std::shared_ptr<AutoRef> ref)
{
    std::lock_guard<std::mutex> lock(mutex_);
    refMap_[callbackName] = ref;
    if (playerCb_ != nullptr) {
        playerCb_->SaveCallbackReference(callbackName, ref);
    }
}

void AVPlayerNapi::ClearCallbackReference()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (playerCb_ != nullptr) {
        playerCb_->ClearCallbackReference();
    }
    refMap_.clear();
}

void AVPlayerNapi::ClearCallbackReference(const std::string &callbackName)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (playerCb_ != nullptr) {
        playerCb_->ClearCallbackReference(callbackName);
    }
    refMap_.erase(callbackName);
}

void AVPlayerNapi::NotifyDuration(int32_t duration)
{
    duration_ = duration;
}

void AVPlayerNapi::NotifyPosition(int32_t position)
{
    position_ = position;
}

void AVPlayerNapi::NotifyState(PlayerStates state)
{
    std::lock_guard<std::mutex> lock(taskMutex_);
    if (state_ != state) {
        state_ = state;
        MEDIA_LOGI("0x%{public}06" PRIXPTR " notify %{public}s", FAKE_POINTER(this), GetCurrentState().c_str());
        stopWait_ = true;
        stateChangeCond_.notify_all();
    }
}

void AVPlayerNapi::NotifyVideoSize(int32_t width, int32_t height)
{
    width_ = width;
    height_ = height;
}

void AVPlayerNapi::NotifyIsLiveStream()
{
    isLiveStream_ = true;
}

void AVPlayerNapi::NotifyDrmInfoUpdated(const std::multimap<std::string, std::vector<uint8_t>> &infos)
{
    MEDIA_LOGD("NotifyDrmInfoUpdated");
    std::unique_lock<std::shared_mutex> lock(drmMutex_);
    for (auto &newItem : infos) {
        auto pos = localDrmInfos_.equal_range(newItem.first);
        if (pos.first == pos.second && pos.first == localDrmInfos_.end()) {
            localDrmInfos_.insert(newItem);
            continue;
        }
        bool isSame = false;
        for (; pos.first != pos.second; ++pos.first) {
            if (newItem.second == pos.first->second) {
                isSame = true;
                break;
            }
        }
        if (!isSame) {
            localDrmInfos_.insert(newItem);
        }
    }
}

void AVPlayerNapi::ResetUserParameters()
{
    url_.clear();
    fileDescriptor_.fd = 0;
    fileDescriptor_.offset = 0;
    fileDescriptor_.length = -1;
    width_ = 0;
    height_ = 0;
    position_ = -1;
    duration_ = -1;
    loop_ = false;
}

void AVPlayerNapi::StartListenCurrentResource()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (playerCb_ != nullptr) {
        playerCb_->Start();
    }
}

void AVPlayerNapi::PauseListenCurrentResource()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (playerCb_ != nullptr) {
        playerCb_->Pause();
    }
}

/**
 * DO NOT hold taskMutex_ before call this function
 * AVPlayerCallback::OnErrorCb() hold AVPlayerCallback::mutex_ and wait taskMutex_, may cause dead lock
*/
void AVPlayerNapi::OnErrorCb(MediaServiceExtErrCodeAPI9 errorCode, const std::string &errorMsg)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (playerCb_ != nullptr) {
        playerCb_->OnErrorCb(errorCode, errorMsg);
    }
}

AVPlayerNapi* AVPlayerNapi::GetJsInstance(napi_env env, napi_callback_info info)
{
    size_t argCount = 0;
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argCount, nullptr, &jsThis, nullptr);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && jsThis != nullptr, nullptr, "failed to napi_get_cb_info");

    AVPlayerNapi *jsPlayer = nullptr;
    status = napi_unwrap(env, jsThis, reinterpret_cast<void **>(&jsPlayer));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && jsPlayer != nullptr, nullptr, "failed to napi_unwrap");

    return jsPlayer;
}

AVPlayerNapi* AVPlayerNapi::GetJsInstanceWithParameter(napi_env env, napi_callback_info info,
    size_t &argc, napi_value *argv)
{
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &jsThis, nullptr);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && jsThis != nullptr, nullptr, "failed to napi_get_cb_info");

    AVPlayerNapi *jsPlayer = nullptr;
    status = napi_unwrap(env, jsThis, reinterpret_cast<void **>(&jsPlayer));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && jsPlayer != nullptr, nullptr, "failed to napi_unwrap");

    return jsPlayer;
}

bool AVPlayerNapi::IsLiveSource() const
{
    return isLiveStream_;
}

int32_t AVPlayerNapi::GetJsApiVersion()
{
    if (player_ != nullptr && getApiVersionFlag_) {
        getApiVersionFlag_ = false;
        player_->GetApiVersion(g_apiVersion);
        MEDIA_LOGI("apiVersion is: %{public}d", g_apiVersion);
    }
    return g_apiVersion;
}

void AVPlayerNapi::AddMediaStreamToAVMediaSource(
    const std::shared_ptr<AVMediaSourceTmp> &srcTmp, std::shared_ptr<AVMediaSource> &mediaSource)
{
    for (const auto &mediaStreamTmp : srcTmp->getAVPlayMediaStreamTmpList()) {
        AVPlayMediaStream mediaStream;
        mediaStream.url = mediaStreamTmp.url;
        mediaStream.width = mediaStreamTmp.width;
        mediaStream.height = mediaStreamTmp.height;
        mediaStream.bitrate = mediaStreamTmp.bitrate;
        mediaSource->AddMediaStream(mediaStream);
    }
}

napi_value AVPlayerNapi::JsIsSeekContinuousSupported(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::isSeekContinuousSupported");
    MEDIA_LOGI("JsIsSeekContinuousSupported In");
    napi_value result = nullptr;
    bool isSeekContinuousSupported = false;
    napi_status status = napi_get_boolean(env, isSeekContinuousSupported, &result);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, result, "napi_get_boolean failed");
    size_t argCount = 0;
    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, nullptr);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstance");
    if (jsPlayer->isReadyReleased_.load()) {
        status = napi_get_boolean(env, false, &result);
        CHECK_AND_RETURN_RET_LOG(status == napi_ok, result, "napi_get_boolean failed");
        return result;
    }
    if (jsPlayer->player_ != nullptr) {
        isSeekContinuousSupported = jsPlayer->player_->IsSeekContinuousSupported();
        status = napi_get_boolean(env, isSeekContinuousSupported, &result);
        CHECK_AND_RETURN_RET_LOG(status == napi_ok, result, "napi_get_boolean failed");
    }
    return result;
}

napi_value AVPlayerNapi::JsSetLoudnessGain(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVPlayerNapi::JsSetLoudnessGain");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsSetLoudnessGain in");

    auto promiseCtx = std::make_unique<AVPlayerContext>(env);
    napi_value args[1] = { nullptr };
    size_t argCount = 1;
    AVPlayerNapi *jsPlayer = AVPlayerNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(jsPlayer != nullptr, result, "failed to GetJsInstanceWithParameter");
    promiseCtx->callbackRef = CommonNapi::CreateReference(env, args[0]);
    promiseCtx->deferred = CommonNapi::CreatePromise(env, promiseCtx->callbackRef, result);

    napi_valuetype valueType = napi_undefined;
    if (argCount < 1 || napi_typeof(env, args[0], &valueType) != napi_ok || valueType != napi_number) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "loudness is not number");
        return result;
    }

    double loudnessGain = 0.0f;
    napi_status status = napi_get_value_double(env, args[0], &loudnessGain);
    if (status != napi_ok || loudnessGain < -90.0f || loudnessGain > 24.0f) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_INVALID_PARAMETER, "invalid parameters, check loudnessGain");
        return result;
    }

    if (!jsPlayer->CanSetLoudnessGain()) {
        jsPlayer->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed/stopped, unsupport audio effect mode operation");
        return result;
    }

    auto task = std::make_shared<TaskHandler<void>>([jsPlayer, loudnessGain]() {
        MEDIA_LOGD("SetLoudnessGain Task");
        if (jsPlayer->player_ != nullptr && jsPlayer->player_->SetLoudnessGain(loudnessGain)) {
            jsPlayer->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "unsupport stream type");
        }
    });
    (void)jsPlayer->taskQue_->EnqueueTask(task);
    MEDIA_LOGI("JsSetLoudnessGain out");
    return result;
}

bool AVPlayerNapi::CanSetLoudnessGain()
{
    auto state = GetCurrentState();
    if (state == AVPlayerState::STATE_COMPLETED || state == AVPlayerState::STATE_PREPARED ||
        state == AVPlayerState::STATE_PLAYING || state == AVPlayerState::STATE_PAUSED ||
        state == AVPlayerState::STATE_STOPPED) {
        return true;
    }
    return false;
}
} // namespace Media
} // namespace OHOS