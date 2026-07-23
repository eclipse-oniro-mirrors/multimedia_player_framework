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

#include "avads_controller_taihe.h"
#include "avplayer_taihe.h"
#include "media_log.h"
#include "media_errors.h"
#include "media_dfx.h"
#include "media_source_taihe.h"

using namespace ANI::Media;

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_METADATA, "AVAdsControllerTaihe"};
    constexpr int32_t ERR_ADS_PARAM_INVALID = 5400108;
}

namespace ANI::Media {

AVAdsControllerImpl::AVAdsControllerImpl()
{
    MEDIA_LOGI("AVAdsControllerImpl Constructor");
}

AVAdsControllerImpl::AVAdsControllerImpl(AVPlayerImpl *player)
    : player_(player)
{
    if (player_ != nullptr) {
        playerInstance_ = player_->GetPlayerInstance();
    }
    MEDIA_LOGI("AVAdsControllerImpl Constructor with player");
}

AVAdsControllerImpl::~AVAdsControllerImpl()
{
    Release();
    MEDIA_LOGI("AVAdsControllerImpl Destructor");
}

void AVAdsControllerImpl::SetPlayer(AVPlayerImpl *player)
{
    player_ = player;
    if (player_ != nullptr) {
        playerInstance_ = player_->GetPlayerInstance();
    } else {
        playerInstance_ = nullptr;
    }
}

std::shared_ptr<OHOS::Media::Player> AVAdsControllerImpl::GetPlayerInstance() const
{
    return playerInstance_;
}

string AVAdsControllerImpl::AddAdsMediaSourceSync(::ohos::multimedia::media::weak::MediaSource src, int32_t startMs)
{
    MediaTrace trace("AVAdsControllerImpl::addAdsMediaSource");
    MEDIA_LOGI("AddAdsMediaSourceSync In");

    string invalidId {};
    if (player_ == nullptr) {
        set_business_error(ERR_ADS_PARAM_INVALID, "controller is released");
        return invalidId;
    }
    if (playerInstance_ == nullptr) {
        set_business_error(ERR_ADS_PARAM_INVALID, "player instance is null");
        return invalidId;
    }
    OHOS::Media::TaskQueue *taskQueue = player_->GetTaskQueue();
    if (taskQueue == nullptr) {
        set_business_error(ERR_ADS_PARAM_INVALID, "task queue is null");
        return invalidId;
    }

    std::shared_ptr<AVMediaSourceTmp> srcTmp = MediaSourceImpl::GetMediaSource(src);
    if (srcTmp == nullptr) {
        set_business_error(ERR_ADS_PARAM_INVALID, "get MediaSource argument failed!");
        return invalidId;
    }
    std::shared_ptr<AVMediaSource> mediaSource = AVPlayerImpl::GetAVMediaSource(src, srcTmp);
    if (mediaSource == nullptr) {
        set_business_error(ERR_ADS_PARAM_INVALID, "create mediaSource failed!");
        return invalidId;
    }

    std::string outId;
    std::shared_ptr<AVPlayerContext> context = std::make_shared<AVPlayerContext>();
    context->asyncTask = AddAdsMediaSourceTask(playerInstance_, taskQueue, mediaSource, startMs, outId);
    context->CheckTaskResult();
    if (!context->errFlag) {
        MEDIA_LOGI("AddAdsMediaSourceSync Out, id: %{public}s", outId.c_str());
        return string(outId);
    }
    return invalidId;
}

void AVAdsControllerImpl::RemoveAdsMediaSource(::taihe::string_view id)
{
    MediaTrace trace("AVAdsControllerImpl::removeAdsMediaSource");
    MEDIA_LOGI("RemoveAdsMediaSource In");

    if (playerInstance_ == nullptr) {
        set_business_error(ERR_ADS_PARAM_INVALID, "controller is released");
        return;
    }

    std::string idStr(id);
    int32_t ret = playerInstance_->RemoveAdsMediaSource(idStr);
    if (ret != MSERR_OK) {
        set_business_error(ERR_ADS_PARAM_INVALID, "removeAdsMediaSource failed");
    }
    MEDIA_LOGI("RemoveAdsMediaSource Out");
}

void AVAdsControllerImpl::SkipCurrentAdsMediaSource()
{
    MediaTrace trace("AVAdsControllerImpl::skipCurrentAdsMediaSource");
    MEDIA_LOGI("SkipCurrentAdsMediaSource In");

    if (player_ == nullptr) {
        MEDIA_LOGE("controller is released");
        return;
    }
    if (player_->GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        MEDIA_LOGE("current state is released, unsupport to skip");
        return;
    }
    if (playerInstance_ == nullptr) {
        MEDIA_LOGE("player instance is null");
        return;
    }

    playerInstance_->SkipCurrentAdsMediaSource();
    MEDIA_LOGI("SkipCurrentAdsMediaSource Out");
}

void AVAdsControllerImpl::DisableAllAdsMediaSource()
{
    MediaTrace trace("AVAdsControllerImpl::disableAllAdsMediaSource");
    MEDIA_LOGI("DisableAllAdsMediaSource In");

    if (playerInstance_ == nullptr) {
        MEDIA_LOGE("controller is released");
        return;
    }

    playerInstance_->DisableAllAdsMediaSource();
    MEDIA_LOGI("DisableAllAdsMediaSource Out");
}

void AVAdsControllerImpl::OnAdsEventListenerLoadingError(
    callback_view<void(::taihe::string_view, uintptr_t)> callback)
{
    MediaTrace trace("AVAdsControllerImpl::OnAdsEventListenerLoadingError");
    MEDIA_LOGD("OnAdsEventListenerLoadingError In");

    ani_env *env = taihe::get_env();
    CHECK_AND_RETURN_LOG(env != nullptr, "Failed to get ani_env");
    std::shared_ptr<taihe::callback<void(::taihe::string_view, uintptr_t)>> taiheCallback =
        std::make_shared<taihe::callback<void(::taihe::string_view, uintptr_t)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);

    if (player_ == nullptr) {
        MEDIA_LOGE("controller is released");
        return;
    }
    if (player_->GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        MEDIA_LOGE("current state is released, unsupport to on event");
        return;
    }
    player_->SaveCallbackReference(AVPlayerEvent::EVENT_ADS_LOADING_ERROR, autoRef);
    MEDIA_LOGI("OnAdsEventListenerLoadingError success");
}

void AVAdsControllerImpl::OffAdsEventListenerLoadingError(
    optional_view<callback<void(::taihe::string_view, uintptr_t)>> callback)
{
    MediaTrace trace("AVAdsControllerImpl::OffAdsEventListenerLoadingError");
    MEDIA_LOGD("OffAdsEventListenerLoadingError In");

    if (player_ != nullptr) {
        player_->ClearCallbackReference(AVPlayerEvent::EVENT_ADS_LOADING_ERROR);
    }
    MEDIA_LOGI("OffAdsEventListenerLoadingError End");
}

void AVAdsControllerImpl::OnAdsListenerAdsStarted(callback_view<void(::taihe::string_view, int64_t)> callback)
{
    MediaTrace trace("AVAdsControllerImpl::OnAdsListenerAdsStarted");
    MEDIA_LOGD("OnAdsListenerAdsStarted In");

    ani_env *env = taihe::get_env();
    CHECK_AND_RETURN_LOG(env != nullptr, "Failed to get ani_env");
    std::shared_ptr<taihe::callback<void(::taihe::string_view, int64_t)>> taiheCallback =
        std::make_shared<taihe::callback<void(::taihe::string_view, int64_t)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);

    if (player_ == nullptr) {
        MEDIA_LOGE("controller is released");
        return;
    }
    if (player_->GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        MEDIA_LOGE("current state is released, unsupport to on event");
        return;
    }
    player_->SaveCallbackReference(AVPlayerEvent::EVENT_ADS_STARTED, autoRef);
    MEDIA_LOGI("OnAdsListenerAdsStarted success");
}

void AVAdsControllerImpl::OffAdsListenerAdsStarted(
    optional_view<callback<void(::taihe::string_view, int64_t)>> callback)
{
    MediaTrace trace("AVAdsControllerImpl::OffAdsListenerAdsStarted");
    MEDIA_LOGD("OffAdsListenerAdsStarted In");

    if (player_ != nullptr) {
        player_->ClearCallbackReference(AVPlayerEvent::EVENT_ADS_STARTED);
    }
    MEDIA_LOGI("OffAdsListenerAdsStarted End");
}

void AVAdsControllerImpl::OnAdsListenerAdsSkipped(callback_view<void(::taihe::string_view)> callback)
{
    MediaTrace trace("AVAdsControllerImpl::OnAdsListenerAdsSkipped");
    MEDIA_LOGD("OnAdsListenerAdsSkipped In");

    ani_env *env = taihe::get_env();
    CHECK_AND_RETURN_LOG(env != nullptr, "Failed to get ani_env");
    std::shared_ptr<taihe::callback<void(::taihe::string_view)>> taiheCallback =
        std::make_shared<taihe::callback<void(::taihe::string_view)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);

    if (player_ == nullptr) {
        MEDIA_LOGE("controller is released");
        return;
    }
    if (player_->GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        MEDIA_LOGE("current state is released, unsupport to on event");
        return;
    }
    player_->SaveCallbackReference(AVPlayerEvent::EVENT_ADS_SKIPPED, autoRef);
    MEDIA_LOGI("OnAdsListenerAdsSkipped success");
}

void AVAdsControllerImpl::OffAdsListenerAdsSkipped(
    optional_view<callback<void(::taihe::string_view)>> callback)
{
    MediaTrace trace("AVAdsControllerImpl::OffAdsListenerAdsSkipped");
    MEDIA_LOGD("OffAdsListenerAdsSkipped In");

    if (player_ != nullptr) {
        player_->ClearCallbackReference(AVPlayerEvent::EVENT_ADS_SKIPPED);
    }
    MEDIA_LOGI("OffAdsListenerAdsSkipped End");
}

void AVAdsControllerImpl::OnAdsListenerAdsCompleted(callback_view<void(::taihe::string_view)> callback)
{
    MediaTrace trace("AVAdsControllerImpl::OnAdsListenerAdsCompleted");
    MEDIA_LOGD("OnAdsListenerAdsCompleted In");

    ani_env *env = taihe::get_env();
    CHECK_AND_RETURN_LOG(env != nullptr, "Failed to get ani_env");
    std::shared_ptr<taihe::callback<void(::taihe::string_view)>> taiheCallback =
        std::make_shared<taihe::callback<void(::taihe::string_view)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);

    if (player_ == nullptr) {
        MEDIA_LOGE("controller is released");
        return;
    }
    if (player_->GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        MEDIA_LOGE("current state is released, unsupport to on event");
        return;
    }
    player_->SaveCallbackReference(AVPlayerEvent::EVENT_ADS_COMPLETED, autoRef);
    MEDIA_LOGI("OnAdsListenerAdsCompleted success");
}

void AVAdsControllerImpl::OffAdsListenerAdsCompleted(
    optional_view<callback<void(::taihe::string_view)>> callback)
{
    MediaTrace trace("AVAdsControllerImpl::OffAdsListenerAdsCompleted");
    MEDIA_LOGD("OffAdsListenerAdsCompleted In");

    if (player_ != nullptr) {
        player_->ClearCallbackReference(AVPlayerEvent::EVENT_ADS_COMPLETED);
    }
    MEDIA_LOGI("OffAdsListenerAdsCompleted End");
}

void AVAdsControllerImpl::Release()
{
    MediaTrace trace("AVAdsControllerImpl::Release");
    MEDIA_LOGI("AVAdsController Release In");

    if (player_ == nullptr) {
        return;
    }
    player_->ClearCallbackReference(AVPlayerEvent::EVENT_ADS_LOADING_ERROR);
    player_->ClearCallbackReference(AVPlayerEvent::EVENT_ADS_STARTED);
    player_->ClearCallbackReference(AVPlayerEvent::EVENT_ADS_SKIPPED);
    player_->ClearCallbackReference(AVPlayerEvent::EVENT_ADS_COMPLETED);

    if (playerInstance_ != nullptr) {
        playerInstance_->DisableAllAdsMediaSource();
    }
    player_ = nullptr;
    playerInstance_ = nullptr;
    MEDIA_LOGI("AVAdsController Release Out");
}

std::shared_ptr<TaskHandler<AdsTaskRet>> AVAdsControllerImpl::AddAdsMediaSourceTask(
    const std::shared_ptr<OHOS::Media::Player> &playerInstance, OHOS::Media::TaskQueue *taskQueue,
    const std::shared_ptr<AVMediaSource> &mediaSource, int32_t startMs, std::string &outId)
{
    CHECK_AND_RETURN_RET_LOG(playerInstance != nullptr, nullptr, "player instance is null");
    CHECK_AND_RETURN_RET_LOG(taskQueue != nullptr, nullptr, "task queue is null");
    auto task = std::make_shared<TaskHandler<AdsTaskRet>>([playerInstance, mediaSource, startMs, &outId]() {
        int32_t ret = playerInstance->AddAdsMediaSource(mediaSource, startMs, outId);
        if (ret != MSERR_OK) {
            return AdsTaskRet(ERR_ADS_PARAM_INVALID, "addAdsMediaSource failed");
        }
        return AdsTaskRet(MSERR_EXT_API9_OK, "Success");
    });
    (void)taskQueue->EnqueueTask(task);
    return task;
}

optional<AVAdsController> CreateAVAdsControllerSync(::ohos::multimedia::media::weak::AVPlayer avplayer)
{
    MediaTrace trace("CreateAVAdsControllerSync");
    MEDIA_LOGI("CreateAVAdsControllerSync In");
    if (avplayer.is_error()) {
        MEDIA_LOGE("AVPlayer weak reference is invalid");
        return optional<AVAdsController>(std::nullopt);
    }
    AVPlayerImpl *playerImpl = reinterpret_cast<AVPlayerImpl *>(avplayer->GetImplPtr());
    if (playerImpl == nullptr) {
        MEDIA_LOGE("AVPlayer is null");
        return optional<AVAdsController>(std::nullopt);
    }

    auto res = make_holder<AVAdsControllerImpl, AVAdsController>(playerImpl);
    if (taihe::has_error()) {
        MEDIA_LOGE("Create AVAdsController failed!");
        taihe::reset_error();
        return optional<AVAdsController>(std::nullopt);
    }

    MEDIA_LOGI("CreateAVAdsControllerSync Out");
    return optional<AVAdsController>(std::in_place, res);
}
}
TH_EXPORT_CPP_API_CreateAVAdsControllerSync(CreateAVAdsControllerSync);
