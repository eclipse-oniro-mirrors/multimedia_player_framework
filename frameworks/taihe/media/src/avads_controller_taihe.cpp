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
}

namespace ANI::Media {

AVAdsControllerImpl::AVAdsControllerImpl()
{
    MEDIA_LOGI("AVAdsControllerImpl Constructor");
}

AVAdsControllerImpl::AVAdsControllerImpl(AVPlayerImpl *player)
{
    player_ = player;
    MEDIA_LOGI("AVAdsControllerImpl Constructor with player");
}

AVAdsControllerImpl::~AVAdsControllerImpl()
{
    MEDIA_LOGI("AVAdsControllerImpl Destructor");
}

void AVAdsControllerImpl::SetPlayer(AVPlayerImpl *player)
{
    std::lock_guard<std::mutex> lock(mutex_);
    player_ = player;
}

AVPlayerImpl *AVAdsControllerImpl::GetPlayer() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return player_;
}

string AVAdsControllerImpl::AddAdsMediaSourceSync(::ohos::multimedia::media::weak::MediaSource src, int64_t startMs)
{
    MediaTrace trace("AVAdsControllerImpl::addAdsMediaSource");
    MEDIA_LOGI("AddAdsMediaSourceSync In");

    string invalidId {};
    AVPlayerImpl *player = GetPlayer();
    if (player == nullptr) {
        set_business_error(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "controller is released");
        return invalidId;
    }

    if (!player->IsControllable()) {
        set_business_error(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, unsupport add ads media source");
        return invalidId;
    }

    std::shared_ptr<AVMediaSourceTmp> srcTmp = MediaSourceImpl::GetMediaSource(src);
    if (srcTmp == nullptr) {
        set_business_error(MSERR_EXT_API9_INVALID_PARAMETER, "get MediaSource argument failed!");
        return invalidId;
    }
    std::shared_ptr<AVMediaSource> mediaSource = AVPlayerImpl::GetAVMediaSource(src, srcTmp);
    if (mediaSource == nullptr) {
        set_business_error(MSERR_EXT_API9_INVALID_PARAMETER, "create mediaSource failed!");
        return invalidId;
    }

    std::string outId;
    std::shared_ptr<AVPlayerContext> context = std::make_shared<AVPlayerContext>();
    context->asyncTask = AddAdsMediaSourceTask(mediaSource, startMs, outId);
    context->CheckTaskResult();
    if (!context->errFlag) {
        MEDIA_LOGI("AddAdsMediaSourceSync Out, id: %{public}s", outId.c_str());
        return string(outId);
    }
    return invalidId;
}

void AVAdsControllerImpl::RemoveAdsMediaSourceSync(::taihe::string_view id)
{
    MediaTrace trace("AVAdsControllerImpl::removeAdsMediaSource");
    MEDIA_LOGI("RemoveAdsMediaSourceSync In");

    AVPlayerImpl *player = GetPlayer();
    if (player == nullptr) {
        set_business_error(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "controller is released");
        return;
    }

    if (!player->IsControllable()) {
        set_business_error(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, unsupport remove ads media source");
        return;
    }

    std::string idStr(id);
    std::shared_ptr<AVPlayerContext> context = std::make_shared<AVPlayerContext>();
    context->asyncTask = RemoveAdsMediaSourceTask(idStr);
    context->CheckTaskResult();
    MEDIA_LOGI("RemoveAdsMediaSourceSync Out");
}

void AVAdsControllerImpl::SkipCurrentAdsMediaSourceSync()
{
    MediaTrace trace("AVAdsControllerImpl::skipCurrentAdsMediaSource");
    MEDIA_LOGI("SkipCurrentAdsMediaSourceSync In");

    AVPlayerImpl *player = GetPlayer();
    if (player == nullptr) {
        set_business_error(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "controller is released");
        return;
    }

    if (!player->IsControllable()) {
        set_business_error(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, unsupport skip current ads media source");
        return;
    }

    std::shared_ptr<AVPlayerContext> context = std::make_shared<AVPlayerContext>();
    context->asyncTask = SkipCurrentAdsMediaSourceTask();
    context->CheckTaskResult();
    MEDIA_LOGI("SkipCurrentAdsMediaSourceSync Out");
}

void AVAdsControllerImpl::DisableAllAdsMediaSourceSync()
{
    MediaTrace trace("AVAdsControllerImpl::disableAllAdsMediaSource");
    MEDIA_LOGI("DisableAllAdsMediaSourceSync In");

    AVPlayerImpl *player = GetPlayer();
    if (player == nullptr) {
        set_business_error(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "controller is released");
        return;
    }

    if (!player->IsControllable()) {
        set_business_error(MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "current state is not prepared/playing/paused/completed, unsupport disable all ads media source");
        return;
    }

    std::shared_ptr<AVPlayerContext> context = std::make_shared<AVPlayerContext>();
    context->asyncTask = DisableAllAdsMediaSourceTask();
    context->CheckTaskResult();
    MEDIA_LOGI("DisableAllAdsMediaSourceSync Out");
}

void AVAdsControllerImpl::OnAdsEventListenerLoadingError(
    callback_view<void(::taihe::string_view, uintptr_t)> callback)
{
    MediaTrace trace("AVAdsControllerImpl::OnAdsEventListenerLoadingError");
    MEDIA_LOGD("OnAdsEventListenerLoadingError In");

    AVPlayerImpl *player = GetPlayer();
    if (player == nullptr) {
        set_business_error(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "controller is released");
        return;
    }

    if (player->GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        player->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is released, unsupport to on event");
        return;
    }

    ani_env *env = taihe::get_env();
    std::shared_ptr<taihe::callback<void(::taihe::string_view, uintptr_t)>> taiheCallback =
        std::make_shared<taihe::callback<void(::taihe::string_view, uintptr_t)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    player->SaveCallbackReference(AVPlayerEvent::EVENT_ADS_LOADING_ERROR, autoRef);
    MEDIA_LOGI("OnAdsEventListenerLoadingError success");
}

void AVAdsControllerImpl::OffAdsEventListenerLoadingError(
    optional_view<callback<void(::taihe::string_view, uintptr_t)>> callback)
{
    MediaTrace trace("AVAdsControllerImpl::OffAdsEventListenerLoadingError");
    MEDIA_LOGD("OffAdsEventListenerLoadingError In");

    AVPlayerImpl *player = GetPlayer();
    if (player == nullptr || player->GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        return;
    }
    player->ClearCallbackReference(AVPlayerEvent::EVENT_ADS_LOADING_ERROR);
    MEDIA_LOGI("OffAdsEventListenerLoadingError End");
}

void AVAdsControllerImpl::OnAdsListenerAdsStarted(callback_view<void(::taihe::string_view, int64_t)> callback)
{
    MediaTrace trace("AVAdsControllerImpl::OnAdsListenerAdsStarted");
    MEDIA_LOGD("OnAdsListenerAdsStarted In");

    AVPlayerImpl *player = GetPlayer();
    if (player == nullptr) {
        set_business_error(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "controller is released");
        return;
    }

    if (player->GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        player->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is released, unsupport to on event");
        return;
    }

    ani_env *env = taihe::get_env();
    std::shared_ptr<taihe::callback<void(::taihe::string_view, int64_t)>> taiheCallback =
        std::make_shared<taihe::callback<void(::taihe::string_view, int64_t)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    player->SaveCallbackReference(AVPlayerEvent::EVENT_ADS_STARTED, autoRef);
    MEDIA_LOGI("OnAdsListenerAdsStarted success");
}

void AVAdsControllerImpl::OffAdsListenerAdsStarted(
    optional_view<callback<void(::taihe::string_view, int64_t)>> callback)
{
    MediaTrace trace("AVAdsControllerImpl::OffAdsListenerAdsStarted");
    MEDIA_LOGD("OffAdsListenerAdsStarted In");

    AVPlayerImpl *player = GetPlayer();
    if (player == nullptr || player->GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        return;
    }
    player->ClearCallbackReference(AVPlayerEvent::EVENT_ADS_STARTED);
    MEDIA_LOGI("OffAdsListenerAdsStarted End");
}

void AVAdsControllerImpl::OnAdsListenerAdsSkipped(callback_view<void(::taihe::string_view)> callback)
{
    MediaTrace trace("AVAdsControllerImpl::OnAdsListenerAdsSkipped");
    MEDIA_LOGD("OnAdsListenerAdsSkipped In");

    AVPlayerImpl *player = GetPlayer();
    if (player == nullptr) {
        set_business_error(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "controller is released");
        return;
    }

    if (player->GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        player->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is released, unsupport to on event");
        return;
    }

    ani_env *env = taihe::get_env();
    std::shared_ptr<taihe::callback<void(::taihe::string_view)>> taiheCallback =
        std::make_shared<taihe::callback<void(::taihe::string_view)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    player->SaveCallbackReference(AVPlayerEvent::EVENT_ADS_SKIPPED, autoRef);
    MEDIA_LOGI("OnAdsListenerAdsSkipped success");
}

void AVAdsControllerImpl::OffAdsListenerAdsSkipped(
    optional_view<callback<void(::taihe::string_view)>> callback)
{
    MediaTrace trace("AVAdsControllerImpl::OffAdsListenerAdsSkipped");
    MEDIA_LOGD("OffAdsListenerAdsSkipped In");

    AVPlayerImpl *player = GetPlayer();
    if (player == nullptr || player->GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        return;
    }
    player->ClearCallbackReference(AVPlayerEvent::EVENT_ADS_SKIPPED);
    MEDIA_LOGI("OffAdsListenerAdsSkipped End");
}

void AVAdsControllerImpl::OnAdsListenerAdsCompleted(callback_view<void(::taihe::string_view)> callback)
{
    MediaTrace trace("AVAdsControllerImpl::OnAdsListenerAdsCompleted");
    MEDIA_LOGD("OnAdsListenerAdsCompleted In");

    AVPlayerImpl *player = GetPlayer();
    if (player == nullptr) {
        set_business_error(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "controller is released");
        return;
    }

    if (player->GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        player->OnErrorCb(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "current state is released, unsupport to on event");
        return;
    }

    ani_env *env = taihe::get_env();
    std::shared_ptr<taihe::callback<void(::taihe::string_view)>> taiheCallback =
        std::make_shared<taihe::callback<void(::taihe::string_view)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    player->SaveCallbackReference(AVPlayerEvent::EVENT_ADS_COMPLETED, autoRef);
    MEDIA_LOGI("OnAdsListenerAdsCompleted success");
}

void AVAdsControllerImpl::OffAdsListenerAdsCompleted(
    optional_view<callback<void(::taihe::string_view)>> callback)
{
    MediaTrace trace("AVAdsControllerImpl::OffAdsListenerAdsCompleted");
    MEDIA_LOGD("OffAdsListenerAdsCompleted In");

    AVPlayerImpl *player = GetPlayer();
    if (player == nullptr || player->GetCurrentState() == AVPlayerState::STATE_RELEASED) {
        return;
    }
    player->ClearCallbackReference(AVPlayerEvent::EVENT_ADS_COMPLETED);
    MEDIA_LOGI("OffAdsListenerAdsCompleted End");
}

void AVAdsControllerImpl::Release()
{
    MediaTrace trace("AVAdsControllerImpl::Release");
    MEDIA_LOGI("AVAdsController Release In");

    AVPlayerImpl *player = GetPlayer();
    if (player == nullptr) {
        return;
    }

    if (player->IsControllable()) {
        std::shared_ptr<AVPlayerContext> context = std::make_shared<AVPlayerContext>();
        context->asyncTask = DisableAllAdsMediaSourceTask();
        context->CheckTaskResult();
    }

    player->ClearCallbackReference(AVPlayerEvent::EVENT_ADS_LOADING_ERROR);
    player->ClearCallbackReference(AVPlayerEvent::EVENT_ADS_STARTED);
    player->ClearCallbackReference(AVPlayerEvent::EVENT_ADS_SKIPPED);
    player->ClearCallbackReference(AVPlayerEvent::EVENT_ADS_COMPLETED);

    SetPlayer(nullptr);
    MEDIA_LOGI("AVAdsController Release Out");
}

std::shared_ptr<TaskHandler<AdsTaskRet>> AVAdsControllerImpl::AddAdsMediaSourceTask(
    const std::shared_ptr<AVMediaSource> &mediaSource, int64_t startMs, std::string &outId)
{
    AVPlayerImpl *player = GetPlayer();
    CHECK_AND_RETURN_RET_LOG(player != nullptr, nullptr, "controller is released");
    std::shared_ptr<OHOS::Media::Player> playerInstance = player->GetPlayerInstance();
    auto task = std::make_shared<TaskHandler<AdsTaskRet>>([playerInstance, mediaSource, startMs, &outId]() {
        int32_t ret = playerInstance->AddAdsMediaSource(mediaSource, startMs, outId);
        if (ret != MSERR_OK) {
            return AdsTaskRet(MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(ret)),
                "failed to add ads media source");
        }
        return AdsTaskRet(MSERR_EXT_API9_OK, "Success");
    });
    (void)player->GetTaskQueue()->EnqueueTask(task);
    return task;
}

std::shared_ptr<TaskHandler<AdsTaskRet>> AVAdsControllerImpl::RemoveAdsMediaSourceTask(const std::string &id)
{
    AVPlayerImpl *player = GetPlayer();
    CHECK_AND_RETURN_RET_LOG(player != nullptr, nullptr, "controller is released");
    std::shared_ptr<OHOS::Media::Player> playerInstance = player->GetPlayerInstance();
    auto task = std::make_shared<TaskHandler<AdsTaskRet>>([playerInstance, id]() {
        int32_t ret = playerInstance->RemoveAdsMediaSource(id);
        if (ret != MSERR_OK) {
            return AdsTaskRet(MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(ret)),
                "failed to remove ads media source");
        }
        return AdsTaskRet(MSERR_EXT_API9_OK, "Success");
    });
    (void)player->GetTaskQueue()->EnqueueTask(task);
    return task;
}

std::shared_ptr<TaskHandler<AdsTaskRet>> AVAdsControllerImpl::SkipCurrentAdsMediaSourceTask()
{
    AVPlayerImpl *player = GetPlayer();
    CHECK_AND_RETURN_RET_LOG(player != nullptr, nullptr, "controller is released");
    std::shared_ptr<OHOS::Media::Player> playerInstance = player->GetPlayerInstance();
    auto task = std::make_shared<TaskHandler<AdsTaskRet>>([playerInstance]() {
        int32_t ret = playerInstance->SkipCurrentAdsMediaSource();
        if (ret != MSERR_OK) {
            return AdsTaskRet(MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(ret)),
                "failed to skip current ads media source");
        }
        return AdsTaskRet(MSERR_EXT_API9_OK, "Success");
    });
    (void)player->GetTaskQueue()->EnqueueTask(task);
    return task;
}

std::shared_ptr<TaskHandler<AdsTaskRet>> AVAdsControllerImpl::DisableAllAdsMediaSourceTask()
{
    AVPlayerImpl *player = GetPlayer();
    CHECK_AND_RETURN_RET_LOG(player != nullptr, nullptr, "controller is released");
    std::shared_ptr<OHOS::Media::Player> playerInstance = player->GetPlayerInstance();
    auto task = std::make_shared<TaskHandler<AdsTaskRet>>([playerInstance]() {
        int32_t ret = playerInstance->DisableAllAdsMediaSource();
        if (ret != MSERR_OK) {
            return AdsTaskRet(MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(ret)),
                "failed to disable all ads media source");
        }
        return AdsTaskRet(MSERR_EXT_API9_OK, "Success");
    });
    (void)player->GetTaskQueue()->EnqueueTask(task);
    return task;
}

optional<AVAdsController> CreateAVAdsControllerSync(::ohos::multimedia::media::weak::AVPlayer avplayer)
{
    MediaTrace trace("CreateAVAdsControllerSync");
    MEDIA_LOGI("CreateAVAdsControllerSync In");

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
