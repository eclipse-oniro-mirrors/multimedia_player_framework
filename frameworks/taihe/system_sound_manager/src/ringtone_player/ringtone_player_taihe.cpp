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

#include "common_taihe.h"
#include "ringtone_player_taihe.h"
#include "system_sound_log.h"

using namespace ANI::Media;

namespace {
const std::string AUDIO_INTERRUPT_CALLBACK_NAME = "audioInterrupt";

constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_AUDIO_NAPI, "RingtonePlayerTaihe"};

const int SUCCESS = 0;
}

namespace ANI::Media {
static const std::map<OHOS::Media::RingtoneState, std::string> STATEMAP = {
    {OHOS::Media::STATE_INVALID, AVPlayerState::STATE_ERROR},
    {OHOS::Media::STATE_NEW, AVPlayerState::STATE_INITIALIZED},
    {OHOS::Media::STATE_PREPARED, AVPlayerState::STATE_PREPARED},
    {OHOS::Media::STATE_RUNNING, AVPlayerState::STATE_PLAYING},
    {OHOS::Media::STATE_STOPPED, AVPlayerState::STATE_STOPPED},
    {OHOS::Media::STATE_RELEASED, AVPlayerState::STATE_RELEASED},
    {OHOS::Media::STATE_PAUSED, AVPlayerState::STATE_PAUSED},
};

static void ThrowError(int32_t errCode, const std::string &errMessage)
{
    RingtoneCommonTaihe::ThrowError(errCode, errMessage);
}

static void ThrowError(const std::string &errMessage)
{
    taihe::set_error(errMessage.c_str());
}

RingtonePlayerImpl::RingtonePlayerImpl(std::shared_ptr<OHOS::Media::RingtonePlayer> ringtonePlayer)
{
    if (ringtonePlayer != nullptr) {
        ringtonePlayer_ = move(ringtonePlayer);
    } else {
        MEDIA_LOGE("Failed to create ringtonePlayer instance.");
    }

    if (ringtonePlayer_ != nullptr && callbackTaihe_ == nullptr) {
        callbackTaihe_ = std::make_shared<RingtonePlayerCallbackTaihe>();
        CHECK_AND_RETURN_LOG(callbackTaihe_ != nullptr, "No memory");
        int32_t ret = ringtonePlayer_->SetRingtonePlayerInterruptCallback(callbackTaihe_);
        MEDIA_LOGI("AudioRendererTaihe::Construct SetRendererCallback %{public}s",
            ret == 0 ? "succeess" : "failed");
    }
}

::taihe::string RingtonePlayerImpl::GetState()
{
    std::string curState = AVPlayerState::STATE_ERROR;
    if (ringtonePlayer_ != nullptr) {
        OHOS::Media::RingtoneState ringtoneState_ = ringtonePlayer_->GetRingtoneState();
        if (STATEMAP.find(ringtoneState_) != STATEMAP.end()) {
            curState = STATEMAP.at(ringtoneState_);
        }
    }
    return curState;
}

::taihe::string RingtonePlayerImpl::GetTitleSync()
{
    std::string title;
    if (ringtonePlayer_ != nullptr) {
        title = ringtonePlayer_->GetTitle();
    } else {
        taihe::set_error("GetTitle: native pointer is nullptr!");
    }
    return title;
}

uintptr_t RingtonePlayerImpl::GetAudioRendererInfoSync()
{
    OHOS::AudioStandard::AudioRendererInfo rendererInfo;
    if (ringtonePlayer_ == nullptr) {
        taihe::set_error("Error: Operation is not supported or failed");
        return 0;
    }

    if (ringtonePlayer_->GetAudioRendererInfo(rendererInfo) == SUCCESS) {
        std::unique_ptr<OHOS::AudioStandard::AudioRendererInfo> audioRendererInfo =
            std::make_unique<OHOS::AudioStandard::AudioRendererInfo>();
        CHECK_AND_RETURN_RET_LOG(audioRendererInfo != nullptr, 0, "No memory");
        audioRendererInfo->contentType = rendererInfo.contentType;
        audioRendererInfo->streamUsage = rendererInfo.streamUsage;
        audioRendererInfo->rendererFlags = rendererInfo.rendererFlags;

        return reinterpret_cast<uintptr_t>(CommonTaihe::CreateAudioRendererInfo(taihe::get_env(), audioRendererInfo));
    }

    taihe::set_error("GetRendererInfo Error: Operation is not supported or failed");
    return 0;
}

void RingtonePlayerImpl::ConfigureSync(::ringtonePlayer::RingtoneOptions const& options)
{
    if (ringtonePlayer_ == nullptr || ringtonePlayer_->Configure(options.volume, options.loop)) {
        taihe::set_error("Error: Operation is not supported or failed");
    }
}

void RingtonePlayerImpl::StartSync()
{
    if (ringtonePlayer_ == nullptr || ringtonePlayer_->Start()) {
        taihe::set_error("Error: Operation is not supported or failed");
    }
}

void RingtonePlayerImpl::StopSync()
{
    if (ringtonePlayer_ == nullptr || ringtonePlayer_->Stop()) {
        taihe::set_error("Error: Operation is not supported or failed");
    }
}

void RingtonePlayerImpl::ReleaseSync()
{
    if (ringtonePlayer_ == nullptr || ringtonePlayer_->Release()) {
        taihe::set_error("Error: Operation is not supported or failed");
    }
}

void RingtonePlayerImpl::OnAudioInterrupt(::taihe::callback_view<void(uintptr_t)> callback)
{
    MEDIA_LOGI("RingtonePlayerTaihe: On callbackName: %{public}s", AUDIO_INTERRUPT_CALLBACK_NAME.c_str());
    if (ringtonePlayer_ == nullptr) {
        ThrowError(TAIHE_ERR_NO_MEMORY, "no memory");
        return;
    }
    std::string cbName = AUDIO_INTERRUPT_CALLBACK_NAME;
    if (!cbName.compare(AUDIO_INTERRUPT_CALLBACK_NAME)) {
        if (callbackTaihe_ == nullptr) {
            ThrowError(TAIHE_ERR_NO_MEMORY, "no memory");
            return;
        }

        std::shared_ptr<taihe::callback<void(uintptr_t)>> taiheCallback =
            std::make_shared<taihe::callback<void(uintptr_t)>>(callback);
        std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
        std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(taihe::get_env(), cacheCallback);

        std::shared_ptr<RingtonePlayerCallbackTaihe> cb =
            std::static_pointer_cast<RingtonePlayerCallbackTaihe>(callbackTaihe_);
        if (cb == nullptr) {
            ThrowError(TAIHE_ERR_NO_MEMORY, "no memory");
            return;
        }
        cb->SaveCallbackReference(cbName, autoRef);
    } else {
        ThrowError(TAIHE_ERR_INVALID_PARAM, "parameter verification failed: The param of type is not supported");
    }
}

void RingtonePlayerImpl::OffAudioInterrupt()
{
    MEDIA_LOGI("Off callbackName: %{public}s", AUDIO_INTERRUPT_CALLBACK_NAME.c_str());
    if (ringtonePlayer_ == nullptr) {
        ThrowError(TAIHE_ERR_NO_MEMORY, "no memory");
        return;
    }
    std::string cbName = AUDIO_INTERRUPT_CALLBACK_NAME;
    if (!cbName.compare(AUDIO_INTERRUPT_CALLBACK_NAME)) {
        if (callbackTaihe_ == nullptr) {
            ThrowError("ringtonePlayerCallbackTaihe is nullptr");
            return;
        }

        std::shared_ptr<RingtonePlayerCallbackTaihe> cb =
            std::static_pointer_cast<RingtonePlayerCallbackTaihe>(callbackTaihe_);
        if (cb == nullptr) {
            ThrowError(TAIHE_ERR_NO_MEMORY, "no memory");
            return;
        }
        cb->RemoveCallbackReference(cbName);
    } else {
        ThrowError(TAIHE_ERR_INVALID_PARAM,
            "parameter verification failed: The param of type is not supported");
    }
}
} // namespace ANI::Media