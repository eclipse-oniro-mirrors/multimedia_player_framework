/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "cj_audio_haptic_player.h"

#include "audio_haptic_log.h"

namespace {

const std::string AUDIO_INTERRUPT_CALLBACK_NAME = "audioInterrupt";
const std::string END_OF_STREAM_CALLBACK_NAME = "endOfStream";

constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_AUDIO_NAPI, "CjAudioHapticPlayer"};
}

namespace OHOS {
namespace Media {


CjAudioHapticPlayerCallback::CjAudioHapticPlayerCallback() {}

CjAudioHapticPlayerCallback::~CjAudioHapticPlayerCallback() {}

void CjAudioHapticPlayerCallback::SaveCallbackReference(const std::string &callbackName, int64_t callbackId)
{
    std::lock_guard<std::mutex> lock(cbMutex_);
    if (callbackName == AUDIO_INTERRUPT_CALLBACK_NAME) {
        auto cb = reinterpret_cast<void(*)(int32_t, int32_t, int32_t)>(callbackId);
        audioInterruptCb_ = CJLambda::Create(cb);
    }
    if (callbackName == END_OF_STREAM_CALLBACK_NAME) {
        auto cb = reinterpret_cast<void(*)()>(callbackId);
        endOfStreamCb_ = CJLambda::Create(cb);
    }
}

void CjAudioHapticPlayerCallback::RemoveCallbackReference(const std::string &callbackName)
{
    std::lock_guard<std::mutex> lock(cbMutex_);

    if (callbackName == AUDIO_INTERRUPT_CALLBACK_NAME) {
        audioInterruptCb_ = nullptr;
    } else if (callbackName == END_OF_STREAM_CALLBACK_NAME) {
        endOfStreamCb_ = nullptr;
    } else {
        MEDIA_LOGE("RemoveCallbackReference: Unknown callback type: %{public}s", callbackName.c_str());
    }
}

void CjAudioHapticPlayerCallback::OnInterrupt(const AudioStandard::InterruptEvent &interruptEvent)
{
    std::lock_guard<std::mutex> lock(cbMutex_);
    MEDIA_LOGI("OnInterrupt: hintType: %{public}d ", interruptEvent.hintType);
    CHECK_AND_RETURN_LOG(audioInterruptCb_ != nullptr, "Cannot find the reference of interrupt callback");
    audioInterruptCb_(interruptEvent.eventType, interruptEvent.forceType, interruptEvent.hintType);
    return;
}

void CjAudioHapticPlayerCallback::OnEndOfStream(void)
{
    std::lock_guard<std::mutex> lock(cbMutex_);
    CHECK_AND_RETURN_LOG(endOfStreamCb_ != nullptr, "Cannot find the reference of endOfStream callback");

    endOfStreamCb_();
    return;
}

void CjAudioHapticPlayerCallback::OnError(int32_t errorCode)
{
    MEDIA_LOGI("OnError from audio haptic player. errorCode %{public}d", errorCode);
}

CjAudioHapticPlayer::CjAudioHapticPlayer(std::shared_ptr<AudioHapticPlayer> audioHapticPlayer)
{
    audioHapticPlayer_ = audioHapticPlayer;
}

CjAudioHapticPlayer::~CjAudioHapticPlayer() = default;

int32_t CjAudioHapticPlayer::IsMuted(int32_t type, bool &ret)
{
    if (!IsLegalAudioHapticType(type)) {
        return ERR_INVALID_ARG;
    }

    ret = audioHapticPlayer_->IsMuted(static_cast<AudioHapticType>(type));
    return SUCCESS;
}

bool CjAudioHapticPlayer::IsLegalAudioHapticType(int32_t audioHapticType)
{
    switch (audioHapticType) {
        case AUDIO_HAPTIC_TYPE_AUDIO:
        case AUDIO_HAPTIC_TYPE_HAPTIC:
            return true;
        default:
            break;
    }
    MEDIA_LOGE("IsLegalAudioHapticType: audioHapticType %{public}d is invalid", audioHapticType);
    return false;
}

int32_t CjAudioHapticPlayer::Start()
{
    return audioHapticPlayer_->Start();
}

int32_t CjAudioHapticPlayer::Stop()
{
    return audioHapticPlayer_->Stop();
}

int32_t CjAudioHapticPlayer::Release()
{
    return audioHapticPlayer_->Release();
}

int32_t CjAudioHapticPlayer::On(const char* type, int64_t callbackId)
{
    if (!cjCallback) {
        cjCallback = std::make_shared<CjAudioHapticPlayerCallback>();
        if (!cjCallback) {
            return -1;
        }
        int32_t ret = audioHapticPlayer_->SetAudioHapticPlayerCallback(cjCallback);
        if (ret != SUCCESS) {
            return ret;
        }
    }
    cjCallback->SaveCallbackReference(type, callbackId);
    return SUCCESS;
}

int32_t CjAudioHapticPlayer::Off(const char* type)
{
    cjCallback->RemoveCallbackReference(type);
    return SUCCESS;
}

} // namespace Media
} // namespace OHOS