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

#include "audio_haptic_player_callback_taihe.h"

#include "audio_haptic_log.h"
#include "common_taihe.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_AUDIO_NAPI, "AudioHapticPlayerCallbackTaihe"};
const std::string AUDIO_INTERRUPT_CALLBACK_NAME = "audioInterrupt";
const std::string END_OF_STREAM_CALLBACK_NAME = "endOfStream";
}

namespace ANI::Media {

AudioHapticPlayerCallbackTaihe::AudioHapticPlayerCallbackTaihe()
{
    MEDIA_LOGI("AudioHapticPlayerCallbackTaihe: instance create");
}

AudioHapticPlayerCallbackTaihe::~AudioHapticPlayerCallbackTaihe()
{
    MEDIA_LOGI("~AudioHapticPlayerCallbackTaihe: instance destroy");
}

void AudioHapticPlayerCallbackTaihe::SaveCallbackReference(const std::string &callbackName,
    std::shared_ptr<AutoRef> callback)
{
    std::lock_guard<std::mutex> lock(cbMutex_);
    if (callbackName == AUDIO_INTERRUPT_CALLBACK_NAME) {
        audioInterruptCb_ = callback;
    } else if (callbackName == END_OF_STREAM_CALLBACK_NAME) {
        endOfStreamCb_ = callback;
    } else {
        MEDIA_LOGE("SaveCallbackReference: Unknown callback type: %{public}s", callbackName.c_str());
        return;
    }
    MEDIA_LOGI("SaveCallbackReference: callbackName: %{public}s", callbackName.c_str());
    if (mainHandler_ == nullptr) {
        std::shared_ptr<OHOS::AppExecFwk::EventRunner> runner = OHOS::AppExecFwk::EventRunner::GetMainEventRunner();
        mainHandler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);
    }
}

void AudioHapticPlayerCallbackTaihe::RemoveCallbackReference(const std::string &callbackName)
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

void AudioHapticPlayerCallbackTaihe::OnInterrupt(const OHOS::AudioStandard::InterruptEvent &interruptEvent)
{
    std::lock_guard<std::mutex> lock(cbMutex_);
    MEDIA_LOGI("OnInterrupt: hintType: %{public}d for taihe", interruptEvent.hintType);
    CHECK_AND_RETURN_LOG(audioInterruptCb_ != nullptr, "Cannot find the reference of interrupt callback");

    std::unique_ptr<AudioHapticPlayerTaiheCallback> cb = std::make_unique<AudioHapticPlayerTaiheCallback>();
    CHECK_AND_RETURN_LOG(cb != nullptr, "No memory");
    cb->callback = audioInterruptCb_;
    cb->callbackName = AUDIO_INTERRUPT_CALLBACK_NAME;
    cb->interruptEvent = interruptEvent;
    return OnInterruptTaiheCallback(cb);
}

void AudioHapticPlayerCallbackTaihe::OnInterruptTaiheCallback(std::unique_ptr<AudioHapticPlayerTaiheCallback> &cb)
{
    if (cb.get() == nullptr) {
        MEDIA_LOGE("AudioHapticPlayerTaiheCallback: cb.get() is null");
        return;
    }

    AudioHapticPlayerTaiheCallback *object = cb.get();
    auto task = [object]() {
        std::shared_ptr<AudioHapticPlayerTaiheCallback> context(
            static_cast<AudioHapticPlayerTaiheCallback*>(object),
            [](AudioHapticPlayerTaiheCallback* ptr) {
                delete ptr;
        });
        CHECK_AND_RETURN_LOG(object != nullptr, "event is nullptr");

        auto func = object->callback->callbackRef_;
        CHECK_AND_RETURN_LOG(func != nullptr, "failed to get callback");
        std::shared_ptr<taihe::callback<void(uintptr_t)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(uintptr_t)>>(func);
        ani_object interruptEventObj =
            CommonTaihe::ToAudioStandardInterruptEvent(taihe::get_env(), object->interruptEvent);
        (*cacheCallback)(reinterpret_cast<uintptr_t>(interruptEventObj));
        delete object;
    };
    if (mainHandler_ == nullptr ||
        !mainHandler_->PostTask(task, cb->callbackName, 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {})) {
        MEDIA_LOGE("Failed to PostTask!");
    }
}

void AudioHapticPlayerCallbackTaihe::OnEndOfStream(void)
{
    std::lock_guard<std::mutex> lock(cbMutex_);
    MEDIA_LOGI("OnEndOfStream in succeed");
    CHECK_AND_RETURN_LOG(endOfStreamCb_ != nullptr, "Cannot find the reference of endOfStream callback");

    std::unique_ptr<AudioHapticPlayerTaiheCallback> cb = std::make_unique<AudioHapticPlayerTaiheCallback>();
    CHECK_AND_RETURN_LOG(cb != nullptr, "No memory");
    cb->callback = endOfStreamCb_;
    cb->callbackName = END_OF_STREAM_CALLBACK_NAME;
    return OnEndOfStreamTaiheCallback(cb);
}

void AudioHapticPlayerCallbackTaihe::OnEndOfStreamTaiheCallback(std::unique_ptr<AudioHapticPlayerTaiheCallback> &cb)
{
    if (cb.get() == nullptr) {
        MEDIA_LOGE("AudioHapticPlayerTaiheCallback: cb.get() is null");
        return;
    }

    AudioHapticPlayerTaiheCallback *object = cb.get();
    auto task = [object]() {
        std::shared_ptr<AudioHapticPlayerTaiheCallback> context(
            static_cast<AudioHapticPlayerTaiheCallback*>(object),
            [](AudioHapticPlayerTaiheCallback* ptr) {
                delete ptr;
        });
        CHECK_AND_RETURN_LOG(object != nullptr, "event is nullptr");

        auto func = object->callback->callbackRef_;
        CHECK_AND_RETURN_LOG(func != nullptr, "failed to get callback");
        std::shared_ptr<taihe::callback<void(uintptr_t)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(uintptr_t)>>(func);
        (*cacheCallback)(CommonTaihe::GetUndefinedPtr(taihe::get_env()));
        delete object;
    };
    if (mainHandler_ == nullptr ||
        !mainHandler_->PostTask(task, cb->callbackName, 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {})) {
        MEDIA_LOGE("Failed to PostTask!");
    }
}

void AudioHapticPlayerCallbackTaihe::OnError(int32_t errorCode)
{
    MEDIA_LOGI("OnError from audio haptic player. errorCode %{public}d", errorCode);
}

} // namespace ANI::Media