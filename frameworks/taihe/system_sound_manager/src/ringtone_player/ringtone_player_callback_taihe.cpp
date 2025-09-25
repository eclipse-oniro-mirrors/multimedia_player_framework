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

#include "ringtone_player_callback_taihe.h"

#include <uv.h>

#include "media_errors.h"
#include "system_sound_log.h"

namespace {
const std::string AUDIO_INTERRUPT_CALLBACK_NAME = "audioInterrupt";

constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_AUDIO_NAPI, "RingtonePlayerCallbackTaihe"};
}

namespace ANI::Media {
RingtonePlayerCallbackTaihe::RingtonePlayerCallbackTaihe()
{
    MEDIA_LOGI("RingtonePlayerCallbackTaihe: instance create");
}

RingtonePlayerCallbackTaihe::~RingtonePlayerCallbackTaihe()
{
    MEDIA_LOGI("RingtonePlayerCallbackTaihe: instance destroy");
}

void RingtonePlayerCallbackTaihe::SaveCallbackReference(const std::string &callbackName,
    std::shared_ptr<AutoRef> callback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (callbackName == AUDIO_INTERRUPT_CALLBACK_NAME) {
        interruptCallback_ = callback;
    } else {
        MEDIA_LOGE("RingtonePlayerCallbackTaihe: Unknown callback type: %{public}s", callbackName.c_str());
        return;
    }
    MEDIA_LOGI("SaveCallbackReference: callbackName: %{public}s", callbackName.c_str());
    if (mainHandler_ == nullptr) {
        std::shared_ptr<OHOS::AppExecFwk::EventRunner> runner = OHOS::AppExecFwk::EventRunner::GetMainEventRunner();
        mainHandler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);
    }
}

void RingtonePlayerCallbackTaihe::RemoveCallbackReference(const std::string &callbackName)
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (callbackName == AUDIO_INTERRUPT_CALLBACK_NAME) {
        interruptCallback_ = nullptr;
    } else {
        MEDIA_LOGE("Unknown callback type: %{public}s", callbackName.c_str());
    }
}

void RingtonePlayerCallbackTaihe::OnInterrupt(const OHOS::AudioStandard::InterruptEvent &interruptEvent)
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("RingtonePlayerCallbackTaihe: OnInterrupt is called");
    MEDIA_LOGI("RingtonePlayerCallbackTaihe: hintType: %{public}d", interruptEvent.hintType);
    CHECK_AND_RETURN_LOG(interruptCallback_ != nullptr, "Cannot find the reference of interrupt callback");

    std::unique_ptr<RingtonePlayerTaiheCallback> cb = std::make_unique<RingtonePlayerTaiheCallback>();
    CHECK_AND_RETURN_LOG(cb != nullptr, "No memory");
    cb->callback = interruptCallback_;
    cb->callbackName = AUDIO_INTERRUPT_CALLBACK_NAME;
    cb->interruptEvent = interruptEvent;
    return OnTaiheCallbackInterrupt(cb);
}

void RingtonePlayerCallbackTaihe::OnTaiheCallbackInterrupt(std::unique_ptr<RingtonePlayerTaiheCallback> &cb)
{
    if (cb.get() == nullptr) {
        MEDIA_LOGE("OnTaiheCallbackVolumeEvent: cb.get() is null");
        return;
    }
    RingtonePlayerTaiheCallback *event = cb.get();
    auto task = [event]() {
        std::shared_ptr<RingtonePlayerTaiheCallback> context(
            static_cast<RingtonePlayerTaiheCallback*>(event),
            [](RingtonePlayerTaiheCallback* ptr) {
                delete ptr;
        });

        CHECK_AND_RETURN_LOG(context->callback != nullptr, "Callback is nullptr");
        auto func = context->callback->callbackRef_;
        CHECK_AND_RETURN_LOG(func != nullptr, "failed to get callback");
        std::shared_ptr<::taihe::callback<void(uintptr_t)>> cacheCallback =
            std::reinterpret_pointer_cast<::taihe::callback<void(uintptr_t)>>(func);
        ani_object interruptEventObj =
            CommonTaihe::ToAudioStandardInterruptEvent(taihe::get_env(), context->interruptEvent);
        (*cacheCallback)(reinterpret_cast<uintptr_t>(interruptEventObj));

        delete event;
    };
    if (mainHandler_ == nullptr ||
        !mainHandler_->PostTask(task, cb->callbackName, 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {})) {
        MEDIA_LOGE("Failed to PostTask!");
    }
}
}  // namespace ANI::Media