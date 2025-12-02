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

#include "screen_capture_monitor_callback_taihe.h"
#include "media_log.h"
#include "scope_guard.h"
#include "media_taihe_utils.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_RECORDER, "ScreenCaptureMonitorCallback"};
}

namespace ANI {
namespace Media {
using namespace OHOS::Media;
using namespace ANI::Media;

const std::string EVENT_SYSTEM_SCREEN_RECORD = "systemScreenRecorder";

ScreenCaptureMonitorCallback::ScreenCaptureMonitorCallback()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR "Instances create", FAKE_POINTER(this));
}

ScreenCaptureMonitorCallback::~ScreenCaptureMonitorCallback()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR "Instances destroy", FAKE_POINTER(this));
}

void ScreenCaptureMonitorCallback::SaveCallbackReference(const std::string &name, std::weak_ptr<AutoRef> ref)
{
    std::lock_guard<std::mutex> lock(mutex_);
    refMap_[name] = ref;
    MEDIA_LOGI("Set callback type: %{public}s", name.c_str());
    if (mainHandler_ == nullptr) {
        std::shared_ptr<OHOS::AppExecFwk::EventRunner> runner = OHOS::AppExecFwk::EventRunner::GetMainEventRunner();
        mainHandler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);
    }
}

void ScreenCaptureMonitorCallback::CancelCallbackReference(const std::string &name)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = refMap_.find(name);
    if (iter != refMap_.end()) {
        refMap_.erase(iter);
    }
    MEDIA_LOGI("Cancel callback type: %{public}s", name.c_str());
}


void ScreenCaptureMonitorCallback::OnScreenCaptureStarted(int32_t pid)
{
    MEDIA_LOGI("OnScreenCaptureStarted S %{public}d", pid);
    std::lock_guard<std::mutex> lock(mutex_);
    if (refMap_.find(EVENT_SYSTEM_SCREEN_RECORD) == refMap_.end()) {
        MEDIA_LOGW("can not find systemScreenRecorder callback!");
        return;
    }

    bool shouldSendCb = OHOS::Media::ScreenCaptureMonitor::GetInstance()->IsSystemScreenRecorder(pid);
    if (!shouldSendCb) {
        MEDIA_LOGW("pid not match, do not send callback!");
        return;
    }

    ScreenCaptureMonitorAniCallback *cb = new(std::nothrow) ScreenCaptureMonitorAniCallback();
    CHECK_AND_RETURN_LOG(cb != nullptr, "cb is nullptr");
    cb->autoRef = refMap_.at(EVENT_SYSTEM_SCREEN_RECORD);
    cb->callbackName = EVENT_SYSTEM_SCREEN_RECORD;
    cb->captureEvent = ScreenCaptureMonitorEvent::SCREENCAPTURE_STARTED;
    MEDIA_LOGI("OnScreenCaptureStarted E");
    auto task = [this, cb]() {
        this->OnTaiheCaptureCallBack(cb);
    };
    bool ret = mainHandler_->PostTask(task, "OnScreenCaptureStarted", 0,
        OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
    if (!ret) {
        MEDIA_LOGE("Failed to PostTask!");
        delete cb;
    }
}

void ScreenCaptureMonitorCallback::OnScreenCaptureFinished(int32_t pid)
{
    MEDIA_LOGI("OnScreenCaptureFinished S %{public}d", pid);
    std::lock_guard<std::mutex> lock(mutex_);
    if (refMap_.find(EVENT_SYSTEM_SCREEN_RECORD) == refMap_.end()) {
        MEDIA_LOGW("can not find systemScreenRecorder callback!");
        return;
    }

    bool shouldSendCb = OHOS::Media::ScreenCaptureMonitor::GetInstance()->IsSystemScreenRecorder(pid);
    if (!shouldSendCb) {
        MEDIA_LOGW("pid not match, do not send callback!");
        return;
    }

    ScreenCaptureMonitorAniCallback *cb = new(std::nothrow) ScreenCaptureMonitorAniCallback();
    CHECK_AND_RETURN_LOG(cb != nullptr, "cb is nullptr");
    cb->autoRef = refMap_.at(EVENT_SYSTEM_SCREEN_RECORD);
    cb->callbackName = EVENT_SYSTEM_SCREEN_RECORD;
    cb->captureEvent = ScreenCaptureMonitorEvent::SCREENCAPTURE_STOPPED;
    MEDIA_LOGI("OnScreenCaptureFinished E");
    auto task = [this, cb]() {
        this->OnTaiheCaptureCallBack(cb);
    };
    bool ret = mainHandler_->PostTask(task, "OnScreenCaptureFinished", 0,
        OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
    if (!ret) {
        MEDIA_LOGE("Failed to PostTask!");
        delete cb;
    }
}

void ScreenCaptureMonitorCallback::OnScreenCaptureDied()
{
    MEDIA_LOGI("ScreenCaptureMonitorCallback::OnScreenCaptureDied S");
    std::lock_guard<std::mutex> lock(mutex_);
    if (refMap_.find(EVENT_SYSTEM_SCREEN_RECORD) == refMap_.end()) {
        MEDIA_LOGW("can not find systemScreenRecorder callback!");
        return;
    }

    ScreenCaptureMonitorAniCallback *cb = new(std::nothrow) ScreenCaptureMonitorAniCallback();
    CHECK_AND_RETURN_LOG(cb != nullptr, "cb is nullptr");
    cb->autoRef = refMap_.at(EVENT_SYSTEM_SCREEN_RECORD);
    cb->callbackName = EVENT_SYSTEM_SCREEN_RECORD;
    cb->captureEvent = ScreenCaptureMonitorEvent::SCREENCAPTURE_DIED;
    MEDIA_LOGI("ScreenCaptureMonitorCallback::OnScreenCaptureDied E");
    auto task = [this, cb]() {
        this->OnTaiheCaptureCallBack(cb);
    };
    bool ret = mainHandler_->PostTask(task, "OnScreenCaptureDied", 0,
        OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
    if (!ret) {
        MEDIA_LOGE("Failed to PostTask!");
        delete cb;
    }
}

void ScreenCaptureMonitorCallback::OnTaiheCaptureCallBack(ScreenCaptureMonitorAniCallback *taiheCb) const
{
    std::string request = taiheCb->callbackName;
    do {
        MEDIA_LOGD("OnTaiheCaptureCallBack is called");
        std::shared_ptr<AutoRef> ref = taiheCb->autoRef.lock();
        CHECK_AND_BREAK_LOG(ref != nullptr, "%{public}s AutoRef is nullptr", request.c_str());
        auto func = ref->callbackRef_;
        CHECK_AND_BREAK_LOG(func != nullptr, "failed to get callback");
        std::shared_ptr<taihe::callback<void(ohos::multimedia::media::ScreenCaptureEvent)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(ohos::multimedia::media::ScreenCaptureEvent)>>(func);
        (*cacheCallback)(static_cast<ohos::multimedia::media::ScreenCaptureEvent::key_t>(taiheCb->captureEvent));
    } while (0);
    delete taiheCb;
}

} // namespace Media
} // namespace ANI