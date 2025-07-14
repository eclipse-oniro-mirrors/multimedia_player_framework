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

#include "screen_capture_monitor_taihe.h"
#include "media_taihe_utils.h"
#include "media_errors.h"
#include "media_log.h"
#include "media_dfx.h"

using namespace ANI::Media;

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_RECORDER, "ScreenCaptureMonitorTaihe"};
}

namespace ANI::Media {
const std::string EVENT_SYSTEM_SCREEN_RECORD = "systemScreenRecorder";

ScreenCaptureMonitorImpl::ScreenCaptureMonitorImpl()
{
    OHOS::sptr<ScreenCaptureMonitorCallback> monitorCb(new ScreenCaptureMonitorCallback());
    monitorCb_ = monitorCb;
    if (monitorCb_ == nullptr) {
        MediaTaiheUtils::ThrowExceptionError("TaiheCreateScreenCaptureMonitor GetScreenCaptureMonitor fail");
        return;
    }
    OHOS::Media::ScreenCaptureMonitor::GetInstance()->RegisterScreenCaptureMonitorListener(monitorCb_);
}

static void SignError(int32_t code, const std::string &param1, const std::string &param2, const std::string &add = "")
{
    std::string message = MSExtErrorAPI9ToString(static_cast<OHOS::Media::MediaServiceExtErrCodeAPI9>(code),
        param1, param2) + add;
    set_business_error(code, message);
}

optional<ohos::multimedia::media::ScreenCaptureMonitor> GetScreenCaptureMonitorSync()
{
    MediaTrace trace("ScreenCaptureMonitorTaihe::GetScreenCaptureMonitorSync");
    MEDIA_LOGI("Taihe GetScreenCaptureMonitorSync Start");
    if (!MediaTaiheUtils::SystemPermission()) {
        SignError(MSERR_EXT_API9_PERMISSION_DENIED, "GetScreenCaptureMonitor", "system");
        return optional<ohos::multimedia::media::ScreenCaptureMonitor>(std::nullopt);
    }
    auto res = make_holder<ScreenCaptureMonitorImpl, ohos::multimedia::media::ScreenCaptureMonitor>();
    if (taihe::has_error()) {
        MEDIA_LOGE("Create ScreenCaptureMonitor failed!");
        taihe::reset_error();
        return optional<ohos::multimedia::media::ScreenCaptureMonitor>(std::nullopt);
    }
    MEDIA_LOGI("Taihe GetScreenCaptureMonitorSync End");
    return optional<ohos::multimedia::media::ScreenCaptureMonitor>(std::in_place, res);
}

bool ScreenCaptureMonitorImpl::GetisSystemScreenRecorderWorking()
{
    MediaTrace trace("ScreenCaptureMonitorImpl::TaiheGetisSystemScreenRecorderWorking");
    MEDIA_LOGI("Taihe GetisSystemScreenRecorderWorking Start");
    if (!MediaTaiheUtils::SystemPermission()) {
        SignError(OHOS::Media::MSERR_EXT_API9_PERMISSION_DENIED, "IsSystemScreenRecorderWorking", "system");
    }
    return OHOS::Media::ScreenCaptureMonitor::GetInstance()->IsSystemScreenRecorderWorking();
}

void ScreenCaptureMonitorImpl::OnSystemScreenRecorder(
    callback_view<void(ohos::multimedia::media::ScreenCaptureEvent)> callback)
{
    MediaTrace trace("ScreenCaptureMonitorTaihe::OnSystemScreenRecorder");
    MEDIA_LOGI("OnSystemScreenRecorder Start");
    if (!MediaTaiheUtils::SystemPermission()) {
        SignError(OHOS::Media::MSERR_EXT_API9_PERMISSION_DENIED, "On", "system");
    }

    std::string callbackName = EVENT_SYSTEM_SCREEN_RECORD;
    ani_env *env = get_env();
    std::shared_ptr<taihe::callback<void(ohos::multimedia::media::ScreenCaptureEvent)>> taiheCallback =
            std::make_shared<taihe::callback<void(ohos::multimedia::media::ScreenCaptureEvent)>>(callback);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);

    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    SetCallbackReference(callbackName, autoRef);

    MEDIA_LOGI("OnSystemScreenRecorder End");
}

void ScreenCaptureMonitorImpl::OffSystemScreenRecorder(
    optional_view<callback<void(ohos::multimedia::media::ScreenCaptureEvent)>> callback)
{
    MediaTrace trace("ScreenCaptureMonitorTaihe::OffSystemScreenRecorder");
    MEDIA_LOGI("OffSystemScreenRecorder Start");
    if (!MediaTaiheUtils::SystemPermission()) {
        SignError(OHOS::Media::MSERR_EXT_API9_PERMISSION_DENIED, "Off", "system");
    }

    std::string callbackName = EVENT_SYSTEM_SCREEN_RECORD;

    CancelCallbackReference(callbackName);
    MEDIA_LOGI("OffSystemScreenRecorder End");
}

void ScreenCaptureMonitorImpl::SetCallbackReference(const std::string &callbackName, std::shared_ptr<AutoRef> ref)
{
    std::lock_guard<std::mutex> lock(mutex_);
    eventCbMap_[callbackName] = ref;
    CHECK_AND_RETURN_LOG(monitorCb_ != nullptr, "monitorCb_ is nullptr!");
    auto taiheCb = static_cast<ScreenCaptureMonitorCallback*>(monitorCb_.GetRefPtr());
    taiheCb->SaveCallbackReference(callbackName, ref);
}

void ScreenCaptureMonitorImpl::CancelCallbackReference(const std::string &callbackName)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_LOG(monitorCb_ != nullptr, "monitorCb_ is nullptr!");
    auto taiheCb = static_cast<ScreenCaptureMonitorCallback*>(monitorCb_.GetRefPtr());
    taiheCb->CancelCallbackReference(callbackName);
    eventCbMap_[callbackName] = nullptr;
}
} // namespace ANI::Media

TH_EXPORT_CPP_API_GetScreenCaptureMonitorSync(GetScreenCaptureMonitorSync);