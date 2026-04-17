/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "focus_changed_listener.h"
#include "screen_capture_server.h"
#include "media_log.h"
#include "media_utils.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "FocusChangedListener"};
}

namespace OHOS::Media {
FocusChangedListener::FocusChangedListener(std::weak_ptr<ScreenCaptureServer> screenCaptureServer)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " SCWindowLifecycleListener Instances create", FAKE_POINTER(this));
    screenCaptureServer_ = screenCaptureServer;
}

void FocusChangedListener::OnFocused(const sptr<Rosen::FocusChangeInfo>& focusChangeInfo)
{
    MEDIA_LOGI("FocusChangedListener::OnFocused Start.");
    auto SCServer = screenCaptureServer_.lock();
    CHECK_AND_RETURN_LOG(SCServer != nullptr, "screenCaptureServer is nullptr");
    SCServer->SetFocusAppMissionId(focusChangeInfo->windowId_);
    MEDIA_LOGI("FocusChangedListener::OnFocused end. windowId %{public}d", focusChangeInfo->windowId_);
}

void FocusChangedListener::OnUnfocused(const sptr<Rosen::FocusChangeInfo>& focusChangeInfo)
{
    MEDIA_LOGI("FocusChangedListener::OnUnfocused Start.");
}
}