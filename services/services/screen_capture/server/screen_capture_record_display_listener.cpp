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

#include "screen_capture_record_display_listener.h"
#include "media_log.h"
#include "screen_capture_server.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "ScreenCaptureControllerServer"};
}

namespace OHOS::Media {
void SCRecordDisplayListener::OnChange(const std::vector<Rosen::DisplayId> &displayIds)
{
    auto SCServer = screenCaptureServer_.lock();
    CHECK_AND_RETURN_LOG(SCServer != nullptr, "screenCaptureServer is null");
    auto currIds = displayIds;
    SCServer->OnUpdateMirrorDisplay(currIds);
}
}