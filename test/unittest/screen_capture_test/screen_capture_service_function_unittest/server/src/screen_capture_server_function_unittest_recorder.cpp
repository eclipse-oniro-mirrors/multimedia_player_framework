/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <unistd.h>
#include <sys/stat.h>
#include "screen_capture_server_function_unittest.h"
#include "ui_extension_ability_connection.h"
#include "image_source.h"
#include "image_type.h"
#include "pixel_map.h"
#include "media_log.h"
#include "media_errors.h"
#include "media_utils.h"
#include "uri_helper.h"
#include "media_dfx.h"
#include "scope_guard.h"
#include "param_wrapper.h"

using namespace testing::ext;
using namespace OHOS::Media::ScreenCaptureTestParam;
using namespace OHOS::Media;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "ScreenCaptureServerFunctionTest"};
}

namespace OHOS {
namespace Media {

void ScreenCaptureServerUnittestCallbackMock::OnError(ScreenCaptureErrorType errorType, int32_t errorCode)
{
    MEDIA_LOGE("OnError() is called, errorType %{public}d, errorCode %{public}d", errorType, errorCode);
}

void ScreenCaptureServerUnittestCallbackMock::OnAudioBufferAvailable(bool isReady, AudioCaptureSourceType type)
{
    MEDIA_LOGD("OnAudioBufferAvailable() is called, isReady:%{public}d, type:%{public}d", isReady, type);
}

void ScreenCaptureServerUnittestCallbackMock::OnVideoBufferAvailable(bool isReady)
{
    MEDIA_LOGD("OnVideoBufferAvailable() is called, isReady:%{public}d", isReady);
}

void ScreenCaptureServerUnittestCallbackMock::OnStateChange(AVScreenCaptureStateCode stateCode)
{
    MEDIA_LOGI("OnStateChange() is called, stateCode %{public}d", stateCode);
}

void ScreenCaptureServerUnittestCallbackMock::OnDisplaySelected(uint64_t displayId)
{
    MEDIA_LOGI("OnDisplaySelected() is called, displayId %{public}" PRIu64, displayId);
}

void ScreenCaptureServerUnittestCallbackMock::OnCaptureContentChanged(AVScreenCaptureContentChangedEvent event,
    ScreenCaptureRect* area)
{
    MEDIA_LOGI("OnCaptureContentChanged() is called, event: %{public}d", event);
}

void ScreenCaptureServerUnittestCallbackMock::OnUserSelected(ScreenCaptureUserSelectionInfo selectionInfo)
{
    MEDIA_LOGI("OnUserSelected() is called, selectType: %{public}d, displayId size %{public}zu",
        selectionInfo.selectType, selectionInfo.displayIds.size());
}

void ScreenCaptureServerUnittestCallbackMock::OnPrivacyProtect(AVScreenCapturePrivacyProtect privacyProtect)
{
    MEDIA_LOGI("OnPrivacyProtect() is called, appPrivacyProtection %{public}d, systemPrivacyProtection %{public}d",
        privacyProtect.appPrivacyProtection, privacyProtect.systemPrivacyProtection);
}

void ScreenCaptureServerUnittestCallbackMock::Stop()
{
    MEDIA_LOGD("Stop() is called");
}
} // Media
} // OHOS