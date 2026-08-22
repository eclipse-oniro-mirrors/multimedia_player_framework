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

#include "screen_capture_service_providers.h"
#include "media_datashare_observer.h"
#include "recorder_server.h"
#include "screen_capture_monitor_server.h"
#include "account_observer.h"
#ifdef SUPPORT_CALL
#include "incall_observer.h"
#endif

namespace OHOS::Media {

class ScreenCaptureServiceProvidersImpl : public IScreenCaptureServiceProviders {
public:
    IInnerScreenCaptureMonitorService &GetScreenCaptureMonitor() override
    {
        return ScreenCaptureMonitorServer::GetInstance();
    }

    std::shared_ptr<IRecorderService> CreateRecorder() override
    {
        return RecorderServer::Create();
    }

    int32_t TryUpdateSettingsValue(const std::string &key, const std::string &value) override
    {
        return OHOS::Media::TryUpdateSettingsValue(key, value);
    }

#ifdef SUPPORT_CALL
    InCallObserver &GetInCallObserver() override
    {
        return InCallObserver::GetInstance();
    }
#endif

    AccountObserver &GetAccountObserver() override
    {
        return AccountObserver::GetInstance();
    }
};

std::unique_ptr<IScreenCaptureServiceProviders> CreateDefaultProviders()
{
    return std::make_unique<ScreenCaptureServiceProvidersImpl>();
}
} // namespace OHOS::Media
