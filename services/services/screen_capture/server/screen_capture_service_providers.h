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

#ifndef SCREEN_CAPTURE_SERVICE_PROVIDERS_H
#define SCREEN_CAPTURE_SERVICE_PROVIDERS_H

#include <memory>
#include <string>

namespace OHOS::Media {

class IInnerScreenCaptureMonitorService;
class IRecorderService;
class InCallObserver;
class AccountObserver;

class IScreenCaptureServiceProviders {
public:
    virtual ~IScreenCaptureServiceProviders() = default;
    virtual IInnerScreenCaptureMonitorService &GetScreenCaptureMonitor() = 0;
    virtual std::shared_ptr<IRecorderService> CreateRecorder() = 0;
    virtual int32_t TryUpdateSettingsValue(const std::string &key, const std::string &value) = 0;
#ifdef SUPPORT_CALL
    virtual InCallObserver &GetInCallObserver() = 0;
#endif
    virtual AccountObserver &GetAccountObserver() = 0;
};

std::unique_ptr<IScreenCaptureServiceProviders> CreateDefaultProviders();

} // namespace OHOS::Media

#endif // SCREEN_CAPTURE_SERVICE_PROVIDERS_H
