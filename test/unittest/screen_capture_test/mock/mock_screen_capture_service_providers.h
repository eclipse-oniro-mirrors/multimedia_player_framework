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

#ifndef MOCK_SCREEN_CAPTURE_SERVICE_PROVIDERS_H
#define MOCK_SCREEN_CAPTURE_SERVICE_PROVIDERS_H

#include <gmock/gmock.h>
#include <memory>
#include "screen_capture_service_providers.h"

namespace OHOS::Media {

class MockScreenCaptureServiceProviders : public IScreenCaptureServiceProviders {
public:
    MOCK_METHOD(std::shared_ptr<AudioCapturerWrapper>, CreateAudioCapturerWrapper,
        (AudioCaptureInfo &, const std::shared_ptr<ScreenCaptureCallBack> &, std::string &&,
            const ScreenCaptureContentFilter &),
        (override));
    IInnerScreenCaptureMonitorService &GetScreenCaptureMonitor() override;
    std::shared_ptr<IRecorderService> CreateRecorder() override;
};

std::unique_ptr<IScreenCaptureServiceProviders> CreateMockProviders();

} // namespace OHOS::Media

#endif // MOCK_SCREEN_CAPTURE_SERVICE_PROVIDERS_H
