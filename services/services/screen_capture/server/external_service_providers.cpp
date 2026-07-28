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

#include "external_service_providers.h"
#include "audio_capturer_wrapper.h"

namespace OHOS::Media {

class CommonServiceProviderImpl : public ICommonServiceProvider {
public:
    std::shared_ptr<AudioCapturerWrapper> CreateAudioCapturerWrapper(AudioCaptureInfo &audioInfo,
        const std::shared_ptr<ScreenCaptureCallBack> &screenCaptureCb, std::string &&name,
        const ScreenCaptureContentFilter &filter) override
    {
        return std::make_shared<AudioCapturerWrapper>(audioInfo, screenCaptureCb, std::move(name), filter);
    }
};

std::unique_ptr<ExternalServiceProviders> CreateDefaultProviders()
{
    auto wrappers = std::make_unique<ExternalServiceProviders>();
    wrappers->commonService = std::make_unique<CommonServiceProviderImpl>();
    return wrappers;
}
} // namespace OHOS::Media
