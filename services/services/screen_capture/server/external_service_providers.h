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

#ifndef EXTERNAL_SERVICE_WRAPPERS_H
#define EXTERNAL_SERVICE_WRAPPERS_H

#include <memory>

namespace OHOS::Rosen {
class DisplayManager;
class ScreenManager;
class WindowManager;
class SessionManagerLite;
} // namespace OHOS::Rosen

namespace OHOS::AudioStandard {
class AudioStreamManager;
}

namespace OHOS::EventFwk {
class CommonEventSubscriber;
class CommonEventData;
class CommonEventPublishInfo;
} // namespace OHOS::EventFwk

namespace OHOS::Media {

class AudioCapturerWrapper;
struct AudioCaptureInfo;
class ScreenCaptureCallBack;
struct ScreenCaptureContentFilter;

class IDisplayManagerProvider {
public:
    virtual ~IDisplayManagerProvider() = default;
    virtual Rosen::DisplayManager &GetInstance() = 0;
};

class IScreenManagerProvider {
public:
    virtual ~IScreenManagerProvider() = default;
    virtual Rosen::ScreenManager &GetInstance() = 0;
};

class IWindowManagerProvider {
public:
    virtual ~IWindowManagerProvider() = default;
    virtual Rosen::WindowManager &GetInstance() = 0;
};

class ISessionManagerLiteProvider {
public:
    virtual ~ISessionManagerLiteProvider() = default;
    virtual Rosen::SessionManagerLite &GetInstance() = 0;
};

class IAudioStreamManagerProvider {
public:
    virtual ~IAudioStreamManagerProvider() = default;
    virtual AudioStandard::AudioStreamManager *GetInstance() = 0;
};

class ICommonServiceProvider {
public:
    virtual ~ICommonServiceProvider() = default;
    virtual bool SubscribeCommonEvent(std::shared_ptr<EventFwk::CommonEventSubscriber> subscriber) = 0;
    virtual bool UnSubscribeCommonEvent(std::shared_ptr<EventFwk::CommonEventSubscriber> subscriber) = 0;
    virtual bool PublishCommonEvent(const EventFwk::CommonEventData &data,
        const EventFwk::CommonEventPublishInfo &publishInfo) = 0;
    virtual std::shared_ptr<AudioCapturerWrapper> CreateAudioCapturerWrapper(AudioCaptureInfo &audioInfo,
        std::shared_ptr<ScreenCaptureCallBack> &screenCaptureCb, std::string &&name,
        const ScreenCaptureContentFilter &filter) = 0;
};

struct ExternalServiceProviders {
    std::unique_ptr<IDisplayManagerProvider> displayManager;
    std::unique_ptr<IScreenManagerProvider> screenManager;
    std::unique_ptr<IWindowManagerProvider> windowManager;
    std::unique_ptr<ISessionManagerLiteProvider> sessionManagerLite;
    std::unique_ptr<IAudioStreamManagerProvider> audioStreamManager;
    std::unique_ptr<ICommonServiceProvider> commonService;
};

std::unique_ptr<ExternalServiceProviders> CreateDefaultProviders();

} // namespace OHOS::Media

#endif // EXTERNAL_SERVICE_WRAPPERS_H
