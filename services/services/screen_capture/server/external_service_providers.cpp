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
#include <display_manager.h>
#include <screen_manager.h>
#include <window_manager.h>
#include <session_manager_lite.h>
#include <audio_stream_manager.h>
#include <common_event_manager.h>
#include "audio_capturer_wrapper.h"

namespace OHOS::Media {

class DisplayManagerProviderImpl : public IDisplayManagerProvider {
public:
    Rosen::DisplayManager &GetInstance() override { return Rosen::DisplayManager::GetInstance(); }
};

class ScreenManagerProviderImpl : public IScreenManagerProvider {
public:
    Rosen::ScreenManager &GetInstance() override { return Rosen::ScreenManager::GetInstance(); }
    Rosen::DMError MakeMirror(Rosen::ScreenId mainScreenId, const std::vector<Rosen::ScreenId> &mirrorScreenId,
        Rosen::ScreenId &screenGroupId) override
    {
        return Rosen::ScreenManager::GetInstance().MakeMirror(mainScreenId, mirrorScreenId, screenGroupId);
    }
    Rosen::DMError MakeMirror(Rosen::ScreenId mainScreenId, const std::vector<Rosen::ScreenId> &mirrorScreenId,
        Rosen::ScreenId &screenGroupId, Rosen::Rotation rotation) override
    {
        return Rosen::ScreenManager::GetInstance().MakeMirror(mainScreenId, mirrorScreenId, screenGroupId, rotation);
    }
    Rosen::DMError MakeMirrorForRecord(const std::vector<Rosen::ScreenId> &mainScreenIds,
        std::vector<Rosen::ScreenId> &mirrorScreenIds, Rosen::ScreenId &screenGroupId) override
    {
        return Rosen::ScreenManager::GetInstance().MakeMirrorForRecord(mainScreenIds, mirrorScreenIds, screenGroupId);
    }
    Rosen::DMError StopMirror(const std::vector<Rosen::ScreenId> &mirrorScreenIds) override
    {
        return Rosen::ScreenManager::GetInstance().StopMirror(mirrorScreenIds);
    }
    Rosen::ScreenId CreateVirtualScreen(const Rosen::VirtualScreenOption &option) override
    {
        return Rosen::ScreenManager::GetInstance().CreateVirtualScreen(option);
    }
};

class WindowManagerProviderImpl : public IWindowManagerProvider {
public:
    Rosen::WindowManager &GetInstance() override { return Rosen::WindowManager::GetInstance(); }
};

class SessionManagerLiteProviderImpl : public ISessionManagerLiteProvider {
public:
    Rosen::SessionManagerLite &GetInstance() override { return Rosen::SessionManagerLite::GetInstance(); }
};

class AudioStreamManagerProviderImpl : public IAudioStreamManagerProvider {
public:
    AudioStandard::AudioStreamManager *GetInstance() override
    {
        return AudioStandard::AudioStreamManager::GetInstance();
    }
};

class CommonServiceProviderImpl : public ICommonServiceProvider {
public:
    bool SubscribeCommonEvent(std::shared_ptr<EventFwk::CommonEventSubscriber> subscriber) override
    {
        return EventFwk::CommonEventManager::SubscribeCommonEvent(subscriber);
    }
    bool UnSubscribeCommonEvent(std::shared_ptr<EventFwk::CommonEventSubscriber> subscriber) override
    {
        return EventFwk::CommonEventManager::UnSubscribeCommonEvent(subscriber);
    }
    bool PublishCommonEvent(const EventFwk::CommonEventData &data,
        const EventFwk::CommonEventPublishInfo &publishInfo) override
    {
        return EventFwk::CommonEventManager::PublishCommonEvent(data, publishInfo);
    }
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
    wrappers->displayManager = std::make_unique<DisplayManagerProviderImpl>();
    wrappers->screenManager = std::make_unique<ScreenManagerProviderImpl>();
    wrappers->windowManager = std::make_unique<WindowManagerProviderImpl>();
    wrappers->sessionManagerLite = std::make_unique<SessionManagerLiteProviderImpl>();
    wrappers->audioStreamManager = std::make_unique<AudioStreamManagerProviderImpl>();
    wrappers->commonService = std::make_unique<CommonServiceProviderImpl>();
    return wrappers;
}
} // namespace OHOS::Media
