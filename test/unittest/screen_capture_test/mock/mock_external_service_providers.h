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

#ifndef MOCK_EXTERNAL_SERVICE_PROVIDERS_H
#define MOCK_EXTERNAL_SERVICE_PROVIDERS_H

#include <gmock/gmock.h>
#include <memory>
#include <audio_stream_manager.h>
#include <display_manager.h>
#include <screen_manager.h>
#include <window_manager.h>
#include <session_manager_lite.h>
#include "external_service_providers.h"

namespace OHOS::Media {

class MockDisplayManagerProvider : public IDisplayManagerProvider {
public:
    MOCK_METHOD(Rosen::DisplayManager &, GetInstance, (), (override));
};

class MockScreenManagerProvider : public IScreenManagerProvider {
public:
    MOCK_METHOD(Rosen::ScreenManager &, GetInstance, (), (override));
};

class MockWindowManagerProvider : public IWindowManagerProvider {
public:
    MOCK_METHOD(Rosen::WindowManager &, GetInstance, (), (override));
};

class MockSessionManagerLiteProvider : public ISessionManagerLiteProvider {
public:
    MOCK_METHOD(Rosen::SessionManagerLite &, GetInstance, (), (override));
};

class MockAudioStreamManagerProvider : public IAudioStreamManagerProvider {
public:
    MOCK_METHOD(AudioStandard::AudioStreamManager *, GetInstance, (), (override));
};

class MockCommonServiceProvider : public ICommonServiceProvider {
public:
    MOCK_METHOD(bool, SubscribeCommonEvent, (std::shared_ptr<EventFwk::CommonEventSubscriber>), (override));
    MOCK_METHOD(bool, UnSubscribeCommonEvent, (std::shared_ptr<EventFwk::CommonEventSubscriber>), (override));
    MOCK_METHOD(bool, PublishCommonEvent, (const EventFwk::CommonEventData &, const EventFwk::CommonEventPublishInfo &),
        (override));
    MOCK_METHOD(std::shared_ptr<AudioCapturerWrapper>, CreateAudioCapturerWrapper,
        (AudioCaptureInfo &, std::shared_ptr<ScreenCaptureCallBack> &, std::string &&,
            const ScreenCaptureContentFilter &),
        (override));
};

std::unique_ptr<ExternalServiceProviders> CreateMockProviders();

} // namespace OHOS::Media

#endif // MOCK_EXTERNAL_SERVICE_PROVIDERS_H
