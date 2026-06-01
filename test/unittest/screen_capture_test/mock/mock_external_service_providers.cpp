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

#include "mock_external_service_providers.h"

namespace OHOS::Media {

static Rosen::DMError DefaultMakeMirror3(Rosen::ScreenId mainScreenId,
    const std::vector<Rosen::ScreenId> &mirrorScreenId, Rosen::ScreenId &screenGroupId)
{
    return Rosen::ScreenManager::GetInstance().MakeMirror(mainScreenId, mirrorScreenId, screenGroupId);
}

static Rosen::DMError DefaultMakeMirror4(Rosen::ScreenId mainScreenId,
    const std::vector<Rosen::ScreenId> &mirrorScreenId, Rosen::ScreenId &screenGroupId, Rosen::Rotation rotation)
{
    return Rosen::ScreenManager::GetInstance().MakeMirror(mainScreenId, mirrorScreenId, screenGroupId, rotation);
}

static Rosen::DMError DefaultMakeMirrorForRecord(const std::vector<Rosen::ScreenId> &mainScreenIds,
    std::vector<Rosen::ScreenId> &mirrorScreenIds, Rosen::ScreenId &screenGroupId)
{
    return Rosen::ScreenManager::GetInstance().MakeMirrorForRecord(mainScreenIds, mirrorScreenIds, screenGroupId);
}

static Rosen::DMError DefaultStopMirror(const std::vector<Rosen::ScreenId> &mirrorScreenIds)
{
    return Rosen::ScreenManager::GetInstance().StopMirror(mirrorScreenIds);
}

static Rosen::ScreenId DefaultCreateVirtualScreen(const Rosen::VirtualScreenOption &option)
{
    return Rosen::ScreenManager::GetInstance().CreateVirtualScreen(option);
}

std::unique_ptr<ExternalServiceProviders> CreateMockProviders()
{
    auto providers = std::make_unique<ExternalServiceProviders>();
    providers->displayManager = std::make_unique<MockDisplayManagerProvider>();
    providers->screenManager = std::make_unique<MockScreenManagerProvider>();
    providers->windowManager = std::make_unique<MockWindowManagerProvider>();
    providers->sessionManagerLite = std::make_unique<MockSessionManagerLiteProvider>();
    providers->audioStreamManager = std::make_unique<MockAudioStreamManagerProvider>();
    providers->commonService = std::make_unique<MockCommonServiceProvider>();

    EXPECT_CALL(*static_cast<MockDisplayManagerProvider *>(providers->displayManager.get()), GetInstance())
        .WillRepeatedly(testing::ReturnRef(Rosen::DisplayManager::GetInstance()));
    EXPECT_CALL(*static_cast<MockScreenManagerProvider *>(providers->screenManager.get()), GetInstance())
        .WillRepeatedly(testing::ReturnRef(Rosen::ScreenManager::GetInstance()));
    EXPECT_CALL(*static_cast<MockWindowManagerProvider *>(providers->windowManager.get()), GetInstance())
        .WillRepeatedly(testing::ReturnRef(Rosen::WindowManager::GetInstance()));
    EXPECT_CALL(*static_cast<MockSessionManagerLiteProvider *>(providers->sessionManagerLite.get()), GetInstance())
        .WillRepeatedly(testing::ReturnRef(Rosen::SessionManagerLite::GetInstance()));
    EXPECT_CALL(*static_cast<MockAudioStreamManagerProvider *>(providers->audioStreamManager.get()), GetInstance())
        .WillRepeatedly(testing::Return(AudioStandard::AudioStreamManager::GetInstance()));

    auto screenMock = static_cast<MockScreenManagerProvider *>(providers->screenManager.get());
    EXPECT_CALL(*screenMock, MakeMirror(testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::Invoke(DefaultMakeMirror3));
    EXPECT_CALL(*screenMock, MakeMirror(testing::_, testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::Invoke(DefaultMakeMirror4));
    EXPECT_CALL(*screenMock, MakeMirrorForRecord(testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::Invoke(DefaultMakeMirrorForRecord));
    EXPECT_CALL(*screenMock, StopMirror(testing::_)).WillRepeatedly(testing::Invoke(DefaultStopMirror));
    EXPECT_CALL(*screenMock, CreateVirtualScreen(testing::_))
        .WillRepeatedly(testing::Invoke(DefaultCreateVirtualScreen));

    return providers;
}

} // namespace OHOS::Media