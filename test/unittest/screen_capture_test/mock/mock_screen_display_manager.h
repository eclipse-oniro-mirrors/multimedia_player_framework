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

#ifndef MOCK_SCREEN_DISPLAY_MANAGER_H
#define MOCK_SCREEN_DISPLAY_MANAGER_H

#include "display_info.h"
#include "display_manager.h"
#include "screen_info.h"
#include "screen_manager.h"
#include <gmock/gmock.h>

namespace OHOS {
namespace Rosen {

class MockScreenManagerActions {
public:
    inline static MockScreenManagerActions *current = nullptr;

    MockScreenManagerActions()
    {
        current = this;
    }
    ~MockScreenManagerActions()
    {
        current = nullptr;
    }

    MOCK_METHOD(DMError, RegisterScreenListener, (sptr<ScreenManager::IScreenListener> listener));
    MOCK_METHOD(DMError, UnregisterScreenListener, (sptr<ScreenManager::IScreenListener> listener));
    MOCK_METHOD(DMError, RegisterRecordDisplayListener, (sptr<ScreenManager::IRecordDisplayListener> listener));
    MOCK_METHOD(DMError, UnRegisterRecordDisplayListener, (sptr<ScreenManager::IRecordDisplayListener> listener));
};

class MockDisplayManagerActions {
public:
    inline static MockDisplayManagerActions *current = nullptr;

    MockDisplayManagerActions()
    {
        current = this;
    }
    ~MockDisplayManagerActions()
    {
        current = nullptr;
    }

    MOCK_METHOD(DMError, RegisterPrivateWindowListener, (sptr<DisplayManager::IPrivateWindowListener> listener));
    MOCK_METHOD(DMError, UnregisterPrivateWindowListener, (sptr<DisplayManager::IPrivateWindowListener> listener));
};

// Action classes for the link-time-overridden display/screen *flow* methods.
// Each override checks the matching `current` pointer; when null it returns a
// safe fallback (nullptr for sptr, DM_OK for DMError, true for bool,
// SCREEN_ID_INVALID for CreateVirtualScreen) reproducing the no-display-service
// test-env behaviour the rest of the suite already relies on.
//
// MakeMirror is overloaded on ScreenManager; gmock cannot declare several
// methods with one name, so the overloads are exposed under distinct names
// (MakeMirror / MakeMirrorWithRotation / MakeMirrorWithRegion).
class MockScreenManagerFlowActions {
public:
    inline static MockScreenManagerFlowActions *current = nullptr;

    MockScreenManagerFlowActions()
    {
        current = this;
    }
    ~MockScreenManagerFlowActions()
    {
        current = nullptr;
    }

    MOCK_METHOD(sptr<Screen>, GetScreenById, (ScreenId screenId));
    MOCK_METHOD(ScreenId, CreateVirtualScreen, (VirtualScreenOption option));
    MOCK_METHOD(DMError, DestroyVirtualScreen, (ScreenId screenId, bool isCallingByThirdParty));
    MOCK_METHOD(DMError, MakeMirror,
        (ScreenId mainScreenId, std::vector<ScreenId> mirrorScreenId, ScreenId &screenGroupId));
    MOCK_METHOD(DMError, MakeMirrorWithRotation,
        (ScreenId mainScreenId, std::vector<ScreenId> mirrorScreenId, ScreenId &screenGroupId, Rotation rotation));
    MOCK_METHOD(DMError, MakeMirrorWithRegion,
        (ScreenId mainScreenId, std::vector<ScreenId> mirrorScreenId, DMRect mainScreenRegion,
            ScreenId &screenGroupId));
    MOCK_METHOD(DMError, MakeMirrorForRecord,
        (const std::vector<ScreenId> &mainScreenIds, std::vector<ScreenId> &mirrorScreenIds, ScreenId &screenGroupId));
    MOCK_METHOD(DMError, SetMultiScreenMode,
        (ScreenId mainScreenId, ScreenId secondaryScreenId, MultiScreenMode screenMode));
    MOCK_METHOD(DMError, SetMultiScreenRelativePosition,
        (MultiScreenPositionOptions mainScreenOptions, MultiScreenPositionOptions secondScreenOption));
    MOCK_METHOD(DMError, StopMirror, (const std::vector<ScreenId> &mirrorScreenIds));
    MOCK_METHOD(DMError, AddVirtualScreenWhiteList, (ScreenId screenId, const std::vector<uint64_t> &missionIds));
    MOCK_METHOD(DMError, RemoveVirtualScreenWhiteList, (ScreenId screenId, const std::vector<uint64_t> &missionIds));
    MOCK_METHOD(DMError, SetVirtualScreenSurface, (ScreenId screenId, sptr<Surface> surface));
    MOCK_METHOD(DMError, SetVirtualMirrorScreenCanvasRotation, (ScreenId screenId, bool canvasRotation));
    MOCK_METHOD(DMError, ResizeVirtualScreen,
        (ScreenId screenId, uint32_t width, uint32_t height, uint32_t renderWidth, uint32_t renderHeight));
    MOCK_METHOD(DMError, SetVirtualMirrorScreenScaleMode, (ScreenId screenId, ScreenScaleMode scaleMode));
    MOCK_METHOD(DMError, SetVirtualScreenMaxRefreshRate,
        (ScreenId id, uint32_t refreshRate, uint32_t &actualRefreshRate));
    MOCK_METHOD(DMError, SetScreenSkipProtectedWindow, (const std::vector<ScreenId> &screenIds, bool isEnable));
    MOCK_METHOD(DMError, SetVirtualScreenAutoRotation, (ScreenId screenId, bool enable));
    MOCK_METHOD(DMError, SetScreenPrivacyWindowTagSwitch,
        (ScreenId screenId, const std::vector<std::string> &privacyWindowTag, bool enable));
    MOCK_METHOD(DMError, QueryMultiScreenCapture, (const std::vector<ScreenId> &displayIdList, DMRect &rect));
};

class MockDisplayManagerFlowActions {
public:
    inline static MockDisplayManagerFlowActions *current = nullptr;

    MockDisplayManagerFlowActions()
    {
        current = this;
    }
    ~MockDisplayManagerFlowActions()
    {
        current = nullptr;
    }

    MOCK_METHOD(sptr<Display>, GetDefaultDisplaySync, (bool isFromNapi, int32_t userId));
    MOCK_METHOD(sptr<Display>, GetDisplayById, (DisplayId displayId));
    MOCK_METHOD(std::vector<DisplayId>, GetAllDisplayIds, (int32_t userId));
    MOCK_METHOD(bool, ConvertScreenIdToRsScreenId, (ScreenId screenId, ScreenId &rsScreenId));
    MOCK_METHOD(void, SetVirtualScreenBlackList,
        (ScreenId screenId, std::vector<uint64_t> &windowIdList, std::vector<uint64_t> surfaceIdList,
            std::vector<uint8_t> typeBlackList));
    MOCK_METHOD(void, DisablePowerOffRenderControl, (ScreenId screenId));
    MOCK_METHOD(DMError, SetVirtualScreenSecurityExemption,
        (ScreenId screenId, uint32_t pid, std::vector<uint64_t> &windowIdList));
    MOCK_METHOD(DMError, GetScreenAreaOfDisplayArea,
        (DisplayId displayId, const DMRect &displayArea, ScreenId &screenId, DMRect &screenArea));
};

} // namespace Rosen
} // namespace OHOS

#endif // MOCK_SCREEN_DISPLAY_MANAGER_H
