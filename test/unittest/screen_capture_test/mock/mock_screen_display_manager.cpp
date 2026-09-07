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

#include "mock_screen_display_manager.h"

#include "mock_display_objects.h"

namespace OHOS {
namespace Rosen {

DMError ScreenManager::RegisterScreenListener(sptr<IScreenListener> listener)
{
    if (MockScreenManagerActions::current) {
        return MockScreenManagerActions::current->RegisterScreenListener(listener);
    }
    return DMError::DM_OK;
}

DMError ScreenManager::UnregisterScreenListener(sptr<IScreenListener> listener)
{
    if (MockScreenManagerActions::current) {
        return MockScreenManagerActions::current->UnregisterScreenListener(listener);
    }
    return DMError::DM_OK;
}

#ifdef PC_STANDARD
DMError ScreenManager::RegisterRecordDisplayListener(sptr<IRecordDisplayListener> listener)
{
    if (MockScreenManagerActions::current) {
        return MockScreenManagerActions::current->RegisterRecordDisplayListener(listener);
    }
    return DMError::DM_OK;
}

DMError ScreenManager::UnRegisterRecordDisplayListener(sptr<IRecordDisplayListener> listener)
{
    if (MockScreenManagerActions::current) {
        return MockScreenManagerActions::current->UnRegisterRecordDisplayListener(listener);
    }
    return DMError::DM_OK;
}
#endif

DMError DisplayManager::RegisterPrivateWindowListener(sptr<IPrivateWindowListener> listener)
{
    if (MockDisplayManagerActions::current) {
        return MockDisplayManagerActions::current->RegisterPrivateWindowListener(listener);
    }
    return DMError::DM_OK;
}

DMError DisplayManager::UnregisterPrivateWindowListener(sptr<IPrivateWindowListener> listener)
{
    if (MockDisplayManagerActions::current) {
        return MockDisplayManagerActions::current->UnregisterPrivateWindowListener(listener);
    }
    return DMError::DM_OK;
}

// Provide the key functions for DisplayInfo / ScreenInfo so their vtables/VTTs
// are emitted into this (test) translation unit. libwmutil_base.so holds the real
// definitions but does not export the vtable symbols (hidden visibility), so
// any in-test `new DisplayInfo()/ScreenInfo()` would otherwise leave the
// vtable/VTT undefined. The display-success paths only invoke non-virtual
// getters on these objects, so a stub Marshalling (never called) is sufficient.
bool DisplayInfo::Marshalling(Parcel &parcel) const
{
    (void)parcel;
    return false;
}

bool ScreenInfo::Marshalling(Parcel &parcel) const
{
    (void)parcel;
    return false;
}

// ---- ScreenManager flow overrides ----

sptr<Screen> ScreenManager::GetScreenById(ScreenId screenId)
{
    if (MockScreenManagerFlowActions::current) {
        return MockScreenManagerFlowActions::current->GetScreenById(screenId);
    }
    return MakeMockScreen(screenId);
}

ScreenId ScreenManager::CreateVirtualScreen(VirtualScreenOption option)
{
    if (MockScreenManagerFlowActions::current) {
        return MockScreenManagerFlowActions::current->CreateVirtualScreen(option);
    }
    return static_cast<ScreenId>(1);
}

DMError ScreenManager::DestroyVirtualScreen(ScreenId screenId, bool isCallingByThirdParty)
{
    if (MockScreenManagerFlowActions::current) {
        return MockScreenManagerFlowActions::current->DestroyVirtualScreen(screenId, isCallingByThirdParty);
    }
    return DMError::DM_OK;
}

DMError ScreenManager::MakeMirror(ScreenId mainScreenId, std::vector<ScreenId> mirrorScreenId, ScreenId &screenGroupId)
{
    if (MockScreenManagerFlowActions::current) {
        return MockScreenManagerFlowActions::current->MakeMirror(mainScreenId, mirrorScreenId, screenGroupId);
    }
    return DMError::DM_OK;
}

DMError ScreenManager::MakeMirror(ScreenId mainScreenId, std::vector<ScreenId> mirrorScreenId, ScreenId &screenGroupId,
    Rotation rotation)
{
    if (MockScreenManagerFlowActions::current) {
        return MockScreenManagerFlowActions::current->MakeMirrorWithRotation(mainScreenId, mirrorScreenId,
            screenGroupId, rotation);
    }
    return DMError::DM_OK;
}

DMError ScreenManager::MakeMirror(ScreenId mainScreenId, std::vector<ScreenId> mirrorScreenId, DMRect mainScreenRegion,
    ScreenId &screenGroupId)
{
    if (MockScreenManagerFlowActions::current) {
        return MockScreenManagerFlowActions::current->MakeMirrorWithRegion(mainScreenId, mirrorScreenId,
            mainScreenRegion, screenGroupId);
    }
    return DMError::DM_OK;
}

DMError ScreenManager::MakeMirrorForRecord(const std::vector<ScreenId> &mainScreenIds,
    std::vector<ScreenId> &mirrorScreenIds, ScreenId &screenGroupId)
{
    if (MockScreenManagerFlowActions::current) {
        return MockScreenManagerFlowActions::current->MakeMirrorForRecord(mainScreenIds, mirrorScreenIds,
            screenGroupId);
    }
    return DMError::DM_OK;
}

DMError ScreenManager::SetMultiScreenMode(ScreenId mainScreenId, ScreenId secondaryScreenId, MultiScreenMode screenMode)
{
    if (MockScreenManagerFlowActions::current) {
        return MockScreenManagerFlowActions::current->SetMultiScreenMode(mainScreenId, secondaryScreenId, screenMode);
    }
    return DMError::DM_OK;
}

DMError ScreenManager::SetMultiScreenRelativePosition(MultiScreenPositionOptions mainScreenOptions,
    MultiScreenPositionOptions secondScreenOption)
{
    if (MockScreenManagerFlowActions::current) {
        return MockScreenManagerFlowActions::current->SetMultiScreenRelativePosition(mainScreenOptions,
            secondScreenOption);
    }
    return DMError::DM_OK;
}

DMError ScreenManager::StopMirror(const std::vector<ScreenId> &mirrorScreenIds)
{
    if (MockScreenManagerFlowActions::current) {
        return MockScreenManagerFlowActions::current->StopMirror(mirrorScreenIds);
    }
    return DMError::DM_OK;
}

DMError ScreenManager::AddVirtualScreenWhiteList(ScreenId screenId, const std::vector<uint64_t> &missionIds)
{
    if (MockScreenManagerFlowActions::current) {
        return MockScreenManagerFlowActions::current->AddVirtualScreenWhiteList(screenId, missionIds);
    }
    return DMError::DM_OK;
}

DMError ScreenManager::RemoveVirtualScreenWhiteList(ScreenId screenId, const std::vector<uint64_t> &missionIds)
{
    if (MockScreenManagerFlowActions::current) {
        return MockScreenManagerFlowActions::current->RemoveVirtualScreenWhiteList(screenId, missionIds);
    }
    return DMError::DM_OK;
}

DMError ScreenManager::SetVirtualScreenSurface(ScreenId screenId, sptr<Surface> surface)
{
    if (MockScreenManagerFlowActions::current) {
        return MockScreenManagerFlowActions::current->SetVirtualScreenSurface(screenId, surface);
    }
    return DMError::DM_OK;
}

DMError ScreenManager::SetVirtualMirrorScreenCanvasRotation(ScreenId screenId, bool canvasRotation)
{
    if (MockScreenManagerFlowActions::current) {
        return MockScreenManagerFlowActions::current->SetVirtualMirrorScreenCanvasRotation(screenId, canvasRotation);
    }
    return DMError::DM_OK;
}

DMError ScreenManager::ResizeVirtualScreen(ScreenId screenId, uint32_t width, uint32_t height, uint32_t renderWidth,
    uint32_t renderHeight)
{
    if (MockScreenManagerFlowActions::current) {
        return MockScreenManagerFlowActions::current->ResizeVirtualScreen(screenId, width, height, renderWidth,
            renderHeight);
    }
    return DMError::DM_OK;
}

DMError ScreenManager::SetVirtualMirrorScreenScaleMode(ScreenId screenId, ScreenScaleMode scaleMode)
{
    if (MockScreenManagerFlowActions::current) {
        return MockScreenManagerFlowActions::current->SetVirtualMirrorScreenScaleMode(screenId, scaleMode);
    }
    return DMError::DM_OK;
}

DMError ScreenManager::SetVirtualScreenMaxRefreshRate(ScreenId id, uint32_t refreshRate, uint32_t &actualRefreshRate)
{
    if (MockScreenManagerFlowActions::current) {
        return MockScreenManagerFlowActions::current->SetVirtualScreenMaxRefreshRate(id, refreshRate,
            actualRefreshRate);
    }
    return DMError::DM_OK;
}

DMError ScreenManager::SetScreenSkipProtectedWindow(const std::vector<ScreenId> &screenIds, bool isEnable)
{
    if (MockScreenManagerFlowActions::current) {
        return MockScreenManagerFlowActions::current->SetScreenSkipProtectedWindow(screenIds, isEnable);
    }
    return DMError::DM_OK;
}

DMError ScreenManager::SetVirtualScreenAutoRotation(ScreenId screenId, bool enable)
{
    if (MockScreenManagerFlowActions::current) {
        return MockScreenManagerFlowActions::current->SetVirtualScreenAutoRotation(screenId, enable);
    }
    return DMError::DM_OK;
}

DMError ScreenManager::SetScreenPrivacyWindowTagSwitch(ScreenId screenId,
    const std::vector<std::string> &privacyWindowTag, bool enable)
{
    if (MockScreenManagerFlowActions::current) {
        return MockScreenManagerFlowActions::current->SetScreenPrivacyWindowTagSwitch(screenId, privacyWindowTag,
            enable);
    }
    return DMError::DM_OK;
}

DMError ScreenManager::QueryMultiScreenCapture(const std::vector<ScreenId> &displayIdList, DMRect &rect)
{
    if (MockScreenManagerFlowActions::current) {
        return MockScreenManagerFlowActions::current->QueryMultiScreenCapture(displayIdList, rect);
    }
    return DMError::DM_ERROR_DEVICE_NOT_SUPPORT;
}

// ---- DisplayManager flow overrides ----

sptr<Display> DisplayManager::GetDefaultDisplaySync(bool isFromNapi, int32_t userId)
{
    if (MockDisplayManagerFlowActions::current) {
        return MockDisplayManagerFlowActions::current->GetDefaultDisplaySync(isFromNapi, userId);
    }
    return MakeMockDisplay(0);
}

sptr<Display> DisplayManager::GetDisplayById(DisplayId displayId)
{
    if (MockDisplayManagerFlowActions::current) {
        return MockDisplayManagerFlowActions::current->GetDisplayById(displayId);
    }
    return (displayId == 0) ? MakeMockDisplay(0) : nullptr;
}

std::vector<DisplayId> DisplayManager::GetAllDisplayIds(int32_t userId)
{
    if (MockDisplayManagerFlowActions::current) {
        return MockDisplayManagerFlowActions::current->GetAllDisplayIds(userId);
    }
    return {};
}

bool DisplayManager::ConvertScreenIdToRsScreenId(ScreenId screenId, ScreenId &rsScreenId)
{
    if (MockDisplayManagerFlowActions::current) {
        return MockDisplayManagerFlowActions::current->ConvertScreenIdToRsScreenId(screenId, rsScreenId);
    }
    return false;
}

void DisplayManager::SetVirtualScreenBlackList(ScreenId screenId, std::vector<uint64_t> &windowIdList,
    std::vector<uint64_t> surfaceIdList, std::vector<uint8_t> typeBlackList)
{
    if (MockDisplayManagerFlowActions::current) {
        MockDisplayManagerFlowActions::current->SetVirtualScreenBlackList(screenId, windowIdList, surfaceIdList,
            typeBlackList);
    }
}

void DisplayManager::DisablePowerOffRenderControl(ScreenId screenId)
{
    if (MockDisplayManagerFlowActions::current) {
        MockDisplayManagerFlowActions::current->DisablePowerOffRenderControl(screenId);
    }
}

DMError DisplayManager::SetVirtualScreenSecurityExemption(ScreenId screenId, uint32_t pid,
    std::vector<uint64_t> &windowIdList)
{
    if (MockDisplayManagerFlowActions::current) {
        return MockDisplayManagerFlowActions::current->SetVirtualScreenSecurityExemption(screenId, pid, windowIdList);
    }
    return DMError::DM_OK;
}

DMError DisplayManager::GetScreenAreaOfDisplayArea(DisplayId displayId, const DMRect &displayArea, ScreenId &screenId,
    DMRect &screenArea)
{
    if (MockDisplayManagerFlowActions::current) {
        return MockDisplayManagerFlowActions::current->GetScreenAreaOfDisplayArea(displayId, displayArea, screenId,
            screenArea);
    }
    return DMError::DM_OK;
}

} // namespace Rosen
} // namespace OHOS
