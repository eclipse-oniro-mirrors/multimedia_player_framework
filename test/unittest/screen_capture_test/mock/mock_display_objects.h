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

#ifndef MOCK_DISPLAY_OBJECTS_H
#define MOCK_DISPLAY_OBJECTS_H

#include "display.h"
#include "display_info.h"
#include "screen.h"
#include "screen_info.h"

namespace OHOS {
namespace Rosen {

// Concrete subtypes of Display/Screen whose protected ctors become reachable
// (protected is accessible from derived; the test toolchain also builds with
// -Dprotected=public). Display/Screen getters read from the Info object passed
// to the ctor, so a fully-populated DisplayInfo/ScreenInfo yields controlled
// return values from GetId/GetWidth/GetScreenId/GetParentId/GetVirtualWidth...
class MockDisplay : public Display {
public:
    explicit MockDisplay(sptr<DisplayInfo> info) : Display("sc_test_display", info) {}
};

class MockScreen : public Screen {
public:
    explicit MockScreen(sptr<ScreenInfo> info) : Screen(info) {}
};

// Build a Display populated with controlled field values. screenId is what
// Display::GetScreenId() returns (used by SCS GetDisplayIdOfWindows /
// SetupVirtualScreenMirror). width/height feed Display::GetWidth()/GetHeight()
// (used by CreateVirtualScreen logging + MakeVirtualScreenExtended positioning).
inline sptr<Display> MakeMockDisplay(ScreenId screenId, int32_t width = 720, int32_t height = 1280, float vpr = 2.0f,
    DisplayId displayId = DISPLAY_ID_INVALID)
{
    auto info = new DisplayInfo();
    info->SetDisplayId(displayId);
    info->SetScreenId(screenId);
    info->SetWidth(width);
    info->SetHeight(height);
    info->SetPhysicalWidth(width);
    info->SetPhysicalHeight(height);
    info->SetVirtualPixelRatio(vpr);
    info->SetRotation(Rotation::ROTATION_0);
    return sptr<Display>(new MockDisplay(info));
}

// Build a Screen populated with controlled field values. Only GetId() is read
// on the success paths under test (PrepareVirtualScreenMirror null-check), but
// the remaining fields are populated for completeness.
inline sptr<Screen> MakeMockScreen(ScreenId screenId, ScreenId parentId = SCREEN_ID_INVALID,
    uint32_t virtualWidth = 720, uint32_t virtualHeight = 1280)
{
    auto info = new ScreenInfo();
    info->SetScreenId(screenId);
    info->SetParentId(parentId);
    info->SetVirtualWidth(virtualWidth);
    info->SetVirtualHeight(virtualHeight);
    info->SetRsId(screenId);
    info->SetIsScreenGroup(false);
    return sptr<Screen>(new MockScreen(info));
}

} // namespace Rosen
} // namespace OHOS

#endif // MOCK_DISPLAY_OBJECTS_H
