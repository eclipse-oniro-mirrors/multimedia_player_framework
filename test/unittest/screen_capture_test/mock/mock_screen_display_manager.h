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

#include "display_manager.h"
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

} // namespace Rosen
} // namespace OHOS

#endif // MOCK_SCREEN_DISPLAY_MANAGER_H
