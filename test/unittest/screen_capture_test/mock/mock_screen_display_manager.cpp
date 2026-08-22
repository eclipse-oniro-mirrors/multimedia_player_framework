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

} // namespace Rosen
} // namespace OHOS
