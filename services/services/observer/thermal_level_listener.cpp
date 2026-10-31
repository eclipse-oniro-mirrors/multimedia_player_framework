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

#include "thermal_level_listener.h"

#include "thermal_observer.h"

namespace OHOS {
namespace Media {
bool ThermalLevelListener::OnThermalLevelChanged(OHOS::PowerMgr::ThermalLevel level)
{
    return ThermalObserver::GetInstance().OnThermalLevelChanged(level);
}

bool ThermalLevelListener::OnAsyncThermalLevelChanged(OHOS::PowerMgr::ThermalLevel level)
{
    return ThermalObserver::GetInstance().OnThermalLevelChanged(level);
}
} // namespace Media
} // namespace OHOS
