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

#ifndef THERMAL_LEVEL_LISTENER_H
#define THERMAL_LEVEL_LISTENER_H

#include "thermal_level_callback_stub.h"

namespace OHOS {
namespace Media {
class ThermalLevelListener : public PowerMgr::ThermalLevelCallbackStub {
public:
    ThermalLevelListener() = default;
    ~ThermalLevelListener() override = default;
    bool OnThermalLevelChanged(OHOS::PowerMgr::ThermalLevel level) override;
    bool OnAsyncThermalLevelChanged(OHOS::PowerMgr::ThermalLevel level) override;
};
} // namespace Media
} // namespace OHOS
#endif // THERMAL_LEVEL_LISTENER_H
