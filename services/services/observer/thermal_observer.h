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

#ifndef THERMAL_OBSERVER_H
#define THERMAL_OBSERVER_H

#include <memory>
#include <mutex>
#include <vector>

#include "nocopyable.h"
#include "refbase.h"
#include "thermal_level_info.h"
#include "thermal_level_listener.h"
#include "thermal_observer_callback.h"

namespace OHOS {
namespace Media {
class ThermalObserver {
public:
    static ThermalObserver &GetInstance();
    virtual bool RegisterThermalObserverCallBack(std::weak_ptr<ThermalObserverCallBack> callback);
    virtual void UnregisterThermalObserverCallBack(std::weak_ptr<ThermalObserverCallBack> callback);
    bool OnThermalLevelChanged(OHOS::PowerMgr::ThermalLevel level);

private:
    ThermalObserver() = default;
    ~ThermalObserver();
    DISALLOW_COPY_AND_MOVE(ThermalObserver);
    void RegisterServiceEvent();
    void UnregisterServiceEvent();

    std::mutex mutex_;
    sptr<ThermalLevelListener> thermalListener_{nullptr};
    std::vector<std::weak_ptr<ThermalObserverCallBack>> callbacks_;
};
} // namespace Media
} // namespace OHOS
#endif // THERMAL_OBSERVER_H
