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

#include "thermal_observer.h"

#include "media_errors.h"
#include "media_log.h"
#include "thermal_mgr_client.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "ThermalObserver"};
} // namespace

namespace OHOS {
namespace Media {
ThermalObserver::~ThermalObserver()
{
    std::unique_lock<std::mutex> lock(mutex_);
    UnregisterServiceEvent();
}

ThermalObserver &ThermalObserver::GetInstance()
{
    static ThermalObserver instance;
    return instance;
}

bool ThermalObserver::RegisterThermalObserverCallBack(std::weak_ptr<ThermalObserverCallBack> callback)
{
    std::unique_lock<std::mutex> lock(mutex_);
    auto callbackPtr = callback.lock();
    if (callbackPtr == nullptr) {
        MEDIA_LOGE("ThermalObserver callback is null");
        return false;
    }
    if (thermalListener_ == nullptr) {
        RegisterServiceEvent();
    }
    callbacks_.push_back(callback);
    MEDIA_LOGI("ThermalObserver RegisterThermalObserverCallBack vecSize: %{public}zu", callbacks_.size());
    return true;
}

void ThermalObserver::UnregisterThermalObserverCallBack(std::weak_ptr<ThermalObserverCallBack> callback)
{
    std::unique_lock<std::mutex> lock(mutex_);
    auto unregisterCallBack = callback.lock();
    CHECK_AND_RETURN(unregisterCallBack != nullptr);
    for (auto iter = callbacks_.begin(); iter != callbacks_.end();) {
        auto iterCallback = iter->lock();
        if (iterCallback == unregisterCallBack || iterCallback == nullptr) {
            iter = callbacks_.erase(iter);
        } else {
            ++iter;
        }
    }
    if (callbacks_.empty()) {
        UnregisterServiceEvent();
    }
    MEDIA_LOGI("ThermalObserver UnregisterThermalObserverCallBack vecSize: %{public}zu", callbacks_.size());
}

bool ThermalObserver::OnThermalLevelChanged(OHOS::PowerMgr::ThermalLevel level)
{
    std::unique_lock<std::mutex> lock(mutex_);
    for (auto &callback : callbacks_) {
        auto callbackPtr = callback.lock();
        if (callbackPtr) {
            callbackPtr->OnThermalLevelChanged(level);
        }
    }
    return true;
}

void ThermalObserver::RegisterServiceEvent()
{
    auto listener = sptr<ThermalLevelListener>::MakeSptr();
    bool ret = PowerMgr::ThermalMgrClient::GetInstance().SubscribeThermalLevelCallback(listener, false);
    if (ret) {
        thermalListener_ = listener;
        MEDIA_LOGI("ThermalObserver register thermal level listener success");
    } else {
        MEDIA_LOGE("ThermalObserver register thermal level listener failed");
    }
}

void ThermalObserver::UnregisterServiceEvent()
{
    if (thermalListener_ != nullptr) {
        PowerMgr::ThermalMgrClient::GetInstance().UnSubscribeThermalLevelCallback(thermalListener_);
        thermalListener_ = nullptr;
    }
}
} // namespace Media
} // namespace OHOS
