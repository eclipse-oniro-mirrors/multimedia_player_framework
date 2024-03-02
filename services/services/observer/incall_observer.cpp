/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
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

#include "incall_observer.h"
#include <unistd.h>
#include <functional>
#include "media_log.h"
#include "media_errors.h"
#include "hisysevent.h"
#include "telephony_observer_client.h"
#include "call_manager_client.h"
#include "core_service_client.h"
#include "iservice_registry.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN, "InCallObserver"};
}

using namespace OHOS::Telephony;
namespace OHOS {
namespace Media {

InCallObserver& InCallObserver::GetInstance()
{
    static InCallObserver instance;
    instance.Init();
    return instance;
}

InCallObserver::InCallObserver()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

InCallObserver::~InCallObserver()
{
    UnRegisterObserver();
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

bool InCallObserver::IsInCall()
{
    return inCall_;
}

void InCallObserver::RegisterScreenCaptureCallBack(std::weak_ptr<ScreenCaptureObserverCallBack> callback)
{
    screenCaptureObserverCallBack_ = callback;
}

void InCallObserver::UnRegisterScreenCaptureCallBack(std::weak_ptr<ScreenCaptureObserverCallBack> callback)
{
    if (screenCaptureObserverCallBack_ == callback) {
        screenCaptureObserverCallBack_ = null;
    }
}

void InCallObserver::OnCallStateUpdated(bool inCall)
{
    std::unique_lock<std::mutex> lock(mutex_);
    inCall_ = inCall;
    if (screenCaptureObserverCallBack_.expired()) {
        screenCaptureObserverCallBack_.lock()->StopAndReleaseScreenCapture();
    }
}

bool InCallObserver::Init()
{
    MEDIA_LOGI("Create InCallObserver");
    if (isTelephonyStateListenerDied_) {
        MEDIA_LOGI("InCallObserver died or first start, Register inCall observer");
        RegisterObserver();
        isTelephonyStateListenerDied_ = false;
        return true;
    }
    return true;
}

void InCallObserver::RegisterObserver()
{
    MEDIA_LOGI("Register InCall Listener");
    for (int slotId = 0; slotId < OHOS::Telephony::SIM_SLOT_COUNT; slotId++) {
        MEDIA_LOGI("Register Listener slotId:%{public}d", slotId);
        auto telephonyObserver_ = std::make_unique<MediaTelephonyListener>().release();
        auto res = TelephonyObserverClient::GetInstance().AddStateObserver(telephonyObserver_, slotId,
            TelephonyObserverBroker::OBSERVER_MASK_CALL_STATE, true);
        MEDIA_LOGI("InCallObserver init telephony observer ret:%{public}d", res);
        mediaTelephonyListeners_.push_back(telephonyObserver_);
    }
    isTelephonyStateListenerDied_ = false;
}

void InCallObserver::UnRegisterObserver()
{
    MEDIA_LOGI("UnRegister InCall Listener");
    for (int slotId = 0; slotId < OHOS::Telephony::SIM_SLOT_COUNT; slotId++) {
        MEDIA_LOGI("UnRegister Listener slotId:%{public}d", slotId);
        TelephonyObserverClient::GetInstance().RemoveStateObserver(slotId,
            TelephonyObserverBroker::OBSERVER_MASK_CALL_STATE);
    }
    mediaTelephonyListeners_.clear();
    isTelephonyStateListenerDied_ = true;
}
}
}