/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
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
#include "call_manager_client.h"
#include "media_log.h"
#include "media_errors.h"
#include "hisysevent.h"
#include "telephony_observer_client.h"
#include "telephony_types.h"
#include "telephony_errors.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "InCallObserver"};
}

using namespace OHOS;
using namespace OHOS::Telephony;
namespace OHOS {
namespace Media {

InCallObserver& InCallObserver::GetInstance()
{
    static InCallObserver instance;
    return instance;
}

InCallObserver::InCallObserver(): taskQue_("IncallObs")
{
    taskQue_.Start();
    Init();
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

InCallObserver::~InCallObserver()
{
    UnRegisterObserver();
    taskQue_.Stop();
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

bool InCallObserver::IsInCall(bool refreshState)
{
    if (refreshState) {
        UnRegisterObserver();
        RegisterObserver();
    }
    MEDIA_LOGI("InCallObserver is inCall: %{public}d", inCall_.load());
    return inCall_.load();
}

bool InCallObserver::RegisterInCallObserverCallBack(std::weak_ptr<InCallObserverCallBack> callback)
{
    MEDIA_LOGI("InCallObserver::RegisterInCallObserverCallBack START.");
    std::unique_lock<std::mutex> lock(mutex_);
    auto task = std::make_shared<TaskHandler<bool>>([&, this, callback] {
        auto callbackPtr = callback.lock();
        if (callbackPtr) {
            inCallObserverCallBacks_.push_back(callback);
            return true;
        }
        MEDIA_LOGI("0x%{public}06" PRIXPTR "InCallObserver CallBack is null", FAKE_POINTER(this));
        return false;
    });
    int32_t ret = taskQue_.EnqueueTask(task);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, false, "RegisterInCallObserverCallBack: EnqueueTask failed.");

    auto result = task->GetResult();
    CHECK_AND_RETURN_RET_LOG(result.HasResult(), false, "RegisterInCallObserverCallBack: GetResult failed.");
    MEDIA_LOGI("InCallObserver::RegisterInCallObserverCallBack vecSize: %{public}d",
        static_cast<int32_t>(inCallObserverCallBacks_.size()));
    return result.Value();
}

void InCallObserver::UnregisterInCallObserverCallBack(std::weak_ptr<InCallObserverCallBack> callback)
{
    MEDIA_LOGI("InCallObserver::UnregisterInCallObserverCallBack START.");
    std::unique_lock<std::mutex> lock(mutex_);
    auto task = std::make_shared<TaskHandler<void>>([&, this, callback] {
        auto unregisterCallBack = callback.lock();
        for (auto iter = inCallObserverCallBacks_.begin(); iter != inCallObserverCallBacks_.end();) {
            auto iterCallback = (*iter).lock();
            if (iterCallback == unregisterCallBack || iterCallback == nullptr) {
                MEDIA_LOGD("0x%{public}06" PRIXPTR "UnregisterInCallObserverCallBack",
                    FAKE_POINTER(iterCallback.get()));
                iter = inCallObserverCallBacks_.erase(iter);
            } else {
                iter++;
            }
        }
        MEDIA_LOGI("UnregisterInCallObserverCallBack END. inCallObserverCallBacks_.size(): %{public}d",
            static_cast<int32_t>(inCallObserverCallBacks_.size()));
    });
    taskQue_.EnqueueTask(task);
    MEDIA_LOGI("InCallObserver::UnregisterInCallObserverCallBack END.");
}

bool InCallObserver::OnCallStateUpdated(bool inCall)
{
    MEDIA_LOGD("InCallObserver::OnCallStateUpdated START.");
    std::unique_lock<std::mutex> lock(mutex_);
    if (inCall_.load() == inCall) {
        return true;
    }
    MEDIA_LOGI("Update InCall Status %{public}d", static_cast<int32_t>(inCall));
    inCall_.store(inCall);
    bool ret = true;
    for (auto iter = inCallObserverCallBacks_.begin(); iter != inCallObserverCallBacks_.end(); iter++) {
        auto callbackPtr = (*iter).lock();
        MEDIA_LOGD("0x%{public}06" PRIXPTR "OnCallStateUpdated", FAKE_POINTER(callbackPtr.get()));
        if (callbackPtr) {
            MEDIA_LOGD("0x%{public}06" PRIXPTR "OnCallStateUpdated NotifyTelCallStateUpdated start",
                FAKE_POINTER(callbackPtr.get()));
            ret &= callbackPtr->NotifyTelCallStateUpdated(inCall);
            MEDIA_LOGD("OnCallStateUpdated NotifyTelCallStateUpdated ret: %{public}d.", ret);
        }
    }
    return ret;
}

bool InCallObserver::Init()
{
    if (isTelephonyStateListenerDied_) {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " InCallObserver Init, Register Observer", FAKE_POINTER(this));
        UnRegisterObserver();
        RegisterObserver();
        isTelephonyStateListenerDied_ = false;
    } else {
        MEDIA_LOGI("InCallObserver exist : %{public}d", isTelephonyStateListenerDied_);
    }
    return true;
}

bool InCallObserver::RegisterObserver()
{
    MEDIA_LOGI("InCallObserver Register InCall Listener");
    std::unique_lock<std::mutex> lock(mutex_);
    bool ret = false;
    auto telephonyObserver_ = std::make_unique<MediaTelephonyListener>().release();
    auto observerRes = TelephonyObserverClient::GetInstance().AddStateObserver(telephonyObserver_, -1,
        TelephonyObserverBroker::OBSERVER_MASK_CALL_STATE, true);
    if (observerRes == OHOS::Telephony::TELEPHONY_SUCCESS) {
        ret = true;
        mediaTelephonyListeners_.push_back(telephonyObserver_);
    } else {
        MEDIA_LOGI("InCallObserver Register Listener observer ret:%{public}d", observerRes);
    }
    return ret;
}

void InCallObserver::UnRegisterObserver()
{
    MEDIA_LOGI("UnRegister InCall Listener");
    std::unique_lock<std::mutex> lock(mutex_);
    TelephonyObserverClient::GetInstance().RemoveStateObserver(-1,
        TelephonyObserverBroker::OBSERVER_MASK_CALL_STATE);
    mediaTelephonyListeners_.clear();
}
}
}