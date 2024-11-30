/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
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

#include "account_observer.h"
#include "media_log.h"
#include "media_errors.h"
#include "os_account_manager.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "AccountObserver"};
}
using namespace OHOS;
namespace OHOS {
namespace Media {

AccountObserver& AccountObserver::GetInstance()
{
    static AccountObserver instance;
    instance.Init();
    return instance;
}

AccountObserver::AccountObserver()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

AccountObserver::~AccountObserver()
{
    UnregisterObserver();
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

bool AccountObserver::RegisterAccountObserverCallBack(std::weak_ptr<AccountObserverCallBack> callback)
{
    MEDIA_LOGI("AccountObserver::RegisterAccountObserverCallBack START.");
    std::unique_lock<std::mutex> lock(mutex_);
    auto callbackPtr = callback.lock();
    if (callbackPtr) {
        accountObserverCallBacks_.push_back(callback);
        return true;
    }
    MEDIA_LOGI("0x%{public}06" PRIXPTR "AccountObserver CallBack is null", FAKE_POINTER(this));
    return false;
}

void AccountObserver::UnregisterAccountObserverCallBack(std::weak_ptr<AccountObserverCallBack> callback)
{
    MEDIA_LOGI("AccountObserver::UnregisterAccountObserverCallBack Start.");
    std::unique_lock<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_LOG(callback.lock(), "callback is null");
    for (auto iter = accountObserverCallBacks_.begin(); iter != accountObserverCallBacks_.end();) {
        if ((*iter).lock() == callback.lock()) {
            iter = accountObserverCallBacks_.erase(iter);
        } else {
            iter++;
        }
    }
    MEDIA_LOGI("UnregisterAccountObserverCallBack END. accountObserverCallBacks_.size(): %{public}d",
        static_cast<int32_t>(accountObserverCallBacks_.size()));
}

bool AccountObserver::OnAccountsSwitch()
{
    std::unique_lock<std::mutex> lock(mutex_);
    bool ret = true;
    for (auto accountObserverCallBack : accountObserverCallBacks_) {
        auto callbackPtr = accountObserverCallBack.lock();
        if (callbackPtr) {
            MEDIA_LOGI("0x%{public}06" PRIXPTR " Stop and Release CallBack", FAKE_POINTER(this));
            ret &= callbackPtr->StopAndRelease(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_STOPPED_BY_USER_SWITCHES);
        } else {
            MEDIA_LOGI("0x%{public}06" PRIXPTR "AccountObserver CallBack is null", FAKE_POINTER(this));
        }
    }
    return ret;
}

bool AccountObserver::Init()
{
    if (isAccountListenerDied_.load()) {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " AccountObserver Init, Register Observer", FAKE_POINTER(this));
        UnregisterObserver();
        if (RegisterObserver()) {
            isAccountListenerDied_.store(false);
        }
    } else {
        MEDIA_LOGI("AccountObserver exist : %{public}d", isAccountListenerDied_.load());
    }
    return true;
}

bool AccountObserver::RegisterObserver()
{
    MEDIA_LOGI("AccountObserver Register");
    std::unique_lock<std::mutex> lock(mutex_);
    AccountSA::OsAccountSubscribeInfo osAccountSubscribeInfo;
    osAccountSubscribeInfo.SetOsAccountSubscribeType(AccountSA::OS_ACCOUNT_SUBSCRIBE_TYPE::SWITCHED);
    osAccountSubscribeInfo.SetName("ScreenCaptureAccountSubscriber");
    accountListener_ = std::make_shared<AccountListener>(osAccountSubscribeInfo);
    if (accountListener_ == nullptr) {
        MEDIA_LOGE("make AccountListener failed");
        return false;
    }
    ErrCode errCode = AccountSA::OsAccountManager::SubscribeOsAccount(accountListener_);
    CHECK_AND_RETURN_RET_LOG(errCode == ERR_OK, false, "subscribe failed, error code: %{public}d", errCode);

    return true;
}

void AccountObserver::UnregisterObserver()
{
    MEDIA_LOGI("AccountObserver Unregister");
    std::unique_lock<std::mutex> lock(mutex_);
    if (accountListener_) {
        AccountSA::OsAccountManager::UnsubscribeOsAccount(accountListener_);
    }
    isAccountListenerDied_.store(true);
}
} // namespace Media
} // namespace OHOS