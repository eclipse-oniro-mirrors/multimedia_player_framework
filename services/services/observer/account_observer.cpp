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
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "AccountObserver"};
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
    std::unique_lock<std::mutex> lock(mutex_);
    auto callbackPtr = callback.lock();
    if (callbackPtr) {
        accountObserverCallBack_ = callback;
        return true;
    } else {
        MEDIA_LOGI("0x%{public}06" PRIXPTR "AccountObserver CallBack is null", FAKE_POINTER(this));
    }
    return false;
}

void AccountObserver::UnRegisterAccountObserverCallBack()
{
    if (!accountObserverCallBack_.expired()) {
        accountObserverCallBack_.reset();
    }
}

bool AccountObserver::OnAccountsSwitch()
{
    std::unique_lock<std::mutex> lock(mutex_);
    auto callbackPtr = accountObserverCallBack_.lock();
    if (callbackPtr) {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " Stop and Release CallBack", FAKE_POINTER(this));
        return callbackPtr->StopAndRelease(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_STOPPED_BY_CALL);
    } else {
        MEDIA_LOGI("0x%{public}06" PRIXPTR "AccountObserver CallBack is null", FAKE_POINTER(this));
    }
    return true;
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
    CHECK_AND_RETURN_RET_LOG(errCode == ERR_OK, false, "subscribe failed, error code: %{public}d", errcode);

    return true;
}

void AccountObserver::UnregisterObserver()
{
    MEDIA_LOGI("AccountObserver Unregister");
    std::unique_lock<std::mutex> lock(mutex_);
    if (accountListener_) {
        AccountSA::OsAccountManager::UnsubscribeOsAccount(accountListener_);
        accountListener_ = nullptr;
    }
    isAccountListenerDied_.store(true);
}
} // namespace Media
} // namespace OHOS