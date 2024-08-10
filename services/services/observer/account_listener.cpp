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

#include "account_listener.h"
#include "account_observer.h"
#include "os_account_manager.h"
#include "media_log.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "AccountListener"};
}


namespace OHOS {
namespace Media {

AccountListener::AccountListener(const AccountSA::OsAccountSubscribeInfo &subscribeInfo)
    : AccountSA::OsAccountSubscriber(subscribeInfo)
{}

AccountListener::~AccountListener() {}

void AccountListener::OnAccountsSwitch(const int &newId, const int &oldId)
{
    MEDIA_LOGI("accounts switch");
    AccountObserver::GetInstance().OnAccountsSwitch();
}

} // namespace Media
} // namespace OHOS