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

#ifndef ACCOUNT_OBSERVER_H
#define ACCOUNT_OBSERVER_H

#include "os_account_subscribe_info.h"
#include "os_account_subscriber.h"
#include "account_listener.h"
#include "screen_capture.h"

namespace OHOS {
namespace Media {
class AccountObserverCallback {
public:
    virtual ~AccountObserverCallback() = default;
    virtual bool StopAndRelease(AVScreenCaptureStateCode state);
};

class AccountObserver {
public:
    static InCallObserver& GetInstance();
    bool RegisterObserver();
    void UnregisterObserver();
    explicit AccountObserver();
    ~AccountObserver();
    bool OnAccountSwitch();
    bool RegisterAccountObserverCallBack(std::weak_ptr<AccountObserverCallBack> callback);
    void UnregisterAccountObserverCallBack
};
} // namespace Media
} // namespace OHOS
#endif // ACCOUNT_OBSERVER_H