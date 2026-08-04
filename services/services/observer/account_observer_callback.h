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

#ifndef ACCOUNT_OBSERVER_CALLBACK_H
#define ACCOUNT_OBSERVER_CALLBACK_H

#include "screen_capture.h"

namespace OHOS {
namespace Media {

class AccountObserverCallBack {
public:
    virtual ~AccountObserverCallBack() = default;
    virtual bool StopAndRelease(AVScreenCaptureStateCode state) = 0;
    virtual bool NotifyStopAndRelease(AVScreenCaptureStateCode state) = 0;
    virtual void Release() = 0;
};

} // namespace Media
} // namespace OHOS
#endif // ACCOUNT_OBSERVER_CALLBACK_H
