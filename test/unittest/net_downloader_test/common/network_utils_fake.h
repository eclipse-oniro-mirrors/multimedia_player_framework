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

#ifndef NETWORK_UTILS_FAKE_H
#define NETWORK_UTILS_FAKE_H

#include "network_utils.h"

namespace OHOS {
namespace Media {
namespace MediaSourceUtils {

void SetFakeNetworkType(NetConnType type);
NetConnType GetFakeNetworkType();
void ResetFakeNetworkType();

class FakeNetworkTypeGuard {
public:
    explicit FakeNetworkTypeGuard(NetConnType type) : prev_(GetFakeNetworkType())
    {
        SetFakeNetworkType(type);
    }
    ~FakeNetworkTypeGuard()
    {
        SetFakeNetworkType(prev_);
    }

private:
    NetConnType prev_;
};

} // namespace MediaSourceUtils
} // namespace Media
} // namespace OHOS

#endif // NETWORK_UTILS_FAKE_H
