/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef RELIABILITY_XCOLLIE_H
#define RELIABILITY_XCOLLIE_H
#include <string>
#include "gmock/gmock.h"
#include "singleton.h"
#include "xcollie/xcollie_define.h"

using XCollieCallback = std::function<void (void *)>;
namespace OHOS {
namespace HiviewDFX {
class XCollie : public Singleton<XCollie> {
    DECLARE_SINGLETON(XCollie);
public:
    MOCK_METHOD5(SetTimer, int(const std::string &, unsigned int, XCollieCallback, void *, unsigned int));
    MOCK_METHOD1(CancelTimer, void(int));
    MOCK_METHOD3(SetTimerCount, int(const std::string &, unsigned int, int));
    MOCK_METHOD3(TriggerTimerCount, void(const std::string &, bool, const std::string &));
};
} // end of namespace HiviewDFX
} // end of namespace OHOS
#endif

