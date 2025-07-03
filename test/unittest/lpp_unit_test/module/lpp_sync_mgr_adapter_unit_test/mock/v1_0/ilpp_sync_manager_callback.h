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

#ifndef OHOS_HDI_LOW_POWER_PLAYER_V1_0_ILPPSYNCMANAGERCALLBACK_H
#define OHOS_HDI_LOW_POWER_PLAYER_V1_0_ILPPSYNCMANAGERCALLBACK_H

#include <refbase.h>
#include <stdint.h>
#include <string>

namespace OHOS {
namespace HDI {
namespace LowPowerPlayer {
namespace V1_0 {

class ILppSyncManagerCallback : public RefBase {
public:

    virtual ~ILppSyncManagerCallback() = default;

    virtual int32_t OnError(int32_t errorCode, const std::string& errorMsg) = 0;

    virtual int32_t OnTargetArrived(int64_t targetPts, bool isTimeout) = 0;

    virtual int32_t OnRenderStarted() = 0;

    virtual int32_t OnEos() = 0;

    virtual int32_t OnFirstFrameReady() = 0;

    virtual int32_t OnInfo(int32_t infoCode, const std::string& infoMsg) = 0;
};
} // V1_0
} // LowPowerPlayer
} // HDI
} // OHOS

#endif // OHOS_HDI_LOW_POWER_PLAYER_V1_0_ILPPSYNCMANAGERCALLBACK_H

