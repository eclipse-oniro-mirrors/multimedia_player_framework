/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_HDI_LOW_POWER_PLAYER_V1_0_ILOWPOWERPLAYERFACTORY_H
#define OHOS_HDI_LOW_POWER_PLAYER_V1_0_ILOWPOWERPLAYERFACTORY_H

#include <refbase.h>

#include "ilpp_sync_manager_adapter.h"

namespace OHOS {
namespace HDI {
namespace LowPowerPlayer {
namespace V1_0 {
class ILowPowerPlayerFactory : public RefBase {
public:

    ~ILowPowerPlayerFactory()
    {
    }

    static sptr<OHOS::HDI::LowPowerPlayer::V1_0::ILowPowerPlayerFactory> Get(bool isStub = false)
    {
        return sptr<ILowPowerPlayerFactory>::MakeSptr();
    }
    static sptr<OHOS::HDI::LowPowerPlayer::V1_0::ILowPowerPlayerFactory> Get(const std::string &serviceName,
        bool isStub = false)
    {
        return sptr<ILowPowerPlayerFactory>::MakeSptr();
    }

    int32_t CreateSyncMgr(sptr<OHOS::HDI::LowPowerPlayer::V1_0::ILppSyncManagerAdapter>& syncMgrAdapter,
        uint32_t& syncMgrId)
    {
        syncMgrAdapter
            = sptr<OHOS::HDI::LowPowerPlayer::V1_0::ILppSyncManagerAdapter>::MakeSptr();
        syncMgrId = 1;
        return 0;
    }

    int32_t DestroySyncMgr(uint32_t syncMgrId)
    {
        return 0;
    }
};
} // V1_0
} // LowPowerPlayer
} // HDI
} // OHOS

#endif // OHOS_HDI_LOW_POWER_PLAYER_V1_0_ILOWPOWERPLAYERFACTORY_H

