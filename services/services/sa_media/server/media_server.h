/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef MEDIA_SERVER_H
#define MEDIA_SERVER_H

#include "media_service_stub.h"
#include "system_ability.h"
#include "nocopyable.h"
#ifdef SUPPORT_START_STOP_ON_DEMAND
#ifdef CROSS_PLATFORM
#inlcude <fstream>
#include "nlohmann/json.hpp"
#endif
#endif

namespace OHOS {
namespace Media {
class __attribute__((visibility("default"))) MediaServer : public SystemAbility, public MediaServiceStub {
    DECLARE_SYSTEM_ABILITY(MediaServer);
public:
    explicit MediaServer(int32_t systemAbilityId, bool runOnCreate = true);
    ~MediaServer();

    int32_t FreezeStubForPids(const std::set<int32_t> &pidList, bool isProxy) override;

    int32_t ResetAllProxy() override;

    // IStandardMediaService override
    sptr<IRemoteObject> GetSubSystemAbility(IStandardMediaService::MediaSystemAbility subSystemId,
        const sptr<IRemoteObject> &listener) override;
    sptr<IRemoteObject> GetSubSystemAbilityWithTimeOut(IStandardMediaService::MediaSystemAbility subSystemId,
        const sptr<IRemoteObject> &listener, uint32_t timeoutMs) override;
    
    bool CanKillMediaService() override;

protected:
    // SystemAbility override
    void OnDump() override;
    void OnStart() override;
    void OnStop() override;
#ifdef SUPPORT_START_STOP_ON_DEMAND
    int32_t OnIdle(const SystemAbilityOnDemandReason& idleReason) override;
    int32_t GetUnloadDelayTime();
#endif
    int32_t Dump(int32_t fd, const std::vector<std::u16string>& args) override;

private:
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;
    sptr<IRemoteObject> GetSubSystemAbilityPart(IStandardMediaService::MediaSystemAbility subSystemId);
#ifdef SUPPORT_START_STOP_ON_DEMAND
    int32_t unloadDelayTime_ {-1};
#endif
};
} // namespace Media
} // namespace OHOS
#endif // MEDIA_SERVER_H
