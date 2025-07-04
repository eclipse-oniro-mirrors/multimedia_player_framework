/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "media_service_helper.h"
#include "media_log.h"
#include "common/log.h"
#include "i_media_service.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SYSTEM_PLAYER, "MediaServiceHelper"};
}

namespace OHOS {
namespace Media {
bool MediaServiceHelper::CanKillMediaService()
{
    bool canKill = MediaServiceFactory::GetInstance().CanKillMediaService();
    MEDIA_LOGW("media service can be killed = %{public}d", canKill);
    return canKill;
}

int32_t MediaServiceHelper::ProxyForFreeze(const std::set<int32_t> &pidList, bool isProxy)
{
    return MediaServiceFactory::GetInstance().ProxyForFreeze(pidList, isProxy);
}

int32_t MediaServiceHelper::ResetAllProxy()
{
    return MediaServiceFactory::GetInstance().ResetAllProxy();
}
} // namespace Media
} // namespace OHOS