/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "monitor_server_object.h"
#include "media_log.h"
#include "media_errors.h"
#include "monitor_server.h"
namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN, "MonitorServerObject"};
}

namespace OHOS {
namespace Media {
int32_t MonitorServerObject::RegisterMonitor(int32_t pid)
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Pid %{public}d RegisterMonitor", FAKE_POINTER(this), pid);
    std::lock_guard<std::mutex> lock(monitorMutex_);
    return MonitorServer::GetInstance().RegisterObj(pid, wptr(this));
}

int32_t MonitorServerObject::CancellationMonitor(int32_t pid)
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Pid %{public}d CancellationMonitor", FAKE_POINTER(this), pid);
    std::lock_guard<std::mutex> lock(monitorMutex_);
    return MonitorServer::GetInstance().CancellationObj(pid, wptr(this));
}

int32_t MonitorServerObject::IpcAbnormality()
{
    std::lock_guard<std::mutex> lock(monitorMutex_);
    if (alarmed_) {
        return MSERR_OK;
    }

    MEDIA_LOGE("IpcAbnormality");
    if (DoIpcAbnormality() == MSERR_OK) {
        alarmed_ = true;
    }
    return MSERR_OK;
}

int32_t MonitorServerObject::IpcRecovery(bool fromMonitor)
{
    std::lock_guard<std::mutex> lock(monitorMutex_);
    if (!alarmed_) {
        return MSERR_OK;
    }

    MEDIA_LOGE("IpcRecovery %{public}d ", fromMonitor);
    if (DoIpcRecovery(fromMonitor) == MSERR_OK) {
        alarmed_ = false;
    }
    return MSERR_OK;
}
} // namespace Media
} // namespace OHOS