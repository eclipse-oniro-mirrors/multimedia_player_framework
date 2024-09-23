/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "monitorservicestub_fuzzer.h"
#include <cmath>
#include <iostream>
#include "string_ex.h"
#include "directory_ex.h"
#include <unistd.h>
#include "media_server.h"
#include "media_parcel.h"
#include "i_standard_monitor_service.h"
#include "stub_common.h"

using namespace std;
using namespace OHOS;
using namespace Media;

namespace OHOS {
namespace Media {
MonitorServiceStubFuzzer::MonitorServiceStubFuzzer()
{
}

MonitorServiceStubFuzzer::~MonitorServiceStubFuzzer()
{
}

const int32_t SYSTEM_ABILITY_ID = 3002;
const bool RUN_ON_CREATE = false;
bool MonitorServiceStubFuzzer::FuzzMonitorOnRemoteRequest(uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return true;
    }
    std::shared_ptr<MediaServer> mediaServer =
        std::make_shared<MediaServer>(SYSTEM_ABILITY_ID, RUN_ON_CREATE);
    sptr<IRemoteObject> listener = new(std::nothrow) MediaListenerStubFuzzer();
    sptr<IRemoteObject> monitor = mediaServer->GetSubSystemAbility(
        IStandardMediaService::MediaSystemAbility::MEDIA_MONITOR, listener);
    if (monitor == nullptr) {
        return false;
    }

    sptr<IRemoteStub<IStandardMonitorService>> monitorStub =
        iface_cast<IRemoteStub<IStandardMonitorService>>(monitor);
    if (monitorStub == nullptr) {
        return false;
    }

    const int maxIpcNum = 10;
    for (uint32_t code = 0; code <= maxIpcNum; code++) {
        MessageParcel msg;
        msg.WriteInterfaceToken(monitorStub->GetDescriptor());
        msg.WriteBuffer(data, size);
        msg.RewindRead(0);
        MessageParcel reply;
        MessageOption option;
        monitorStub->OnRemoteRequest(code, msg, reply, option);
    }

    return true;
}
}

bool FuzzTestMonitorOnRemoteRequest(uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return true;
    }

    if (size < sizeof(int32_t)) {
        return true;
    }
    MonitorServiceStubFuzzer testMonitor;
    return testMonitor.FuzzMonitorOnRemoteRequest(data, size);
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzTestMonitorOnRemoteRequest(data, size);
    return 0;
}