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

#include "screencaptureservicestub_fuzzer.h"
#include <cmath>
#include <iostream>
#include "string_ex.h"
#include "directory_ex.h"
#include <unistd.h>
#include "media_server.h"
#include "media_parcel.h"
#include "i_standard_screen_capture_service.h"
#include "stub_common.h"

using namespace std;
using namespace OHOS;
using namespace Media;

namespace OHOS {
namespace Media {
ScreenCaptureServiceStubFuzzer::ScreenCaptureServiceStubFuzzer()
{
}

ScreenCaptureServiceStubFuzzer::~ScreenCaptureServiceStubFuzzer()
{
}

const int32_t SYSTEM_ABILITY_ID = 3002;
const bool RUN_ON_CREATE = false;
bool ScreenCaptureServiceStubFuzzer::FuzzScreenCaptureOnRemoteRequest(uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return true;
    }
    std::shared_ptr<MediaServer> mediaServer =
        std::make_shared<MediaServer>(SYSTEM_ABILITY_ID, RUN_ON_CREATE);
    sptr<IRemoteObject> listener = new(std::nothrow) MediaListenerStubFuzzer();
    sptr<IRemoteObject> screencapture = mediaServer->GetSubSystemAbility(
        IStandardMediaService::MediaSystemAbility::MEDIA_SCREEN_CAPTURE, listener);
    if (screencapture == nullptr) {
        return false;
    }

    sptr<IRemoteStub<IStandardScreenCaptureService>> screencaptureStub =
        iface_cast<IRemoteStub<IStandardScreenCaptureService>>(screencapture);
    if (screencaptureStub == nullptr) {
        return false;
    }

    const int maxIpcNum = 32;
    bool isWirteToken = size > 0 && data[0] % 9 != 0;
    for (uint32_t code = 0; code <= maxIpcNum; code++) {
        MessageParcel msg;
        if (isWirteToken) {
            msg.WriteInterfaceToken(screencaptureStub->GetDescriptor());
        }
        msg.WriteBuffer(data, size);
        msg.RewindRead(0);
        MessageParcel reply;
        MessageOption option;
        screencaptureStub->OnRemoteRequest(code, msg, reply, option);
    }

    return true;
}
}

bool FuzzTestScreenCaptureOnRemoteRequest(uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return true;
    }

    if (size < sizeof(int32_t)) {
        return true;
    }
    ScreenCaptureServiceStubFuzzer testScreenCapture;
    return testScreenCapture.FuzzScreenCaptureOnRemoteRequest(data, size);
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzTestScreenCaptureOnRemoteRequest(data, size);
    return 0;
}
