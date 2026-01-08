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

#ifndef SCREEN_CAPTURE_CONTROLLER_STUB_H
#define SCREEN_CAPTURE_CONTROLLER_STUB_H

#include <map>
#include <gmock/gmock.h>
#include "i_standard_screen_capture_controller.h"
#include "screen_capture_controller_server.h"
#include "media_death_recipient.h"

namespace OHOS {
namespace Media {
class ScreenCaptureControllerStub : public IRemoteStub<IStandardScreenCaptureController>, public NoCopyable {
public:
    static sptr<ScreenCaptureControllerStub> Create()
    {
        sptr<ScreenCaptureControllerStub> screenCaptureStub = new(std::nothrow) ScreenCaptureControllerStub();
        return screenCaptureStub;
    }
    virtual ~ScreenCaptureControllerStub() = default;

    MOCK_METHOD(int32_t, ReportAVScreenCaptureUserChoice, (int32_t sessionId, std::string choice), (override));
    MOCK_METHOD(int32_t, GetAVScreenCaptureConfigurableParameters,
        (int32_t sessionId, std::string &resultStr), (override));
    MOCK_METHOD(int32_t, DestroyStub, (), (override));
    MOCK_METHOD(int, OnRemoteRequest, (uint32_t code, MessageParcel &data,
        MessageParcel &reply, MessageOption &option), (override));
    MOCK_METHOD(int32_t, ReportAVScreenCaptureUserChoiceInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, GetAVScreenCaptureConfigurableParametersInner, (MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD(int32_t, DestroyStubInner, (MessageParcel &data, MessageParcel &reply));
};
} // namespace Media
} // namespace OHOS
#endif // SCREEN_CAPTURE_CONTROLLER_STUB_H