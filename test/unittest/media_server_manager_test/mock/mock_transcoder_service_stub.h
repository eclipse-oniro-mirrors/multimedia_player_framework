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

#ifndef MOCK_TRANSCODER_SERVICE_STUB_H
#define MOCK_TRANSCODER_SERVICE_STUB_H

#include "avbuffer_queue.h"
#include "gmock/gmock.h"
#include "transcoder_service_stub.h"

namespace OHOS {
namespace Media {

class MockTransCoderServiceStub : public TransCoderServiceStub {
public:
    class MockIRemoteObject : public IRemoteObject {
    public:
        virtual ~MockIRemoteObject() = default;
        int32_t GetObjectRefCount() override
        {
            return 0;
        }
        int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
        {
            return 0;
        }
        bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) override
        {
            return true;
        }
        bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) override
        {
            return true;
        }
        int Dump(int fd, const std::vector<std::u16string> &args) override
        {
            return 0;
        }
    };
    MockTransCoderServiceStub() = default;
    ~MockTransCoderServiceStub() override = default;
    sptr<IRemoteObject> AsObject() override
    {
        return new MockIRemoteObject();
    }

    MOCK_METHOD(sptr<TransCoderServiceStub>, GetInstance, (), ());
};

} // namespace Media
} // namespace OHOS

#endif // MOCK_TRANSCODER_SERVICE_STUB_H
  