/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef PLAYER_SERVICE_PROXY_TEST_H
#define PLAYER_SERVICE_PROXY_TEST_H

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <string>
#include <memory>
#include <vector>
#include <map>
#include "i_standard_player_service.h"
#include "i_standard_player_listener.h"
#include "player_service_proxy.h"

namespace OHOS {
namespace Media {

class MockRemoteObject : public IRemoteObject {
public:
    explicit MockRemoteObject() : IRemoteObject(u"MockRemoteObject") {}
    ~MockRemoteObject() = default;

    MOCK_METHOD(int, SendRequest, (uint32_t code, MessageParcel &data,
        MessageParcel &reply, MessageOption &option), (override));

    MOCK_METHOD(bool, IsProxyObject, (), (override));

    MOCK_METHOD(int32_t, GetRefCount, (), (override));

    MOCK_METHOD(int, Release, (), (override));

    MOCK_METHOD(sptr<IRemoteBroker>, AsInterface, (), (override));

    MOCK_METHOD(bool, Marshalling, (MessageParcel &parcel), (override));

    MOCK_METHOD(void, ExtendObjectInterfaceClassId, (uint16_t classId), (override));

    MOCK_METHOD(int32_t, GetObjectInterfaceClassId, (), (override));

    MOCK_METHOD(const std::u16string, GetObjectDescriptor, (), (override));
};

class PlayerServiceProxyTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void) override
    {
        mockRemote_ = sptr<MockRemoteObject>::MakeRaw();
        proxy_ = new PlayerServiceProxy(mockRemote_);
    }
    void TearDown(void) override
    {
        delete proxy_;
        proxy_ = nullptr;
        mockRemote_ = nullptr;
    }

protected:
    sptr<MockRemoteObject> mockRemote_;
    PlayerServiceProxy *proxy_ = nullptr;
};

} // namespace Media
} // namespace OHOS

#endif // PLAYER_SERVICE_PROXY_TEST_H
