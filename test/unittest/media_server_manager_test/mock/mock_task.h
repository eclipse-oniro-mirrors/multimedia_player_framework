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

#ifndef MOCK_TASK_H
#define MOCK_TASK_H

#include "osal/task/task.h"
#include "media_server_manager.h"
#include "media_service_stub.h"
#include "gmock/gmock.h"

namespace OHOS {
namespace Media {
class MockTask : public Task {
public:
    explicit MockTask(const char* taskName)
        : Task(std::string(taskName))
    {}
    ~MockTask() override {};
    MOCK_METHOD(bool, IsTaskRunning, (), ());
};

class MockMediaServiceStub : public MediaServiceStub {
public:
    explicit MockMediaServiceStub() {};
    ~MockMediaServiceStub() override {};
    sptr<IRemoteObject> GetSubSystemAbility(MediaSystemAbility subSystemId,
        const sptr<IRemoteObject>& listener) override
    {
        return nullptr;
    }
    sptr<IRemoteObject> GetSubSystemAbilityWithTimeOut(MediaSystemAbility subSystemId,
        const sptr<IRemoteObject>& listener, uint32_t timeoutMs) override
    {
        return nullptr;
    }
    MOCK_METHOD(void, ReleaseClientListener, (), (override));
    MOCK_METHOD(bool, CanKillMediaService, (), (override));
    MOCK_METHOD(int32_t, SetDeathListener, (const sptr<IRemoteObject> &object), ());
};
class MockMediaServerManager : public MediaServerManager {
public:
    explicit MockMediaServerManager() {};
    ~MockMediaServerManager() override {};
    MOCK_METHOD(sptr<IRemoteObject>, CreateRecorderStubObject, (), ());
};
} // namespace Media
} // namespace OHOS
#endif
