/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef MONITOR_SERVER_OBJECT_UNITTEST_H
#define MONITOR_SERVER_OBJECT_UNITTEST_H

#include "gtest/gtest.h"
#include "monitor_server_object.h"

namespace OHOS {
namespace Media {
constexpr const int32_t NUM_1 = 1;

class TestMonitorServerObject;

class MonitorServerObjectUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);

    std::shared_ptr<TestMonitorServerObject> object_ {nullptr};
};

class TestMonitorServerObject : public MonitorServerObject {
public:
    int32_t DoIpcAbnormality() override
    {
        return NUM_1;
    }
    int32_t DoIpcRecovery(bool fromMonitor) override
    {
        return NUM_1;
    }
};

} // namespace Media
} // namespace OHOS
#endif // MONITOR_SERVER_OBJECT_UNITTEST_H