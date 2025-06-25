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

#ifndef MEDIA_SERVER_MANAGER_UNITTEST_H
#define MEDIA_SERVER_MANAGER_UNITTEST_H

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "mock/avmetadatahelper_service_stub.h"
#include "mock/player_service_stub.h"
#include "mock/recorder_service_stub.h"
#include "mock/recorder_profiles_service_stub.h"
#include "mock/screen_capture_controller_stub.h"
#include "mock/screen_capture_service_stub.h"
#include "mock/transcoder_service_stub.h"
#include "media_server_manager.h"

namespace OHOS {
namespace Media {
class MediaServerManagerUnitTest : public testing::Test {
public:
    // SetUpTestCase: Called before all test cases
    static void SetUpTestCase(void);
    // TearDownTestCase: Called after all test case
    static void TearDownTestCase(void);
    // SetUp: Called before each test cases
    void SetUp(void);
    // TearDown: Called after each test cases
    void TearDown(void);
};

class MockTask : public Task {
public:
    explicit MockTask(const std::string& name, const std::string& groupId = "", TaskType type = TaskType::SINGLETON,
        TaskPriority priority = TaskPriority::NORMAL, bool singleLoop = true):Task(name, groupId, type,
        priority, singleLoop) {}
    MOCK_METHOD(bool, IsTaskRunning, (), (override));
};
} // namespace Media
} // namespace OHOS
#endif // MEDIA_SERVER_MANAGER_UNITTEST_H