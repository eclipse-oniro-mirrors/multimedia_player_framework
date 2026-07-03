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

#ifndef PLAYER_LISTENER_TEST_H
#define PLAYER_LISTENER_TEST_H

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <string>
#include <memory>
#include <vector>
#include "i_standard_player_listener.h"

namespace OHOS {
namespace Media {

class MockIStandardPlayerListener : public IStandardPlayerListener {
public:
    MOCK_METHOD(void, OnError, (PlayerErrorType errorType, int32_t errorCode), (override));
    MOCK_METHOD(void, OnError, (int32_t errorCode, const std::string &errorMsg), (override));
    MOCK_METHOD(void, OnInfo, (PlayerOnInfoType type, int32_t extra, const Format &infoBody), (override));
    MOCK_METHOD(void, SetFreezeFlag, (bool isFrozen), (override));
    MOCK_METHOD(void, SetInterruptListenerFlag, (bool isRegistered), (override));
};

class PlayerListenerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void) {}
    void TearDown(void) {}

protected:
    std::shared_ptr<MockIStandardPlayerListener> mockListener_;
};

} // namespace Media
} // namespace OHOS

#endif // PLAYER_LISTENER_TEST_H
