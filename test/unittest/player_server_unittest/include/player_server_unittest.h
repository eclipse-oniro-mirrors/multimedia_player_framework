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

#ifndef PLAYER_UNITTEST_H
#define PLAYER_UNITTEST_H

#include "gtest/gtest.h"
#include "player_server_mock.h"
#include "window.h"

namespace OHOS {
namespace Media {

struct ErrorScenario {
    PlayerErrorType type;
    int32_t code;
    std::string expectedPrefix;
};

class PlayerServerTestAccessor : public PlayerServer {
public:
    inline int32_t Init() override
    {
        return PlayerServer::Init();
    }
    inline int32_t InitTaskMgr()
    {
        return taskMgr_.Init();
    }
};
class PlayerServerUnitTest : public testing::Test {
public:
    // SetUpTestCase: Called before all test cases
    static void SetUpTestCase(void);
    // TearDownTestCase: Called after all test case
    static void TearDownTestCase(void);
    // SetUp: Called before each test cases
    void SetUp(void);
    // TearDown: Called after each test cases
    void TearDown(void);
protected:
    std::shared_ptr<PlayerServerMock> player_ = nullptr;
    std::shared_ptr<PlayerCallbackTest> callback_ = nullptr;
    void PlayFunTest(const std::string &protocol = PlayerTestParam::LOCAL_PLAY);
    void GetSetParaFunTest();
    void MediaServiceErrCodeTest(MediaServiceErrCode code);
    void MediaServiceExtErrCodeAPI9Test(MediaServiceExtErrCodeAPI9 code);
};
} // namespace Media
} // namespace OHOS

#endif