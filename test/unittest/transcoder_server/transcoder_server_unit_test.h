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

#ifndef TRANSCODER_UNIT_TEST_H
#define TRANSCODER_UNIT_TEST_H

#include "gtest/gtest.h"
#include "transcoder_server.h"

namespace OHOS {
namespace Media {
class TransCoderUnitTest : public testing::Test {
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
    std::shared_ptr<ITransCoderService> transcoder_ = nullptr;
};

class TransCoderCallbackTest : public TransCoderCallback, public NoCopyable {
public:
    ~TransCoderCallbackTest() {}
    void OnError(int32_t errorCode, const std::string &errorMsg) override;
    void OnInfo(int32_t type, int32_t extra) override;
    TransCoderServer::RecStatus status_ = TransCoderServer::REC_INITIALIZED;
    bool CheckStateChange();
};
} // namespace Media
} // namespace OHOS

#endif