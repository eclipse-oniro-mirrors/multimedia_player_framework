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
#ifndef NATIVE_AVTRANSCODER_UNIT_TEST_H
#define NATIVE_AVTRANSCODER_UNIT_TEST_H

#include "gtest/gtest.h"
#include "avtranscoder.h"

struct MockUserData {
    OH_AVTranscoder_State state_ = OH_AVTranscoder_State::AVTRANSCODER_CANCELLED;
};

class NativeAVTranscoderUnitTest : public testing::Test {
public:
    // SetUpTestCase: Called before all test cases
    static void SetUpTestCase(void);
    // TearDownTestCase: Called after all test case
    static void TearDownTestCase(void);
    // SetUp: Called before each test cases
    void SetUp(void);
    // TearDown: Called after each test cases
    void TearDown(void);

    void InitAVTranscoderCallback(OH_AVTranscoder* transcoder, MockUserData& mockUserData);
    void InitAVTranscoderConfig(OH_AVTranscoder_Config* config, int32_t srcFd, int32_t dstFd);
};

#endif // NATIVE_AVTRANSCODER_UNIT_TEST_H