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

#ifndef SOUNDPOOL_STREAM_UNITTEST_H
#define SOUNDPOOL_STREAM_UNITTEST_H

#include "gtest/gtest.h"
#include "stream.h"
#include "mock_audiorenderer.h"

namespace OHOS {
namespace Media {
class SoundPoolStreamUnitTest  : public testing::Test {
public:
    // SetUpTestCase: Called before all test cases
    static void SetUpTestCase(void);
    // TearDownTestCase: Called after all test case
    static void TearDownTestCase(void);
    // SetUp: Called before each test cases
    void SetUp(void);
    // TearDown: Called after each test cases
    void TearDown(void);

    std::shared_ptr<Stream> stream_;
};
class MockISoundPoolCallback : public ISoundPoolCallback {
public:
    MOCK_METHOD(void, OnLoadCompleted, (int32_t soundId), ());
    MOCK_METHOD(void, OnPlayFinished, (int32_t streamID), ());
    MOCK_METHOD(void, OnError, (int32_t errorCode), ());
};
} // namespace Media
} // namespace OHOS
#endif // SOUNDPOOL_STREAM_UNITTEST_H
