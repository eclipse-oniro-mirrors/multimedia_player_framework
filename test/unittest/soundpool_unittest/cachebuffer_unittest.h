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

#ifndef SOUNDPOOL_CACHEBUFFER_UNITTEST_H
#define SOUNDPOOL_CACHEBUFFER_UNITTEST_H

#include <gmock/gmock.h>

#include "audio_stream.h"
#include "gtest/gtest.h"
#include "stream_unittest.h"

namespace OHOS {
namespace Media {
class SoundPoolCacheBufferUnitTest  : public testing::Test {
public:
    // SetUpTestCase: Called before all test cases
    static void SetUpTestCase(void);
    // TearDownTestCase: Called after all test case
    static void TearDownTestCase(void);
    // SetUp: Called before each test cases
    void SetUp(void);
    // TearDown: Called after each test cases
    void TearDown(void);

    std::shared_ptr<AudioStream> cacheBuffer_;
};
} // namespace Media
} // namespace OHOS
#endif // SOUNDPOOL_CACHEBUFFER_UNITTEST_H
