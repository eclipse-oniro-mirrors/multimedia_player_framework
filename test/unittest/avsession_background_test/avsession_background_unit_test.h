/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
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

#ifndef AVSESSION_BACKGROUND_UNIT_TEST_H
#define AVSESSION_BACKGROUND_UNIT_TEST_H

#include "gtest/gtest.h"
#include "avsession_background.h"

namespace OHOS {
namespace Media {
namespace Test {
class AVsessionBackgroundUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);
};
} // namespace Test
} // namespace Media
} // namespace OHOS
#endif // AVSESSION_BACKGROUND_UNIT_TEST_H
