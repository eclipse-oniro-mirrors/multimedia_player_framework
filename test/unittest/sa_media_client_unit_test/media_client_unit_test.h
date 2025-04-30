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

#ifndef MEDIA_CLIENT_UNIT_TEST_H
#define MEDIA_CLIENT_UNIT_TEST_H

#include "gtest/gtest.h"
#include "i_standard_media_service.h"
#include "i_standard_recorder_service.h"

#ifdef SUPPORT_PLAYER
#undef SUPPORT_PLAYER
#endif
#ifdef SUPPORT_METADATA
#undef SUPPORT_METADATA
#endif
#ifdef SUPPORT_RECORDER
#undef SUPPORT_RECORDER
#endif
#ifdef SUPPORT_SCREEN_CAPTURE
#undef SUPPORT_SCREEN_CAPTURE
#endif
#define SUPPORT_PLAYER
#define SUPPORT_METADATA
#define SUPPORT_SCREEN_CAPTURE
#define SUPPORT_RECORDER
#include "media_client.h"
#undef SUPPORT_RECORDER
#undef SUPPORT_METADATA
#undef SUPPORT_PLAYER
#undef SUPPORT_SCREEN_CAPTURE

namespace OHOS {
namespace Media {
class MediaClientUnitTest : public testing::Test {
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
} // namespace Media
} // namespace OHOS
#endif // MEDIA_CLIENT_UNIT_TEST_H