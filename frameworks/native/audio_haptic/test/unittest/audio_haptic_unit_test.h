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

#ifndef AUDIO_HAPTIC_UNIT_TEST_H
#define AUDIO_HAPTIC_UNIT_TEST_H

#include "gtest/gtest.h"

#include "audio_haptic_manager.h"
#include "audio_haptic_player.h"

namespace OHOS {
namespace Media {
class AudioHapticUnitTest : public testing::Test {
public:
    // SetUpTestCase: Called before all test cases
    static void SetUpTestCase(void);
    // TearDownTestCase: Called after all test case
    static void TearDownTestCase(void);
    // SetUp: Called before each test cases
    void SetUp(void);
    // TearDown: Called after each test cases
    void TearDown(void);

    static std::shared_ptr<AudioHapticManager> g_audioHapticManager;
    static int32_t g_sourceId;
    static std::shared_ptr<AudioHapticPlayer> g_audioHapticPlayer;
};
} // namespace Media
} // namespace OHOS
#endif // AUDIO_HAPTIC_UNIT_TEST_H