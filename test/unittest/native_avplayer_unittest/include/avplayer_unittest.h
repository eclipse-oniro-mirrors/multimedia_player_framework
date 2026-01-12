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
#ifndef AVPLAYER_UNITTEST_H
#define AVPLAYER_UNITTEST_H

#include "gtest/gtest.h"
#include "avplayer.h"
#include "avplayer_base.h"
#include "media_source.h"
#include <condition_variable>
#include <mutex>
#include <thread>

class AVPlayerUnitTest : public testing::Test {
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

class AVPlayerMp4UnitTest : public testing::Test {
public:
    // SetUpTestCase: Called before all test cases
    static void SetUpTestCase(void);
    // TearDownTestCase: Called after all test case
    static void TearDownTestCase(void);
    // SetUp: Called before each test cases
    void SetUp(void);
    // TearDown: Called after each test cases
    void TearDown(void);

    // Wait for player to reach target state within timeoutMs milliseconds
    void WaitForStateWithCV(AVPlayerState targetState, int32_t timeoutMs);
    // Callback function for player info events
    static void OnInfoCallback(OH_AVPlayer *player, AVPlayerOnInfoType type, OH_AVFormat* infoBody, void *userData)
    {
        auto *test = static_cast<AVPlayerMp4UnitTest*>(userData);
        if (type == AV_INFO_TYPE_STATE_CHANGE) {
            int32_t state;
            OH_AVFormat_GetIntValue(infoBody, OH_PLAYER_STATE, &state);

            std::lock_guard<std::mutex> lock(test->mutex_);
            test->currentState_ = static_cast<AVPlayerState>(state);
            test->cv_.notify_all();
        }
    }
protected:
    OH_AVPlayer *player_ = nullptr;
private:
    std::mutex mutex_;
    std::condition_variable cv_;
    AVPlayerState currentState_ = AV_IDLE;
};

#endif // AVPLAYER_UNITTEST_H