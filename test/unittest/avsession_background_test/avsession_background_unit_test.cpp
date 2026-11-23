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

#include "avsession_background_unit_test.h"
#include <memory>
#include "player.h"
#include "player_server.h"

namespace OHOS {
namespace Media {
namespace Test {
using namespace std;
using namespace testing::ext;

namespace {
constexpr int32_t TEST_UID_1 = 999991;
constexpr int32_t TEST_UID_2 = 999992;
constexpr int32_t TEST_UID_NONEXISTENT = 999999;
} // namespace

void AVsessionBackgroundUnitTest::SetUpTestCase(void) {}

void AVsessionBackgroundUnitTest::TearDownTestCase(void) {}

void AVsessionBackgroundUnitTest::SetUp(void)
{
    std::lock_guard<std::mutex> lock(AVsessionBackground::Instance().mutex_);
    AVsessionBackground::Instance().playerMap_.clear();
}

void AVsessionBackgroundUnitTest::TearDown(void)
{
    std::lock_guard<std::mutex> lock(AVsessionBackground::Instance().mutex_);
    AVsessionBackground::Instance().playerMap_.clear();
}

/**
 * @tc.name  : AVsessionBackground_Instance_001
 * @tc.number: AVsessionBackground_Instance_001
 * @tc.desc  : Test Instance returns the same singleton reference
 */
HWTEST_F(AVsessionBackgroundUnitTest, AVsessionBackground_Instance_001, TestSize.Level1)
{
    AVsessionBackground &inst1 = AVsessionBackground::Instance();
    AVsessionBackground &inst2 = AVsessionBackground::Instance();
    EXPECT_EQ(&inst1, &inst2);
}

/**
 * @tc.name  : AVsessionBackground_Init_001
 * @tc.number: AVsessionBackground_Init_001
 * @tc.desc  : Test Init skips registration when already initialized
 */
HWTEST_F(AVsessionBackgroundUnitTest, AVsessionBackground_Init_001, TestSize.Level1)
{
    AVsessionBackground &instance = AVsessionBackground::Instance();
    bool savedInit = instance.init_;
    instance.init_ = true;
    instance.Init();
    EXPECT_TRUE(instance.init_);
    instance.init_ = false;
    instance.Init();
    instance.init_ = savedInit;
}

/**
 * @tc.name  : AVsessionBackground_AddListener_001
 * @tc.number: AVsessionBackground_AddListener_001
 * @tc.desc  : Test AddListener adds single and multiple players for same uid
 */
HWTEST_F(AVsessionBackgroundUnitTest, AVsessionBackground_AddListener_001, TestSize.Level1)
{
    auto player1 = PlayerServer::Create();
    ASSERT_NE(player1, nullptr);
    auto player2 = PlayerServer::Create();
    ASSERT_NE(player2, nullptr);

    AVsessionBackground::Instance().AddListener(player1, TEST_UID_1);
    {
        auto it = AVsessionBackground::Instance().playerMap_.find(TEST_UID_1);
        ASSERT_NE(it, AVsessionBackground::Instance().playerMap_.end());
        EXPECT_EQ(it->second.size(), 1U);
    }

    AVsessionBackground::Instance().AddListener(player2, TEST_UID_1);
    {
        auto it = AVsessionBackground::Instance().playerMap_.find(TEST_UID_1);
        ASSERT_NE(it, AVsessionBackground::Instance().playerMap_.end());
        EXPECT_EQ(it->second.size(), 2U);
    }
}

/**
 * @tc.name  : AVsessionBackground_AddListener_002
 * @tc.number: AVsessionBackground_AddListener_002
 * @tc.desc  : Test AddListener cleans expired weak_ptr entries in same uid list
 */
HWTEST_F(AVsessionBackgroundUnitTest, AVsessionBackground_AddListener_002, TestSize.Level1)
{
    auto player1 = PlayerServer::Create();
    ASSERT_NE(player1, nullptr);
    AVsessionBackground::Instance().AddListener(player1, TEST_UID_1);
    player1.reset();

    auto player2 = PlayerServer::Create();
    ASSERT_NE(player2, nullptr);
    AVsessionBackground::Instance().AddListener(player2, TEST_UID_1);

    auto it = AVsessionBackground::Instance().playerMap_.find(TEST_UID_1);
    ASSERT_NE(it, AVsessionBackground::Instance().playerMap_.end());
    EXPECT_EQ(it->second.size(), 1U);
    EXPECT_EQ(it->second.front().lock(), player2);
}

/**
 * @tc.name  : AVsessionBackground_AddListener_003
 * @tc.number: AVsessionBackground_AddListener_003
 * @tc.desc  : Test AddListener erases uid key when all weak_ptrs for that uid expire
 */
HWTEST_F(AVsessionBackgroundUnitTest, AVsessionBackground_AddListener_003, TestSize.Level1)
{
    auto player1 = PlayerServer::Create();
    ASSERT_NE(player1, nullptr);
    AVsessionBackground::Instance().AddListener(player1, TEST_UID_1);
    player1.reset();

    auto player2 = PlayerServer::Create();
    ASSERT_NE(player2, nullptr);
    AVsessionBackground::Instance().AddListener(player2, TEST_UID_2);

    EXPECT_EQ(AVsessionBackground::Instance().playerMap_.find(TEST_UID_1),
        AVsessionBackground::Instance().playerMap_.end());
    auto it = AVsessionBackground::Instance().playerMap_.find(TEST_UID_2);
    ASSERT_NE(it, AVsessionBackground::Instance().playerMap_.end());
    EXPECT_EQ(it->second.size(), 1U);
}

/**
 * @tc.name  : AVsessionBackground_OnAudioSessionChecked_001
 * @tc.number: AVsessionBackground_OnAudioSessionChecked_001
 * @tc.desc  : Test OnAudioSessionChecked with nonexistent uid and expired weak_ptr
 */
HWTEST_F(AVsessionBackgroundUnitTest, AVsessionBackground_OnAudioSessionChecked_001, TestSize.Level1)
{
    AVsessionBackground::Instance().OnAudioSessionChecked(TEST_UID_NONEXISTENT);

    auto player1 = PlayerServer::Create();
    ASSERT_NE(player1, nullptr);
    AVsessionBackground::Instance().AddListener(player1, TEST_UID_1);
    player1.reset();

    AVsessionBackground::Instance().OnAudioSessionChecked(TEST_UID_1);
    EXPECT_NE(AVsessionBackground::Instance().playerMap_.find(TEST_UID_1),
        AVsessionBackground::Instance().playerMap_.end());
}

/**
 * @tc.name  : AVsessionBackground_OnAudioSessionChecked_002
 * @tc.number: AVsessionBackground_OnAudioSessionChecked_002
 * @tc.desc  : Test OnAudioSessionChecked skips non-playing player and pauses playing player
 */
HWTEST_F(AVsessionBackgroundUnitTest, AVsessionBackground_OnAudioSessionChecked_002, TestSize.Level1)
{
    auto idlePlayer = std::static_pointer_cast<PlayerServer>(PlayerServer::Create());
    ASSERT_NE(idlePlayer, nullptr);
    idlePlayer->lastOpStatus_ = PLAYER_IDLE;
    idlePlayer->isBackgroundChanged_ = false;

    auto playingPlayer = std::static_pointer_cast<PlayerServer>(PlayerServer::Create());
    ASSERT_NE(playingPlayer, nullptr);
    playingPlayer->lastOpStatus_ = PLAYER_STARTED;
    playingPlayer->isBackgroundChanged_ = false;

    AVsessionBackground::Instance().AddListener(idlePlayer, TEST_UID_2);
    AVsessionBackground::Instance().AddListener(playingPlayer, TEST_UID_2);

    AVsessionBackground::Instance().OnAudioSessionChecked(TEST_UID_2);

    EXPECT_FALSE(idlePlayer->isBackgroundChanged_);
    EXPECT_TRUE(playingPlayer->isBackgroundChanged_);
    EXPECT_TRUE(playingPlayer->isBackgroundCb_);
    EXPECT_EQ(playingPlayer->backgroundState_, PLAYER_PAUSED);
}

/**
 * @tc.name  : AVsessionBackground_SessionCallbacks_001
 * @tc.number: AVsessionBackground_SessionCallbacks_001
 * @tc.desc  : Test SessionListener override callbacks execute safely
 */
HWTEST_F(AVsessionBackgroundUnitTest, AVsessionBackground_SessionCallbacks_001, TestSize.Level1)
{
    AVSession::AVSessionDescriptor descriptor;
    AVsessionBackground &instance = AVsessionBackground::Instance();
    instance.OnSessionCreate(descriptor);
    instance.OnSessionRelease(descriptor);
    instance.OnTopSessionChange(descriptor);
    EXPECT_EQ(&AVsessionBackground::Instance(), &instance);
}
} // namespace Test
} // namespace Media
} // namespace OHOS
