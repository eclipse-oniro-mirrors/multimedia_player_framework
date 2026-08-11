/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "player_listener_test.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {

HWTEST_F(PlayerListenerTest, OnError_WithType_001, TestSize.Level0)
{
    auto mockListener = std::make_shared<MockIStandardPlayerListener>();
    ASSERT_NE(mockListener, nullptr);
    EXPECT_CALL(*mockListener, OnError(PlayerErrorType::PLAYER_ERROR_UNKNOWN, 1001)).Times(1);
    mockListener->OnError(PlayerErrorType::PLAYER_ERROR_UNKNOWN, 1001);
}

HWTEST_F(PlayerListenerTest, OnError_WithMsg_001, TestSize.Level0)
{
    auto mockListener = std::make_shared<MockIStandardPlayerListener>();
    ASSERT_NE(mockListener, nullptr);
    std::string errorMsg = "Test error message";
    EXPECT_CALL(*mockListener, OnError(1001, errorMsg)).Times(1);
    mockListener->OnError(1001, errorMsg);
}

HWTEST_F(PlayerListenerTest, OnInfo_001, TestSize.Level0)
{
    auto mockListener = std::make_shared<MockIStandardPlayerListener>();
    ASSERT_NE(mockListener, nullptr);
    Format infoBody;
    EXPECT_CALL(*mockListener, OnInfo(PlayerOnInfoType::INFO_TYPE_SEEKDONE, 0, _)).Times(1);
    mockListener->OnInfo(PlayerOnInfoType::INFO_TYPE_SEEKDONE, 0, infoBody);
}

HWTEST_F(PlayerListenerTest, SetFreezeFlag_True_001, TestSize.Level0)
{
    auto mockListener = std::make_shared<MockIStandardPlayerListener>();
    ASSERT_NE(mockListener, nullptr);
    EXPECT_CALL(*mockListener, SetFreezeFlag(true)).Times(1);
    mockListener->SetFreezeFlag(true);
}

HWTEST_F(PlayerListenerTest, SetFreezeFlag_False_001, TestSize.Level0)
{
    auto mockListener = std::make_shared<MockIStandardPlayerListener>();
    ASSERT_NE(mockListener, nullptr);
    EXPECT_CALL(*mockListener, SetFreezeFlag(false)).Times(1);
    mockListener->SetFreezeFlag(false);
}

HWTEST_F(PlayerListenerTest, SetInterruptListenerFlag_True_001, TestSize.Level0)
{
    auto mockListener = std::make_shared<MockIStandardPlayerListener>();
    ASSERT_NE(mockListener, nullptr);
    EXPECT_CALL(*mockListener, SetInterruptListenerFlag(true)).Times(1);
    mockListener->SetInterruptListenerFlag(true);
}

HWTEST_F(PlayerListenerTest, SetInterruptListenerFlag_False_001, TestSize.Level0)
{
    auto mockListener = std::make_shared<MockIStandardPlayerListener>();
    ASSERT_NE(mockListener, nullptr);
    EXPECT_CALL(*mockListener, SetInterruptListenerFlag(false)).Times(1);
    mockListener->SetInterruptListenerFlag(false);
}

HWTEST_F(PlayerListenerTest, PlayerErrorType_Values_001, TestSize.Level0)
{
    EXPECT_EQ(static_cast<int32_t>(PlayerErrorType::PLAYER_ERROR), 0);
    EXPECT_EQ(static_cast<int32_t>(PlayerErrorType::PLAYER_ERROR_UNKNOWN), 1);
    EXPECT_EQ(static_cast<int32_t>(PlayerErrorType::PLAY_ERR), 0x10001);
    EXPECT_EQ(static_cast<int32_t>(PlayerErrorType::NET_ERR), 0x10002);
}

HWTEST_F(PlayerListenerTest, PlayerOnInfoType_Values_001, TestSize.Level0)
{
    EXPECT_EQ(static_cast<int32_t>(PlayerOnInfoType::INFO_TYPE_SEEKDONE), 1);
    EXPECT_EQ(static_cast<int32_t>(PlayerOnInfoType::INFO_TYPE_SPEEDDONE), 2);
    EXPECT_EQ(static_cast<int32_t>(PlayerOnInfoType::INFO_TYPE_BITRATEDONE), 3);
    EXPECT_EQ(static_cast<int32_t>(PlayerOnInfoType::INFO_TYPE_EOS), 4);
    EXPECT_EQ(static_cast<int32_t>(PlayerOnInfoType::INFO_TYPE_STATE_CHANGE), 5);
    EXPECT_EQ(static_cast<int32_t>(PlayerOnInfoType::INFO_TYPE_POSITION_UPDATE), 6);
}

HWTEST_F(PlayerListenerTest, MultipleCallbacks_001, TestSize.Level0)
{
    auto mockListener = std::make_shared<MockIStandardPlayerListener>();
    ASSERT_NE(mockListener, nullptr);

    Format infoBody;
    EXPECT_CALL(*mockListener, OnInfo(PlayerOnInfoType::INFO_TYPE_POSITION_UPDATE, 0, _)).Times(3);
    mockListener->OnInfo(PlayerOnInfoType::INFO_TYPE_POSITION_UPDATE, 0, infoBody);
    mockListener->OnInfo(PlayerOnInfoType::INFO_TYPE_POSITION_UPDATE, 0, infoBody);
    mockListener->OnInfo(PlayerOnInfoType::INFO_TYPE_POSITION_UPDATE, 0, infoBody);
}

HWTEST_F(PlayerListenerTest, OnError_WithEmptyMsg_001, TestSize.Level0)
{
    auto mockListener = std::make_shared<MockIStandardPlayerListener>();
    ASSERT_NE(mockListener, nullptr);
    std::string errorMsg = "";
    EXPECT_CALL(*mockListener, OnError(0, errorMsg)).Times(1);
    mockListener->OnError(0, errorMsg);
}

HWTEST_F(PlayerListenerTest, OnInfo_WithExtra_001, TestSize.Level0)
{
    auto mockListener = std::make_shared<MockIStandardPlayerListener>();
    ASSERT_NE(mockListener, nullptr);
    Format infoBody;
    EXPECT_CALL(*mockListener, OnInfo(PlayerOnInfoType::INFO_TYPE_BUFFERING_UPDATE, 50, _)).Times(1);
    mockListener->OnInfo(PlayerOnInfoType::INFO_TYPE_BUFFERING_UPDATE, 50, infoBody);
}

} // namespace Media
} // namespace OHOS
