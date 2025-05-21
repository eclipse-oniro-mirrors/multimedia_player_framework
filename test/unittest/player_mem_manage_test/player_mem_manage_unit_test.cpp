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

#include "player_mem_manage_unit_test.h"
#include <unistd.h>
#include <functional>
#include "media_log.h"
#include "media_errors.h"
#include "hiplayer_impl.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing::ext;
static const int32_t SEC_TEST = 200;
static const int32_t ERR_TEST = -10;

void PlayerMemManageUnitTest::SetUpTestCase(void)
{
}

void PlayerMemManageUnitTest::TearDownTestCase(void)
{
}

void PlayerMemManageUnitTest::SetUp(void)
{
    playerServerMem_ = std::make_shared<PlayerMemManage>();
    playerServerMem_->probeTaskQueue_ = make_unique<TaskQueue>("test_TaskQueueName");
    playerServerMem_->appStateListener_ = std::make_shared<AppStateListener>();
    testCall1.resetFrontGroundRecall = []() {
        std::cout << "This is a test_lambda function." << std::endl;
    };
    testCall1.resetBackGroundRecall = []() {
        std::cout << "This is a test_lambda function." << std::endl;
    };
    testCall1.resetMemmgrRecall = []() {
        std::cout << "This is a test_lambda function." << std::endl;
    };
    testCall1.recoverRecall = []() {
        std::cout << "This is a test_lambda function." << std::endl;
    };
    testCall1.signAddr = nullptr;
    testCall2.resetFrontGroundRecall = []() {
        std::cout << "This is a test_lambda function." << std::endl;
    };
    testCall2.resetBackGroundRecall = []() {
        std::cout << "This is a test_lambda function." << std::endl;
    };
    testCall2.resetMemmgrRecall = []() {
        std::cout << "This is a test_lambda function." << std::endl;
    };
    testCall2.recoverRecall = []() {
        std::cout << "This is a test_lambda function." << std::endl;
    };
    testCall2.signAddr = nullptr;
}

void PlayerMemManageUnitTest::TearDown(void)
{
    playerServerMem_ = nullptr;
}

/**
 * @tc.name  : PlayerMemManageGetInstance_001
 * @tc.number: PlayerMemManageGetInstance_001
 * @tc.desc  : Test  GetInstance interface
 */
HWTEST_F(PlayerMemManageUnitTest, PlayerMemManageGetInstance_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, playerServerMem_);
    PlayerMemManage::AppPlayerInfo appPlayerInfo;
    PlayerMemManage::PidPlayersInfo testInfo1;
    testInfo1.emplace(1, appPlayerInfo);
    playerServerMem_->playerManage_.emplace(1, testInfo1);
    PlayerMemManage &test = PlayerMemManage::GetInstance();
    EXPECT_NE(test.isParsed_, playerServerMem_->isParsed_);
}

/**
 * @tc.name  : PlayerMemManageFindBackGroundPlayerFromVec_001
 * @tc.number: PlayerMemManageFindBackGroundPlayerFromVec_001
 * @tc.desc  : Test  FindBackGroundPlayerFromVec interface
 */
HWTEST_F(PlayerMemManageUnitTest, PlayerMemManageFindBackGroundPlayerFromVec_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, playerServerMem_);
    PlayerMemManage::AppPlayerInfo appPlayerInfo;
    appPlayerInfo.appState = static_cast<int32_t>(AppState::APP_STATE_BACK_GROUND);
    testCall2.signAddr = nullptr;
    appPlayerInfo.memRecallStructVec.push_back(testCall1);
    appPlayerInfo.memRecallStructVec.push_back(testCall2);
    std::chrono::seconds duration(SEC_TEST);
    appPlayerInfo.appEnterFrontTime = (std::chrono::steady_clock::now() + duration);

    PlayerMemManage::PidPlayersInfo testInfo1;
    testInfo1.emplace(1, appPlayerInfo);
    playerServerMem_->playerManage_.emplace(1, testInfo1);

    playerServerMem_->FindBackGroundPlayerFromVec(appPlayerInfo);
    EXPECT_NE(playerServerMem_, nullptr);
}

/**
 * @tc.name  : PlayerMemManageFindFrontGroundPlayerFromVec_001
 * @tc.number: PlayerMemManageFindFrontGroundPlayerFromVec_001
 * @tc.desc  : Test  FindFrontGroundPlayerFromVec interface
 */
HWTEST_F(PlayerMemManageUnitTest, PlayerMemManageFindFrontGroundPlayerFromVec_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, playerServerMem_);
    PlayerMemManage::AppPlayerInfo appPlayerInfo;
    appPlayerInfo.appState = static_cast<int32_t>(AppState::APP_STATE_FRONT_GROUND);
    appPlayerInfo.memRecallStructVec.push_back(testCall1);
    appPlayerInfo.memRecallStructVec.push_back(testCall2);
    std::chrono::seconds duration(SEC_TEST);
    appPlayerInfo.appEnterFrontTime = (std::chrono::steady_clock::now() + duration);

    PlayerMemManage::PidPlayersInfo testInfo1;
    testInfo1.emplace(1, appPlayerInfo);
    playerServerMem_->playerManage_.emplace(1, testInfo1);

    playerServerMem_->FindFrontGroundPlayerFromVec(appPlayerInfo);
    EXPECT_NE(appPlayerInfo.appEnterFrontTime, std::chrono::steady_clock::now());
}

/**
 * @tc.name  : PlayerMemManageFindProbeTaskPlayer_001
 * @tc.number: PlayerMemManageFindProbeTaskPlayer_001
 * @tc.desc  : Test  FindProbeTaskPlayer interface
 */
HWTEST_F(PlayerMemManageUnitTest, PlayerMemManageFindProbeTaskPlayer_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, playerServerMem_);
    PlayerMemManage::AppPlayerInfo appPlayerInfo;
    appPlayerInfo.appState = static_cast<int32_t>(AppState::APP_STATE_FRONT_GROUND);
    appPlayerInfo.memRecallStructVec.push_back(testCall1);
    appPlayerInfo.memRecallStructVec.push_back(testCall2);
    PlayerMemManage::PidPlayersInfo testInfo1;
    testInfo1.emplace(1, appPlayerInfo);
    PlayerMemManage::PidPlayersInfo testInfo2;
    appPlayerInfo.appState = static_cast<int32_t>(AppState::APP_STATE_BACK_GROUND);
    testInfo2.emplace(2, appPlayerInfo);
    playerServerMem_->playerManage_.emplace(1, testInfo1);
    playerServerMem_->playerManage_.emplace(2, testInfo2);
    playerServerMem_->FindProbeTaskPlayer();
    EXPECT_NE(appPlayerInfo.appEnterFrontTime, std::chrono::steady_clock::now());
}

/**
 * @tc.name  : PlayerMemManageInit_001
 * @tc.number: PlayerMemManageInit_001
 * @tc.desc  : Test  Init interface
 */
HWTEST_F(PlayerMemManageUnitTest, PlayerMemManageInit_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, playerServerMem_);
    playerServerMem_->isParsed_ = true;
    playerServerMem_->isAppStateListenerRemoteDied_ = false;
    bool ret = false;

    PlayerMemManage::AppPlayerInfo appPlayerInfo;
    PlayerMemManage::PidPlayersInfo testInfo1;
    testInfo1.emplace(1, appPlayerInfo);
    playerServerMem_->playerManage_.emplace(1, testInfo1);

    ret = playerServerMem_->Init();
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name  : PlayerMemManageHandleForceReclaim_001
 * @tc.number: PlayerMemManageHandleForceReclaim_001
 * @tc.desc  : Test  HandleForceReclaim interface
 */
HWTEST_F(PlayerMemManageUnitTest, PlayerMemManageHandleForceReclaim_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, playerServerMem_);
    int32_t uid = 2;
    int32_t pid = 1;
    int32_t ret = -1;
    PlayerMemManage::AppPlayerInfo appPlayerInfo;
    appPlayerInfo.appState = static_cast<int32_t>(AppState::APP_STATE_FRONT_GROUND);
    appPlayerInfo.memRecallStructVec.push_back(testCall1);
    appPlayerInfo.memRecallStructVec.push_back(testCall2);
    PlayerMemManage::PidPlayersInfo testInfo1;
    testInfo1.emplace(1, appPlayerInfo);
    PlayerMemManage::PidPlayersInfo testInfo2;
    appPlayerInfo.appState = static_cast<int32_t>(AppState::APP_STATE_BACK_GROUND);
    testInfo2.emplace(2, appPlayerInfo);
    playerServerMem_->playerManage_.emplace(1, testInfo1);
    playerServerMem_->playerManage_.emplace(2, testInfo2);
    ret = playerServerMem_->HandleForceReclaim(3, pid);
    EXPECT_EQ(ret, 0);
    ret = playerServerMem_->HandleForceReclaim(uid, 3);
    EXPECT_EQ(ret, 0);
    ret = playerServerMem_->HandleForceReclaim(uid, pid);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name  : PlayerMemManageHandleForceReclaim_002
 * @tc.number: PlayerMemManageHandleForceReclaim_002
 * @tc.desc  : Test  HandleForceReclaim interface
 */
HWTEST_F(PlayerMemManageUnitTest, PlayerMemManageHandleForceReclaim_002, TestSize.Level0)
{
    ASSERT_NE(nullptr, playerServerMem_);
    int32_t ret = -1;
    PlayerMemManage::AppPlayerInfo appPlayerInfo;
    appPlayerInfo.appState = static_cast<int32_t>(AppState::APP_STATE_BACK_GROUND);
    appPlayerInfo.memRecallStructVec.push_back(testCall1);
    appPlayerInfo.memRecallStructVec.push_back(testCall2);
    PlayerMemManage::PidPlayersInfo testInfo2;
    testInfo2.emplace(2, appPlayerInfo);
    playerServerMem_->playerManage_.emplace(2, testInfo2);
    ret = playerServerMem_->HandleForceReclaim(2, 2);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name  : PlayerMemManageHandleOnTrimLevelLow_001
 * @tc.number: PlayerMemManageHandleOnTrimLevelLow_001
 * @tc.desc  : Test  HandleOnTrimLevelLow interface
 */
HWTEST_F(PlayerMemManageUnitTest, PlayerMemManageHandleOnTrimLevelLow_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, playerServerMem_);
    PlayerMemManage::AppPlayerInfo appPlayerInfo;
    appPlayerInfo.appState = static_cast<int32_t>(AppState::APP_STATE_FRONT_GROUND);
    appPlayerInfo.memRecallStructVec.push_back(testCall1);
    appPlayerInfo.memRecallStructVec.push_back(testCall2);
    PlayerMemManage::PidPlayersInfo testInfo1;
    testInfo1.emplace(1, appPlayerInfo);
    PlayerMemManage::PidPlayersInfo testInfo2;
    appPlayerInfo.appState = static_cast<int32_t>(AppState::APP_STATE_BACK_GROUND);
    testInfo2.emplace(2, appPlayerInfo);
    playerServerMem_->playerManage_.emplace(1, testInfo1);
    playerServerMem_->playerManage_.emplace(2, testInfo2);
    playerServerMem_->HandleOnTrimLevelLow();
    EXPECT_EQ(playerServerMem_->isParsed_, false);
}

/**
 * @tc.name  : PlayerMemManageHandleOnTrim_001
 * @tc.number: PlayerMemManageHandleOnTrim_001
 * @tc.desc  : Test  HandleOnTrim interface
 */
HWTEST_F(PlayerMemManageUnitTest, PlayerMemManageHandleOnTrim_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, playerServerMem_);
    int32_t ret = -1;
    ::OHOS::Memory::SystemMemoryLevel testLevel = ::OHOS::Memory::SystemMemoryLevel::MEMORY_LEVEL_MODERATE;

    PlayerMemManage::AppPlayerInfo appPlayerInfo;
    PlayerMemManage::PidPlayersInfo testInfo1;
    testInfo1.emplace(1, appPlayerInfo);
    playerServerMem_->playerManage_.emplace(1, testInfo1);

    ret = playerServerMem_->HandleOnTrim(testLevel);
    EXPECT_EQ(ret, 0);
    ret = playerServerMem_->HandleOnTrim(::OHOS::Memory::SystemMemoryLevel::MEMORY_LEVEL_LOW);
    EXPECT_EQ(ret, 0);
    ret = playerServerMem_->HandleOnTrim(::OHOS::Memory::SystemMemoryLevel::MEMORY_LEVEL_CRITICAL);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name  : PlayerMemManageRecordAppState_001
 * @tc.number: PlayerMemManageRecordAppState_001
 * @tc.desc  : Test  RecordAppState interface
 */
HWTEST_F(PlayerMemManageUnitTest, PlayerMemManageRecordAppState_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, playerServerMem_);
    int32_t ret = -1;
    PlayerMemManage::AppPlayerInfo appPlayerInfo;
    appPlayerInfo.appState = static_cast<int32_t>(AppState::APP_STATE_BACK_GROUND);
    appPlayerInfo.memRecallStructVec.push_back(testCall1);
    appPlayerInfo.memRecallStructVec.push_back(testCall2);
    PlayerMemManage::PidPlayersInfo testInfo2;
    testInfo2.emplace(2, appPlayerInfo);
    playerServerMem_->playerManage_.emplace(2, testInfo2);
    ret = playerServerMem_->RecordAppState(3, 3, 3);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name  : PlayerMemManageHandleOnConnected_001
 * @tc.number: PlayerMemManageHandleOnConnected_001
 * @tc.desc  : Test  HandleOnConnected interface
 */
HWTEST_F(PlayerMemManageUnitTest, PlayerMemManageHandleOnConnected_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, playerServerMem_);
    playerServerMem_->isAppStateListenerRemoteDied_ = true;
    playerServerMem_->HandleOnConnected();
    EXPECT_EQ(playerServerMem_->isAppStateListenerRemoteDied_, false);
    EXPECT_EQ(playerServerMem_->isAppStateListenerConnected_, true);
}

/**
 * @tc.name  : PlayerMemManageWritePurgeableEvent_001
 * @tc.number: PlayerMemManageWritePurgeableEvent_001
 * @tc.desc  : Test  WritePurgeableEvent interface
 */
HWTEST_F(PlayerMemManageUnitTest, PlayerMemManageWritePurgeableEvent_001, TestSize.Level0)
{
    ASSERT_NE(nullptr, playerServerMem_);
    playerServerMem_->isParsed_ = true;

    PlayerMemManage::AppPlayerInfo appPlayerInfo;
    PlayerMemManage::PidPlayersInfo testInfo1;
    testInfo1.emplace(1, appPlayerInfo);
    playerServerMem_->playerManage_.emplace(1, testInfo1);

    playerServerMem_->WritePurgeableEvent(ERR_TEST, ERR_TEST);
    EXPECT_EQ(playerServerMem_->isAppStateListenerRemoteDied_, false);
}
} // namespace Media
} // namespace OHOS
