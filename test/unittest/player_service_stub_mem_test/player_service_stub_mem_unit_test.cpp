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

#include "player_service_stub_mem_unit_test.h"
#include "media_errors.h"
#include "player_server_mem.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing::ext;

void PlayerServiceStubMemUnitTest::SetUpTestCase(void) {}

void PlayerServiceStubMemUnitTest::TearDownTestCase(void) {}

void PlayerServiceStubMemUnitTest::SetUp(void) {}

void PlayerServiceStubMemUnitTest::TearDown(void) {}

/**
 * @tc.name  : PlayerServiceStubMem_Create_001
 * @tc.number: PlayerServiceStubMem_Create_001
 * @tc.desc  : Test PlayerServiceStubMem Create and Init initialize memRecallStruct_
 */
HWTEST_F(PlayerServiceStubMemUnitTest, PlayerServiceStubMem_Create_001, TestSize.Level1)
{
    sptr<PlayerServiceStub> stub = PlayerServiceStubMem::Create();
    if (stub != nullptr) {
        auto stubMem = static_cast<PlayerServiceStubMem *>(stub.GetRefPtr());
        EXPECT_NE(stubMem->playerServer_, nullptr);
        EXPECT_EQ(stubMem->memRecallStruct_.signAddr, &(stubMem->playerServer_));
        EXPECT_TRUE(stubMem->memRecallStruct_.resetFrontGroundRecall != nullptr);
        EXPECT_TRUE(stubMem->memRecallStruct_.resetBackGroundRecall != nullptr);
        EXPECT_TRUE(stubMem->memRecallStruct_.resetMemmgrRecall != nullptr);
        EXPECT_TRUE(stubMem->memRecallStruct_.recoverRecall != nullptr);
        EXPECT_EQ(stubMem->Release(), MSERR_OK);
    }
}

/**
 * @tc.name  : PlayerServiceStubMem_Init_001
 * @tc.number: PlayerServiceStubMem_Init_001
 * @tc.desc  : Test Init when playerServer_ is nullptr and when already initialized
 */
HWTEST_F(PlayerServiceStubMemUnitTest, PlayerServiceStubMem_Init_001, TestSize.Level1)
{
    sptr<PlayerServiceStubMem> stubMem = new (std::nothrow) PlayerServiceStubMem();
    ASSERT_NE(stubMem, nullptr);
    EXPECT_EQ(stubMem->memRecallStruct_.signAddr, nullptr);

    int32_t ret = stubMem->Init();
    EXPECT_EQ(ret, MSERR_OK);
    ASSERT_NE(stubMem->playerServer_, nullptr);
    EXPECT_EQ(stubMem->memRecallStruct_.signAddr, &(stubMem->playerServer_));
    auto firstServer = stubMem->playerServer_;

    // Second Init should reuse existing playerServer_
    ret = stubMem->Init();
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(stubMem->playerServer_, firstServer);

    EXPECT_EQ(stubMem->Release(), MSERR_OK);
}

/**
 * @tc.name  : PlayerServiceStubMem_DestroyStubAndRelease_001
 * @tc.number: PlayerServiceStubMem_DestroyStubAndRelease_001
 * @tc.desc  : Test DestroyStub and Release deregister from PlayerMemManage and release server
 */
HWTEST_F(PlayerServiceStubMemUnitTest, PlayerServiceStubMem_DestroyStubAndRelease_001, TestSize.Level1)
{
    sptr<PlayerServiceStubMem> stubMem1 = new (std::nothrow) PlayerServiceStubMem();
    ASSERT_NE(stubMem1, nullptr);
    ASSERT_EQ(stubMem1->Init(), MSERR_OK);
    EXPECT_EQ(stubMem1->DestroyStub(), MSERR_OK);

    sptr<PlayerServiceStubMem> stubMem2 = new (std::nothrow) PlayerServiceStubMem();
    ASSERT_NE(stubMem2, nullptr);
    ASSERT_EQ(stubMem2->Init(), MSERR_OK);
    EXPECT_EQ(stubMem2->Release(), MSERR_OK);
}

/**
 * @tc.name  : PlayerServiceStubMem_MemManageRecall_001
 * @tc.number: PlayerServiceStubMem_MemManageRecall_001
 * @tc.desc  : Test all four memory management recall methods with valid playerServer_
 */
HWTEST_F(PlayerServiceStubMemUnitTest, PlayerServiceStubMem_MemManageRecall_001, TestSize.Level1)
{
    sptr<PlayerServiceStubMem> stubMem = new (std::nothrow) PlayerServiceStubMem();
    ASSERT_NE(stubMem, nullptr);
    ASSERT_EQ(stubMem->Init(), MSERR_OK);
    ASSERT_NE(stubMem->playerServer_, nullptr);

    stubMem->ResetFrontGroundForMemManageRecall();
    stubMem->ResetBackGroundForMemManageRecall();
    stubMem->ResetMemmgrForMemManageRecall();
    stubMem->RecoverByMemManageRecall();

    // Flush taskQue_ via barrier task before checking/releasing
    auto barrier = std::make_shared<TaskHandler<void>>([] {});
    (void)stubMem->taskQue_.EnqueueTask(barrier);
    (void)barrier->GetResult();

    EXPECT_EQ(stubMem->Release(), MSERR_OK);
}

/**
 * @tc.name  : PlayerServiceStubMem_MemManageRecall_002
 * @tc.number: PlayerServiceStubMem_MemManageRecall_002
 * @tc.desc  : Test memory management recall methods and callbacks when playerServer_ is nullptr
 */
HWTEST_F(PlayerServiceStubMemUnitTest, PlayerServiceStubMem_MemManageRecall_002, TestSize.Level1)
{
    sptr<PlayerServiceStubMem> stubMem = new (std::nothrow) PlayerServiceStubMem();
    ASSERT_NE(stubMem, nullptr);
    ASSERT_EQ(stubMem->Init(), MSERR_OK);

    // Release and clear playerServer_ to test nullptr branch in recall tasks and destructor
    PlayerMemManage::GetInstance().DeregisterPlayerServer(stubMem->memRecallStruct_);
    (void)stubMem->playerServer_->Release();
    stubMem->playerServer_ = nullptr;

    stubMem->ResetFrontGroundForMemManageRecall();
    stubMem->ResetBackGroundForMemManageRecall();
    stubMem->ResetMemmgrForMemManageRecall();
    stubMem->RecoverByMemManageRecall();

    if (stubMem->memRecallStruct_.resetFrontGroundRecall) {
        stubMem->memRecallStruct_.resetFrontGroundRecall();
    }
    if (stubMem->memRecallStruct_.resetBackGroundRecall) {
        stubMem->memRecallStruct_.resetBackGroundRecall();
    }
    if (stubMem->memRecallStruct_.resetMemmgrRecall) {
        stubMem->memRecallStruct_.resetMemmgrRecall();
    }
    if (stubMem->memRecallStruct_.recoverRecall) {
        stubMem->memRecallStruct_.recoverRecall();
    }

    auto barrier = std::make_shared<TaskHandler<void>>([] {});
    (void)stubMem->taskQue_.EnqueueTask(barrier);
    (void)barrier->GetResult();
    EXPECT_EQ(stubMem->playerServer_, nullptr);
}
} // namespace Media
} // namespace OHOS
