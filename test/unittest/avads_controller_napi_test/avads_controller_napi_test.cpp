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

#include "avads_controller_napi_test.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Media;

namespace {
constexpr int32_t ERR_ADS_PARAM_INVALID = 5400108;
constexpr int32_t MSERR_INVALID_OPERATION = -1;
}

HWTEST_F(AVAdsControllerNapiTest, Constructor_001, TestSize.Level0)
{
    auto controller = std::make_unique<AVAdsControllerNapi>();
    ASSERT_NE(controller, nullptr);
}

HWTEST_F(AVAdsControllerNapiTest, Destructor_001, TestSize.Level0)
{
    auto controller = std::make_unique<AVAdsControllerNapi>();
    ASSERT_NE(controller, nullptr);
}

HWTEST_F(AVAdsControllerNapiTest, SetPlayer_Nullptr_001, TestSize.Level0)
{
    auto controller = std::make_unique<AVAdsControllerNapi>();
    ASSERT_NE(controller, nullptr);

    void* nullPlayer = nullptr;
    controller->SetPlayer(nullPlayer);
    EXPECT_EQ(controller->GetPlayer(), nullptr);
}

HWTEST_F(AVAdsControllerNapiTest, SetPlayer_Valid_001, TestSize.Level0)
{
    auto controller = std::make_unique<AVAdsControllerNapi>();
    ASSERT_NE(controller, nullptr);

    int dummyPlayer = 42;
    controller->SetPlayer(&dummyPlayer);
    EXPECT_NE(controller->GetPlayer(), nullptr);
}

HWTEST_F(AVAdsControllerNapiTest, GetPlayer_NullAfterConstruction_001, TestSize.Level0)
{
    auto controller = std::make_unique<AVAdsControllerNapi>();
    ASSERT_NE(controller, nullptr);

    EXPECT_EQ(controller->GetPlayer(), nullptr);
}

HWTEST_F(AVAdsControllerNapiTest, GetPlayer_AfterSetPlayer_001, TestSize.Level0)
{
    auto controller = std::make_unique<AVAdsControllerNapi>();
    ASSERT_NE(controller, nullptr);

    int dummyPlayer = 42;
    controller->SetPlayer(&dummyPlayer);
    EXPECT_EQ(controller->GetPlayer(), &dummyPlayer);
}

HWTEST_F(AVAdsControllerNapiTest, SetPlayer_MultipleTimes_001, TestSize.Level0)
{
    auto controller = std::make_unique<AVAdsControllerNapi>();
    ASSERT_NE(controller, nullptr);

    int player1 = 1;
    int player2 = 2;

    controller->SetPlayer(&player1);
    EXPECT_EQ(controller->GetPlayer(), &player1);

    controller->SetPlayer(&player2);
    EXPECT_EQ(controller->GetPlayer(), &player2);
}

HWTEST_F(AVAdsControllerNapiTest, ThreadSafety_SetPlayer_GetPlayer_001, TestSize.Level0)
{
    auto controller = std::make_unique<AVAdsControllerNapi>();
    ASSERT_NE(controller, nullptr);

    int player1 = 1;
    int player2 = 2;

    controller->SetPlayer(&player1);
    EXPECT_EQ(controller->GetPlayer(), &player1);

    controller->SetPlayer(&player2);
    EXPECT_EQ(controller->GetPlayer(), &player2);
}

HWTEST_F(AVAdsControllerNapiTest, MutexProtection_001, TestSize.Level0)
{
    auto controller = std::make_unique<AVAdsControllerNapi>();
    ASSERT_NE(controller, nullptr);

    int dummyPlayer = 42;
    controller->SetPlayer(&dummyPlayer);

    EXPECT_NE(controller->GetPlayer(), nullptr);
}

HWTEST_F(AVAdsControllerNapiTest, ConcurrentAccess_001, TestSize.Level1)
{
    auto controller = std::make_unique<AVAdsControllerNapi>();
    ASSERT_NE(controller, nullptr);

    int dummyPlayer = 42;

    controller->SetPlayer(&dummyPlayer);
    auto player1 = controller->GetPlayer();
    auto player2 = controller->GetPlayer();

    EXPECT_EQ(player1, player2);
}

HWTEST_F(AVAdsControllerNapiInterfaceTest, AdsAsyncContext_Constructor_001, TestSize.Level0)
{
    void* env = nullptr;
    auto ctx = std::make_unique<AdsAsyncContext>(env);
    ASSERT_NE(ctx, nullptr);
    EXPECT_EQ(ctx->opType, AdsAsyncContext::OpType::ADD);
    EXPECT_EQ(ctx->mediaSource, nullptr);
    EXPECT_EQ(ctx->startMs, 0);
    EXPECT_EQ(ctx->adId, "");
    EXPECT_EQ(ctx->outId, "");
    EXPECT_EQ(ctx->player, nullptr);
    EXPECT_FALSE(ctx->errFlag);
    EXPECT_EQ(ctx->errCode, 0);
    EXPECT_EQ(ctx->errMessage, "");
}

HWTEST_F(AVAdsControllerNapiInterfaceTest, AdsAsyncContext_OpType_ADD_001, TestSize.Level0)
{
    void* env = nullptr;
    auto ctx = std::make_unique<AdsAsyncContext>(env);
    ASSERT_NE(ctx, nullptr);
    ctx->opType = AdsAsyncContext::OpType::ADD;
    EXPECT_EQ(ctx->opType, AdsAsyncContext::OpType::ADD);
}

HWTEST_F(AVAdsControllerNapiInterfaceTest, AdsAsyncContext_OpType_REMOVE_001, TestSize.Level0)
{
    void* env = nullptr;
    auto ctx = std::make_unique<AdsAsyncContext>(env);
    ASSERT_NE(ctx, nullptr);
    ctx->opType = AdsAsyncContext::OpType::REMOVE;
    EXPECT_EQ(ctx->opType, AdsAsyncContext::OpType::REMOVE);
}

HWTEST_F(AVAdsControllerNapiInterfaceTest, AdsAsyncContext_OpType_SKIP_001, TestSize.Level0)
{
    void* env = nullptr;
    auto ctx = std::make_unique<AdsAsyncContext>(env);
    ASSERT_NE(ctx, nullptr);
    ctx->opType = AdsAsyncContext::OpType::SKIP;
    EXPECT_EQ(ctx->opType, AdsAsyncContext::OpType::SKIP);
}

HWTEST_F(AVAdsControllerNapiInterfaceTest, AdsAsyncContext_OpType_DISABLE_ALL_001, TestSize.Level0)
{
    void* env = nullptr;
    auto ctx = std::make_unique<AdsAsyncContext>(env);
    ASSERT_NE(ctx, nullptr);
    ctx->opType = AdsAsyncContext::OpType::DISABLE_ALL;
    EXPECT_EQ(ctx->opType, AdsAsyncContext::OpType::DISABLE_ALL);
}

HWTEST_F(AVAdsControllerNapiInterfaceTest, AdsAsyncContext_SetStartMs_001, TestSize.Level0)
{
    void* env = nullptr;
    auto ctx = std::make_unique<AdsAsyncContext>(env);
    ASSERT_NE(ctx, nullptr);

    ctx->startMs = 1000;
    EXPECT_EQ(ctx->startMs, 1000);
}

HWTEST_F(AVAdsControllerNapiInterfaceTest, AdsAsyncContext_SetStartMs_Zero_001, TestSize.Level0)
{
    void* env = nullptr;
    auto ctx = std::make_unique<AdsAsyncContext>(env);
    ASSERT_NE(ctx, nullptr);

    ctx->startMs = 0;
    EXPECT_EQ(ctx->startMs, 0);
}

HWTEST_F(AVAdsControllerNapiInterfaceTest, AdsAsyncContext_SetStartMs_Negative_001, TestSize.Level0)
{
    void* env = nullptr;
    auto ctx = std::make_unique<AdsAsyncContext>(env);
    ASSERT_NE(ctx, nullptr);

    ctx->startMs = -1000;
    EXPECT_EQ(ctx->startMs, -1000);
}

HWTEST_F(AVAdsControllerNapiInterfaceTest, AdsAsyncContext_SetStartMs_Large_001, TestSize.Level0)
{
    void* env = nullptr;
    auto ctx = std::make_unique<AdsAsyncContext>(env);
    ASSERT_NE(ctx, nullptr);

    ctx->startMs = 999999999999LL;
    EXPECT_EQ(ctx->startMs, 999999999999LL);
}

HWTEST_F(AVAdsControllerNapiInterfaceTest, AdsAsyncContext_SetAdId_001, TestSize.Level0)
{
    void* env = nullptr;
    auto ctx = std::make_unique<AdsAsyncContext>(env);
    ASSERT_NE(ctx, nullptr);

    ctx->adId = "test_ad_id";
    EXPECT_EQ(ctx->adId, "test_ad_id");
}

HWTEST_F(AVAdsControllerNapiInterfaceTest, AdsAsyncContext_SetAdId_Empty_001, TestSize.Level0)
{
    void* env = nullptr;
    auto ctx = std::make_unique<AdsAsyncContext>(env);
    ASSERT_NE(ctx, nullptr);

    ctx->adId = "";
    EXPECT_EQ(ctx->adId, "");
}

HWTEST_F(AVAdsControllerNapiInterfaceTest, AdsAsyncContext_SetOutId_001, TestSize.Level0)
{
    void* env = nullptr;
    auto ctx = std::make_unique<AdsAsyncContext>(env);
    ASSERT_NE(ctx, nullptr);

    ctx->outId = "test_out_id";
    EXPECT_EQ(ctx->outId, "test_out_id");
}

HWTEST_F(AVAdsControllerNapiInterfaceTest, AdsAsyncContext_SetOutId_Empty_001, TestSize.Level0)
{
    void* env = nullptr;
    auto ctx = std::make_unique<AdsAsyncContext>(env);
    ASSERT_NE(ctx, nullptr);

    ctx->outId = "";
    EXPECT_EQ(ctx->outId, "");
}

HWTEST_F(AVAdsControllerNapiInterfaceTest, AdsAsyncContext_SetErrFlag_True_001, TestSize.Level0)
{
    void* env = nullptr;
    auto ctx = std::make_unique<AdsAsyncContext>(env);
    ASSERT_NE(ctx, nullptr);

    ctx->errFlag = true;
    EXPECT_TRUE(ctx->errFlag);
}

HWTEST_F(AVAdsControllerNapiInterfaceTest, AdsAsyncContext_SetErrFlag_False_001, TestSize.Level0)
{
    void* env = nullptr;
    auto ctx = std::make_unique<AdsAsyncContext>(env);
    ASSERT_NE(ctx, nullptr);

    ctx->errFlag = false;
    EXPECT_FALSE(ctx->errFlag);
}

HWTEST_F(AVAdsControllerNapiInterfaceTest, AdsAsyncContext_SetErrCode_001, TestSize.Level0)
{
    void* env = nullptr;
    auto ctx = std::make_unique<AdsAsyncContext>(env);
    ASSERT_NE(ctx, nullptr);

    ctx->errCode = ERR_ADS_PARAM_INVALID;
    EXPECT_EQ(ctx->errCode, ERR_ADS_PARAM_INVALID);
}

HWTEST_F(AVAdsControllerNapiInterfaceTest, AdsAsyncContext_SetErrCode_Zero_001, TestSize.Level0)
{
    void* env = nullptr;
    auto ctx = std::make_unique<AdsAsyncContext>(env);
    ASSERT_NE(ctx, nullptr);

    ctx->errCode = 0;
    EXPECT_EQ(ctx->errCode, 0);
}

HWTEST_F(AVAdsControllerNapiInterfaceTest, AdsAsyncContext_SetErrCode_Negative_001, TestSize.Level0)
{
    void* env = nullptr;
    auto ctx = std::make_unique<AdsAsyncContext>(env);
    ASSERT_NE(ctx, nullptr);

    ctx->errCode = -1;
    EXPECT_EQ(ctx->errCode, -1);
}

HWTEST_F(AVAdsControllerNapiInterfaceTest, AdsAsyncContext_SetErrMessage_001, TestSize.Level0)
{
    void* env = nullptr;
    auto ctx = std::make_unique<AdsAsyncContext>(env);
    ASSERT_NE(ctx, nullptr);

    ctx->errMessage = "Test error message";
    EXPECT_EQ(ctx->errMessage, "Test error message");
}

HWTEST_F(AVAdsControllerNapiInterfaceTest, AdsAsyncContext_SetErrMessage_Empty_001, TestSize.Level0)
{
    void* env = nullptr;
    auto ctx = std::make_unique<AdsAsyncContext>(env);
    ASSERT_NE(ctx, nullptr);

    ctx->errMessage = "";
    EXPECT_EQ(ctx->errMessage, "");
}

HWTEST_F(AVAdsControllerNapiInterfaceTest, AdsAsyncContext_AllFields_ADD_001, TestSize.Level0)
{
    void* env = nullptr;
    auto ctx = std::make_unique<AdsAsyncContext>(env);
    ASSERT_NE(ctx, nullptr);

    ctx->opType = AdsAsyncContext::OpType::ADD;
    ctx->startMs = 5000;
    ctx->adId = "ad_123";
    ctx->outId = "out_456";
    ctx->errFlag = false;
    ctx->errCode = 0;
    ctx->errMessage = "";

    EXPECT_EQ(ctx->opType, AdsAsyncContext::OpType::ADD);
    EXPECT_EQ(ctx->startMs, 5000);
    EXPECT_EQ(ctx->adId, "ad_123");
    EXPECT_EQ(ctx->outId, "out_456");
    EXPECT_FALSE(ctx->errFlag);
    EXPECT_EQ(ctx->errCode, 0);
    EXPECT_EQ(ctx->errMessage, "");
}

HWTEST_F(AVAdsControllerNapiInterfaceTest, AdsAsyncContext_AllFields_REMOVE_001, TestSize.Level0)
{
    void* env = nullptr;
    auto ctx = std::make_unique<AdsAsyncContext>(env);
    ASSERT_NE(ctx, nullptr);

    ctx->opType = AdsAsyncContext::OpType::REMOVE;
    ctx->adId = "remove_ad_123";
    ctx->errFlag = false;
    ctx->errCode = 0;

    EXPECT_EQ(ctx->opType, AdsAsyncContext::OpType::REMOVE);
    EXPECT_EQ(ctx->adId, "remove_ad_123");
    EXPECT_FALSE(ctx->errFlag);
}

HWTEST_F(AVAdsControllerNapiInterfaceTest, AdsAsyncContext_AllFields_SKIP_001, TestSize.Level0)
{
    void* env = nullptr;
    auto ctx = std::make_unique<AdsAsyncContext>(env);
    ASSERT_NE(ctx, nullptr);

    ctx->opType = AdsAsyncContext::OpType::SKIP;
    ctx->errFlag = false;
    ctx->errCode = 0;

    EXPECT_EQ(ctx->opType, AdsAsyncContext::OpType::SKIP);
    EXPECT_FALSE(ctx->errFlag);
}

HWTEST_F(AVAdsControllerNapiInterfaceTest, AdsAsyncContext_AllFields_DISABLE_ALL_001, TestSize.Level0)
{
    void* env = nullptr;
    auto ctx = std::make_unique<AdsAsyncContext>(env);
    ASSERT_NE(ctx, nullptr);

    ctx->opType = AdsAsyncContext::OpType::DISABLE_ALL;
    ctx->errFlag = false;
    ctx->errCode = 0;

    EXPECT_EQ(ctx->opType, AdsAsyncContext::OpType::DISABLE_ALL);
    EXPECT_FALSE(ctx->errFlag);
}

HWTEST_F(AVAdsControllerNapiInterfaceTest, AdsAsyncContext_WithError_001, TestSize.Level0)
{
    void* env = nullptr;
    auto ctx = std::make_unique<AdsAsyncContext>(env);
    ASSERT_NE(ctx, nullptr);

    ctx->opType = AdsAsyncContext::OpType::ADD;
    ctx->player = nullptr;
    ctx->errFlag = true;
    ctx->errCode = MSERR_INVALID_OPERATION;
    ctx->errMessage = "Player is nullptr";

    EXPECT_EQ(ctx->opType, AdsAsyncContext::OpType::ADD);
    EXPECT_TRUE(ctx->errFlag);
    EXPECT_EQ(ctx->errCode, MSERR_INVALID_OPERATION);
    EXPECT_EQ(ctx->errMessage, "Player is nullptr");
    EXPECT_EQ(ctx->player, nullptr);
}

HWTEST_F(AVAdsControllerNapiInterfaceTest, AdsAsyncContext_DefaultValues_001, TestSize.Level0)
{
    void* env = nullptr;
    auto ctx = std::make_unique<AdsAsyncContext>(env);
    ASSERT_NE(ctx, nullptr);

    EXPECT_EQ(ctx->opType, AdsAsyncContext::OpType::ADD);
    EXPECT_EQ(ctx->mediaSource, nullptr);
    EXPECT_EQ(ctx->startMs, 0);
    EXPECT_EQ(ctx->adId, "");
    EXPECT_EQ(ctx->outId, "");
    EXPECT_EQ(ctx->player, nullptr);
    EXPECT_FALSE(ctx->errFlag);
    EXPECT_EQ(ctx->errCode, 0);
    EXPECT_EQ(ctx->errMessage, "");
}

HWTEST_F(AVAdsControllerNapiTest, OpType_Enum_Values_001, TestSize.Level0)
{
    EXPECT_EQ(static_cast<uint8_t>(AdsAsyncContext::OpType::ADD), 0);
    EXPECT_EQ(static_cast<uint8_t>(AdsAsyncContext::OpType::REMOVE), 1);
    EXPECT_EQ(static_cast<uint8_t>(AdsAsyncContext::OpType::SKIP), 2);
    EXPECT_EQ(static_cast<uint8_t>(AdsAsyncContext::OpType::DISABLE_ALL), 3);
}

HWTEST_F(AVAdsControllerNapiTest, OpType_AllCases_001, TestSize.Level0)
{
    for (uint8_t i = 0; i <= 3; ++i) {
        auto opType = static_cast<AdsAsyncContext::OpType>(i);
        void* env = nullptr;
        auto ctx = std::make_unique<AdsAsyncContext>(env);
        ASSERT_NE(ctx, nullptr);
        ctx->opType = opType;
        EXPECT_EQ(ctx->opType, opType);
    }
}
