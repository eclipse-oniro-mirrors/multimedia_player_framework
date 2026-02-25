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

#include <iostream>
#include "lpp_audio_callback_looper_unit_test.h"
#include "plugin/plugin_time.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing;
using namespace testing::ext;
const int32_t ERROR = -1;

void LppAudioCallbackLooperUnitTest::SetUpTestCase(void)
{
}

void LppAudioCallbackLooperUnitTest::TearDownTestCase(void)
{
}

void LppAudioCallbackLooperUnitTest::SetUp(void)
{
    string streamerId = std::string("LppA_");
    lppAudioCallbackLooper_ = std::make_shared<LppAudioCallbackLooper>(streamerId);
}

void LppAudioCallbackLooperUnitTest::TearDown(void)
{
    lppAudioCallbackLooper_ = nullptr;
}

/**
* @tc.name    : Test DoPositionUpdate API
* @tc.number  : DoPositionUpdate_001
* @tc.desc    : Test DoPositionUpdate
*/
HWTEST_F(LppAudioCallbackLooperUnitTest, DoPositionUpdate_001, TestSize.Level0)
{
    lppAudioCallbackLooper_->positionUpdateIdx_.store(0);
    std::shared_ptr<ILppAudioStreamerEngine> engineMock = std::make_shared<ILppAudioStreamerEngine>();
    std::shared_ptr<ILppAudioStreamerEngineObs> obsMock = std::make_shared<ILppAudioStreamerEngineObs>();
    lppAudioCallbackLooper_->task_ = nullptr;
    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = 0; }),
                Return(MSERR_OK)
            )
        );
    EXPECT_CALL(*obsMock, OnPositionUpdated(_)).Times(1);
    lppAudioCallbackLooper_->obs_ = obsMock;
    lppAudioCallbackLooper_->engine_ = engineMock;
    lppAudioCallbackLooper_->DoPositionUpdate(0);

    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = 0; }),
                Return(ERROR)
            )
        );
    lppAudioCallbackLooper_->obs_ = obsMock;
    lppAudioCallbackLooper_->engine_ = engineMock;
    lppAudioCallbackLooper_->DoPositionUpdate(0);

    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = Plugins::HST_TIME_NONE; }),
                Return(MSERR_OK)
            )
        );
    lppAudioCallbackLooper_->obs_ = obsMock;
    lppAudioCallbackLooper_->engine_ = engineMock;
    lppAudioCallbackLooper_->DoPositionUpdate(0);

    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = Plugins::HST_TIME_NONE; }),
                Return(ERROR)
            )
        );
    lppAudioCallbackLooper_->obs_ = obsMock;
    lppAudioCallbackLooper_->engine_ = engineMock;
    lppAudioCallbackLooper_->DoPositionUpdate(0);

    int32_t res = -1;
    int64_t pos = -1;
    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = 0; }),
                Return(MSERR_OK)
            )
        );
    res = engineMock->GetCurrentPosition(pos);
    EXPECT_EQ(res, MSERR_OK);
    EXPECT_EQ(pos, 0);
}

/**
* @tc.name    : Test DoPositionUpdate API
* @tc.number  : DoPositionUpdate_002
* @tc.desc    : Test DoPositionUpdate
*/
HWTEST_F(LppAudioCallbackLooperUnitTest, DoPositionUpdate_002, TestSize.Level0)
{
    lppAudioCallbackLooper_->positionUpdateIdx_.store(0);
    std::shared_ptr<ILppAudioStreamerEngine> engineMock = std::make_shared<ILppAudioStreamerEngine>();
    std::shared_ptr<ILppAudioStreamerEngineObs> obsMock = std::make_shared<ILppAudioStreamerEngineObs>();
    lppAudioCallbackLooper_->task_ = nullptr;
    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = 0; }),
                Return(MSERR_OK)
            )
        );
    EXPECT_CALL(*obsMock, OnPositionUpdated(_)).Times(1);
    lppAudioCallbackLooper_->obs_ = obsMock;
    lppAudioCallbackLooper_->engine_ = engineMock;
    lppAudioCallbackLooper_->DoPositionUpdate(0);

    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = 0; }),
                Return(ERROR)
            )
        );
    lppAudioCallbackLooper_->obs_ = obsMock;
    lppAudioCallbackLooper_->engine_ = engineMock;
    lppAudioCallbackLooper_->DoPositionUpdate(0);

    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = Plugins::HST_TIME_NONE; }),
                Return(MSERR_OK)
            )
        );
    lppAudioCallbackLooper_->obs_ = obsMock;
    lppAudioCallbackLooper_->engine_ = engineMock;
    lppAudioCallbackLooper_->DoPositionUpdate(0);

    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = Plugins::HST_TIME_NONE; }),
                Return(ERROR)
            )
        );
    lppAudioCallbackLooper_->obs_ = obsMock;
    lppAudioCallbackLooper_->engine_ = engineMock;
    lppAudioCallbackLooper_->DoPositionUpdate(0);

    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = Plugins::HST_TIME_NONE; }),
                Return(MSERR_OK)
            )
        );
    lppAudioCallbackLooper_->obs_ = obsMock;
    lppAudioCallbackLooper_->engine_ = engineMock;
    lppAudioCallbackLooper_->DoPositionUpdate(0);

    int32_t res = -1;
    int64_t pos = -1;
    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = 0; }),
                Return(MSERR_OK)
            )
        );
    res = engineMock->GetCurrentPosition(pos);
    EXPECT_EQ(res, MSERR_OK);
    EXPECT_EQ(pos, 0);
}

/**
* @tc.name    : Test DoPositionUpdate API
* @tc.number  : DoPositionUpdate_003
* @tc.desc    : Test DoPositionUpdate
*/
HWTEST_F(LppAudioCallbackLooperUnitTest, DoPositionUpdate_003, TestSize.Level0)
{
    lppAudioCallbackLooper_->positionUpdateIdx_.store(0);
    std::shared_ptr<ILppAudioStreamerEngine> engineMock = std::make_shared<ILppAudioStreamerEngine>();
    std::shared_ptr<ILppAudioStreamerEngineObs> obsMock = std::make_shared<ILppAudioStreamerEngineObs>();
    lppAudioCallbackLooper_->task_ = nullptr;
    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = 0; }),
                Return(MSERR_OK)
            )
        );
    EXPECT_CALL(*obsMock, OnPositionUpdated(_)).Times(2);
    lppAudioCallbackLooper_->obs_ = obsMock;
    lppAudioCallbackLooper_->engine_ = engineMock;
    lppAudioCallbackLooper_->DoPositionUpdate(0);

    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = 0; }),
                Return(ERROR)
            )
        );
    lppAudioCallbackLooper_->obs_ = obsMock;
    lppAudioCallbackLooper_->engine_ = engineMock;
    lppAudioCallbackLooper_->DoPositionUpdate(0);

    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = 0; }),
                Return(MSERR_OK)
            )
        );
    lppAudioCallbackLooper_->obs_ = obsMock;
    lppAudioCallbackLooper_->engine_ = engineMock;
    lppAudioCallbackLooper_->DoPositionUpdate(0);

    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = Plugins::HST_TIME_NONE; }),
                Return(MSERR_OK)
            )
        );
    lppAudioCallbackLooper_->obs_ = obsMock;
    lppAudioCallbackLooper_->engine_ = engineMock;
    lppAudioCallbackLooper_->DoPositionUpdate(0);

    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = Plugins::HST_TIME_NONE; }),
                Return(ERROR)
            )
        );
    lppAudioCallbackLooper_->obs_ = obsMock;
    lppAudioCallbackLooper_->engine_ = engineMock;
    lppAudioCallbackLooper_->DoPositionUpdate(0);

    int32_t res = -1;
    int64_t pos = -1;
    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = 0; }),
                Return(MSERR_OK)
            )
        );
    res = engineMock->GetCurrentPosition(pos);
    EXPECT_EQ(res, MSERR_OK);
    EXPECT_EQ(pos, 0);
}

/**
* @tc.name    : Test DoPositionUpdate API
* @tc.number  : DoPositionUpdate_004
* @tc.desc    : Test DoPositionUpdate
*/
HWTEST_F(LppAudioCallbackLooperUnitTest, DoPositionUpdate_004, TestSize.Level0)
{
    lppAudioCallbackLooper_->positionUpdateIdx_.store(0);
    std::shared_ptr<ILppAudioStreamerEngine> engineMock = std::make_shared<ILppAudioStreamerEngine>();
    std::shared_ptr<ILppAudioStreamerEngineObs> obsMock = std::make_shared<ILppAudioStreamerEngineObs>();
    lppAudioCallbackLooper_->task_ = nullptr;
    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = 0; }),
                Return(MSERR_OK)
            )
        );
    EXPECT_CALL(*obsMock, OnPositionUpdated(_)).Times(2);
    lppAudioCallbackLooper_->obs_ = obsMock;
    lppAudioCallbackLooper_->engine_ = engineMock;
    lppAudioCallbackLooper_->DoPositionUpdate(0);

    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = 0; }),
                Return(ERROR)
            )
        );
    lppAudioCallbackLooper_->obs_ = obsMock;
    lppAudioCallbackLooper_->engine_ = engineMock;
    lppAudioCallbackLooper_->DoPositionUpdate(0);

    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = 0; }),
                Return(MSERR_OK)
            )
        );
    lppAudioCallbackLooper_->obs_ = obsMock;
    lppAudioCallbackLooper_->engine_ = engineMock;
    lppAudioCallbackLooper_->DoPositionUpdate(0);

    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = Plugins::HST_TIME_NONE; }),
                Return(MSERR_OK)
            )
        );
    lppAudioCallbackLooper_->obs_ = obsMock;
    lppAudioCallbackLooper_->engine_ = engineMock;
    lppAudioCallbackLooper_->DoPositionUpdate(0);

    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = Plugins::HST_TIME_NONE; }),
                Return(ERROR)
            )
        );
    lppAudioCallbackLooper_->obs_ = obsMock;
    lppAudioCallbackLooper_->engine_ = engineMock;
    lppAudioCallbackLooper_->DoPositionUpdate(0);

    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = Plugins::HST_TIME_NONE; }),
                Return(MSERR_OK)
            )
        );
    lppAudioCallbackLooper_->obs_ = obsMock;
    lppAudioCallbackLooper_->engine_ = engineMock;
    lppAudioCallbackLooper_->DoPositionUpdate(0);

    int32_t res = -1;
    int64_t pos = -1;
    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = 0; }),
                Return(MSERR_OK)
            )
        );
    res = engineMock->GetCurrentPosition(pos);
    EXPECT_EQ(res, MSERR_OK);
    EXPECT_EQ(pos, 0);
}

/**
* @tc.name    : Test DoPositionUpdate API
* @tc.number  : DoPositionUpdate_005
* @tc.desc    : Test DoPositionUpdate
*/
HWTEST_F(LppAudioCallbackLooperUnitTest, DoPositionUpdate_005, TestSize.Level0)
{
    lppAudioCallbackLooper_->positionUpdateIdx_.store(0);
    std::shared_ptr<ILppAudioStreamerEngine> engineMock = std::make_shared<ILppAudioStreamerEngine>();
    std::shared_ptr<ILppAudioStreamerEngineObs> obsMock = std::make_shared<ILppAudioStreamerEngineObs>();
    lppAudioCallbackLooper_->task_ = nullptr;
    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = 0; }),
                Return(MSERR_OK)
            )
        );
    EXPECT_CALL(*obsMock, OnPositionUpdated(_)).Times(2);
    lppAudioCallbackLooper_->obs_ = obsMock;
    lppAudioCallbackLooper_->engine_ = engineMock;
    lppAudioCallbackLooper_->DoPositionUpdate(0);

    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = 0; }),
                Return(MSERR_OK)
            )
        );
    lppAudioCallbackLooper_->obs_ = obsMock;
    lppAudioCallbackLooper_->engine_ = engineMock;
    lppAudioCallbackLooper_->DoPositionUpdate(0);

    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = Plugins::HST_TIME_NONE; }),
                Return(MSERR_OK)
            )
        );
    lppAudioCallbackLooper_->obs_ = obsMock;
    lppAudioCallbackLooper_->engine_ = engineMock;
    lppAudioCallbackLooper_->DoPositionUpdate(0);

    int32_t res = -1;
    int64_t pos = -1;
    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = 0; }),
                Return(MSERR_OK)
            )
        );
    res = engineMock->GetCurrentPosition(pos);
    EXPECT_EQ(res, MSERR_OK);
    EXPECT_EQ(pos, 0);
}

/**
* @tc.name    : Test DoPositionUpdate API
* @tc.number  : DoPositionUpdate_006
* @tc.desc    : Test DoPositionUpdate
*/
HWTEST_F(LppAudioCallbackLooperUnitTest, DoPositionUpdate_006, TestSize.Level0)
{
    lppAudioCallbackLooper_->positionUpdateIdx_.store(0);
    std::shared_ptr<ILppAudioStreamerEngine> engineMock = std::make_shared<ILppAudioStreamerEngine>();
    std::shared_ptr<ILppAudioStreamerEngineObs> obsMock = std::make_shared<ILppAudioStreamerEngineObs>();
    lppAudioCallbackLooper_->task_ = nullptr;
    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = 0; }),
                Return(MSERR_OK)
            )
        );
    EXPECT_CALL(*obsMock, OnPositionUpdated(_)).Times(2);
    lppAudioCallbackLooper_->obs_ = obsMock;
    lppAudioCallbackLooper_->engine_ = engineMock;
    lppAudioCallbackLooper_->DoPositionUpdate(0);

    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = 0; }),
                Return(MSERR_OK)
            )
        );
    lppAudioCallbackLooper_->obs_ = obsMock;
    lppAudioCallbackLooper_->engine_ = engineMock;
    lppAudioCallbackLooper_->DoPositionUpdate(0);

    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = 0; }),
                Return(ERROR)
            )
        );
    lppAudioCallbackLooper_->obs_ = obsMock;
    lppAudioCallbackLooper_->engine_ = engineMock;
    lppAudioCallbackLooper_->DoPositionUpdate(0);

    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = Plugins::HST_TIME_NONE; }),
                Return(MSERR_OK)
            )
        );
    lppAudioCallbackLooper_->obs_ = obsMock;
    lppAudioCallbackLooper_->engine_ = engineMock;
    lppAudioCallbackLooper_->DoPositionUpdate(0);

    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = Plugins::HST_TIME_NONE; }),
                Return(ERROR)
            )
        );
    lppAudioCallbackLooper_->obs_ = obsMock;
    lppAudioCallbackLooper_->engine_ = engineMock;
    lppAudioCallbackLooper_->DoPositionUpdate(0);

    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = Plugins::HST_TIME_NONE; }),
                Return(MSERR_OK)
            )
        );
    lppAudioCallbackLooper_->obs_ = obsMock;
    lppAudioCallbackLooper_->engine_ = engineMock;
    lppAudioCallbackLooper_->DoPositionUpdate(0);

    int32_t res = -1;
    int64_t pos = -1;
    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = 0; }),
                Return(MSERR_OK)
            )
        );
    res = engineMock->GetCurrentPosition(pos);
    EXPECT_EQ(res, MSERR_OK);
    EXPECT_EQ(pos, 0);
}

/**
* @tc.name    : Test DoPositionUpdate API
* @tc.number  : DoPositionUpdate_007
* @tc.desc    : Test DoPositionUpdate
*/
HWTEST_F(LppAudioCallbackLooperUnitTest, DoPositionUpdate_007, TestSize.Level0)
{
    lppAudioCallbackLooper_->positionUpdateIdx_.store(0);
    std::shared_ptr<ILppAudioStreamerEngine> engineMock = std::make_shared<ILppAudioStreamerEngine>();
    std::shared_ptr<ILppAudioStreamerEngineObs> obsMock = std::make_shared<ILppAudioStreamerEngineObs>();
    lppAudioCallbackLooper_->task_ = nullptr;
    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = 0; }),
                Return(MSERR_OK)
            )
        );
    EXPECT_CALL(*obsMock, OnPositionUpdated(_)).Times(3);
    lppAudioCallbackLooper_->obs_ = obsMock;
    lppAudioCallbackLooper_->engine_ = engineMock;
    lppAudioCallbackLooper_->DoPositionUpdate(0);

    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = 0; }),
                Return(MSERR_OK)
            )
        );
    lppAudioCallbackLooper_->obs_ = obsMock;
    lppAudioCallbackLooper_->engine_ = engineMock;
    lppAudioCallbackLooper_->DoPositionUpdate(0);

    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = 0; }),
                Return(MSERR_OK)
            )
        );
    lppAudioCallbackLooper_->obs_ = obsMock;
    lppAudioCallbackLooper_->engine_ = engineMock;
    lppAudioCallbackLooper_->DoPositionUpdate(0);

    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = Plugins::HST_TIME_NONE; }),
                Return(MSERR_OK)
            )
        );
    lppAudioCallbackLooper_->obs_ = obsMock;
    lppAudioCallbackLooper_->engine_ = engineMock;
    lppAudioCallbackLooper_->DoPositionUpdate(0);

    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = Plugins::HST_TIME_NONE; }),
                Return(MSERR_OK)
            )
        );
    lppAudioCallbackLooper_->obs_ = obsMock;
    lppAudioCallbackLooper_->engine_ = engineMock;
    lppAudioCallbackLooper_->DoPositionUpdate(0);

    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = Plugins::HST_TIME_NONE; }),
                Return(MSERR_OK)
            )
        );
    lppAudioCallbackLooper_->obs_ = obsMock;
    lppAudioCallbackLooper_->engine_ = engineMock;
    lppAudioCallbackLooper_->DoPositionUpdate(0);

    int32_t res = -1;
    int64_t pos = -1;
    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = 0; }),
                Return(MSERR_OK)
            )
        );
    res = engineMock->GetCurrentPosition(pos);
    EXPECT_EQ(res, MSERR_OK);
    EXPECT_EQ(pos, 0);
}

/**
* @tc.name    : Test DoPositionUpdate API
* @tc.number  : DoPositionUpdate_008
* @tc.desc    : Test DoPositionUpdate
*/
HWTEST_F(LppAudioCallbackLooperUnitTest, DoPositionUpdate_008, TestSize.Level0)
{
    lppAudioCallbackLooper_->positionUpdateIdx_.store(0);
    std::shared_ptr<ILppAudioStreamerEngine> engineMock = std::make_shared<ILppAudioStreamerEngine>();
    std::shared_ptr<ILppAudioStreamerEngineObs> obsMock = std::make_shared<ILppAudioStreamerEngineObs>();
    lppAudioCallbackLooper_->task_ = nullptr;
    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = 0; }),
                Return(MSERR_OK)
            )
        );
    EXPECT_CALL(*obsMock, OnPositionUpdated(_)).Times(1);
    lppAudioCallbackLooper_->obs_ = obsMock;
    lppAudioCallbackLooper_->engine_ = engineMock;
    lppAudioCallbackLooper_->DoPositionUpdate(0);

    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = 0; }),
                Return(ERROR)
            )
        );
    lppAudioCallbackLooper_->obs_ = obsMock;
    lppAudioCallbackLooper_->engine_ = engineMock;
    lppAudioCallbackLooper_->DoPositionUpdate(0);

    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = 0; }),
                Return(ERROR)
            )
        );
    lppAudioCallbackLooper_->obs_ = obsMock;
    lppAudioCallbackLooper_->engine_ = engineMock;
    lppAudioCallbackLooper_->DoPositionUpdate(0);

    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = Plugins::HST_TIME_NONE; }),
                Return(ERROR)
            )
        );
    lppAudioCallbackLooper_->obs_ = obsMock;
    lppAudioCallbackLooper_->engine_ = engineMock;
    lppAudioCallbackLooper_->DoPositionUpdate(0);

    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = Plugins::HST_TIME_NONE; }),
                Return(ERROR)
            )
        );
    lppAudioCallbackLooper_->obs_ = obsMock;
    lppAudioCallbackLooper_->engine_ = engineMock;
    lppAudioCallbackLooper_->DoPositionUpdate(0);

    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = Plugins::HST_TIME_NONE; }),
                Return(MSERR_OK)
            )
        );
    lppAudioCallbackLooper_->obs_ = obsMock;
    lppAudioCallbackLooper_->engine_ = engineMock;
    lppAudioCallbackLooper_->DoPositionUpdate(0);

    int32_t res = -1;
    int64_t pos = -1;
    EXPECT_CALL(*engineMock, GetCurrentPosition(_))
        .WillOnce(
            DoAll(
                Invoke([](int64_t &currentPosition) { currentPosition = 0; }),
                Return(MSERR_OK)
            )
        );
    res = engineMock->GetCurrentPosition(pos);
    EXPECT_EQ(res, MSERR_OK);
    EXPECT_EQ(pos, 0);
}

} // namespace Media
} // namespace OHOS