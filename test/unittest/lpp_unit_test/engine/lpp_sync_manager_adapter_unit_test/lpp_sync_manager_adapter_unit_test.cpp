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


#include "gtest/gtest.h"
#include "lpp_sync_manager_adapter_unit_test.h"
#include "media_lpp_errors.h"


using namespace std;
using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace Media {
using namespace OHOS::HDI::Base;
void LppSyncManagerAdapterUnitTest::SetUpTestCase(void)
{
}

void LppSyncManagerAdapterUnitTest::TearDownTestCase(void)
{
}

void LppSyncManagerAdapterUnitTest::SetUp(void)
{
    lppSyncManagerAdapter_ = std::make_shared<LppSyncManagerAdapter>();
    mockEventReceiver_ = std::make_shared<Pipeline::MockEventReceiver>();
}

void LppSyncManagerAdapterUnitTest::TearDown(void)
{
    lppSyncManagerAdapter_ = nullptr;
}

/**
* @tc.name    : Test OnError API
* @tc.number  : OnError_001
* @tc.desc    : Test OnError interface
*/
HWTEST_F(LppSyncManagerAdapterUnitTest, OnError_001, TestSize.Level0)
{
    int32_t errorCode = HDF_ERR_OK;
    string str = "";
    EXPECT_CALL(*mockEventReceiver_, OnEvent(_)).Times(0);
    lppSyncManagerAdapter_->eventReceiver_ = mockEventReceiver_;
    lppSyncManagerAdapter_->OnError(errorCode, str);
}

/**
* @tc.name    : Test BindOutputBuffers API
* @tc.number  : BindOutputBuffers_001
* @tc.desc    : Test BindOutputBuffers interface
*/
HWTEST_F(LppSyncManagerAdapterUnitTest, BindOutputBuffers_001, TestSize.Level0)
{
    std::map<uint32_t, sptr<SurfaceBuffer>> bufferMap;
    bufferMap[0] = nullptr;
    int32_t res = lppSyncManagerAdapter_->BindOutputBuffers(bufferMap);
    EXPECT_NE(res, MSERR_OK);
}

}  // namespace Media
}  // namespace OHOS