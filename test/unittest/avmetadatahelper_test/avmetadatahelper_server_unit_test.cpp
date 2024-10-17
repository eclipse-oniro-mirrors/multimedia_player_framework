/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "avmetadatahelper_server_unit_test.h"
#include "avmetadatahelper_server.h"
#include "media_log.h"
#include "media_errors.h"
#include "engine_factory_repo.h"
#include "uri_helper.h"
#include "media_dfx.h"
#include "ipc_skeleton.h"

using namespace OHOS;
using namespace OHOS::Media;
using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {
namespace Test {
void AVMetadataHelperServerUnitTest::SetUpTestCase(void) {}

void AVMetadataHelperServerUnitTest::TearDownTestCase(void) {}

void AVMetadataHelperServerUnitTest::SetUp(void)
{
    avmetadataHelperServer_ = std::make_shared<AVMetadataHelperServer>();
}

void AVMetadataHelperServerUnitTest::TearDown(void)
{
    avmetadataHelperServer_ = nullptr;
}

/**
 * @tc.name: SetHelperCallback
 * @tc.desc: SetHelperCallback
 * @tc.type: FUNC
 */
HWTEST_F(AVMetadataHelperServerUnitTest, SetHelperCallback, TestSize.Level1)
{
    std::shared_ptr<HelperCallback> callback = std::make_shared<TestHelperCallback>();
    avmetadataHelperServer_->currState_ = HelperStates::HELPER_IDLE;
    int32_t ret = avmetadataHelperServer_->SetHelperCallback(callback);
    avmetadataHelperServer_->currState_ = HelperStates::HELPER_STATE_ERROR;
    ret = avmetadataHelperServer_->SetHelperCallback(callback);
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/**
 * @tc.name: ChangeState
 * @tc.desc: ChangeState
 * @tc.type: FUNC
 */
HWTEST_F(AVMetadataHelperServerUnitTest, ChangeState, TestSize.Level1)
{
    HelperStates state = HelperStates::HELPER_STATE_ERROR;
    avmetadataHelperServer_->ChangeState(state);
    state = HelperStates::HELPER_PREPARED;
    avmetadataHelperServer_->currState_ = HelperStates::HELPER_IDLE;
    avmetadataHelperServer_->ChangeState(state);
    avmetadataHelperServer_->currState_ = HelperStates::HELPER_RELEASED;
    avmetadataHelperServer_->ChangeState(state);
    state = HelperStates::HELPER_CALL_DONE;
    avmetadataHelperServer_->currState_ = HelperStates::HELPER_CALL_DONE;
    avmetadataHelperServer_->ChangeState(state);
    avmetadataHelperServer_->currState_ = HelperStates::HELPER_PREPARED;
    avmetadataHelperServer_->ChangeState(state);
    state = HelperStates::HELPER_RELEASED;
    avmetadataHelperServer_->currState_ = HelperStates::HELPER_IDLE;
    avmetadataHelperServer_->ChangeState(state);
    avmetadataHelperServer_->currState_ = HelperStates::HELPER_PREPARED;
    avmetadataHelperServer_->ChangeState(state);
    avmetadataHelperServer_->currState_ = HelperStates::HELPER_CALL_DONE;
    avmetadataHelperServer_->ChangeState(state);
    state = HelperStates::HELPER_STATE_ERROR;
    avmetadataHelperServer_->ChangeState(state);
    EXPECT_EQ(avmetadataHelperServer_->currState_, HelperStates::HELPER_STATE_ERROR);
}

/**
 * @tc.name: NotifyErrorCallback
 * @tc.desc: NotifyErrorCallback
 * @tc.type: FUNC
 */
HWTEST_F(AVMetadataHelperServerUnitTest, NotifyErrorCallback, TestSize.Level1)
{
    int32_t code = 0;
    const std::string msg = "test";
    avmetadataHelperServer_->helperCb_ = nullptr;
    avmetadataHelperServer_->NotifyErrorCallback(code, msg);
    avmetadataHelperServer_->helperCb_ = std::make_shared<TestHelperCallback>();
    avmetadataHelperServer_->NotifyErrorCallback(code, msg);
    EXPECT_EQ(avmetadataHelperServer_->isLiveStream_, false);
}

/**
 * @tc.name: GetStatusDescription
 * @tc.desc: GetStatusDescription
 * @tc.type: FUNC
 */
HWTEST_F(AVMetadataHelperServerUnitTest, GetStatusDescription, TestSize.Level1)
{
    int32_t status = -1;
    avmetadataHelperServer_->GetStatusDescription(status);
    status = 5;
    avmetadataHelperServer_->GetStatusDescription(status);
    status = 2;
    avmetadataHelperServer_->GetStatusDescription(status);
    EXPECT_EQ(avmetadataHelperServer_->isLiveStream_, false);
}
}  // namespace Test
}  // namespace Media
}  // namespace OHOS