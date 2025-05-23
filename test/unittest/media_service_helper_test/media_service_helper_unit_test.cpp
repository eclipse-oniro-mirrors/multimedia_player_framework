/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "media_service_helper_unit_test.h"
#include "media_errors.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {

void MediaServiceHelperUnitTest::SetUpTestCase(void)
{
}

void MediaServiceHelperUnitTest::TearDownTestCase(void)
{
}

void MediaServiceHelperUnitTest::SetUp(void)
{
}

void MediaServiceHelperUnitTest::TearDown(void)
{
}

HWTEST_F(MediaServiceHelperUnitTest, CanKillMediaService_001, TestSize.Level0)
{
    EXPECT_TRUE(MediaServiceHelper::CanKillMediaService());
}

HWTEST_F(MediaServiceHelperUnitTest, CanKillMediaService_002, TestSize.Level0)
{
    std::shared_ptr<Player> player = PlayerFactory::CreatePlayer();
    EXPECT_TRUE(MediaServiceHelper::CanKillMediaService());
}

HWTEST_F(MediaServiceHelperUnitTest, CanKillMediaService_003, TestSize.Level0)
{
    std::shared_ptr<Player> player = PlayerFactory::CreatePlayer();
    std::shared_ptr<Recorder> recoder = RecorderFactory::CreateRecorder();
    EXPECT_FALSE(MediaServiceHelper::CanKillMediaService());
}

HWTEST_F(MediaServiceHelperUnitTest, CanKillMediaService_004, TestSize.Level0)
{
    std::shared_ptr<Player> player = PlayerFactory::CreatePlayer();
    std::shared_ptr<IRecorderProfilesService> recorderProfilesService =
        MediaServiceFactory::GetInstance().CreateRecorderProfilesService();
    EXPECT_FALSE(MediaServiceHelper::CanKillMediaService());
}

HWTEST_F(MediaServiceHelperUnitTest, CanKillMediaService_005, TestSize.Level0)
{
    std::shared_ptr<Player> player = PlayerFactory::CreatePlayer();
    std::shared_ptr<ScreenCapture> screenCapture = ScreenCaptureFactory::CreateScreenCapture();
    EXPECT_FALSE(MediaServiceHelper::CanKillMediaService());
}

HWTEST_F(MediaServiceHelperUnitTest, CanKillMediaService_006, TestSize.Level0)
{
    std::shared_ptr<Player> player = PlayerFactory::CreatePlayer();
    std::shared_ptr<ScreenCaptureController> controller =
        ScreenCaptureControllerFactory::CreateScreenCaptureController();
    std::shared_ptr<IScreenCaptureController> controllerClient =
        MediaServiceFactory::GetInstance().CreateScreenCaptureControllerClient();
    EXPECT_FALSE(MediaServiceHelper::CanKillMediaService());
}

HWTEST_F(MediaServiceHelperUnitTest, CanKillMediaService_007, TestSize.Level0)
{
    std::shared_ptr<Player> player = PlayerFactory::CreatePlayer();
    std::shared_ptr<TransCoder> transCoder = TransCoderFactory::CreateTransCoder();
    EXPECT_FALSE(MediaServiceHelper::CanKillMediaService());
}

HWTEST_F(MediaServiceHelperUnitTest, CanKillMediaService_008, TestSize.Level0)
{
    std::shared_ptr<Player> player = PlayerFactory::CreatePlayer();
    std::shared_ptr<AVMetadataHelper> avMetadata = AVMetadataHelperFactory::CreateAVMetadataHelper();
    EXPECT_FALSE(MediaServiceHelper::CanKillMediaService());
}

} // namespace Media
} // namespace OHOS