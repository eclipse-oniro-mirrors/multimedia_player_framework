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

#include "media_server_manager_test.h"
#include "media_errors.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing::ext;

void MediaServerManagerTest::SetUpTestCase(void)
{
}

void MediaServerManagerTest::TearDownTestCase(void)
{
}

void MediaServerManagerTest::SetUp(void)
{
}

void MediaServerManagerTest::TearDown(void)
{
}

/**
 * @tc.name  : DestroyStubObject
 * @tc.number: DestroyStubObject
 * @tc.desc  : FUNC
 */
HWTEST_F(MediaServerManagerTest, DestroyStubObject, TestSize.Level1)
{
    sptr<IRemoteObject> recorder =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::RECORDER);
    EXPECT_NE(recorder, nullptr);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::RECORDER, recorder);
    sptr<IRemoteObject> player =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::PLAYER);
    EXPECT_NE(player, nullptr);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::PLAYER, player);
    sptr<IRemoteObject> avmetadatahelper =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::AVMETADATAHELPER);
    EXPECT_NE(avmetadatahelper, nullptr);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::AVMETADATAHELPER, avmetadatahelper);
    sptr<IRemoteObject> avcodecList =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::AVCODECLIST);
    EXPECT_NE(avcodecList, nullptr);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::AVCODECLIST, avcodecList);
    sptr<IRemoteObject> avcodec =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::AVCODEC);
    EXPECT_NE(avcodec, nullptr);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::AVCODEC, avcodec);
    sptr<IRemoteObject> recorderProfiles =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::RECORDERPROFILES);
    EXPECT_NE(recorderProfiles, nullptr);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::RECORDERPROFILES, recorderProfiles);
    sptr<IRemoteObject> monitor =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::MONITOR);
    EXPECT_NE(monitor, nullptr);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::MONITOR, monitor);
    sptr<IRemoteObject> screenCapture =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::SCREEN_CAPTURE);
    EXPECT_NE(screenCapture, nullptr);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::SCREEN_CAPTURE, screenCapture);
    sptr<IRemoteObject> screenCaptureController =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::SCREEN_CAPTURE_CONTROLLER);
    EXPECT_NE(screenCaptureController, nullptr);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::SCREEN_CAPTURE_CONTROLLER,
        screenCaptureController);
    sptr<IRemoteObject> transcoder =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::TRANSCODER);
    EXPECT_NE(transcoder, nullptr);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::TRANSCODER, transcoder);
    sptr<IRemoteObject> screenCaptureMonitor =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::SCREEN_CAPTURE_MONITOR);
    EXPECT_NE(screenCaptureMonitor, nullptr);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::SCREEN_CAPTURE_MONITOR,
        screenCaptureMonitor);
}

/**
 * @tc.name  : DestroyStubObjectByPid
 * @tc.number: DestroyStubObjectByPid
 * @tc.desc  : FUNC
 */
HWTEST_F(MediaServerManagerTest, DestroyStubObjectByPid, TestSize.Level1)
{
    sptr<IRemoteObject> recorder =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::RECORDER);
    EXPECT_NE(recorder, nullptr);
    sptr<IRemoteObject> player =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::PLAYER);
    EXPECT_NE(player, nullptr);
    sptr<IRemoteObject> avmetadatahelper =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::AVMETADATAHELPER);
    EXPECT_NE(avmetadatahelper, nullptr);
    sptr<IRemoteObject> avcodecList =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::AVCODECLIST);
    EXPECT_NE(avcodecList, nullptr);
    sptr<IRemoteObject> avcodec =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::AVCODEC);
    EXPECT_NE(avcodec, nullptr);
    sptr<IRemoteObject> recorderProfiles =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::RECORDERPROFILES);
    EXPECT_NE(recorderProfiles, nullptr);
    sptr<IRemoteObject> monitor =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::MONITOR);
    EXPECT_NE(monitor, nullptr);
    sptr<IRemoteObject> screenCapture =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::SCREEN_CAPTURE);
    EXPECT_NE(screenCapture, nullptr);
    sptr<IRemoteObject> screenCaptureController =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::SCREEN_CAPTURE_CONTROLLER);
    EXPECT_NE(screenCaptureController, nullptr);
    sptr<IRemoteObject> transcoder =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::TRANSCODER);
    EXPECT_NE(transcoder, nullptr);
    sptr<IRemoteObject> screenCaptureMonitor =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::SCREEN_CAPTURE_MONITOR);
    EXPECT_NE(screenCaptureMonitor, nullptr);
    pid_t pid = IPCSkeleton::GetCallingPid();
    MediaServerManager::GetInstance().DestroyStubObjectForPid(pid);
}
}
}