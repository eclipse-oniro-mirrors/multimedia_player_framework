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
using namespace testing;
using namespace testing::ext;

static const int32_t PID_TEST = 12345;

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
 * @tc.name  : FreezeStubForPids_001
 * @tc.number: FreezeStubForPids_001
 * @tc.desc  : Test FreezeStubForPids interface
 */
HWTEST_F(MediaServerManagerTest, FreezeStubForPids_001, TestSize.Level1)
{
    sptr<IRemoteObject> player =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::PLAYER);
    ASSERT_NE(player, nullptr);
    int32_t pid = IPCSkeleton::GetCallingPid();
    std::set<int32_t> pidList;
    pidList.insert(pid);
    auto isProxy = true;
    auto ret = MediaServerManager::GetInstance().FreezeStubForPids(pidList, isProxy);
    EXPECT_EQ(ret, 0);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::PLAYER, player);
}

/**
 * @tc.name  : FreezeStubForPids_002
 * @tc.number: FreezeStubForPids_002
 * @tc.desc  : Test FreezeStubForPids interface
 */
HWTEST_F(MediaServerManagerTest, FreezeStubForPids_002, TestSize.Level1)
{
    sptr<IRemoteObject> player =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::PLAYER);
    ASSERT_NE(player, nullptr);
    std::set<int32_t> pidList;
    pidList.insert(PID_TEST);
    auto isProxy = true;
    auto ret = MediaServerManager::GetInstance().FreezeStubForPids(pidList, isProxy);
    EXPECT_EQ(ret, 0);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::PLAYER, player);
}

/**
 * @tc.name  : FreezeStubForPids_003
 * @tc.number: FreezeStubForPids_003
 * @tc.desc  : Test FreezeStubForPids interface
 */
HWTEST_F(MediaServerManagerTest, FreezeStubForPids_003, TestSize.Level1)
{
    sptr<IRemoteObject> player =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::PLAYER);
    ASSERT_NE(player, nullptr);
    int32_t pid = IPCSkeleton::GetCallingPid();
    std::set<int32_t> pidList;
    pidList.insert(pid);
    auto isProxy = false;
    auto ret = MediaServerManager::GetInstance().FreezeStubForPids(pidList, isProxy);
    EXPECT_EQ(ret, 0);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::PLAYER, player);
}

/**
 * @tc.name  : ResetAllProxy_001
 * @tc.number: ResetAllProxy_001
 * @tc.desc  : Test ResetAllProxy interface
 */
HWTEST_F(MediaServerManagerTest, ResetAllProxy, TestSize.Level1)
{
    sptr<IRemoteObject> player =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::PLAYER);
    ASSERT_NE(player, nullptr);
    auto ret = MediaServerManager::GetInstance().ResetAllProxy();
    EXPECT_EQ(ret, 0);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::PLAYER, player);
}

/**
 * @tc.name  : DestroyStubObject_001
 * @tc.number: DestroyStubObject_001
 * @tc.desc  : Test DestroyStubObject interface
 */
HWTEST_F(MediaServerManagerTest, DestroyStubObject_001, TestSize.Level1)
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
    EXPECT_EQ(avcodecList, nullptr);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::AVCODECLIST, avcodecList);
    sptr<IRemoteObject> avcodec =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::AVCODEC);
    EXPECT_EQ(avcodec, nullptr);
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
 * @tc.name  : DestroyStubObjectForPid_001
 * @tc.number: DestroyStubObjectForPid_001
 * @tc.desc  : Test DestroyStubObjectForPid interface
 */
HWTEST_F(MediaServerManagerTest, DestroyStubObjectForPid_001, TestSize.Level1)
{
    sptr<IRemoteObject> recorder =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::RECORDER);
    EXPECT_NE(recorder, nullptr);
    pid_t pid = IPCSkeleton::GetCallingPid();
    MediaServerManager::GetInstance().DestroyStubObjectForPid(pid);
    EXPECT_EQ(MediaServerManager::GetInstance().recorderStubMap_.size(), 0);
}

/**
 * @tc.name  : DestroyAVPlayerStubForPid_001
 * @tc.number: DestroyAVPlayerStubForPid_001
 * @tc.desc  : Test DestroyAVPlayerStubForPid interface
 */
HWTEST_F(MediaServerManagerTest, DestroyAVPlayerStubForPid_001, TestSize.Level1)
{
    sptr<MockMonitorServiceStub> mockMonitorServiceStub = new (std::nothrow) MockMonitorServiceStub();
    ASSERT_NE(mockMonitorServiceStub, nullptr);
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    sptr<IRemoteObject> object = mockMonitorServiceStub->AsObject();
    ASSERT_NE(object, nullptr);
    pid_t testPid = PID_TEST;
    mediaServerManager.avMetadataHelperStubMap_[object] = testPid;
    ASSERT_EQ(mediaServerManager.avMetadataHelperStubMap_.size(), 1);
    mediaServerManager.DestroyAVPlayerStubForPid(testPid);
    ASSERT_EQ(mediaServerManager.avMetadataHelperStubMap_.size(), 0);
}

/**
 * @tc.name  : DestroyAVRecorderStubForPid_001
 * @tc.number: DestroyAVRecorderStubForPid_001
 * @tc.desc  : Test DestroyAVRecorderStubForPid interface
 */
HWTEST_F(MediaServerManagerTest, DestroyAVRecorderStubForPid_001, TestSize.Level1)
{
    sptr<MockMonitorServiceStub> mockMonitorServiceStub = new (std::nothrow) MockMonitorServiceStub();
    ASSERT_NE(mockMonitorServiceStub, nullptr);
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    sptr<IRemoteObject> object = mockMonitorServiceStub->AsObject();
    ASSERT_NE(object, nullptr);
    pid_t testPid = PID_TEST;
    mediaServerManager.recorderStubMap_[object] = testPid;
    ASSERT_EQ(mediaServerManager.recorderStubMap_.size(), 1);
    mediaServerManager.DestroyAVRecorderStubForPid(testPid);
    ASSERT_EQ(mediaServerManager.recorderStubMap_.size(), 0);
}

/**
 * @tc.name  : DestroyAVRecorderStubForPid_002
 * @tc.number: DestroyAVRecorderStubForPid_002
 * @tc.desc  : Test DestroyAVRecorderStubForPid interface
 */
HWTEST_F(MediaServerManagerTest, DestroyAVRecorderStubForPid_002, TestSize.Level1)
{
    sptr<MockMonitorServiceStub> mockMonitorServiceStub = new (std::nothrow) MockMonitorServiceStub();
    ASSERT_NE(mockMonitorServiceStub, nullptr);
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    sptr<IRemoteObject> object = mockMonitorServiceStub->AsObject();
    ASSERT_NE(object, nullptr);
    pid_t testPid = PID_TEST;
    mediaServerManager.recorderProfilesStubMap_[object] = testPid;
    ASSERT_EQ(mediaServerManager.recorderProfilesStubMap_.size(), 1);
    mediaServerManager.DestroyAVRecorderStubForPid(testPid);
    ASSERT_EQ(mediaServerManager.recorderProfilesStubMap_.size(), 0);
}

/**
 * @tc.name  : DestroyAVTranscoderStubForPid_001
 * @tc.number: DestroyAVTranscoderStubForPid_001
 * @tc.desc  : Test DestroyAVTranscoderStubForPid interface
 */
HWTEST_F(MediaServerManagerTest, DestroyAVTranscoderStubForPid_001, TestSize.Level1)
{
    sptr<MockMonitorServiceStub> mockMonitorServiceStub = new (std::nothrow) MockMonitorServiceStub();
    ASSERT_NE(mockMonitorServiceStub, nullptr);
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    sptr<IRemoteObject> object = mockMonitorServiceStub->AsObject();
    ASSERT_NE(object, nullptr);
    pid_t testPid = PID_TEST;
    mediaServerManager.transCoderStubMap_[object] = testPid;
    ASSERT_EQ(mediaServerManager.transCoderStubMap_.size(), 1);
    mediaServerManager.DestroyAVTranscoderStubForPid(testPid);
    ASSERT_EQ(mediaServerManager.transCoderStubMap_.size(), 0);
}

/**
 * @tc.name  : DestroyAVCodecStubForPid_001
 * @tc.number: DestroyAVCodecStubForPid_001
 * @tc.desc  : Test DestroyAVCodecStubForPid interface
 */
HWTEST_F(MediaServerManagerTest, DestroyAVCodecStubForPid_001, TestSize.Level1)
{
    sptr<MockMonitorServiceStub> mockMonitorServiceStub = new (std::nothrow) MockMonitorServiceStub();
    ASSERT_NE(mockMonitorServiceStub, nullptr);
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    sptr<IRemoteObject> object = mockMonitorServiceStub->AsObject();
    ASSERT_NE(object, nullptr);
    pid_t testPid = PID_TEST;
    mediaServerManager.avCodecStubMap_[object] = testPid;
    ASSERT_EQ(mediaServerManager.avCodecStubMap_.size(), 1);
    mediaServerManager.DestroyAVCodecStubForPid(testPid);
    ASSERT_EQ(mediaServerManager.avCodecStubMap_.size(), 0);
}

/**
 * @tc.name  : DestroyAVCodecStubForPid_002
 * @tc.number: DestroyAVCodecStubForPid_002
 * @tc.desc  : Test DestroyAVCodecStubForPid interface
 */
HWTEST_F(MediaServerManagerTest, DestroyAVCodecStubForPid_002, TestSize.Level1)
{
    sptr<MockMonitorServiceStub> mockMonitorServiceStub = new (std::nothrow) MockMonitorServiceStub();
    ASSERT_NE(mockMonitorServiceStub, nullptr);
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    sptr<IRemoteObject> object = mockMonitorServiceStub->AsObject();
    ASSERT_NE(object, nullptr);
    pid_t testPid = PID_TEST;
    mediaServerManager.avCodecListStubMap_[object] = testPid;
    ASSERT_EQ(mediaServerManager.avCodecListStubMap_.size(), 1);
    mediaServerManager.DestroyAVCodecStubForPid(testPid);
    ASSERT_EQ(mediaServerManager.avCodecListStubMap_.size(), 0);
}

/**
 * @tc.name  : DestroyAVScreenCaptureStubForPid_001
 * @tc.number: DestroyAVScreenCaptureStubForPid_001
 * @tc.desc  : Test DestroyAVScreenCaptureStubForPid interface
 */
HWTEST_F(MediaServerManagerTest, DestroyAVScreenCaptureStubForPid_001, TestSize.Level1)
{
    sptr<MockMonitorServiceStub> mockMonitorServiceStub = new (std::nothrow) MockMonitorServiceStub();
    ASSERT_NE(mockMonitorServiceStub, nullptr);
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    sptr<IRemoteObject> object = mockMonitorServiceStub->AsObject();
    ASSERT_NE(object, nullptr);
    pid_t testPid = PID_TEST;
    mediaServerManager.screenCaptureStubMap_[object] = testPid;
    ASSERT_EQ(mediaServerManager.screenCaptureStubMap_.size(), 1);
    mediaServerManager.DestroyAVScreenCaptureStubForPid(testPid);
    ASSERT_EQ(mediaServerManager.screenCaptureStubMap_.size(), 0);
}

/**
 * @tc.name  : DestroyAVScreenCaptureStubForPid_002
 * @tc.number: DestroyAVScreenCaptureStubForPid_002
 * @tc.desc  : Test DestroyAVScreenCaptureStubForPid interface
 */
HWTEST_F(MediaServerManagerTest, DestroyAVScreenCaptureStubForPid_002, TestSize.Level1)
{
    sptr<MockMonitorServiceStub> mockMonitorServiceStub = new (std::nothrow) MockMonitorServiceStub();
    ASSERT_NE(mockMonitorServiceStub, nullptr);
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    sptr<IRemoteObject> object = mockMonitorServiceStub->AsObject();
    ASSERT_NE(object, nullptr);
    pid_t testPid = PID_TEST;
    mediaServerManager.screenCaptureMonitorStubMap_[object] = testPid;
    ASSERT_EQ(mediaServerManager.screenCaptureMonitorStubMap_.size(), 1);
    mediaServerManager.DestroyAVScreenCaptureStubForPid(testPid);
    ASSERT_EQ(mediaServerManager.screenCaptureMonitorStubMap_.size(), 0);
}

/**
 * @tc.name  : DestroyAVScreenCaptureStubForPid_003
 * @tc.number: DestroyAVScreenCaptureStubForPid_003
 * @tc.desc  : Test DestroyAVScreenCaptureStubForPid interface
 */
HWTEST_F(MediaServerManagerTest, DestroyAVScreenCaptureStubForPid_003, TestSize.Level1)
{
    sptr<MockMonitorServiceStub> mockMonitorServiceStub = new (std::nothrow) MockMonitorServiceStub();
    ASSERT_NE(mockMonitorServiceStub, nullptr);
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    sptr<IRemoteObject> object = mockMonitorServiceStub->AsObject();
    ASSERT_NE(object, nullptr);
    pid_t testPid = PID_TEST;
    mediaServerManager.screenCaptureControllerStubMap_[object] = testPid;
    ASSERT_EQ(mediaServerManager.screenCaptureControllerStubMap_.size(), 1);
    mediaServerManager.DestroyAVScreenCaptureStubForPid(testPid);
    ASSERT_EQ(mediaServerManager.screenCaptureControllerStubMap_.size(), 0);
}

/**
 * @tc.name  : DestroyStubObject_002
 * @tc.number: DestroyStubObject_002
 * @tc.desc  : Test DestroyStubObject interface
 */
HWTEST_F(MediaServerManagerTest, DestroyStubObject_002, TestSize.Level1)
{
    sptr<MockMonitorServiceStub> mockMonitorServiceStub = new (std::nothrow) MockMonitorServiceStub();
    ASSERT_NE(mockMonitorServiceStub, nullptr);
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    sptr<IRemoteObject> object = mockMonitorServiceStub->AsObject();
    ASSERT_NE(object, nullptr);
    pid_t testPid = IPCSkeleton::GetCallingPid();
    mediaServerManager.avCodecStubMap_[object] = testPid;
    ASSERT_EQ(mediaServerManager.avCodecStubMap_.size(), 1);
    mediaServerManager.DestroyStubObject(MediaServerManager::StubType::AVCODEC, object);
    ASSERT_EQ(mediaServerManager.avCodecStubMap_.size(), 0);
}

/**
 * @tc.name  : DestroyAVScreenCaptureStub_001
 * @tc.number: DestroyAVScreenCaptureStub_001
 * @tc.desc  : Test DestroyAVScreenCaptureStub interface
 */
HWTEST_F(MediaServerManagerTest, DestroyAVScreenCaptureStub_001, TestSize.Level1)
{
    sptr<MockMonitorServiceStub> mockMonitorServiceStub = new (std::nothrow) MockMonitorServiceStub();
    ASSERT_NE(mockMonitorServiceStub, nullptr);
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    sptr<IRemoteObject> object1 = nullptr;
    sptr<IRemoteObject> object2 = mockMonitorServiceStub->AsObject();
    ASSERT_NE(object2, nullptr);
    pid_t testPid = 1;
    mediaServerManager.screenCaptureControllerStubMap_[object2] = testPid;
    ASSERT_EQ(mediaServerManager.screenCaptureControllerStubMap_.size(), 1);
    mediaServerManager.DestroyAVScreenCaptureStub(MediaServerManager::StubType::SCREEN_CAPTURE, object1, testPid);
    ASSERT_EQ(mediaServerManager.screenCaptureControllerStubMap_.size(), 1);
    mediaServerManager.DestroyAVScreenCaptureStub(MediaServerManager::StubType::SCREEN_CAPTURE_CONTROLLER,
        object2, testPid);
}

/**
 * @tc.name  : DestroyAVScreenCaptureStub_002
 * @tc.number: DestroyAVScreenCaptureStub_002
 * @tc.desc  : Test DestroyAVScreenCaptureStub interface
 */
HWTEST_F(MediaServerManagerTest, DestroyAVScreenCaptureStub_002, TestSize.Level1)
{
    sptr<MockMonitorServiceStub> mockMonitorServiceStub = new (std::nothrow) MockMonitorServiceStub();
    ASSERT_NE(mockMonitorServiceStub, nullptr);
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    sptr<IRemoteObject> object1 = nullptr;
    sptr<IRemoteObject> object2 = mockMonitorServiceStub->AsObject();
    ASSERT_NE(object2, nullptr);
    pid_t testPid = 2;
    mediaServerManager.screenCaptureMonitorStubMap_[object2] = testPid;
    ASSERT_EQ(mediaServerManager.screenCaptureMonitorStubMap_.size(), 1);
    mediaServerManager.DestroyAVScreenCaptureStub(MediaServerManager::StubType::SCREEN_CAPTURE_MONITOR,
        object1, testPid);
    ASSERT_EQ(mediaServerManager.screenCaptureMonitorStubMap_.size(), 1);
}

/**
 * @tc.name  : DestroyAVScreenCaptureStub_003
 * @tc.number: DestroyAVScreenCaptureStub_003
 * @tc.desc  : Test DestroyAVScreenCaptureStub interface
 */
HWTEST_F(MediaServerManagerTest, DestroyAVScreenCaptureStub_003, TestSize.Level1)
{
    sptr<MockMonitorServiceStub> mockMonitorServiceStub = new (std::nothrow) MockMonitorServiceStub();
    ASSERT_NE(mockMonitorServiceStub, nullptr);
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    sptr<IRemoteObject> object1 = nullptr;
    sptr<IRemoteObject> object2 = mockMonitorServiceStub->AsObject();
    ASSERT_NE(object2, nullptr);
    pid_t testPid = 3;
    mediaServerManager.screenCaptureControllerStubMap_[object2] = testPid;
    ASSERT_EQ(mediaServerManager.screenCaptureControllerStubMap_.size(), 1);
    mediaServerManager.DestroyAVScreenCaptureStub(MediaServerManager::StubType::SCREEN_CAPTURE_CONTROLLER,
        object1, testPid);
    ASSERT_EQ(mediaServerManager.screenCaptureControllerStubMap_.size(), 1);
    mediaServerManager.DestroyAVScreenCaptureStub(MediaServerManager::StubType::TRANSCODER, object1, testPid);
    mediaServerManager.DestroyAVScreenCaptureStub(MediaServerManager::StubType::SCREEN_CAPTURE_CONTROLLER,
        object2, testPid);
}

/**
 * @tc.name  : DestroyAVPlayerStub_001
 * @tc.number: DestroyAVPlayerStub_001
 * @tc.desc  : Test DestroyAVPlayerStub interface
 */
HWTEST_F(MediaServerManagerTest, DestroyAVPlayerStub_001, TestSize.Level1)
{
    sptr<MockMonitorServiceStub> mockMonitorServiceStub = new (std::nothrow) MockMonitorServiceStub();
    ASSERT_NE(mockMonitorServiceStub, nullptr);
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    sptr<IRemoteObject> object1 = nullptr;
    sptr<IRemoteObject> object2 = mockMonitorServiceStub->AsObject();
    ASSERT_NE(object2, nullptr);
    pid_t pid = IPCSkeleton::GetCallingPid();
    mediaServerManager.playerStubMap_[object2] = pid;
    ASSERT_EQ(mediaServerManager.playerStubMap_.size(), 1);
    mediaServerManager.DestroyAVPlayerStub(MediaServerManager::StubType::PLAYER, object1, pid);
    ASSERT_EQ(mediaServerManager.playerStubMap_.size(), 1);
}

/**
 * @tc.name  : DestroyAVPlayerStub_002
 * @tc.number: DestroyAVPlayerStub_002
 * @tc.desc  : Test DestroyAVPlayerStub interface
 */
HWTEST_F(MediaServerManagerTest, DestroyAVPlayerStub_002, TestSize.Level1)
{
    sptr<MockMonitorServiceStub> mockMonitorServiceStub = new (std::nothrow) MockMonitorServiceStub();
    ASSERT_NE(mockMonitorServiceStub, nullptr);
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    sptr<IRemoteObject> object1 = nullptr;
    sptr<IRemoteObject> object2 = mockMonitorServiceStub->AsObject();
    ASSERT_NE(object2, nullptr);
    pid_t pid = IPCSkeleton::GetCallingPid();
    mediaServerManager.avMetadataHelperStubMap_[object2] = pid;
    ASSERT_EQ(mediaServerManager.avMetadataHelperStubMap_.size(), 1);
    mediaServerManager.DestroyAVPlayerStub(MediaServerManager::StubType::AVMETADATAHELPER, object1, pid);
    ASSERT_EQ(mediaServerManager.avMetadataHelperStubMap_.size(), 1);
    mediaServerManager.DestroyAVPlayerStub(MediaServerManager::StubType::RECORDER, object1, pid);
}

/**
 * @tc.name  : DestroyAVRecorderStub_001
 * @tc.number: DestroyAVRecorderStub_001
 * @tc.desc  : Test DestroyAVRecorderStub interface
 */
HWTEST_F(MediaServerManagerTest, DestroyAVRecorderStub_001, TestSize.Level1)
{
    sptr<MockMonitorServiceStub> mockMonitorServiceStub = new (std::nothrow) MockMonitorServiceStub();
    ASSERT_NE(mockMonitorServiceStub, nullptr);
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    sptr<IRemoteObject> object1 = nullptr;
    sptr<IRemoteObject> object2 = mockMonitorServiceStub->AsObject();
    ASSERT_NE(object2, nullptr);
    pid_t pid = IPCSkeleton::GetCallingPid();
    mediaServerManager.recorderStubMap_[object2] = pid;
    ASSERT_EQ(mediaServerManager.recorderStubMap_.size(), 1);
    mediaServerManager.DestroyAVRecorderStub(MediaServerManager::StubType::RECORDER, object1, pid);
    ASSERT_EQ(mediaServerManager.recorderStubMap_.size(), 1);
}

/**
 * @tc.name  : DestroyAVRecorderStub_002
 * @tc.number: DestroyAVRecorderStub_002
 * @tc.desc  : Test DestroyAVRecorderStub interface
 */
HWTEST_F(MediaServerManagerTest, DestroyAVRecorderStub_002, TestSize.Level1)
{
    sptr<MockRecorderProfilesServiceStub> mockRecorderProfilesServiceStub =
        new (std::nothrow) MockRecorderProfilesServiceStub();
    ASSERT_NE(mockRecorderProfilesServiceStub, nullptr);
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    sptr<IRemoteObject> object = mockRecorderProfilesServiceStub->AsObject();
    ASSERT_NE(object, nullptr);
    pid_t pid = IPCSkeleton::GetCallingPid();
    mediaServerManager.recorderProfilesStubMap_[object] = pid;
    ASSERT_EQ(mediaServerManager.recorderProfilesStubMap_.size(), 1);
    mediaServerManager.DestroyAVRecorderStub(MediaServerManager::StubType::RECORDERPROFILES, object, pid);
    ASSERT_EQ(mediaServerManager.recorderProfilesStubMap_.size(), 0);
    mediaServerManager.DestroyAVRecorderStub(MediaServerManager::StubType::SCREEN_CAPTURE, object, pid);
}

/**
 * @tc.name  : DestroyAVTransCoderStub_001
 * @tc.number: DestroyAVTransCoderStub_001
 * @tc.desc  : Test DestroyAVTransCoderStub interface
 */
HWTEST_F(MediaServerManagerTest, DestroyAVTransCoderStub_001, TestSize.Level1)
{
    sptr<MockTransCoderServiceStub> mockTransCoderServiceStub = new (std::nothrow) MockTransCoderServiceStub();
    ASSERT_NE(mockTransCoderServiceStub, nullptr);
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    sptr<IRemoteObject> object1 = nullptr;
    sptr<IRemoteObject> object2 = mockTransCoderServiceStub->AsObject();
    ASSERT_NE(object2, nullptr);
    pid_t pid = IPCSkeleton::GetCallingPid();
    mediaServerManager.transCoderStubMap_[object2] = pid;
    ASSERT_EQ(mediaServerManager.transCoderStubMap_.size(), 1);
    mediaServerManager.DestroyAVTransCoderStub(MediaServerManager::StubType::TRANSCODER, object1, pid);
    ASSERT_EQ(mediaServerManager.transCoderStubMap_.size(), 1);
    mediaServerManager.DestroyAVTransCoderStub(MediaServerManager::StubType::SCREEN_CAPTURE_MONITOR, object1, pid);
}

/**
 * @tc.name  : DestroyAVCodecStub_001
 * @tc.number: DestroyAVCodecStub_001
 * @tc.desc  : Test DestroyAVCodecStub interface
 */
HWTEST_F(MediaServerManagerTest, DestroyAVCodecStub_001, TestSize.Level1)
{
    sptr<MockTransCoderServiceStub> mockTransCoderServiceStub = new (std::nothrow) MockTransCoderServiceStub();
    ASSERT_NE(mockTransCoderServiceStub, nullptr);
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    sptr<IRemoteObject> object2 = nullptr;
    sptr<IRemoteObject> object1 = mockTransCoderServiceStub->AsObject();
    ASSERT_NE(object1, nullptr);
    pid_t pid = IPCSkeleton::GetCallingPid();
    mediaServerManager.avCodecStubMap_[object2] = pid;
    ASSERT_EQ(mediaServerManager.avCodecStubMap_.size(), 1);
    mediaServerManager.DestroyAVCodecStub(MediaServerManager::StubType::AVCODEC, object1, pid);
    ASSERT_EQ(mediaServerManager.avCodecStubMap_.size(), 1);
    mediaServerManager.DestroyAVCodecStub(MediaServerManager::StubType::AVCODEC, object2, pid);
    ASSERT_EQ(mediaServerManager.avCodecStubMap_.size(), 0);
}

/**
 * @tc.name  : DestroyAVCodecStub_002
 * @tc.number: DestroyAVCodecStub_002
 * @tc.desc  : Test DestroyStubObjectForPid interface
 */
HWTEST_F(MediaServerManagerTest, DestroyAVCodecStub_002, TestSize.Level1)
{
    sptr<MockTransCoderServiceStub> mockTransCoderServiceStub = new (std::nothrow) MockTransCoderServiceStub();
    ASSERT_NE(mockTransCoderServiceStub, nullptr);
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    sptr<IRemoteObject> object1 = mockTransCoderServiceStub->AsObject();
    ASSERT_NE(object1, nullptr);
    sptr<IRemoteObject> object2 = nullptr;
    pid_t pid = IPCSkeleton::GetCallingPid();
    mediaServerManager.avCodecListStubMap_[object2] = pid;
    ASSERT_EQ(mediaServerManager.avCodecListStubMap_.size(), 1);
    mediaServerManager.DestroyAVCodecStub(MediaServerManager::StubType::AVCODECLIST, object1, pid);
    ASSERT_EQ(mediaServerManager.avCodecListStubMap_.size(), 1);
    mediaServerManager.DestroyAVCodecStub(MediaServerManager::StubType::AVCODECLIST, object2, pid);
    ASSERT_EQ(mediaServerManager.avCodecListStubMap_.size(), 0);
    mediaServerManager.DestroyAVCodecStub(MediaServerManager::StubType::SCREEN_CAPTURE_MONITOR, object2, pid);
}

/**
 * @tc.name  : CreateStubObject_002
 * @tc.number: CreateStubObject_002
 * @tc.desc  : Test CreateStubObject interface
 */
HWTEST_F(MediaServerManagerTest, CreateStubObject_002, TestSize.Level1)
{
    sptr<MockMonitorServiceStub> mockMonitorServiceStub = new (std::nothrow) MockMonitorServiceStub();
    ASSERT_NE(mockMonitorServiceStub, nullptr);
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    sptr<IRemoteObject> object1 = mockMonitorServiceStub->AsObject();
    ASSERT_NE(object1, nullptr);
    pid_t testPid = PID_TEST;
    mediaServerManager.recorderProfilesStubMap_[object1] = testPid;
    ASSERT_EQ(mediaServerManager.recorderProfilesStubMap_.size(), 1);
    sptr<IRemoteObject> object2 = mediaServerManager.CreateStubObject(MediaServerManager::StubType::RECORDERPROFILES);
    ASSERT_NE(object2, nullptr);
}
}
}