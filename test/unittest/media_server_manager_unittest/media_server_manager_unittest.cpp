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

#include "media_server_manager_unittest.h"
#include "media_errors.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing;
using namespace testing::ext;

constexpr int32_t TEST_NUM1 = 1234;
constexpr int32_t TEST_NUM2 = 5678;
constexpr int32_t TEST_NUM3 = 512;
void MediaServerManagerUnitTest::SetUpTestCase(void)
{
}

void MediaServerManagerUnitTest::TearDownTestCase(void)
{
}

void MediaServerManagerUnitTest::SetUp(void)
{
}

void MediaServerManagerUnitTest::TearDown(void)
{
}

/**
 * @tc.name  : Test CreateStubObject API
 * @tc.number: CreateStubObject_001
 * @tc.desc  : Test case RECORDERPROFILES, TRANSCODER, AVMETADATAHELPER
 *             and invalid type of CreateStubObject interface
 */
HWTEST_F(MediaServerManagerUnitTest, CreateStubObject_001, TestSize.Level1)
{
    sptr<IRemoteObject> ret =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::RECORDERPROFILES);
    EXPECT_NE(ret, nullptr);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::RECORDERPROFILES, ret);
    ret = MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::TRANSCODER);
    EXPECT_NE(ret, nullptr);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::TRANSCODER, ret);
    ret = MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::AVMETADATAHELPER);
    EXPECT_NE(ret, nullptr);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::AVMETADATAHELPER, ret);
    MediaServerManager::StubType invalidType = static_cast<MediaServerManager::StubType>(-1);
    ret = MediaServerManager::GetInstance().CreateStubObject(invalidType);
    MediaServerManager::GetInstance().DestroyStubObject(invalidType, ret);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name  : Test DestroyAVCodecStub API
 * @tc.number: DestroyAVCodecStub_001
 * @tc.desc  : Test case AVCODEC
 *             Test if it->first == object && it->first != object
 */
HWTEST_F(MediaServerManagerUnitTest, DestroyAVCodecStub_001, TestSize.Level1)
{
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    sptr<IRemoteObject> object1 = MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::TRANSCODER);
    sptr<IRemoteObject> object2 = MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::AVCODEC);
    pid_t pid = 0;
    mediaServerManager.avCodecStubMap_[object2] = pid;
    ASSERT_EQ(mediaServerManager.avCodecStubMap_.size(), 1);
    mediaServerManager.DestroyAVCodecStub(MediaServerManager::AVCODEC, object1, pid);
    ASSERT_EQ(mediaServerManager.avCodecStubMap_.size(), 1);
    mediaServerManager.DestroyAVCodecStub(MediaServerManager::AVCODEC, object2, pid);
    ASSERT_EQ(mediaServerManager.avCodecStubMap_.size(), 0);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::TRANSCODER, object1);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::AVCODEC, object2);
}

/**
 * @tc.name  : Test DestroyAVCodecStub API
 * @tc.number: DestroyAVCodecStub_002
 * @tc.desc  : Test case AVCODECLIST and invalid type of DestroyAVCodecStub interface
 *             Test if it->first == object && it->first != object
 */
HWTEST_F(MediaServerManagerUnitTest, DestroyAVCodecStub_002, TestSize.Level1)
{
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    sptr<IRemoteObject> object1 = MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::TRANSCODER);
    sptr<IRemoteObject> object2 = MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::AVCODECLIST);
    pid_t pid = 0;
    mediaServerManager.avCodecListStubMap_[object2] = pid;
    ASSERT_EQ(mediaServerManager.avCodecListStubMap_.size(), 1);
    mediaServerManager.DestroyAVCodecStub(MediaServerManager::StubType::AVCODECLIST, object1, pid);
    ASSERT_EQ(mediaServerManager.avCodecListStubMap_.size(), 1);
    mediaServerManager.DestroyAVCodecStub(MediaServerManager::StubType::AVCODECLIST, object2, pid);
    ASSERT_EQ(mediaServerManager.avCodecListStubMap_.size(), 0);
    mediaServerManager.DestroyAVCodecStub(MediaServerManager::StubType::SCREEN_CAPTURE_MONITOR, object2, pid);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::TRANSCODER, object1);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::AVCODECLIST, object2);
}

/**
 * @tc.name  : Test DestroyAVTransCoderStub API
 * @tc.number: DestroyAVTransCoderStub_001
 * @tc.desc  : Test case AVCODEC and invalid type of DestroyAVCodecStub interface
 *             Test if it->first == object && it->first != object
 */
HWTEST_F(MediaServerManagerUnitTest, DestroyAVTransCoderStub_001, TestSize.Level1)
{
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    sptr<IRemoteObject> object1 = nullptr;
    sptr<IRemoteObject> object2 = MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::TRANSCODER);
    pid_t pid = 0;
    mediaServerManager.transCoderStubMap_[object2] = pid;
    ASSERT_EQ(mediaServerManager.transCoderStubMap_.size(), 1);
    mediaServerManager.DestroyAVTransCoderStub(MediaServerManager::TRANSCODER, object1, pid);
    ASSERT_EQ(mediaServerManager.transCoderStubMap_.size(), 1);
    mediaServerManager.DestroyAVTransCoderStub(MediaServerManager::TRANSCODER, object2, pid);
    ASSERT_EQ(mediaServerManager.transCoderStubMap_.size(), 0);
    mediaServerManager.DestroyAVTransCoderStub(MediaServerManager::StubType::SCREEN_CAPTURE_MONITOR, object1, pid);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::TRANSCODER, object2);
}

/**
 * @tc.name  : Test DestroyAVPlayerStub API
 * @tc.number: DestroyAVPlayerStub_001
 * @tc.desc  : Test case AVMETADATAHELPER and invalid type of DestroyAVCodecStub interface
 *             Test if it->first == object && it->first != object
 */
HWTEST_F(MediaServerManagerUnitTest, DestroyAVPlayerStub_001, TestSize.Level1)
{
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    sptr<IRemoteObject> object1 = MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::TRANSCODER);
    sptr<IRemoteObject> object2 =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::AVMETADATAHELPER);
    pid_t pid = 0;
    mediaServerManager.avMetadataHelperStubMap_[object2] = pid;
    ASSERT_EQ(mediaServerManager.avMetadataHelperStubMap_.size(), 1);
    mediaServerManager.DestroyAVPlayerStub(MediaServerManager::AVMETADATAHELPER, object1, pid);
    ASSERT_EQ(mediaServerManager.avMetadataHelperStubMap_.size(), 1);
    mediaServerManager.DestroyAVPlayerStub(MediaServerManager::AVMETADATAHELPER, object2, pid);
    ASSERT_EQ(mediaServerManager.avMetadataHelperStubMap_.size(), 0);
    mediaServerManager.DestroyAVPlayerStub(MediaServerManager::StubType::SCREEN_CAPTURE_MONITOR, object1, pid);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::TRANSCODER, object1);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::AVMETADATAHELPER, object2);
}

/**
 * @tc.name  : Test DestroyAVRecorderStub API
 * @tc.number: DestroyAVRecorderStub_001
 * @tc.desc  : Test case RECORDER and invalid type of DestroyAVCodecStub interface
 *             Test if it->first != object
 */
HWTEST_F(MediaServerManagerUnitTest, DestroyAVRecorderStub_001, TestSize.Level1)
{
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    sptr<IRemoteObject> object1 = nullptr;
    sptr<IRemoteObject> object2 = MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::RECORDER);
    pid_t pid = 0;
    mediaServerManager.recorderStubMap_[object2] = pid;
    ASSERT_EQ(mediaServerManager.recorderStubMap_.size(), 1);
    mediaServerManager.DestroyAVRecorderStub(MediaServerManager::StubType::RECORDER, object1, pid);
    ASSERT_EQ(mediaServerManager.recorderStubMap_.size(), 1);
    mediaServerManager.DestroyAVRecorderStub(MediaServerManager::StubType::RECORDER, object2, pid);
    ASSERT_EQ(mediaServerManager.recorderStubMap_.size(), 0);
    mediaServerManager.DestroyAVRecorderStub(MediaServerManager::StubType::SCREEN_CAPTURE, object1, pid);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::RECORDER, object2);
}

/**
 * @tc.name  : Test DestroyAVRecorderStub API
 * @tc.number: DestroyAVRecorderStub_002
 * @tc.desc  : Test case RECORDERPROFILES
 *             Test if it->first != object and it->first == object
 */
HWTEST_F(MediaServerManagerUnitTest, DestroyAVRecorderStub_002, TestSize.Level1)
{
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    sptr<IRemoteObject> object1 = MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::TRANSCODER);
    sptr<IRemoteObject> object2 =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::RECORDERPROFILES);
    pid_t pid = 0;
    mediaServerManager.recorderProfilesStubMap_[object2] = pid;
    ASSERT_EQ(mediaServerManager.recorderProfilesStubMap_.size(), 1);
    mediaServerManager.DestroyAVRecorderStub(MediaServerManager::StubType::RECORDERPROFILES, object1, pid);
    ASSERT_EQ(mediaServerManager.recorderProfilesStubMap_.size(), 1);
    mediaServerManager.DestroyAVRecorderStub(MediaServerManager::StubType::RECORDERPROFILES, object2, pid);
    ASSERT_EQ(mediaServerManager.recorderProfilesStubMap_.size(), 0);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::RECORDERPROFILES, object2);
}

/**
 * @tc.name  : Test CreateRecorderProfilesStubObject API
 * @tc.number: CreateRecorderProfilesStubObject_001
 * @tc.desc  : Test all
 */
HWTEST_F(MediaServerManagerUnitTest, CreateRecorderProfilesStubObject_001, TestSize.Level1)
{
    sptr<IRemoteObject> ret =
        MediaServerManager::GetInstance().CreateRecorderProfilesStubObject();
    EXPECT_NE(ret, nullptr);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::RECORDERPROFILES, ret);
}

/**
 * @tc.name  : Test CreateTransCoderStubObject API
 * @tc.number: CreateTransCoderStubObject_001
 * @tc.desc  : Test all
 */
HWTEST_F(MediaServerManagerUnitTest, CreateTransCoderStubObject_001, TestSize.Level1)
{
    sptr<IRemoteObject> ret =
        MediaServerManager::GetInstance().CreateTransCoderStubObject();
    EXPECT_NE(ret, nullptr);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::TRANSCODER, ret);
}

/**
 * @tc.name  : Test CreateAVMetadataHelperStubObject API
 * @tc.number: CreateAVMetadataHelperStubObject_001
 * @tc.desc  : Test all
 */
HWTEST_F(MediaServerManagerUnitTest, CreateAVMetadataHelperStubObject_001, TestSize.Level1)
{
    sptr<IRemoteObject> ret =
        MediaServerManager::GetInstance().CreateAVMetadataHelperStubObject();
    EXPECT_NE(ret, nullptr);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::AVMETADATAHELPER, ret);
}

/**
 * @tc.name  : Test DestroyAVScreenCaptureStub API
 * @tc.number: DestroyAVScreenCaptureStub_001
 * @tc.desc  : Test case SCREEN_CAPTURE if it->first != object
 *             Test case invalid type of DestroyAVScreenCaptureStub interface
 */
HWTEST_F(MediaServerManagerUnitTest, DestroyAVScreenCaptureStub_001, TestSize.Level1)
{
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    sptr<IRemoteObject> object1 = MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::TRANSCODER);
    sptr<IRemoteObject> object2 =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::SCREEN_CAPTURE);
    pid_t pid = 0;
    mediaServerManager.screenCaptureStubMap_[object2] = pid;
    ASSERT_EQ(mediaServerManager.screenCaptureStubMap_.size(), 1);
    mediaServerManager.DestroyAVScreenCaptureStub(MediaServerManager::StubType::SCREEN_CAPTURE, object1, pid);
    ASSERT_EQ(mediaServerManager.screenCaptureStubMap_.size(), 1);
    mediaServerManager.DestroyAVScreenCaptureStub(MediaServerManager::StubType::SCREEN_CAPTURE, object2, pid);
    ASSERT_EQ(mediaServerManager.screenCaptureStubMap_.size(), 0);
    mediaServerManager.DestroyAVScreenCaptureStub(MediaServerManager::TRANSCODER, object2, pid);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::TRANSCODER, object1);
}

/**
 * @tc.name  : Test DestroyAVScreenCaptureStub API
 * @tc.number: DestroyAVScreenCaptureStub_002
 * @tc.desc  : Test case SCREEN_CAPTURE_CONTROLLER if it->first != object
 */
HWTEST_F(MediaServerManagerUnitTest, DestroyAVScreenCaptureStub_002, TestSize.Level1)
{
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    sptr<IRemoteObject> object1 = MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::TRANSCODER);
    sptr<IRemoteObject> object2 =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::SCREEN_CAPTURE_CONTROLLER);
    pid_t pid = 0;
    mediaServerManager.screenCaptureControllerStubMap_[object2] = pid;
    ASSERT_EQ(mediaServerManager.screenCaptureControllerStubMap_.size(), 1);
    mediaServerManager.DestroyAVScreenCaptureStub(MediaServerManager::StubType::SCREEN_CAPTURE_CONTROLLER,
        object1, pid);
    ASSERT_EQ(mediaServerManager.screenCaptureControllerStubMap_.size(), 1);
    mediaServerManager.DestroyAVScreenCaptureStub(MediaServerManager::StubType::SCREEN_CAPTURE_CONTROLLER,
        object2, pid);
    ASSERT_EQ(mediaServerManager.screenCaptureControllerStubMap_.size(), 0);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::TRANSCODER, object1);
}

/**
 * @tc.name  : Test DestroyAVScreenCaptureStubForPid API
 * @tc.number: DestroyAVScreenCaptureStubForPid_001
 * @tc.desc  : Test entry deletion for valid PID and no deletion for non-existent PID in screen capture maps.
 */
HWTEST_F(MediaServerManagerUnitTest, DestroyAVScreenCaptureStubForPid_001, TestSize.Level1)
{
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    mediaServerManager.screenCaptureStubMap_.clear();
    mediaServerManager.screenCaptureMonitorStubMap_.clear();
    mediaServerManager.screenCaptureControllerStubMap_.clear();
    sptr<IRemoteObject> screenCaptureStub =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::SCREEN_CAPTURE);
    sptr<IRemoteObject> screenCaptureMonitorStub =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::SCREEN_CAPTURE_MONITOR);
    sptr<IRemoteObject> screenCaptureControllerStub =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::SCREEN_CAPTURE_CONTROLLER);
    pid_t testPid = TEST_NUM1;
    mediaServerManager.screenCaptureStubMap_[screenCaptureStub] = testPid;
    mediaServerManager.screenCaptureMonitorStubMap_[screenCaptureMonitorStub] = testPid;
    mediaServerManager.screenCaptureControllerStubMap_[screenCaptureControllerStub] = testPid;
    ASSERT_EQ(mediaServerManager.screenCaptureStubMap_.size(), 1);
    ASSERT_EQ(mediaServerManager.screenCaptureMonitorStubMap_.size(), 1);
    ASSERT_EQ(mediaServerManager.screenCaptureControllerStubMap_.size(), 1);
    mediaServerManager.DestroyAVScreenCaptureStubForPid(testPid);
    ASSERT_EQ(mediaServerManager.screenCaptureStubMap_.size(), 0);
    ASSERT_EQ(mediaServerManager.screenCaptureMonitorStubMap_.size(), 0);
    ASSERT_EQ(mediaServerManager.screenCaptureControllerStubMap_.size(), 0);
    mediaServerManager.screenCaptureStubMap_[screenCaptureStub] = testPid;
    mediaServerManager.screenCaptureMonitorStubMap_[screenCaptureMonitorStub] = testPid;
    mediaServerManager.screenCaptureControllerStubMap_[screenCaptureControllerStub] = testPid;
    pid_t nonExistentPid = TEST_NUM2;
    mediaServerManager.DestroyAVScreenCaptureStubForPid(nonExistentPid);
    ASSERT_EQ(mediaServerManager.screenCaptureStubMap_.size(), 1);
    ASSERT_EQ(mediaServerManager.screenCaptureMonitorStubMap_.size(), 1);
    ASSERT_EQ(mediaServerManager.screenCaptureControllerStubMap_.size(), 1);
    mediaServerManager.screenCaptureStubMap_.clear();
    mediaServerManager.screenCaptureMonitorStubMap_.clear();
    mediaServerManager.screenCaptureControllerStubMap_.clear();
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::SCREEN_CAPTURE, screenCaptureStub);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::SCREEN_CAPTURE_MONITOR,
        screenCaptureMonitorStub);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::SCREEN_CAPTURE_CONTROLLER,
        screenCaptureControllerStub);
}

/**
 * @tc.name  : Test DestroyAVScreenCaptureStubForPid API
 * @tc.number: DestroyAVScreenCaptureStubForPid_002
 * @tc.desc  : Test deletion of multiple entries with the same PID in screen capture maps.
 */
HWTEST_F(MediaServerManagerUnitTest, DestroyAVScreenCaptureStubForPid_002, TestSize.Level1)
{
    pid_t testPid = TEST_NUM1;
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    sptr<IRemoteObject> screenCaptureStub =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::SCREEN_CAPTURE);
    sptr<IRemoteObject> screenCaptureMonitorStub =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::SCREEN_CAPTURE_MONITOR);
    sptr<IRemoteObject> screenCaptureControllerStub =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::SCREEN_CAPTURE_CONTROLLER);
    sptr<IRemoteObject> anotherScreenCaptureStub =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::SCREEN_CAPTURE);
    sptr<IRemoteObject> anotherScreenCaptureMonitorStub =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::SCREEN_CAPTURE_MONITOR);
    sptr<IRemoteObject> anotherScreenCaptureControllerStub =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::SCREEN_CAPTURE_CONTROLLER);
    
    mediaServerManager.screenCaptureStubMap_[screenCaptureStub] = testPid;
    mediaServerManager.screenCaptureStubMap_[anotherScreenCaptureStub] = testPid;
    mediaServerManager.screenCaptureMonitorStubMap_[screenCaptureMonitorStub] = testPid;
    mediaServerManager.screenCaptureMonitorStubMap_[anotherScreenCaptureMonitorStub] = testPid;
    mediaServerManager.screenCaptureControllerStubMap_[screenCaptureControllerStub] = testPid;
    mediaServerManager.screenCaptureControllerStubMap_[anotherScreenCaptureControllerStub] = testPid;
    ASSERT_EQ(mediaServerManager.screenCaptureStubMap_.size(), 2);
    ASSERT_EQ(mediaServerManager.screenCaptureMonitorStubMap_.size(), 2);
    ASSERT_EQ(mediaServerManager.screenCaptureControllerStubMap_.size(), 2);
    
    mediaServerManager.DestroyAVScreenCaptureStubForPid(testPid);
    ASSERT_EQ(mediaServerManager.screenCaptureStubMap_.size(), 0);
    ASSERT_EQ(mediaServerManager.screenCaptureMonitorStubMap_.size(), 0);
    ASSERT_EQ(mediaServerManager.screenCaptureControllerStubMap_.size(), 0);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::SCREEN_CAPTURE, screenCaptureStub);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::SCREEN_CAPTURE_MONITOR,
        screenCaptureMonitorStub);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::SCREEN_CAPTURE_CONTROLLER,
        screenCaptureControllerStub);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::SCREEN_CAPTURE, anotherScreenCaptureStub);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::SCREEN_CAPTURE_MONITOR,
        anotherScreenCaptureMonitorStub);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::SCREEN_CAPTURE_CONTROLLER,
        anotherScreenCaptureControllerStub);
}

/**
 * @tc.name  : Test GetPlayerPids API
 * @tc.number: GetPlayerPids_001
 * @tc.desc  : Test all
 */
HWTEST_F(MediaServerManagerUnitTest, GetPlayerPids_001, TestSize.Level1)
{
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    std::vector<pid_t> ret = mediaServerManager.GetPlayerPids();
    ASSERT_TRUE(ret.empty());
}

/**
 * @tc.name  : Test DestroyAVCodecStubForPid API
 * @tc.number: DestroyAVCodecStubForPid_001
 * @tc.desc  : Test that entries in avCodecStubMap_
 *             and avCodecListStubMap_ are correctly deleted when a single PID exists.
 */
HWTEST_F(MediaServerManagerUnitTest, DestroyAVCodecStubForPid_001, TestSize.Level1)
{
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    mediaServerManager.avCodecStubMap_.clear();
    mediaServerManager.avCodecListStubMap_.clear();

    sptr<IRemoteObject> avCodecStub = MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::AVCODEC);
    sptr<IRemoteObject> avCodecListStub =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::AVCODECLIST);
    pid_t testPid = TEST_NUM1;
    mediaServerManager.avCodecStubMap_[avCodecStub] = testPid;
    mediaServerManager.avCodecListStubMap_[avCodecListStub] = testPid;
    ASSERT_EQ(mediaServerManager.avCodecStubMap_.size(), 1);
    ASSERT_EQ(mediaServerManager.avCodecListStubMap_.size(), 1);
    mediaServerManager.DestroyAVCodecStubForPid(testPid);
    ASSERT_EQ(mediaServerManager.avCodecStubMap_.size(), 0);
    ASSERT_EQ(mediaServerManager.avCodecListStubMap_.size(), 0);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::AVCODEC, avCodecStub);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::AVCODECLIST, avCodecListStub);
}

/**
 * @tc.name  : Test DestroyAVCodecStubForPid API
 * @tc.number: DestroyAVCodecStubForPid_002
 * @tc.desc  : Test that avCodecStubMap_ and avCodecListStubMap_ remain unchanged when the target PID does not exist.
 */
HWTEST_F(MediaServerManagerUnitTest, DestroyAVCodecStubForPid_002, TestSize.Level1)
{
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    mediaServerManager.avCodecStubMap_.clear();
    mediaServerManager.avCodecListStubMap_.clear();

    sptr<IRemoteObject> avCodecStub = MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::AVCODEC);
    sptr<IRemoteObject> avCodecListStub =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::AVCODECLIST);
    pid_t testPid = TEST_NUM1;
    pid_t nonExistentPid = TEST_NUM2;
    mediaServerManager.avCodecStubMap_[avCodecStub] = testPid;
    mediaServerManager.avCodecListStubMap_[avCodecListStub] = testPid;
    ASSERT_EQ(mediaServerManager.avCodecStubMap_.size(), 1);
    ASSERT_EQ(mediaServerManager.avCodecListStubMap_.size(), 1);
    mediaServerManager.DestroyAVCodecStubForPid(nonExistentPid);
    ASSERT_EQ(mediaServerManager.avCodecStubMap_.size(), 1);
    ASSERT_EQ(mediaServerManager.avCodecListStubMap_.size(), 1);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::AVCODEC, avCodecStub);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::AVCODECLIST, avCodecListStub);
}

/**
 * @tc.name  : Test DestroyAVCodecStubForPid API
 * @tc.number: DestroyAVCodecStubForPid_003
 * @tc.desc  : Test all entries with the same PID in avCodecStubMap_ and avCodecListStubMap_ are correctly deleted.
 */
HWTEST_F(MediaServerManagerUnitTest, DestroyAVCodecStubForPid_003, TestSize.Level1)
{
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    mediaServerManager.avCodecStubMap_.clear();
    mediaServerManager.avCodecListStubMap_.clear();
    sptr<IRemoteObject> avCodecStub1 =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::TRANSCODER);
    sptr<IRemoteObject> avCodecStub2 =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::AVCODEC);
    sptr<IRemoteObject> avCodecListStub1 =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::TRANSCODER);
    sptr<IRemoteObject> avCodecListStub2 =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::AVCODECLIST);
    pid_t testPid = TEST_NUM1;
    mediaServerManager.avCodecStubMap_[avCodecStub1] = testPid;
    mediaServerManager.avCodecStubMap_[avCodecStub2] = testPid;
    mediaServerManager.avCodecListStubMap_[avCodecListStub1] = testPid;
    mediaServerManager.avCodecListStubMap_[avCodecListStub2] = testPid;
    ASSERT_EQ(mediaServerManager.avCodecStubMap_.size(), 2);
    ASSERT_EQ(mediaServerManager.avCodecListStubMap_.size(), 2);
    mediaServerManager.DestroyAVCodecStubForPid(testPid);
    ASSERT_EQ(mediaServerManager.avCodecStubMap_.size(), 0);
    ASSERT_EQ(mediaServerManager.avCodecListStubMap_.size(), 0);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::TRANSCODER, avCodecStub1);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::AVCODEC, avCodecStub2);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::TRANSCODER, avCodecListStub1);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::AVCODECLIST, avCodecListStub2);
}

/**
 * @tc.name  : Test DestroyAVCodecStubForPid API
 * @tc.number: DestroyAVCodecStubForPid_004
 * @tc.desc  : Test that the function executes without exceptions when avCodecStubMap_
 *             and avCodecListStubMap_ are empty.
 */
HWTEST_F(MediaServerManagerUnitTest, DestroyAVCodecStubForPid_004, TestSize.Level1)
{
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    mediaServerManager.avCodecStubMap_.clear();
    mediaServerManager.avCodecListStubMap_.clear();
    ASSERT_TRUE(mediaServerManager.avCodecStubMap_.empty());
    ASSERT_TRUE(mediaServerManager.avCodecListStubMap_.empty());
    pid_t testPid = TEST_NUM1;
    mediaServerManager.DestroyAVCodecStubForPid(testPid);
    ASSERT_TRUE(mediaServerManager.avCodecStubMap_.empty());
    ASSERT_TRUE(mediaServerManager.avCodecListStubMap_.empty());
}

/**
 * @tc.name  : Test CanKillMediaService API
 * @tc.number: CanKillMediaService_001
 * @tc.desc  : Test all
 */
HWTEST_F(MediaServerManagerUnitTest, CanKillMediaService_001, TestSize.Level1)
{
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    bool ret = mediaServerManager.CanKillMediaService();
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name  : Test DestroyAVPlayerStubForPid API
 * @tc.number: DestroyAVPlayerStubForPid_001
 * @tc.desc  : Test the second else branch when itPlayer->second != pid.
 */
HWTEST_F(MediaServerManagerUnitTest, DestroyAVPlayerStubForPid_001, TestSize.Level1)
{
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();

    mediaServerManager.playerStubMap_.clear();
    mediaServerManager.avMetadataHelperStubMap_.clear();
    mediaServerManager.pidToPlayerStubMap_.clear();
    sptr<IRemoteObject> playerStub1 = MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::PLAYER);
    sptr<IRemoteObject> playerStub2 = MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::PLAYER);
    pid_t testPid = TEST_NUM1;
    pid_t anotherPid = TEST_NUM2;
    mediaServerManager.playerStubMap_[playerStub1] = testPid;
    mediaServerManager.playerStubMap_[playerStub2] = anotherPid;
    mediaServerManager.pidToPlayerStubMap_[testPid].insert(playerStub1);
    ASSERT_EQ(mediaServerManager.playerStubMap_.size(), 2);
    mediaServerManager.DestroyAVPlayerStubForPid(testPid);

    ASSERT_EQ(mediaServerManager.playerStubMap_.size(), 1);
    ASSERT_EQ(mediaServerManager.playerStubMap_.count(playerStub2), 1);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::PLAYER, playerStub1);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::PLAYER, playerStub2);
}

/**
 * @tc.name  : Test DestroyAVPlayerStubForPid API
 * @tc.number: DestroyAVPlayerStubForPid_002
 * @tc.desc  : Test the third if branch when itAvMetadata->second == pid.
 */
HWTEST_F(MediaServerManagerUnitTest, DestroyAVPlayerStubForPid_002, TestSize.Level1)
{
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    
    mediaServerManager.playerStubMap_.clear();
    mediaServerManager.avMetadataHelperStubMap_.clear();
    mediaServerManager.pidToPlayerStubMap_.clear();
    
    sptr<IRemoteObject> avMetadataHelperStub1 =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::AVMETADATAHELPER);
    sptr<IRemoteObject> avMetadataHelperStub2 =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::AVMETADATAHELPER);
    pid_t testPid = TEST_NUM1;

    mediaServerManager.avMetadataHelperStubMap_[avMetadataHelperStub1] = testPid;
    mediaServerManager.avMetadataHelperStubMap_[avMetadataHelperStub2] = testPid;
    ASSERT_EQ(mediaServerManager.avMetadataHelperStubMap_.size(), 2);
    mediaServerManager.DestroyAVPlayerStubForPid(testPid);
    ASSERT_EQ(mediaServerManager.avMetadataHelperStubMap_.size(), 0);

    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::AVMETADATAHELPER, avMetadataHelperStub1);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::AVMETADATAHELPER, avMetadataHelperStub2);
}

/**
 * @tc.name  : Test DestroyAVPlayerStubForPid API
 * @tc.number: DestroyAVPlayerStubForPid_003
 * @tc.desc  : Test the third else branch when itAvMetadata->second != pid.
 */
HWTEST_F(MediaServerManagerUnitTest, DestroyAVPlayerStubForPid_003, TestSize.Level1)
{
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    
    mediaServerManager.playerStubMap_.clear();
    mediaServerManager.avMetadataHelperStubMap_.clear();
    mediaServerManager.pidToPlayerStubMap_.clear();
    sptr<IRemoteObject> avMetadataHelperStub1 =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::AVMETADATAHELPER);
    sptr<IRemoteObject> avMetadataHelperStub2 =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::AVMETADATAHELPER);
    pid_t testPid = TEST_NUM1;
    pid_t anotherPid = TEST_NUM2;
    mediaServerManager.avMetadataHelperStubMap_[avMetadataHelperStub1] = testPid;
    mediaServerManager.avMetadataHelperStubMap_[avMetadataHelperStub2] = anotherPid;
    ASSERT_EQ(mediaServerManager.avMetadataHelperStubMap_.size(), 2);
    mediaServerManager.DestroyAVPlayerStubForPid(testPid);

    ASSERT_EQ(mediaServerManager.avMetadataHelperStubMap_.size(), 1);
    ASSERT_EQ(mediaServerManager.avMetadataHelperStubMap_.count(avMetadataHelperStub2), 1);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::AVMETADATAHELPER, avMetadataHelperStub1);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::AVMETADATAHELPER, avMetadataHelperStub2);
}

/**
 * @tc.name  : Test DestroyAVRecorderStubForPid API
 * @tc.number: DestroyAVRecorderStubForPid_001
 * @tc.desc  : Test the first if branch when itRecorder->second == pid.
 */
HWTEST_F(MediaServerManagerUnitTest, DestroyAVRecorderStubForPid_001, TestSize.Level1)
{
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();

    mediaServerManager.recorderStubMap_.clear();
    mediaServerManager.recorderProfilesStubMap_.clear();
    sptr<IRemoteObject> recorderStub = MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::RECORDER);
    pid_t testPid = TEST_NUM1;
    mediaServerManager.recorderStubMap_[recorderStub] = testPid;
    ASSERT_EQ(mediaServerManager.recorderStubMap_.size(), 1);
    mediaServerManager.DestroyAVRecorderStubForPid(testPid);
    ASSERT_EQ(mediaServerManager.recorderStubMap_.size(), 0);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::RECORDER, recorderStub);
}

/**
 * @tc.name  : Test DestroyAVRecorderStubForPid API
 * @tc.number: DestroyAVRecorderStubForPid_002
 * @tc.desc  : Test the first else branch when itRecorder->second != pid.
 */
HWTEST_F(MediaServerManagerUnitTest, DestroyAVRecorderStubForPid_002, TestSize.Level1)
{
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    
    mediaServerManager.recorderStubMap_.clear();
    mediaServerManager.recorderProfilesStubMap_.clear();
    sptr<IRemoteObject> recorderStub1 =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::RECORDER);
    sptr<IRemoteObject> recorderStub2 =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::RECORDER);
    pid_t testPid = TEST_NUM1;
    pid_t anotherPid = TEST_NUM2;
    mediaServerManager.recorderStubMap_[recorderStub1] = testPid;
    mediaServerManager.recorderStubMap_[recorderStub2] = anotherPid;
    ASSERT_EQ(mediaServerManager.recorderStubMap_.size(), 2);
    mediaServerManager.DestroyAVRecorderStubForPid(testPid);
    ASSERT_EQ(mediaServerManager.recorderStubMap_.size(), 1);
    ASSERT_TRUE(mediaServerManager.recorderStubMap_.count(recorderStub2) == 1);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::RECORDER, recorderStub1);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::RECORDER, recorderStub2);
}

/**
 * @tc.name  : Test DestroyAVRecorderStubForPid API
 * @tc.number: DestroyAVRecorderStubForPid_003
 * @tc.desc  : Test the second if branch when itMediaProfile->second == pid.
 */
HWTEST_F(MediaServerManagerUnitTest, DestroyAVRecorderStubForPid_003, TestSize.Level1)
{
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();

    mediaServerManager.recorderStubMap_.clear();
    mediaServerManager.recorderProfilesStubMap_.clear();
    sptr<IRemoteObject> mediaProfileStub =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::RECORDERPROFILES);
    pid_t testPid = TEST_NUM1;
    mediaServerManager.recorderProfilesStubMap_[mediaProfileStub] = testPid;
    ASSERT_EQ(mediaServerManager.recorderProfilesStubMap_.size(), 1);
    mediaServerManager.DestroyAVRecorderStubForPid(testPid);
    ASSERT_EQ(mediaServerManager.recorderProfilesStubMap_.size(), 0);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::RECORDERPROFILES, mediaProfileStub);
}

/**
 * @tc.name  : Test DestroyAVRecorderStubForPid API
 * @tc.number: DestroyAVRecorderStubForPid_004
 * @tc.desc  : Test the second else branch when itMediaProfile->second != pid.
 */
HWTEST_F(MediaServerManagerUnitTest, DestroyAVRecorderStubForPid_004, TestSize.Level1)
{
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();

    mediaServerManager.recorderStubMap_.clear();
    mediaServerManager.recorderProfilesStubMap_.clear();
    sptr<IRemoteObject> mediaProfileStub1 =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::RECORDERPROFILES);
    sptr<IRemoteObject> mediaProfileStub2 =
        MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::RECORDER);
    pid_t testPid = TEST_NUM1;
    pid_t anotherPid = TEST_NUM2;
    mediaServerManager.recorderProfilesStubMap_[mediaProfileStub1] = testPid;
    mediaServerManager.recorderProfilesStubMap_[mediaProfileStub2] = anotherPid;
    ASSERT_EQ(mediaServerManager.recorderProfilesStubMap_.size(), 2);
    mediaServerManager.DestroyAVRecorderStubForPid(testPid);
    ASSERT_EQ(mediaServerManager.recorderProfilesStubMap_.size(), 1);
    ASSERT_TRUE(mediaServerManager.recorderProfilesStubMap_.count(mediaProfileStub2) == 1);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::RECORDERPROFILES, mediaProfileStub1);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::RECORDER, mediaProfileStub2);
}

/**
 * @tc.name  : Test GetMemUsageForPlayer API
 * @tc.number: GetMemUsageForPlayer_001
 * @tc.desc  : Test the first else case when stub->GetMemoryUsage() returns non-zero.
 */
HWTEST_F(MediaServerManagerUnitTest, GetMemUsageForPlayer_001, TestSize.Level1)
{
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();

    mediaServerManager.playerStubMap_.clear();
    mediaServerManager.playerPidMem_.clear();
    mediaServerManager.needReleaseTaskCount_ = 0;
    sptr<IRemoteObject> object = MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::PLAYER);
    pid_t testPid = TEST_NUM1;
    mediaServerManager.playerStubMap_[object] = testPid;
    mediaServerManager.playerPidMem_[testPid] = TEST_NUM3;
    bool result = mediaServerManager.GetMemUsageForPlayer();
    ASSERT_EQ(mediaServerManager.playerPidMem_.size(), 1);
    ASSERT_EQ(mediaServerManager.playerPidMem_[testPid], 1234);
    ASSERT_TRUE(result);
    mediaServerManager.playerStubMap_.clear();
    mediaServerManager.playerPidMem_.clear();
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::PLAYER, object);
}

/**
 * @tc.name  : Test GetMemUsageForPlayer API
 * @tc.number: GetMemUsageForPlayer_002
 * @tc.desc  : Test the second if branch when memoryList doesn't contain pid and mem != 0.
 */
HWTEST_F(MediaServerManagerUnitTest, GetMemUsageForPlayer_002, TestSize.Level1)
{
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();

    mediaServerManager.playerStubMap_.clear();
    mediaServerManager.playerPidMem_.clear();
    mediaServerManager.needReleaseTaskCount_ = 0;
    pid_t testPid = TEST_NUM1;
    mediaServerManager.playerPidMem_[testPid] = 1024;
    bool result = mediaServerManager.GetMemUsageForPlayer();
    ASSERT_EQ(mediaServerManager.playerPidMem_.size(), 1);
    ASSERT_EQ(mediaServerManager.playerPidMem_[testPid], 0);
    ASSERT_TRUE(result);
    mediaServerManager.playerPidMem_.clear();
}

/**
 * @tc.name  : Test GetMemUsageForPlayer API
 * @tc.number: GetMemUsageForPlayer_003
 * @tc.desc  : Test when memoryList contains pid and mem != 0.
 */
HWTEST_F(MediaServerManagerUnitTest, GetMemUsageForPlayer_003, TestSize.Level1)
{
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();

    mediaServerManager.playerStubMap_.clear();
    mediaServerManager.playerPidMem_.clear();
    mediaServerManager.needReleaseTaskCount_ = 0;
    sptr<IRemoteObject> object = MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::PLAYER);
    pid_t testPid = TEST_NUM1;
    mediaServerManager.playerStubMap_[object] = testPid;
    mediaServerManager.playerPidMem_[testPid] = TEST_NUM3;
    bool result = mediaServerManager.GetMemUsageForPlayer();
    ASSERT_EQ(mediaServerManager.playerPidMem_.size(), 1);
    ASSERT_EQ(mediaServerManager.playerPidMem_[testPid], 1234);
    ASSERT_TRUE(result);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::PLAYER, object);
}

/**
 * @tc.name  : Test GetMemUsageForPlayer API
 * @tc.number: GetMemUsageForPlayer_004
 * @tc.desc  : Test when memoryList doesn't contain pid and mem == 0.
 */
HWTEST_F(MediaServerManagerUnitTest, GetMemUsageForPlayer_004, TestSize.Level1)
{
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();

    mediaServerManager.playerStubMap_.clear();
    mediaServerManager.playerPidMem_.clear();
    mediaServerManager.needReleaseTaskCount_ = 0;
    pid_t testPid = TEST_NUM1;
    mediaServerManager.playerPidMem_[testPid] = 0;
    bool result = mediaServerManager.GetMemUsageForPlayer();
    ASSERT_EQ(mediaServerManager.playerPidMem_.size(), 0);
    ASSERT_FALSE(result);
}

/**
 * @tc.name  : Test GetMemUsageForPlayer API
 * @tc.number: GetMemUsageForPlayer_005
 * @tc.desc  : Test when memoryList contains pid and mem == 0.
 */
HWTEST_F(MediaServerManagerUnitTest, GetMemUsageForPlayer_005, TestSize.Level1)
{
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    
    mediaServerManager.playerStubMap_.clear();
    mediaServerManager.playerPidMem_.clear();
    mediaServerManager.needReleaseTaskCount_ = 0;
    sptr<IRemoteObject> object = MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::PLAYER);
    pid_t testPid = TEST_NUM1;
    mediaServerManager.playerStubMap_[object] = testPid;
    mediaServerManager.playerPidMem_[testPid] = 0;
    bool result = mediaServerManager.GetMemUsageForPlayer();
    ASSERT_EQ(mediaServerManager.playerPidMem_.size(), 1);
    ASSERT_TRUE(result);
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::PLAYER, object);
}

/**
 * @tc.name  : Test DestoryMemoryReportTask API
 * @tc.number: DestoryMemoryReportTask_001
 * @tc.desc  : Test memoryReportTask = nullptr.
 *             Test memoryReportTask && !memoryReportTask->IsTaskRunning()
 */
HWTEST_F(MediaServerManagerUnitTest, DestoryMemoryReportTask_001, TestSize.Level1)
{
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();
    
    mediaServerManager.memoryReportTask_ = nullptr;
    mediaServerManager.DestoryMemoryReportTask();
    ASSERT_TRUE(mediaServerManager.memoryReportTask_ == nullptr);
    auto mockTask = std::make_unique<MockTask>("testName");
    EXPECT_CALL(*mockTask, IsTaskRunning()).WillRepeatedly(Return(false));
    mediaServerManager.memoryReportTask_ = std::move(mockTask);
    mediaServerManager.DestoryMemoryReportTask();
}

/**
 * @tc.name  : Test DestoryMemoryReportTask API
 * @tc.number: DestoryMemoryReportTask_002
 * @tc.desc  : Test memoryReportTask && memoryReportTask->IsTaskRunning()
 */
HWTEST_F(MediaServerManagerUnitTest, DestoryMemoryReportTask_002, TestSize.Level1)
{
    MediaServerManager& mediaServerManager = MediaServerManager::GetInstance();

    auto mockTask = std::make_unique<MockTask>("testName");
    EXPECT_CALL(*mockTask, IsTaskRunning()).WillRepeatedly(Return(true));
    mediaServerManager.memoryReportTask_ = std::move(mockTask);
    mediaServerManager.DestoryMemoryReportTask();
}
}
}