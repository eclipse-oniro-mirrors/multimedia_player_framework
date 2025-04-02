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

#include "screen_capture_server_function_unittest.h"

using namespace testing::ext;
using namespace OHOS::Media::ScreenCaptureTestParam;
using namespace OHOS::Media;

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE,
        "ScreenCaptureServerFunctionTest"};
    constexpr int32_t ROOT_UID = 0;
}

namespace OHOS {
namespace Media {

/**
* @tc.name: LimitIdGenerator_001
* @tc.desc: idGenerator get invalid newId
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, LimitIdGenerator_001, TestSize.Level2)
{
    int32_t limit = 0;
    UniqueIDGenerator idGenerator(limit);
    ASSERT_EQ(idGenerator.GetNewID(), -1);
}

/**
* @tc.name: LimitIdGenerator_002
* @tc.desc: idGenerator get valid newId
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, LimitIdGenerator_002, TestSize.Level2)
{
    int32_t limit = 10;
    UniqueIDGenerator idGenerator(limit);
    ASSERT_EQ(idGenerator.GetNewID(), 1);
}

/**
* @tc.name: LimitIdGenerator_003
* @tc.desc: idGenerator return valid/invalid ID
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, LimitIdGenerator_003, TestSize.Level2)
{
    int32_t limit = 10;
    UniqueIDGenerator idGenerator(limit);
    int32_t id = idGenerator.GetNewID();
    ASSERT_EQ(idGenerator.ReturnID(id), id);
    ASSERT_EQ(idGenerator.ReturnID(0), -1);
    ASSERT_EQ(idGenerator.ReturnID(limit + 1), -1);
}

/**
* @tc.name: ProcessScreenCaptureServerMap_001
* @tc.desc: AddScreenCaptureServerMap
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, ProcessScreenCaptureServerMap_001, TestSize.Level2)
{
    int32_t sessionId = ScreenCaptureServer::gIdGenerator_.GetNewID();
    std::shared_ptr<ScreenCaptureServer> server = std::make_shared<ScreenCaptureServer>();
    server->SetSessionId(sessionId);
    int32_t sizeBefore = ScreenCaptureServer::serverMap_.size();
    ScreenCaptureServer::AddScreenCaptureServerMap(sessionId, server);
    ASSERT_EQ(ScreenCaptureServer::serverMap_.size(), sizeBefore + 1);
    ScreenCaptureServer::RemoveScreenCaptureServerMap(sessionId);
}

/**
* @tc.name: ProcessScreenCaptureServerMap_002
* @tc.desc: RemoveScreenCaptureServerMap
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, ProcessScreenCaptureServerMap_002, TestSize.Level2)
{
    int32_t sessionId = ScreenCaptureServer::gIdGenerator_.GetNewID();
    std::shared_ptr<ScreenCaptureServer> server = std::make_shared<ScreenCaptureServer>();
    server->SetSessionId(sessionId);
    int32_t sizeBefore = ScreenCaptureServer::serverMap_.size();
    ScreenCaptureServer::AddScreenCaptureServerMap(sessionId, server);
    ScreenCaptureServer::RemoveScreenCaptureServerMap(sessionId);
    ASSERT_EQ(ScreenCaptureServer::serverMap_.size(), sizeBefore);
}

/**
* @tc.name: CheckGetScreenCaptureServerById_001
* @tc.desc: GetScreenCaptureServerByIdWithLock: sessionId exists in serverMap_
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CheckGetScreenCaptureServerById_001, TestSize.Level2)
{
    int32_t sessionId = ScreenCaptureServer::gIdGenerator_.GetNewID();
    std::shared_ptr<ScreenCaptureServer> server = std::make_shared<ScreenCaptureServer>();
    server->SetSessionId(sessionId);
    ScreenCaptureServer::AddScreenCaptureServerMap(sessionId, server);
    ASSERT_NE(ScreenCaptureServer::GetScreenCaptureServerByIdWithLock(sessionId), nullptr);
    ScreenCaptureServer::RemoveScreenCaptureServerMap(sessionId);
}

/**
* @tc.name: CheckGetScreenCaptureServerById_002
* @tc.desc: GetScreenCaptureServerByIdWithLock: sessionId not exists in serverMap_
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CheckGetScreenCaptureServerById_002, TestSize.Level2)
{
    ScreenCaptureServer::serverMap_.clear();
    UniqueIDGenerator gIdGenerator(20);
    int32_t sessionId = gIdGenerator.GetNewID();
    ASSERT_EQ(ScreenCaptureServer::GetScreenCaptureServerByIdWithLock(sessionId), nullptr);
    ScreenCaptureServer::gIdGenerator_.ReturnID(sessionId);
}

/**
* @tc.name: CountStartedSCSNumByPid_001
* @tc.desc: CountStartedScreenCaptureServerNumByPid
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CountStartedSCSNumByPid_001, TestSize.Level2)
{
    ScreenCaptureServer::serverMap_.clear();
    UniqueIDGenerator gIdGenerator(20);
    int32_t sessionId = gIdGenerator.GetNewID();
    std::shared_ptr<ScreenCaptureServer> server = std::make_shared<ScreenCaptureServer>();
    server->SetSessionId(sessionId);
    server->appInfo_.appPid = 1;
    ScreenCaptureServer::AddScreenCaptureServerMap(sessionId, server);
    ScreenCaptureServer::AddStartedSessionIdList(sessionId);
    MEDIA_LOGD("mapSize: %{public}d", static_cast<int32_t>(ScreenCaptureServer::serverMap_.size()));
    ASSERT_NE(ScreenCaptureServer::CountStartedScreenCaptureServerNumByPid(server->appInfo_.appPid), 0);

    ScreenCaptureServer::RemoveStartedSessionIdList(sessionId);
    ScreenCaptureServer::RemoveScreenCaptureServerMap(sessionId);
}

/**
* @tc.name: CheckScreenCaptureSessionIdLimit_001
* @tc.desc: CheckScreenCaptureSessionIdLimit: success
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CheckScreenCaptureSessionIdLimit_001, TestSize.Level2)
{
    ScreenCaptureServer::serverMap_.clear();
    std::shared_ptr<ScreenCaptureServer> server = std::make_shared<ScreenCaptureServer>();
    server->appInfo_.appUid = 1;
    ASSERT_EQ(ScreenCaptureServer::CheckScreenCaptureSessionIdLimit(server->appInfo_.appUid), true);
}

/**
* @tc.name: CheckScreenCaptureSessionIdLimit_002
* @tc.desc: CheckScreenCaptureSessionIdLimit: fail, current appUid has too many ScreenCaptureServer instances
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CheckScreenCaptureSessionIdLimit_002, TestSize.Level2)
{
    ScreenCaptureServer::serverMap_.clear();
    std::vector<std::shared_ptr<ScreenCaptureServer>> serverList;
    for (int32_t i = 0; i <= ScreenCaptureServer::maxSessionPerUid_; i++) {
        std::shared_ptr<ScreenCaptureServer> server = std::make_shared<ScreenCaptureServer>();
        serverList.push_back(server);
        int32_t sessionId = i + 1;
        server->SetSessionId(sessionId);
        server->appInfo_.appUid = 0;
        ASSERT_EQ(ScreenCaptureServer::CheckScreenCaptureSessionIdLimit(server->appInfo_.appUid), true);
        ScreenCaptureServer::AddScreenCaptureServerMap(sessionId, server);
    }
    std::shared_ptr<ScreenCaptureServer> server = std::make_shared<ScreenCaptureServer>();
    int32_t sessionId = ScreenCaptureServer::maxSessionPerUid_ + 1;
    server->SetSessionId(sessionId);
    server->appInfo_.appUid = 0;
    ASSERT_EQ(ScreenCaptureServer::CheckScreenCaptureSessionIdLimit(server->appInfo_.appUid), false);
    ScreenCaptureServer::serverMap_.clear();
}

/**
* @tc.name: CheckScreenCaptureAppLimit_001
* @tc.desc: CheckScreenCaptureAppLimit: true, appNum less than maxAppLimit_
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CheckScreenCaptureAppLimit_001, TestSize.Level2)
{
    ScreenCaptureServer::serverMap_.clear();
    int32_t curAppUid = ROOT_UID + 1;
    ASSERT_EQ(ScreenCaptureServer::CheckScreenCaptureAppLimit(curAppUid), true);
}

/**
* @tc.name: CheckScreenCaptureAppLimit_002
* @tc.desc: CheckScreenCaptureAppLimit: true, appNum exists
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CheckScreenCaptureAppLimit_002, TestSize.Level2)
{
    ScreenCaptureServer::serverMap_.clear();
    std::shared_ptr<ScreenCaptureServer> server = std::make_shared<ScreenCaptureServer>();
    int32_t sessionId = ScreenCaptureServer::gIdGenerator_.GetNewID();
    server->SetSessionId(sessionId);
    server->appInfo_.appUid = ROOT_UID + 1;
    ScreenCaptureServer::AddScreenCaptureServerMap(sessionId, server);
    ASSERT_EQ(ScreenCaptureServer::CheckScreenCaptureAppLimit(ROOT_UID + 1), true);
    ScreenCaptureServer::RemoveScreenCaptureServerMap(sessionId);
}

/**
* @tc.name: CheckScreenCaptureAppLimit_003
* @tc.desc: CheckScreenCaptureAppLimit: false, appNum reach maxAppLimit_
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CheckScreenCaptureAppLimit_003, TestSize.Level2)
{
    ScreenCaptureServer::serverMap_.clear();
    std::vector<std::shared_ptr<ScreenCaptureServer>> serverList;
    UniqueIDGenerator gIdGenerator(20);
    for (int32_t i = 0; i <= ScreenCaptureServer::maxAppLimit_; i++) {
        std::shared_ptr<ScreenCaptureServer> server = std::make_shared<ScreenCaptureServer>();
        serverList.push_back(server);
        int32_t sessionId = gIdGenerator.GetNewID();
        server->SetSessionId(sessionId);
        server->appInfo_.appUid = ROOT_UID + i;
        ScreenCaptureServer::AddScreenCaptureServerMap(sessionId, server);
    }
    ASSERT_EQ(ScreenCaptureServer::CheckScreenCaptureAppLimit(ROOT_UID + ScreenCaptureServer::maxAppLimit_ + 1), false);
    ScreenCaptureServer::serverMap_.clear();
}

/**
* @tc.name: ProcessStartedSessionIdList_001
* @tc.desc: AddStartedSessionIdList
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, ProcessStartedSessionIdList_001, TestSize.Level2)
{
    int32_t beforeSize = ScreenCaptureServer::startedSessionIDList_.size();
    UniqueIDGenerator gIdGenerator(20);
    int32_t sessionId = gIdGenerator.GetNewID();
    ScreenCaptureServer::AddStartedSessionIdList(sessionId);
    ASSERT_EQ(ScreenCaptureServer::startedSessionIDList_.size(), beforeSize + 1);
    ScreenCaptureServer::RemoveStartedSessionIdList(sessionId);
    ScreenCaptureServer::gIdGenerator_.ReturnID(sessionId);
}

/**
* @tc.name: ProcessStartedSessionIdList_002
* @tc.desc: RemoveStartedSessionIdList
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, ProcessStartedSessionIdList_002, TestSize.Level2)
{
    int32_t beforeSize = ScreenCaptureServer::startedSessionIDList_.size();
    UniqueIDGenerator gIdGenerator(20);
    int32_t sessionId = gIdGenerator.GetNewID();
    ScreenCaptureServer::AddStartedSessionIdList(sessionId);
    ScreenCaptureServer::RemoveStartedSessionIdList(sessionId);
    ASSERT_EQ(ScreenCaptureServer::startedSessionIDList_.size(), beforeSize);
    ScreenCaptureServer::gIdGenerator_.ReturnID(sessionId);
}

/**
* @tc.name: GetStartedSCSPidList_001
* @tc.desc: GetStartedScreenCaptureServerPidList
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, GetStartedSCSPidList_001, TestSize.Level2)
{
    std::shared_ptr<ScreenCaptureServer> server = std::make_shared<ScreenCaptureServer>();
    UniqueIDGenerator gIdGenerator(20);
    int32_t sessionId = gIdGenerator.GetNewID();
    server->SetSessionId(sessionId);
    ScreenCaptureServer::AddScreenCaptureServerMap(sessionId, server);
    ScreenCaptureServer::AddStartedSessionIdList(sessionId);
    MEDIA_LOGD("GetStartedSCSPidList_001 listSize: %{public}d, mapSize: %{public}d",
        static_cast<int32_t>(ScreenCaptureServer::GetStartedScreenCaptureServerPidList().size()),
        static_cast<int32_t>(ScreenCaptureServer::serverMap_.size()));
    ASSERT_EQ(ScreenCaptureServer::GetStartedScreenCaptureServerPidList().size()
        <= ScreenCaptureServer::serverMap_.size(), true);
    ScreenCaptureServer::RemoveStartedSessionIdList(sessionId);
    ScreenCaptureServer::RemoveScreenCaptureServerMap(sessionId);
}

/**
* @tc.name: GetStartedSCSPidList_002
* @tc.desc: GetAllStartedSessionIdList
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, GetStartedSCSPidList_002, TestSize.Level2)
{
    std::shared_ptr<ScreenCaptureServer> server = std::make_shared<ScreenCaptureServer>();
    UniqueIDGenerator gIdGenerator(20);
    int32_t sessionId = gIdGenerator.GetNewID();
    server->SetSessionId(sessionId);
    ScreenCaptureServer::AddScreenCaptureServerMap(sessionId, server);
    ScreenCaptureServer::AddStartedSessionIdList(sessionId);
    ASSERT_EQ(ScreenCaptureServer::GetAllStartedSessionIdList().size() <= ScreenCaptureServer::serverMap_.size(), true);
    ScreenCaptureServer::RemoveStartedSessionIdList(sessionId);
    ScreenCaptureServer::RemoveScreenCaptureServerMap(sessionId);
}

/**
* @tc.name: GetStartedSCSPidList_003
* @tc.desc: GetRunningScreenCaptureInstancePid
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, GetStartedSCSPidList_003, TestSize.Level2)
{
    std::shared_ptr<ScreenCaptureServer> server = std::make_shared<ScreenCaptureServer>();
    UniqueIDGenerator gIdGenerator(20);
    int32_t sessionId = gIdGenerator.GetNewID();
    server->SetSessionId(sessionId);
    ScreenCaptureServer::AddScreenCaptureServerMap(sessionId, server);
    ScreenCaptureServer::AddStartedSessionIdList(sessionId);
    std::list<int32_t> pidList{};
    ASSERT_EQ(ScreenCaptureServer::GetRunningScreenCaptureInstancePid(pidList), MSERR_OK);
}

/**
* @tc.name: CheckCanSCInstanceBeCreate_001
* @tc.desc: CanScreenCaptureInstanceBeCreate: true
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CheckCanSCInstanceBeCreate_001, TestSize.Level2)
{
    ScreenCaptureServer::serverMap_.clear();
    ASSERT_EQ(ScreenCaptureServer::CanScreenCaptureInstanceBeCreate(ROOT_UID), true);
}

/**
* @tc.name: CheckCanSCInstanceBeCreate_002
* @tc.desc: CanScreenCaptureInstanceBeCreate: false, exceed ScreenCaptureServer maxSessionPerUid limit.
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CheckCanSCInstanceBeCreate_002, TestSize.Level2)
{
    ScreenCaptureServer::serverMap_.clear();
    std::vector<std::shared_ptr<ScreenCaptureServer>> serverList;
    UniqueIDGenerator gIdGenerator(20);
    for (int32_t i = 0; i <= ScreenCaptureServer::maxSessionPerUid_; i++) {
        std::shared_ptr<ScreenCaptureServer> server = std::make_shared<ScreenCaptureServer>();
        serverList.push_back(server);
        int32_t sessionId = gIdGenerator.GetNewID();
        server->SetSessionId(sessionId);
        server->appInfo_.appUid = 0;
        ASSERT_EQ(ScreenCaptureServer::CanScreenCaptureInstanceBeCreate(server->appInfo_.appUid), true);
        ScreenCaptureServer::AddScreenCaptureServerMap(sessionId, server);
    }
    ASSERT_EQ(ScreenCaptureServer::CanScreenCaptureInstanceBeCreate(0), false);
    ScreenCaptureServer::serverMap_.clear();
}

/**
* @tc.name: CreateSCNewInstance_001
* @tc.desc: CreateScreenCaptureNewInstance: newInstance exists
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CreateSCNewInstance_001, TestSize.Level2)
{
    ASSERT_NE(ScreenCaptureServer::CreateScreenCaptureNewInstance(), nullptr);
}

/**
* @tc.name: CreateSCNewInstance_002
* @tc.desc: CreateScreenCaptureNewInstance: nullptr
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CreateSCNewInstance_002, TestSize.Level2)
{
    std::queue<int32_t> tmpQ;
    while (!ScreenCaptureServer::gIdGenerator_.availableIDs_.empty()) {
        tmpQ.push(ScreenCaptureServer::gIdGenerator_.availableIDs_.front());
        ScreenCaptureServer::gIdGenerator_.availableIDs_.pop();
    }
    ASSERT_EQ(ScreenCaptureServer::CreateScreenCaptureNewInstance(), nullptr);

    while (!tmpQ.empty()) {
        ScreenCaptureServer::gIdGenerator_.availableIDs_.push(tmpQ.front());
        tmpQ.pop();
    }
}

/**
* @tc.name: CreateSCNewInstance_003
* @tc.desc: Create: success
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CreateSCNewInstance_003, TestSize.Level2)
{
    ScreenCaptureServer::serverMap_.clear();
    ASSERT_NE(ScreenCaptureServer::Create(), nullptr);
}

/**
* @tc.name: CheckFirstStartPidInstance_001
* @tc.desc: startedSessionIDList_ is empty not ROOT_UID
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CheckFirstStartPidInstance_001, TestSize.Level2)
{
    ScreenCaptureServer::serverMap_.clear();
    ScreenCaptureServer::startedSessionIDList_.clear();
    screenCaptureServer_->appInfo_.appPid = 1;
    ASSERT_EQ(screenCaptureServer_->IsFirstStartPidInstance(screenCaptureServer_->appInfo_.appPid), true);
    ASSERT_EQ(screenCaptureServer_->IsLastStartedPidInstance(screenCaptureServer_->appInfo_.appPid), false);
}

/**
* @tc.name: CheckFirstStartPidInstance_002
* @tc.desc: startedSessionIDList_ exists one sessionId
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CheckFirstStartPidInstance_002, TestSize.Level2)
{
    ScreenCaptureServer::serverMap_.clear();
    ScreenCaptureServer::startedSessionIDList_.clear();
    std::shared_ptr<ScreenCaptureServer> server = std::make_shared<ScreenCaptureServer>();
    int32_t sessionId = ScreenCaptureServer::gIdGenerator_.GetNewID();
    server->SetSessionId(sessionId);
    server->appInfo_.appPid = 1;
    ScreenCaptureServer::AddScreenCaptureServerMap(sessionId, server);
    ScreenCaptureServer::AddStartedSessionIdList(sessionId);
    ASSERT_EQ(server->IsFirstStartPidInstance(server->appInfo_.appPid), false);
    ASSERT_EQ(server->FirstPidUpdatePrivacyUsingPermissionState(server->appInfo_.appPid), true);
    ASSERT_EQ(server->IsLastStartedPidInstance(server->appInfo_.appPid), true);

    ScreenCaptureServer::RemoveScreenCaptureServerMap(sessionId);
    ScreenCaptureServer::serverMap_.clear();
    ScreenCaptureServer::startedSessionIDList_.clear();
}

/**
* @tc.name: CheckFirstPidUpdatePrivacyUsingPermissionState_001
* @tc.desc: startedSessionIDList_ is empty ROOT_UID
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CheckFirstPidUpdatePrivacyUsingPermissionState_001, TestSize.Level2)
{
    ScreenCaptureServer::serverMap_.clear();
    ScreenCaptureServer::startedSessionIDList_.clear();
    std::shared_ptr<ScreenCaptureServer> server = std::make_shared<ScreenCaptureServer>();
    server->appInfo_.appUid = ROOT_UID;
    server->appInfo_.appPid = 1;
    ASSERT_EQ(server->IsFirstStartPidInstance(server->appInfo_.appPid), true);
    ASSERT_EQ(server->FirstPidUpdatePrivacyUsingPermissionState(server->appInfo_.appPid), true);
}

/**
* @tc.name: CheckLastStartedPidInstance_001
* @tc.desc: startedSessionIDList_ exists more than one sessionId
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CheckLastStartedPidInstance_001, TestSize.Level2)
{
    ScreenCaptureServer::serverMap_.clear();
    ScreenCaptureServer::startedSessionIDList_.clear();
    std::vector<std::shared_ptr<ScreenCaptureServer>> serverList;
    UniqueIDGenerator gIdGenerator(20);
    for (int32_t i = 0; i < ScreenCaptureServer::maxSessionPerUid_; i++) {
        std::shared_ptr<ScreenCaptureServer> server = std::make_shared<ScreenCaptureServer>();
        serverList.push_back(server);
        int32_t sessionId = gIdGenerator.GetNewID();
        server->SetSessionId(sessionId);
        server->appInfo_.appPid = 1;
        ScreenCaptureServer::AddScreenCaptureServerMap(sessionId, server);
        ScreenCaptureServer::AddStartedSessionIdList(sessionId);
    }
    screenCaptureServer_->appInfo_.appPid = 1;
    ASSERT_EQ(screenCaptureServer_->IsLastStartedPidInstance(screenCaptureServer_->appInfo_.appPid), false);
    ASSERT_EQ(screenCaptureServer_->LastPidUpdatePrivacyUsingPermissionState(screenCaptureServer_->appInfo_.appPid),
        true);
    
    ScreenCaptureServer::serverMap_.clear();
    ScreenCaptureServer::startedSessionIDList_.clear();
}

/**
* @tc.name: CheckLastPidUpdatePrivacyUsingPermissionState_001
* @tc.desc: startedSessionIDList_ exists one sessionId
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CheckLastPidUpdatePrivacyUsingPermissionState_001, TestSize.Level2)
{
    ScreenCaptureServer::serverMap_.clear();
    ScreenCaptureServer::startedSessionIDList_.clear();
    std::shared_ptr<ScreenCaptureServer> server = std::make_shared<ScreenCaptureServer>();
    int32_t sessionId = ScreenCaptureServer::gIdGenerator_.GetNewID();
    server->SetSessionId(sessionId);
    server->appInfo_.appUid = ROOT_UID;
    server->appInfo_.appPid = 1;
    ScreenCaptureServer::AddScreenCaptureServerMap(sessionId, server);
    ScreenCaptureServer::AddStartedSessionIdList(sessionId);
    ASSERT_EQ(server->IsLastStartedPidInstance(server->appInfo_.appPid), true);
    ASSERT_EQ(server->LastPidUpdatePrivacyUsingPermissionState(server->appInfo_.appPid), true);
}

/**
* @tc.name: StopScreenCaptureByEvent_001
* @tc.desc: StopScreenCaptureByEvent_001
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, StopScreenCaptureByEvent_001, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STOPPED;
    ASSERT_EQ(screenCaptureServer_->StopScreenCaptureByEvent(AVScreenCaptureStateCode::
        SCREEN_CAPTURE_STATE_STOPPED_BY_USER), MSERR_OK);
}

/**
* @tc.name: StopScreenCapture_001
* @tc.desc: StopScreenCapture_001
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, StopScreenCapture_001, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STOPPED;
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

/**
* @tc.name: CheckPrivacyWindowSkipPermission_001
* @tc.desc: CheckPrivacyWindowSkipPermission_001
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CheckPrivacyWindowSkipPermission_001, TestSize.Level2)
{
    std::shared_ptr<ScreenCaptureServer> server = std::make_shared<ScreenCaptureServer>();
    server->appInfo_.appUid = ROOT_UID;
    server->appInfo_.appPid = 1;
    ASSERT_EQ(server->CheckPrivacyWindowSkipPermission(), false);
}

/**
* @tc.name: ProcessSCServerSaUid_001
* @tc.desc: check SCServerSaUid
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, ProcessSCServerSaUid_001, TestSize.Level2)
{
    int32_t saUid = ROOT_UID + 1;
    screenCaptureServer_->SetSCServerSaUid(saUid);
    ASSERT_EQ(screenCaptureServer_->GetSCServerSaUid(), saUid);
}

/**
* @tc.name: ProcesssaUidAppUidMap_001
* @tc.desc: check AddSaAppInfoMap
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, ProcesssaUidAppUidMap_001, TestSize.Level2)
{
    ScreenCaptureServer::saUidAppUidMap_.clear();
    int32_t appUid = ROOT_UID;
    int32_t saUid = appUid + 1;
    ScreenCaptureServer::AddSaAppInfoMap(saUid, appUid);
    ASSERT_EQ(ScreenCaptureServer::saUidAppUidMap_.size(), 1);
}

/**
* @tc.name: ProcesssaUidAppUidMap_002
* @tc.desc: check RemoveSaAppInfoMap
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, ProcesssaUidAppUidMap_002, TestSize.Level2)
{
    ScreenCaptureServer::saUidAppUidMap_.clear();
    int32_t appUid = ROOT_UID;
    int32_t saUid = appUid + 1;
    ScreenCaptureServer::AddSaAppInfoMap(saUid, appUid);
    ASSERT_EQ(ScreenCaptureServer::saUidAppUidMap_.size(), 1);
    ScreenCaptureServer::RemoveSaAppInfoMap(saUid);
    ASSERT_EQ(ScreenCaptureServer::saUidAppUidMap_.size(), 0);
}

/**
* @tc.name: CheckIsSAServiceCalling_001
* @tc.desc: check IsSAServiceCalling
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CheckIsSAServiceCalling_001, TestSize.Level2)
{
    ASSERT_EQ(ScreenCaptureServer::IsSAServiceCalling(), false);
}

/**
* @tc.name: CheckIsSaUidValid_001
* @tc.desc: check IsSaUidValid
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CheckIsSaUidValid_001, TestSize.Level2)
{
    int32_t appUid = ROOT_UID;
    int32_t saUid = -1;
    ASSERT_EQ(ScreenCaptureServer::IsSaUidValid(saUid, appUid), false);
    saUid = appUid + 1;
    ASSERT_EQ(ScreenCaptureServer::IsSaUidValid(saUid, appUid), false);
}

/**
* @tc.name: CheckIsSaUidValid_002
* @tc.desc: saUid not in saUidAppUidMap_
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CheckIsSaUidValid_002, TestSize.Level2)
{
    int32_t appUid = ROOT_UID;
    int32_t saUid = -1;
    ScreenCaptureServer::saUidAppUidMap_ = {};
    ScreenCaptureServer::saUidAppUidMap_[saUid + 1] = {appUid, 0};
    ASSERT_EQ(ScreenCaptureServer::CheckSaUid(saUid, appUid), true);
}

/**
* @tc.name: CheckIsSaUidValid_003
* @tc.desc: saUid in saUidAppUidMap_ and saUid.first == appUid
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CheckIsSaUidValid_003, TestSize.Level2)
{
    int32_t appUid = ROOT_UID;
    int32_t saUid = -1;
    ScreenCaptureServer::saUidAppUidMap_ = {};
    ScreenCaptureServer::saUidAppUidMap_[saUid] = {appUid, 0};
    ASSERT_EQ(ScreenCaptureServer::CheckSaUid(saUid, appUid), true);
}

/**
* @tc.name: CheckIsSaUidValid_004
* @tc.desc: saUid in saUidAppUidMap_ and saUid.first != appUid
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CheckIsSaUidValid_004, TestSize.Level2)
{
    int32_t appUid = ROOT_UID;
    int32_t saUid = -1;
    ScreenCaptureServer::saUidAppUidMap_ = {};
    ScreenCaptureServer::saUidAppUidMap_[saUid] = {appUid + 1, 0};
    ASSERT_EQ(ScreenCaptureServer::CheckSaUid(saUid, appUid), false);
}

/**
* @tc.name: CheckIsSaUidValid_005
* @tc.desc: saUid in saUidAppUidMap_ and saUid.first != appUid
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CheckIsSaUidValid_005, TestSize.Level2)
{
    int32_t appUid = ROOT_UID;
    int32_t saUid = -1;
    ScreenCaptureServer::saUidAppUidMap_ = {};
    ScreenCaptureServer::saUidAppUidMap_[saUid] = {appUid, ScreenCaptureServer::maxSessionPerUid_};
    ASSERT_EQ(ScreenCaptureServer::CheckSaUid(saUid, appUid), false);
}

/**
* @tc.name: SetAndCheckSaLimit_001
* @tc.desc: SetAndCheckSaLimit_001
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, SetAndCheckSaLimit_001, TestSize.Level2)
{
    OHOS::AudioStandard::AppInfo appInfo;
    appInfo.appUid = 0;
    appInfo.appPid = 0;
    appInfo.appTokenId = 0;
    appInfo.appFullTokenId = 0;

    int32_t sessionId = ScreenCaptureServer::gIdGenerator_.GetNewID();
    std::shared_ptr<ScreenCaptureServer> server = std::make_shared<ScreenCaptureServer>();
    server->SetSessionId(sessionId);
    ScreenCaptureServer::AddScreenCaptureServerMap(sessionId, server);

    ASSERT_EQ(server->SetAndCheckAppInfo(appInfo), MSERR_INVALID_OPERATION);
    ASSERT_EQ(server->SetAndCheckSaLimit(appInfo), MSERR_INVALID_OPERATION);
}

/**
* @tc.name: SetAndCheckLimit_001
* @tc.desc: SetAndCheckLimit_001
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, SetAndCheckLimit_001, TestSize.Level2)
{
    ScreenCaptureServer::serverMap_.clear();
    ASSERT_EQ(screenCaptureServer_->SetAndCheckLimit(), MSERR_OK);
}

/**
* @tc.name: SetAndCheckLimit_002
* @tc.desc: SetAndCheckLimit_002
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, SetAndCheckLimit_002, TestSize.Level2)
{
    ScreenCaptureServer::serverMap_.clear();
    std::vector<std::shared_ptr<ScreenCaptureServer>> serverList;
    UniqueIDGenerator gIdGenerator(20);
    for (int32_t i = 0; i <= ScreenCaptureServer::maxSessionPerUid_; i++) {
        std::shared_ptr<ScreenCaptureServer> server = std::make_shared<ScreenCaptureServer>();
        serverList.push_back(server);
        int32_t sessionId = gIdGenerator.GetNewID();
        server->SetSessionId(sessionId);
        server->appInfo_.appUid = IPCSkeleton::GetCallingUid();
        ScreenCaptureServer::AddScreenCaptureServerMap(sessionId, server);
    }
    std::shared_ptr<ScreenCaptureServer> server = std::make_shared<ScreenCaptureServer>();
    int32_t sessionId = gIdGenerator.GetNewID();
    server->SetSessionId(sessionId);
    ASSERT_EQ(server->SetAndCheckLimit(), MSERR_INVALID_OPERATION);
}

/**
* @tc.name: CheckReleaseInner_001
* @tc.desc: CheckReleaseInner_001
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CheckReleaseInner_001, TestSize.Level2)
{
    ScreenCaptureServer::serverMap_.clear();
    ScreenCaptureServer::saUidAppUidMap_.clear();
    UniqueIDGenerator gIdGenerator(20);
    int32_t sessionId = gIdGenerator.GetNewID();
    std::shared_ptr<ScreenCaptureServer> server = std::make_shared<ScreenCaptureServer>();
    server->SetSessionId(sessionId);
    server->captureState_ = AVScreenCaptureState::STOPPED;
    ScreenCaptureServer::AddScreenCaptureServerMap(sessionId, server);

    int32_t appUid = ROOT_UID + 1;
    int32_t saUid = 1;
    server->SetSCServerSaUid(saUid);
    server->AddSaAppInfoMap(saUid, appUid);
    int32_t appInfoMapSizeBefore = ScreenCaptureServer::saUidAppUidMap_.size();
    int32_t serverMapSizeBefore = ScreenCaptureServer::serverMap_.size();
    server->ReleaseInner();

    ASSERT_EQ(ScreenCaptureServer::saUidAppUidMap_.size(), appInfoMapSizeBefore - 1);
    ASSERT_EQ(ScreenCaptureServer::serverMap_.size(), serverMapSizeBefore - 1);
}

/**
* @tc.name: CheckIsIDExist_001
* @tc.desc: CheckIsIDExist_001
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CheckIsIDExist_001, TestSize.Level2)
{
    UniqueIDGenerator gIdGenerator(20);
    int32_t sessionId = gIdGenerator.GetNewID();
    ASSERT_EQ(gIdGenerator.IsIDExists(sessionId), false);
    int32_t sessionId1 = gIdGenerator.ReturnID(sessionId);
    ASSERT_EQ(gIdGenerator.IsIDExists(sessionId1), true);
}

/**
* @tc.name: CheckSpecifiedDataTypeNum_001
* @tc.desc: CheckSCServerSpecifiedDataTypeNum Success
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CheckSpecifiedDataTypeNum_001, TestSize.Level2)
{
    ScreenCaptureServer::serverMap_.clear();
    UniqueIDGenerator gIdGenerator(20);
    int32_t sessionId = gIdGenerator.GetNewID();
    std::shared_ptr<ScreenCaptureServer> server = std::make_shared<ScreenCaptureServer>();
    server->SetSessionId(sessionId);
    server->captureConfig_.dataType = DataType::ORIGINAL_STREAM;
    server->appInfo_.appUid = ROOT_UID;
    ASSERT_EQ(ScreenCaptureServer::CheckSCServerSpecifiedDataTypeNum(server->appInfo_.appUid,
        server->captureConfig_.dataType), true);
}

/**
* @tc.name: CheckSpecifiedDataTypeNum_002
* @tc.desc: CheckSCServerSpecifiedDataTypeNum Failed
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CheckSpecifiedDataTypeNum_002, TestSize.Level2)
{
    ScreenCaptureServer::serverMap_.clear();
    UniqueIDGenerator gIdGenerator(20);
    std::vector<std::shared_ptr<ScreenCaptureServer>> serverList;
    for (int32_t i = 0; i < ScreenCaptureServer::maxSCServerDataTypePerUid_; i++) {
        std::shared_ptr<ScreenCaptureServer> server = std::make_shared<ScreenCaptureServer>();
        serverList.push_back(server);
        int32_t sessionId = gIdGenerator.GetNewID();
        server->SetSessionId(sessionId);
        server->appInfo_.appUid = IPCSkeleton::GetCallingUid();
        server->captureConfig_.dataType = DataType::ORIGINAL_STREAM;
        ScreenCaptureServer::AddScreenCaptureServerMap(sessionId, server);
        ASSERT_EQ(ScreenCaptureServer::CheckSCServerSpecifiedDataTypeNum(server->appInfo_.appUid,
            server->captureConfig_.dataType), true);
    }
    std::shared_ptr<ScreenCaptureServer> server = std::make_shared<ScreenCaptureServer>();
    int32_t sessionId = gIdGenerator.GetNewID();
    server->SetSessionId(sessionId);
    server->appInfo_.appUid = IPCSkeleton::GetCallingUid();
    server->captureConfig_.dataType = DataType::ORIGINAL_STREAM;
    ScreenCaptureServer::AddScreenCaptureServerMap(sessionId, server);
    ASSERT_EQ(ScreenCaptureServer::CheckSCServerSpecifiedDataTypeNum(server->appInfo_.appUid,
        server->captureConfig_.dataType), false);
}

/**
* @tc.name: AddSaAppInfoMap_001
* @tc.desc: AddSaAppInfoMap has sa uid info
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, AddSaAppInfoMap_001, TestSize.Level2)
{
    int32_t saUid = 10086;
    ScreenCaptureServer::saUidAppUidMap_[saUid] = {saUid, 0};
    screenCaptureServer_->AddSaAppInfoMap(saUid, saUid);
    ASSERT_EQ(ScreenCaptureServer::saUidAppUidMap_[saUid].second, 1);
}

/**
* @tc.name: RemoveSaAppInfoMap_001
* @tc.desc: RemoveSaAppInfoMap has sa uid info
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, RemoveSaAppInfoMap_001, TestSize.Level2)
{
    int32_t saUid = 10086;
    ScreenCaptureServer::saUidAppUidMap_[saUid] = {saUid, 1};
    screenCaptureServer_->RemoveSaAppInfoMap(saUid);
    ASSERT_EQ(ScreenCaptureServer::saUidAppUidMap_[saUid].second, 0);
}

/**
* @tc.name: GetBoxSelectedFromJson_001
* @tc.desc: content invalid
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, GetBoxSelectedFromJson_001, TestSize.Level2)
{
    Json::Value root;
    std::string content = "ghgh%^&%^$*^(}{^af&**)";
    bool value;
    screenCaptureServer_->GetBoxSelectedFromJson(root, content, "choice", value);
    ASSERT_NE(screenCaptureServer_, nullptr);
}

/**
* @tc.name: GetBoxSelectedFromJson_002
* @tc.desc: content valid
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, GetBoxSelectedFromJson_002, TestSize.Level2)
{
    Json::Value root;
    std::string content = "{\"choice_\": \"true\"}";
    bool value;
    screenCaptureServer_->GetBoxSelectedFromJson(root, content, "choice", value);
    ASSERT_NE(screenCaptureServer_, nullptr);
}
} // Media
} // OHOS