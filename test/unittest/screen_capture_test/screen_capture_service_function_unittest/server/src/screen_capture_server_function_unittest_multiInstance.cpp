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

#include <algorithm>

#include "screen_capture_monitor_server.h"
#include "screen_capture_server_function_unittest.h"
#include "screen_capture_server_manager.h"

using namespace testing::ext;
using namespace OHOS::Media::ScreenCaptureTestParam;
using namespace OHOS::Media;
using namespace OHOS::Rosen;

namespace {
constexpr int32_t ROOT_UID = 0;
}

namespace OHOS {
namespace Media {
namespace {
inline size_t CountForegroundMissions(const std::vector<MissionInfo> &missions)
{
    return static_cast<size_t>(std::count_if(missions.begin(), missions.end(),
        [](const MissionInfo &m) { return m.isForeground; }));
}
}

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
    int32_t sessionId = ScreenCaptureServerManager::GetInstance().GetNewSessionId();
    std::shared_ptr<ScreenCaptureServer> server = MakeScreenCaptureServerShared();
    server->sessionId_ = sessionId;
    int32_t sizeBefore = ScreenCaptureServerManager::GetInstance().serverMap_.size();
    ScreenCaptureServerManager::GetInstance().RegisterServer(sessionId, server, server->appInfo_.appUid);
    ASSERT_EQ(ScreenCaptureServerManager::GetInstance().serverMap_.size(), sizeBefore + 1);
    ScreenCaptureServerManager::GetInstance().RemoveScreenCaptureServerMap(sessionId);
}

/**
 * @tc.name: ProcessScreenCaptureServerMap_002
 * @tc.desc: RemoveScreenCaptureServerMap
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, ProcessScreenCaptureServerMap_002, TestSize.Level2)
{
    int32_t sessionId = ScreenCaptureServerManager::GetInstance().GetNewSessionId();
    std::shared_ptr<ScreenCaptureServer> server = MakeScreenCaptureServerShared();
    server->sessionId_ = sessionId;
    int32_t sizeBefore = ScreenCaptureServerManager::GetInstance().serverMap_.size();
    ScreenCaptureServerManager::GetInstance().RegisterServer(sessionId, server, server->appInfo_.appUid);
    int32_t sizeAfter = ScreenCaptureServerManager::GetInstance().serverMap_.size();
    ASSERT_EQ(ScreenCaptureServerManager::GetInstance().serverMap_.size(), sizeBefore + 1);
    ScreenCaptureServerManager::GetInstance().RemoveScreenCaptureServerMap(sessionId);
    ASSERT_EQ(ScreenCaptureServerManager::GetInstance().serverMap_.size(), sizeAfter - 1);
}

/**
 * @tc.name: CheckGetScreenCaptureServerById_001
 * @tc.desc: GetScreenCaptureServerById: sessionId exists in serverMap_
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, CheckGetScreenCaptureServerById_001, TestSize.Level2)
{
    int32_t sessionId = ScreenCaptureServerManager::GetInstance().GetNewSessionId();
    std::shared_ptr<ScreenCaptureServer> server = MakeScreenCaptureServerShared();
    server->sessionId_ = sessionId;
    ScreenCaptureServerManager::GetInstance().RegisterServer(sessionId, server, server->appInfo_.appUid);
    ASSERT_NE(ScreenCaptureServerManager::GetInstance().GetScreenCaptureServerById(sessionId).lock(), nullptr);
    ScreenCaptureServerManager::GetInstance().RemoveScreenCaptureServerMap(sessionId);
}

/**
 * @tc.name: CheckGetScreenCaptureServerById_002
 * @tc.desc: GetScreenCaptureServerById: sessionId not exists in serverMap_
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, CheckGetScreenCaptureServerById_002, TestSize.Level2)
{
    ScreenCaptureServerManager::GetInstance().serverMap_.clear();
    UniqueIDGenerator gIdGenerator(20);
    int32_t sessionId = gIdGenerator.GetNewID();
    ASSERT_EQ(ScreenCaptureServerManager::GetInstance().GetScreenCaptureServerById(sessionId).lock(), nullptr);
    ScreenCaptureServerManager::GetInstance().idGenerator_.ReturnID(sessionId);
}

/**
 * @tc.name: CheckScreenCaptureSessionIdLimit_001
 * @tc.desc: CheckScreenCaptureSessionIdLimit: success
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, CheckScreenCaptureSessionIdLimit_001, TestSize.Level2)
{
    ScreenCaptureServerManager::GetInstance().serverMap_.clear();
    std::shared_ptr<ScreenCaptureServer> server = MakeScreenCaptureServerShared();
    server->appInfo_.appUid = 1;
    ASSERT_EQ(ScreenCaptureServerManager::GetInstance().CanScreenCaptureInstanceBeCreate(server->appInfo_.appUid),
        true);
}

/**
 * @tc.name: CheckScreenCaptureSessionIdLimit_002
 * @tc.desc: CheckScreenCaptureSessionIdLimit: fail, current appUid has too many ScreenCaptureServer instances
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, CheckScreenCaptureSessionIdLimit_002, TestSize.Level2)
{
    ScreenCaptureServerManager::GetInstance().serverMap_.clear();
    std::vector<std::shared_ptr<ScreenCaptureServer>> serverList;
    for (int32_t i = 0; i <= ScreenCaptureServerManager::GetInstance().maxSessionPerUid_; i++) {
        std::shared_ptr<ScreenCaptureServer> server = MakeScreenCaptureServerShared();
        serverList.push_back(server);
        int32_t sessionId = i + 1;
        server->sessionId_ = sessionId;
        server->appInfo_.appUid = 0;
        ASSERT_EQ(ScreenCaptureServerManager::GetInstance().CanScreenCaptureInstanceBeCreate(server->appInfo_.appUid),
            true);
        ScreenCaptureServerManager::GetInstance().RegisterServer(sessionId, server, server->appInfo_.appUid);
    }
    std::shared_ptr<ScreenCaptureServer> server = MakeScreenCaptureServerShared();
    int32_t sessionId = ScreenCaptureServerManager::GetInstance().maxSessionPerUid_ + 1;
    server->sessionId_ = sessionId;
    server->appInfo_.appUid = 0;
    ASSERT_EQ(ScreenCaptureServerManager::GetInstance().CanScreenCaptureInstanceBeCreate(server->appInfo_.appUid),
        false);
    ScreenCaptureServerManager::GetInstance().serverMap_.clear();
}

/**
 * @tc.name: CheckScreenCaptureSessionIdLimit_003
 * @tc.desc: iterPtr == nullptr
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, CheckScreenCaptureSessionIdLimit_003, TestSize.Level2)
{
    for (auto iter = ScreenCaptureServerManager::GetInstance().serverMap_.begin();
        iter != ScreenCaptureServerManager::GetInstance().serverMap_.end(); iter++) {
        std::weak_ptr<ScreenCaptureServer> wp;
        (iter->second.server) = wp;
    }
    ASSERT_EQ(ScreenCaptureServerManager::GetInstance().CanScreenCaptureInstanceBeCreate(
                  screenCaptureServer_->appInfo_.appUid),
        true);
}

/**
 * @tc.name: CheckScreenCaptureSessionIdLimit_004
 * @tc.desc: curAppUid != iterPtr->GetAppUid()
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, CheckScreenCaptureSessionIdLimit_004, TestSize.Level2)
{
    ASSERT_EQ(ScreenCaptureServerManager::GetInstance().CanScreenCaptureInstanceBeCreate(
                  screenCaptureServer_->appInfo_.appUid + 1),
        true);
}

/**
 * @tc.name: CheckScreenCaptureAppLimit_001
 * @tc.desc: CheckScreenCaptureAppLimit: true, appNum less than maxAppLimit_
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, CheckScreenCaptureAppLimit_001, TestSize.Level2)
{
    ScreenCaptureServerManager::GetInstance().serverMap_.clear();
    int32_t curAppUid = ROOT_UID + 1;
    ASSERT_EQ(ScreenCaptureServerManager::GetInstance().CanScreenCaptureInstanceBeCreate(curAppUid), true);
}

/**
 * @tc.name: CheckScreenCaptureAppLimit_002
 * @tc.desc: CheckScreenCaptureAppLimit: true, appNum exists
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, CheckScreenCaptureAppLimit_002, TestSize.Level2)
{
    ScreenCaptureServerManager::GetInstance().serverMap_.clear();
    std::shared_ptr<ScreenCaptureServer> server = MakeScreenCaptureServerShared();
    int32_t sessionId = ScreenCaptureServerManager::GetInstance().GetNewSessionId();
    server->sessionId_ = sessionId;
    server->appInfo_.appUid = ROOT_UID + 1;
    ScreenCaptureServerManager::GetInstance().RegisterServer(sessionId, server, server->appInfo_.appUid);
    ASSERT_EQ(ScreenCaptureServerManager::GetInstance().CanScreenCaptureInstanceBeCreate(ROOT_UID + 1), true);
    ScreenCaptureServerManager::GetInstance().RemoveScreenCaptureServerMap(sessionId);
}

/**
 * @tc.name: CheckScreenCaptureAppLimit_003
 * @tc.desc: CheckScreenCaptureAppLimit: false, appNum reach maxAppLimit_
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, CheckScreenCaptureAppLimit_003, TestSize.Level2)
{
    ScreenCaptureServerManager::GetInstance().serverMap_.clear();
    std::vector<std::shared_ptr<ScreenCaptureServer>> serverList;
    UniqueIDGenerator gIdGenerator(20);
    for (int32_t i = 0; i <= ScreenCaptureServerManager::GetInstance().maxAppLimit_; i++) {
        std::shared_ptr<ScreenCaptureServer> server = MakeScreenCaptureServerShared();
        serverList.push_back(server);
        int32_t sessionId = gIdGenerator.GetNewID();
        server->sessionId_ = sessionId;
        server->appInfo_.appUid = ROOT_UID + i;
        ScreenCaptureServerManager::GetInstance().RegisterServer(sessionId, server, server->appInfo_.appUid);
    }
    ASSERT_EQ(ScreenCaptureServerManager::GetInstance().CanScreenCaptureInstanceBeCreate(
                  ROOT_UID + ScreenCaptureServerManager::GetInstance().maxAppLimit_ + 1),
        false);
    ScreenCaptureServerManager::GetInstance().serverMap_.clear();
}

/**
 * @tc.name: CheckCanSCInstanceBeCreate_001
 * @tc.desc: CanScreenCaptureInstanceBeCreate: true
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, CheckCanSCInstanceBeCreate_001, TestSize.Level2)
{
    ScreenCaptureServerManager::GetInstance().serverMap_.clear();
    ASSERT_EQ(ScreenCaptureServerManager::GetInstance().CanScreenCaptureInstanceBeCreate(ROOT_UID), true);
}

/**
 * @tc.name: CheckCanSCInstanceBeCreate_002
 * @tc.desc: CanScreenCaptureInstanceBeCreate: false, exceed ScreenCaptureServer maxSessionPerUid limit.
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, CheckCanSCInstanceBeCreate_002, TestSize.Level2)
{
    ScreenCaptureServerManager::GetInstance().serverMap_.clear();
    std::vector<std::shared_ptr<ScreenCaptureServer>> serverList;
    UniqueIDGenerator gIdGenerator(20);
    for (int32_t i = 0; i <= ScreenCaptureServerManager::GetInstance().maxSessionPerUid_; i++) {
        std::shared_ptr<ScreenCaptureServer> server = MakeScreenCaptureServerShared();
        serverList.push_back(server);
        int32_t sessionId = gIdGenerator.GetNewID();
        server->sessionId_ = sessionId;
        server->appInfo_.appUid = 0;
        ASSERT_EQ(ScreenCaptureServerManager::GetInstance().CanScreenCaptureInstanceBeCreate(server->appInfo_.appUid),
            true);
        ScreenCaptureServerManager::GetInstance().RegisterServer(sessionId, server, server->appInfo_.appUid);
    }
    ASSERT_EQ(ScreenCaptureServerManager::GetInstance().CanScreenCaptureInstanceBeCreate(0), false);
    ScreenCaptureServerManager::GetInstance().serverMap_.clear();
}

/**
 * @tc.name: CreateSCNewInstance_001
 * @tc.desc: CreateScreenCaptureNewInstance: newInstance exists
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, CreateSCNewInstance_001, TestSize.Level2)
{
    ASSERT_NE(MakeScreenCaptureServerViaCreate(), nullptr);
}

/**
 * @tc.name: CreateSCNewInstance_002
 * @tc.desc: CreateScreenCaptureNewInstance: nullptr
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, CreateSCNewInstance_002, TestSize.Level2)
{
    std::queue<int32_t> tmpQ;
    while (!ScreenCaptureServerManager::GetInstance().idGenerator_.availableIDs_.empty()) {
        tmpQ.push(ScreenCaptureServerManager::GetInstance().idGenerator_.availableIDs_.front());
        ScreenCaptureServerManager::GetInstance().idGenerator_.availableIDs_.pop();
    }
    ASSERT_EQ(ScreenCaptureServer::Create(nullptr), nullptr);

    while (!tmpQ.empty()) {
        ScreenCaptureServerManager::GetInstance().idGenerator_.availableIDs_.push(tmpQ.front());
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
    ScreenCaptureServerManager::GetInstance().serverMap_.clear();
    ASSERT_NE(MakeScreenCaptureServerViaCreate(), nullptr);
}

/**
 * @tc.name: CheckFirstStartPidInstance_001
 * @tc.desc: no running capture, first pid instance
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, CheckFirstStartPidInstance_001, TestSize.Level2)
{
    screenCaptureServer_->appInfo_.appPid = 1;
    ASSERT_EQ(screenCaptureServer_->IsFirstStartPidInstance(screenCaptureServer_->appInfo_.appPid), true);
}

/**
 * @tc.name: CheckFirstStartPidInstance_002
 * @tc.desc: pid already running, not first instance
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, CheckFirstStartPidInstance_002, TestSize.Level2)
{
    auto &monitorServer = ScreenCaptureMonitorServer::GetInstance();
    int32_t pid = 1;
    monitorServer.CallOnScreenCaptureStarted(pid);
    ASSERT_EQ(screenCaptureServer_->IsFirstStartPidInstance(pid), false);
    ASSERT_EQ(screenCaptureServer_->FirstPidUpdatePrivacyUsingPermissionState(pid), true);
    monitorServer.CallOnScreenCaptureFinished(pid);
    ASSERT_EQ(screenCaptureServer_->IsLastStartedPidInstance(pid), true);
}

/**
 * @tc.name: CheckFirstPidUpdatePrivacyUsingPermissionState_001
 * @tc.desc: no running capture, first pid instance, ROOT_UID
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, CheckFirstPidUpdatePrivacyUsingPermissionState_001, TestSize.Level2)
{
    std::shared_ptr<ScreenCaptureServer> server = MakeScreenCaptureServerShared();
    server->appInfo_.appUid = ROOT_UID;
    server->appInfo_.appPid = 1;
    ASSERT_EQ(server->IsFirstStartPidInstance(server->appInfo_.appPid), true);
    ASSERT_EQ(server->FirstPidUpdatePrivacyUsingPermissionState(server->appInfo_.appPid), true);
}

/**
 * @tc.name: CheckLastStartedPidInstance_001
 * @tc.desc: multiple running captures, not last instance
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, CheckLastStartedPidInstance_001, TestSize.Level2)
{
    auto &monitorServer = ScreenCaptureMonitorServer::GetInstance();
    int32_t pid = 1;
    monitorServer.CallOnScreenCaptureStarted(pid);
    monitorServer.CallOnScreenCaptureStarted(pid);
    monitorServer.CallOnScreenCaptureFinished(pid);
    ASSERT_EQ(screenCaptureServer_->IsLastStartedPidInstance(pid), false);
    ASSERT_EQ(screenCaptureServer_->LastPidUpdatePrivacyUsingPermissionState(pid), true);
    monitorServer.CallOnScreenCaptureFinished(pid);
}

/**
 * @tc.name: CheckLastPidUpdatePrivacyUsingPermissionState_001
 * @tc.desc: one running capture, last instance
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, CheckLastPidUpdatePrivacyUsingPermissionState_001, TestSize.Level2)
{
    auto &monitorServer = ScreenCaptureMonitorServer::GetInstance();
    std::shared_ptr<ScreenCaptureServer> server = MakeScreenCaptureServerShared();
    server->appInfo_.appUid = ROOT_UID;
    server->appInfo_.appPid = 1;
    monitorServer.CallOnScreenCaptureStarted(server->appInfo_.appPid);
    monitorServer.CallOnScreenCaptureFinished(server->appInfo_.appPid);
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
    ASSERT_EQ(
        screenCaptureServer_->StopScreenCaptureByEvent(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_STOPPED_BY_USER),
        MSERR_OK);
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
    std::shared_ptr<ScreenCaptureServer> server = MakeScreenCaptureServerShared();
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
    screenCaptureServer_->saUid_ = saUid;
    ASSERT_EQ(screenCaptureServer_->saUid_, saUid);
}

/**
 * @tc.name: ProcesssaUidAppUidMap_001
 * @tc.desc: check AddSaAppInfoMap
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, ProcesssaUidAppUidMap_001, TestSize.Level2)
{
    ScreenCaptureServerManager::GetInstance().saUidAppUidMap_.clear();
    int32_t appUid = ROOT_UID;
    int32_t saUid = appUid + 1;
    ScreenCaptureServerManager::GetInstance().AddSaAppInfoMap(saUid, appUid);
    ASSERT_EQ(ScreenCaptureServerManager::GetInstance().saUidAppUidMap_.size(), 1);
}

/**
 * @tc.name: ProcesssaUidAppUidMap_002
 * @tc.desc: check RemoveSaAppInfoMap
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, ProcesssaUidAppUidMap_002, TestSize.Level2)
{
    ScreenCaptureServerManager::GetInstance().saUidAppUidMap_.clear();
    int32_t appUid = ROOT_UID;
    int32_t saUid = appUid + 1;
    ScreenCaptureServerManager::GetInstance().AddSaAppInfoMap(saUid, appUid);
    ASSERT_EQ(ScreenCaptureServerManager::GetInstance().saUidAppUidMap_.size(), 1);
    ScreenCaptureServerManager::GetInstance().RemoveSaAppInfoMap(saUid);
    ASSERT_EQ(ScreenCaptureServerManager::GetInstance().saUidAppUidMap_.size(), 0);
}

/**
 * @tc.name: CheckIsSACalling_001
 * @tc.desc: check IsSACalling
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, CheckIsSACalling_001, TestSize.Level2)
{
    ASSERT_EQ(IsSACalling(), false);
}

/**
 * @tc.name: CheckIsSAUidValid_001
 * @tc.desc: check IsSAUidValid
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, CheckIsSAUidValid_001, TestSize.Level2)
{
    int32_t appUid = ROOT_UID;
    int32_t saUid = -1;
    ASSERT_EQ(ScreenCaptureServerManager::GetInstance().IsSAUidValid(saUid, appUid), false);
    saUid = appUid + 1;
    ASSERT_EQ(ScreenCaptureServerManager::GetInstance().IsSAUidValid(saUid, appUid), false);
}

/**
 * @tc.name: CheckIsSAUidValid_004
 * @tc.desc: saUid in saUidAppUidMap_ and saUid.first != appUid
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, CheckIsSAUidValid_004, TestSize.Level2)
{
    int32_t appUid = ROOT_UID;
    int32_t saUid = -1;
    ScreenCaptureServerManager::GetInstance().saUidAppUidMap_ = {};
    ScreenCaptureServerManager::GetInstance().saUidAppUidMap_[saUid] = {appUid + 1, 0};
    ASSERT_EQ(ScreenCaptureServerManager::GetInstance().IsSAUidValid(saUid, appUid), false);
}

/**
 * @tc.name: CheckIsSAUidValid_005
 * @tc.desc: saUid in saUidAppUidMap_ and saUid.first != appUid
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, CheckIsSAUidValid_005, TestSize.Level2)
{
    int32_t appUid = ROOT_UID;
    int32_t saUid = -1;
    ScreenCaptureServerManager::GetInstance().saUidAppUidMap_ = {};
    ScreenCaptureServerManager::GetInstance().saUidAppUidMap_[saUid] = {appUid,
        ScreenCaptureServerManager::GetInstance().maxSessionPerUid_};
    ASSERT_EQ(ScreenCaptureServerManager::GetInstance().IsSAUidValid(saUid, appUid), false);
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

    int32_t sessionId = ScreenCaptureServerManager::GetInstance().GetNewSessionId();
    std::shared_ptr<ScreenCaptureServer> server = MakeScreenCaptureServerShared();
    server->sessionId_ = sessionId;
    ScreenCaptureServerManager::GetInstance().RegisterServer(sessionId, server, server->appInfo_.appUid);

    ASSERT_EQ(server->SetAndCheckSaLimit(appInfo), MSERR_INVALID_OPERATION);
}

/**
 * @tc.name: SetAndCheckLimit_001
 * @tc.desc: SetAndCheckLimit_001
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, SetAndCheckLimit_001, TestSize.Level2)
{
    ScreenCaptureServerManager::GetInstance().serverMap_.clear();
    ASSERT_EQ(screenCaptureServer_->SetAndCheckLimit(), MSERR_OK);
}

/**
 * @tc.name: SetAndCheckLimit_002
 * @tc.desc: SetAndCheckLimit_002
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, SetAndCheckLimit_002, TestSize.Level2)
{
    ScreenCaptureServerManager::GetInstance().serverMap_.clear();
    std::vector<std::shared_ptr<ScreenCaptureServer>> serverList;
    UniqueIDGenerator gIdGenerator(20);
    for (int32_t i = 0; i <= ScreenCaptureServerManager::GetInstance().maxSessionPerUid_; i++) {
        std::shared_ptr<ScreenCaptureServer> server = MakeScreenCaptureServerShared();
        serverList.push_back(server);
        int32_t sessionId = gIdGenerator.GetNewID();
        server->sessionId_ = sessionId;
        server->appInfo_.appUid = IPCSkeleton::GetCallingUid();
        ScreenCaptureServerManager::GetInstance().RegisterServer(sessionId, server, server->appInfo_.appUid);
    }
    std::shared_ptr<ScreenCaptureServer> server = MakeScreenCaptureServerShared();
    int32_t sessionId = gIdGenerator.GetNewID();
    server->sessionId_ = sessionId;
    ASSERT_EQ(server->SetAndCheckLimit(), MSERR_INVALID_OPERATION);
}

/**
 * @tc.name: CheckReleaseInner_001
 * @tc.desc: CheckReleaseInner_001
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, CheckReleaseInner_001, TestSize.Level2)
{
    ScreenCaptureServerManager::GetInstance().serverMap_.clear();
    ScreenCaptureServerManager::GetInstance().saUidAppUidMap_.clear();
    UniqueIDGenerator gIdGenerator(20);
    int32_t sessionId = gIdGenerator.GetNewID();
    std::shared_ptr<ScreenCaptureServer> server = MakeScreenCaptureServerShared();
    server->sessionId_ = sessionId;
    server->captureState_ = AVScreenCaptureState::STOPPED;
    ScreenCaptureServerManager::GetInstance().RegisterServer(sessionId, server, server->appInfo_.appUid);

    int32_t appUid = ROOT_UID + 1;
    int32_t saUid = 1;
    server->saUid_ = saUid;
    ScreenCaptureServerManager::GetInstance().AddSaAppInfoMap(saUid, appUid);
    int32_t appInfoMapSizeBefore = ScreenCaptureServerManager::GetInstance().saUidAppUidMap_.size();
    int32_t serverMapSizeBefore = ScreenCaptureServerManager::GetInstance().serverMap_.size();
    server->ReleaseInner();

    ASSERT_EQ(ScreenCaptureServerManager::GetInstance().saUidAppUidMap_.size(), appInfoMapSizeBefore - 1);
    ASSERT_EQ(ScreenCaptureServerManager::GetInstance().serverMap_.size(), serverMapSizeBefore - 1);
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
    ScreenCaptureServerManager::GetInstance().serverMap_.clear();
    UniqueIDGenerator gIdGenerator(20);
    int32_t sessionId = gIdGenerator.GetNewID();
    std::shared_ptr<ScreenCaptureServer> server = MakeScreenCaptureServerShared();
    server->sessionId_ = sessionId;
    server->captureConfig_.dataType = DataType::ORIGINAL_STREAM;
    server->appInfo_.appUid = ROOT_UID;
    ASSERT_EQ(ScreenCaptureServerManager::GetInstance().CheckSCServerSpecifiedDataTypeNum(server->appInfo_.appUid,
                  server->captureConfig_.dataType),
        true);
}

/**
 * @tc.name: CheckSpecifiedDataTypeNum_002
 * @tc.desc: CheckSCServerSpecifiedDataTypeNum Failed
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, CheckSpecifiedDataTypeNum_002, TestSize.Level2)
{
    ScreenCaptureServerManager::GetInstance().serverMap_.clear();
    UniqueIDGenerator gIdGenerator(20);
    std::vector<std::shared_ptr<ScreenCaptureServer>> serverList;
    for (int32_t i = 0; i < ScreenCaptureServerManager::GetInstance().maxSCServerDataTypePerUid_; i++) {
        std::shared_ptr<ScreenCaptureServer> server = MakeScreenCaptureServerShared();
        serverList.push_back(server);
        int32_t sessionId = gIdGenerator.GetNewID();
        server->sessionId_ = sessionId;
        server->appInfo_.appUid = IPCSkeleton::GetCallingUid();
        server->captureConfig_.dataType = DataType::ORIGINAL_STREAM;
        ScreenCaptureServerManager::GetInstance().RegisterServer(sessionId, server, server->appInfo_.appUid);
        ScreenCaptureServerManager::GetInstance().UpdateServerDataType(sessionId, server->captureConfig_.dataType);
        ASSERT_EQ(ScreenCaptureServerManager::GetInstance().CheckSCServerSpecifiedDataTypeNum(server->appInfo_.appUid,
                      server->captureConfig_.dataType),
            true);
    }
    std::shared_ptr<ScreenCaptureServer> server = MakeScreenCaptureServerShared();
    int32_t sessionId = gIdGenerator.GetNewID();
    server->sessionId_ = sessionId;
    server->appInfo_.appUid = IPCSkeleton::GetCallingUid();
    server->captureConfig_.dataType = DataType::ORIGINAL_STREAM;
    ScreenCaptureServerManager::GetInstance().RegisterServer(sessionId, server, server->appInfo_.appUid);
    ScreenCaptureServerManager::GetInstance().UpdateServerDataType(sessionId, server->captureConfig_.dataType);
    ASSERT_EQ(ScreenCaptureServerManager::GetInstance().CheckSCServerSpecifiedDataTypeNum(server->appInfo_.appUid,
                  server->captureConfig_.dataType),
        false);
}

/**
 * @tc.name: AddSaAppInfoMap_001
 * @tc.desc: AddSaAppInfoMap has sa uid info
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, AddSaAppInfoMap_001, TestSize.Level2)
{
    int32_t saUid = 10086;
    ScreenCaptureServerManager::GetInstance().saUidAppUidMap_[saUid] = {saUid, 0};
    ScreenCaptureServerManager::GetInstance().AddSaAppInfoMap(saUid, saUid);
    ASSERT_EQ(ScreenCaptureServerManager::GetInstance().saUidAppUidMap_[saUid].second, 1);
}

/**
 * @tc.name: RemoveSaAppInfoMap_001
 * @tc.desc: RemoveSaAppInfoMap has sa uid info
 * @tc.type: FUNC
 */
HWTEST_F(ScreenCaptureServerFunctionTest, RemoveSaAppInfoMap_001, TestSize.Level2)
{
    int32_t saUid = 10086;
    ScreenCaptureServerManager::GetInstance().saUidAppUidMap_[saUid] = {saUid, 1};
    ScreenCaptureServerManager::GetInstance().RemoveSaAppInfoMap(saUid);
    ASSERT_EQ(ScreenCaptureServerManager::GetInstance().saUidAppUidMap_[saUid].second, 0);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ProcessCurDisplayId_001, TestSize.Level2)
{
    uint64_t curWindowInDisplayId = 0;
    screenCaptureServer_->curWindowInDisplayId_.store(curWindowInDisplayId);
    ASSERT_EQ(screenCaptureServer_->curWindowInDisplayId_.load(), curWindowInDisplayId);
}

HWTEST_F(ScreenCaptureServerFunctionTest, NotifyCaptureContentChanged_001, TestSize.Level2)
{
    ScreenCaptureRect *area = nullptr;
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->NotifyCaptureContentChanged(AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_HIDE,
        nullptr);
    screenCaptureServer_->NotifyCaptureContentChanged(
        AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_VISIBLE, area);
    screenCaptureServer_->NotifyCaptureContentChanged(
        AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_UNAVAILABLE, nullptr);
    ASSERT_EQ(screenCaptureServer_->curWindowEvent_,
        AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_UNAVAILABLE);
}

HWTEST_F(ScreenCaptureServerFunctionTest, NotifyCaptureContentChanged_002, TestSize.Level2)
{
    std::unique_ptr<ScreenCaptureRect> area = std::make_unique<ScreenCaptureRect>();
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    area->x = 0;
    area->y = 0;
    area->width = 1;
    area->height = 1;
    screenCaptureServer_->NotifyCaptureContentChanged(AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_HIDE,
        area.get());
    screenCaptureServer_->NotifyCaptureContentChanged(
        AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_VISIBLE, nullptr);
    screenCaptureServer_->NotifyCaptureContentChanged(
        AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_UNAVAILABLE, nullptr);
    ASSERT_EQ(screenCaptureServer_->curWindowEvent_,
        AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_UNAVAILABLE);
}

HWTEST_F(ScreenCaptureServerFunctionTest, NotifyCaptureContentChanged_004, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STOPPED;
    screenCaptureServer_->NotifyCaptureContentChanged(AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_HIDE,
        nullptr);
    ASSERT_EQ(screenCaptureServer_->curWindowEvent_,
        AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_VISIBLE);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SetDefaultDisplayIdOfWindows_001, TestSize.Level2)
{
    screenCaptureServer_->missionInfos_ = {{80, true}};
    screenCaptureServer_->curWindowInDisplayId_.store(SCREEN_ID_INVALID);
    uint64_t displayId = screenCaptureServer_->GetDisplayIdOfWindows();
    ASSERT_NE(displayId, SCREEN_ID_INVALID);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AppMissionId_001, TestSize.Level2)
{
    EXPECT_EQ(screenCaptureServer_->missionInfos_.size(), 0);
    EXPECT_EQ(CountForegroundMissions(screenCaptureServer_->missionInfos_), 0);
    screenCaptureServer_->virtualScreenId_ = 1;
    screenCaptureServer_->missionInfos_.push_back({0, true});
    EXPECT_EQ(screenCaptureServer_->missionInfos_.size(), 1);
    EXPECT_EQ(CountForegroundMissions(screenCaptureServer_->missionInfos_), 1);
    screenCaptureServer_->missionInfos_.push_back({0, true});
    EXPECT_EQ(screenCaptureServer_->missionInfos_.size(), 2);
    EXPECT_EQ(CountForegroundMissions(screenCaptureServer_->missionInfos_), 2);
    screenCaptureServer_->missionInfos_ = {{0, true}, {1, true}, {2, true}};
    EXPECT_EQ(screenCaptureServer_->missionInfos_.size(), 3);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AppMissionId_002, TestSize.Level2)
{
    EXPECT_EQ(screenCaptureServer_->missionInfos_.size(), 0);
    EXPECT_EQ(CountForegroundMissions(screenCaptureServer_->missionInfos_), 0);
    std::vector<uint64_t> allIds;
    screenCaptureServer_->missionInfos_.push_back({0, true});
    screenCaptureServer_->missionInfos_.push_back({1, true});
    screenCaptureServer_->UpdateMissionData(0, Rosen::SessionState::STATE_DISCONNECT, allIds);
    EXPECT_EQ(screenCaptureServer_->missionInfos_.size(), 1);
    EXPECT_EQ(CountForegroundMissions(screenCaptureServer_->missionInfos_), 1);
    screenCaptureServer_->UpdateMissionData(1, Rosen::SessionState::STATE_DISCONNECT, allIds);
    EXPECT_EQ(screenCaptureServer_->missionInfos_.size(), 0);
    EXPECT_EQ(CountForegroundMissions(screenCaptureServer_->missionInfos_), 0);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ParseAppMissionIds_001, TestSize.Level2)
{
    Json::Value appInformation;
    appInformation["bundleName"] = "bundleName_001";
    appInformation["appIndex"] = 0;
    screenCaptureServer_->ParseAppMissionIds(appInformation);
    screenCaptureServer_->SetCaptureConfig(CaptureMode::CAPTURE_SPECIFIED_APP);
    EXPECT_EQ(screenCaptureServer_->captureConfig_.captureMode, CaptureMode::CAPTURE_SPECIFIED_APP);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ParseAppMissionIds_002, TestSize.Level2)
{
    Json::Value appInformation;
    appInformation["bundleName"] = "bundleName_002";
    appInformation["appIndex"] = 0;
    screenCaptureServer_->ParseAppMissionIds(appInformation);
    screenCaptureServer_->missionInfos_.push_back({1, true});
    screenCaptureServer_->SetCaptureConfig(CaptureMode::CAPTURE_SPECIFIED_APP);
    EXPECT_EQ(screenCaptureServer_->captureConfig_.captureMode, CaptureMode::CAPTURE_SPECIFIED_APP);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ParseAppMissionIds_003, TestSize.Level2)
{
    Json::Value appInformation;
    appInformation["bundleName"] = "bundleName_003";
    appInformation["appIndex"] = 0;
    screenCaptureServer_->missionInfos_.push_back({1, true});
    screenCaptureServer_->ParseAppMissionIds(appInformation);
    screenCaptureServer_->SetCaptureConfig(CaptureMode::CAPTURE_SPECIFIED_APP);
    EXPECT_EQ(screenCaptureServer_->captureConfig_.captureMode, CaptureMode::CAPTURE_SPECIFIED_APP);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ParseAppMissionIds_004, TestSize.Level2)
{
    Json::Value appInformation;
    appInformation["bundleName"] = "bundleName_004";
    appInformation["appIndex"] = 0;
    screenCaptureServer_->ParseAppMissionIds(appInformation);
    screenCaptureServer_->missionInfos_.push_back({1, true});
    screenCaptureServer_->SetCaptureConfig(CaptureMode::CAPTURE_SPECIFIED_APP);
    EXPECT_EQ(screenCaptureServer_->captureConfig_.captureMode, CaptureMode::CAPTURE_SPECIFIED_APP);
}
} // namespace Media
} // namespace OHOS
