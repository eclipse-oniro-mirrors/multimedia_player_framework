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

#include "mock/mock_media_utils.h"
#include "screen_capture_monitor_server.h"
#include "screen_capture_server_function_unittest.h"
#include "screen_capture_server_manager.h"

using testing::Return;
using namespace testing::ext;
using namespace OHOS::Media::ScreenCaptureTestParam;
using namespace OHOS::Media;
using namespace OHOS::Rosen;

namespace {
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

HWTEST_F(ScreenCaptureServerFunctionTest, RemoveScreenCaptureServerMap_002, TestSize.Level2)
{
    ScreenCaptureServerManager::GetInstance().serverMap_.clear();
    int32_t invalidSessionId = 999;
    std::shared_ptr<ScreenCaptureServer> server = MakeScreenCaptureServerShared();
    server->sessionId_ = invalidSessionId;
    ScreenCaptureServerManager::GetInstance().serverMap_[invalidSessionId] = {server, 0, DataType::INVAILD};
    int32_t sizeBefore = ScreenCaptureServerManager::GetInstance().serverMap_.size();
    ScreenCaptureServerManager::GetInstance().RemoveScreenCaptureServerMap(invalidSessionId);
    ASSERT_EQ(ScreenCaptureServerManager::GetInstance().serverMap_.size(), sizeBefore - 1);
}

HWTEST_F(ScreenCaptureServerFunctionTest, UpdateServerAppUid_001, TestSize.Level2)
{
    ScreenCaptureServerManager::GetInstance().serverMap_.clear();
    int32_t sessionId = ScreenCaptureServerManager::GetInstance().GetNewSessionId();
    std::shared_ptr<ScreenCaptureServer> server = MakeScreenCaptureServerShared();
    server->sessionId_ = sessionId;
    int32_t originalUid = 100;
    ScreenCaptureServerManager::GetInstance().RegisterServer(sessionId, server, originalUid);
    int32_t newUid = 200;
    ScreenCaptureServerManager::GetInstance().UpdateServerAppUid(sessionId, newUid);
    ASSERT_EQ(ScreenCaptureServerManager::GetInstance().serverMap_[sessionId].appUid, newUid);
    ScreenCaptureServerManager::GetInstance().RemoveScreenCaptureServerMap(sessionId);
}

HWTEST_F(ScreenCaptureServerFunctionTest, UpdateServerAppUid_002, TestSize.Level2)
{
    ScreenCaptureServerManager::GetInstance().serverMap_.clear();
    int32_t nonExistentSessionId = 888;
    int32_t sizeBefore = ScreenCaptureServerManager::GetInstance().serverMap_.size();
    ScreenCaptureServerManager::GetInstance().UpdateServerAppUid(nonExistentSessionId, 300);
    ASSERT_EQ(ScreenCaptureServerManager::GetInstance().serverMap_.size(), sizeBefore);
}

HWTEST_F(ScreenCaptureServerFunctionTest, UpdateServerDataType_001, TestSize.Level2)
{
    ScreenCaptureServerManager::GetInstance().serverMap_.clear();
    int32_t nonExistentSessionId = 777;
    int32_t sizeBefore = ScreenCaptureServerManager::GetInstance().serverMap_.size();
    ScreenCaptureServerManager::GetInstance().UpdateServerDataType(nonExistentSessionId, DataType::ORIGINAL_STREAM);
    ASSERT_EQ(ScreenCaptureServerManager::GetInstance().serverMap_.size(), sizeBefore);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CanScreenCaptureInstanceBeCreate_003, TestSize.Level2)
{
    ScreenCaptureServerManager::GetInstance().serverMap_.clear();
    int32_t maxId = ScreenCaptureServerManager::GetInstance().maxSessionId_;
    for (int32_t i = 1; i <= maxId + 1; i++) {
        ScreenCaptureServerManager::GetInstance().serverMap_[i] = {{}, i, DataType::INVAILD};
    }
    ASSERT_EQ(ScreenCaptureServerManager::GetInstance().CanScreenCaptureInstanceBeCreate(0), false);
    ScreenCaptureServerManager::GetInstance().serverMap_.clear();
}

HWTEST_F(ScreenCaptureServerFunctionTest, RemoveSaAppInfoMap_002, TestSize.Level2)
{
    ScreenCaptureServerManager::GetInstance().saUidAppUidMap_.clear();
    int32_t saUid = 100;
    int32_t appUid = 200;
    ScreenCaptureServerManager::GetInstance().AddSaAppInfoMap(saUid, appUid);
    int32_t sizeBefore = ScreenCaptureServerManager::GetInstance().saUidAppUidMap_.size();
    ScreenCaptureServerManager::GetInstance().RemoveSaAppInfoMap(-1);
    ASSERT_EQ(ScreenCaptureServerManager::GetInstance().saUidAppUidMap_.size(), sizeBefore);
    ScreenCaptureServerManager::GetInstance().saUidAppUidMap_.clear();
}

HWTEST_F(ScreenCaptureServerFunctionTest, RemoveSaAppInfoMap_003, TestSize.Level2)
{
    ScreenCaptureServerManager::GetInstance().saUidAppUidMap_.clear();
    int32_t saUid = 200;
    int32_t appUid = 300;
    ScreenCaptureServerManager::GetInstance().AddSaAppInfoMap(saUid, appUid);
    ScreenCaptureServerManager::GetInstance().AddSaAppInfoMap(saUid, appUid);
    ASSERT_EQ(ScreenCaptureServerManager::GetInstance().saUidAppUidMap_[saUid].second, 2);
    ScreenCaptureServerManager::GetInstance().RemoveSaAppInfoMap(saUid);
    ASSERT_EQ(ScreenCaptureServerManager::GetInstance().saUidAppUidMap_.count(saUid), 1);
    ASSERT_EQ(ScreenCaptureServerManager::GetInstance().saUidAppUidMap_[saUid].second, 1);
    ScreenCaptureServerManager::GetInstance().saUidAppUidMap_.clear();
}

HWTEST_F(ScreenCaptureServerFunctionTest, RemoveSaAppInfoMap_004, TestSize.Level2)
{
    ScreenCaptureServerManager::GetInstance().saUidAppUidMap_.clear();
    int32_t nonExistentSaUid = 999;
    ScreenCaptureServerManager::GetInstance().RemoveSaAppInfoMap(nonExistentSaUid);
    ASSERT_EQ(ScreenCaptureServerManager::GetInstance().saUidAppUidMap_.size(), 0);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckSCServerSpecifiedDataTypeNum_003, TestSize.Level2)
{
    ScreenCaptureServerManager::GetInstance().serverMap_.clear();
    UniqueIDGenerator gIdGenerator(20);
    int32_t sessionId = gIdGenerator.GetNewID();
    std::shared_ptr<ScreenCaptureServer> server = MakeScreenCaptureServerShared();
    server->sessionId_ = sessionId;
    server->appInfo_.appUid = 100;
    server->captureConfig_.dataType = DataType::ORIGINAL_STREAM;
    ScreenCaptureServerManager::GetInstance().RegisterServer(sessionId, server, server->appInfo_.appUid);
    ScreenCaptureServerManager::GetInstance().UpdateServerDataType(sessionId, server->captureConfig_.dataType);
    ASSERT_EQ(
        ScreenCaptureServerManager::GetInstance().CheckSCServerSpecifiedDataTypeNum(999, DataType::ORIGINAL_STREAM),
        true);
    ScreenCaptureServerManager::GetInstance().serverMap_.clear();
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckIsSAUidValid_002, TestSize.Level2)
{
    int32_t saUid = 1;
    int32_t appUid = -1;
    ASSERT_EQ(ScreenCaptureServerManager::GetInstance().IsSAUidValid(saUid, appUid), false);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckIsSAUidValid_003, TestSize.Level2)
{
    ON_CALL(GetMockMediaUtils(), IsSACalling()).WillByDefault(Return(true));
    int32_t saUid = 100;
    int32_t appUid = 200;
    ScreenCaptureServerManager::GetInstance().saUidAppUidMap_.clear();
    ASSERT_EQ(ScreenCaptureServerManager::GetInstance().IsSAUidValid(saUid, appUid), true);
    ScreenCaptureServerManager::GetInstance().saUidAppUidMap_.clear();
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckIsSAUidValid_006, TestSize.Level2)
{
    ON_CALL(GetMockMediaUtils(), IsSACalling()).WillByDefault(Return(true));
    int32_t saUid = 100;
    int32_t registeredAppUid = 200;
    int32_t queryAppUid = 201;
    ScreenCaptureServerManager::GetInstance().saUidAppUidMap_.clear();
    ScreenCaptureServerManager::GetInstance().saUidAppUidMap_[saUid] = {registeredAppUid, 0};
    ASSERT_EQ(ScreenCaptureServerManager::GetInstance().IsSAUidValid(saUid, queryAppUid), false);
    ScreenCaptureServerManager::GetInstance().saUidAppUidMap_.clear();
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckIsSAUidValid_007, TestSize.Level2)
{
    ON_CALL(GetMockMediaUtils(), IsSACalling()).WillByDefault(Return(true));
    int32_t saUid = 100;
    int32_t appUid = 200;
    ScreenCaptureServerManager::GetInstance().saUidAppUidMap_.clear();
    ScreenCaptureServerManager::GetInstance().saUidAppUidMap_[saUid] = {appUid,
        ScreenCaptureServerManager::GetInstance().maxSessionPerUid_};
    ASSERT_EQ(ScreenCaptureServerManager::GetInstance().IsSAUidValid(saUid, appUid), false);
    ScreenCaptureServerManager::GetInstance().saUidAppUidMap_.clear();
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckIsSAUidValid_008, TestSize.Level2)
{
    ON_CALL(GetMockMediaUtils(), IsSACalling()).WillByDefault(Return(true));
    int32_t saUid = 100;
    int32_t appUid = 200;
    ScreenCaptureServerManager::GetInstance().saUidAppUidMap_.clear();
    ScreenCaptureServerManager::GetInstance().saUidAppUidMap_[saUid] = {appUid, 1};
    ASSERT_EQ(ScreenCaptureServerManager::GetInstance().IsSAUidValid(saUid, appUid), true);
    ScreenCaptureServerManager::GetInstance().saUidAppUidMap_.clear();
}
} // namespace Media
} // namespace OHOS
