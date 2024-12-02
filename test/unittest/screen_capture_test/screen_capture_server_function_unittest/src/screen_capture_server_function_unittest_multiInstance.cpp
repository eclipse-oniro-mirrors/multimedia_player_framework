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
}

namespace OHOS {
namespace Media {

/**
* @tc.name: LimitIdGenerator_001
* @tc.desc: LimitIdGenerator_001
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
* @tc.desc: LimitIdGenerator_002
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
* @tc.desc: LimitIdGenerator_003
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
* @tc.desc: ProcessScreenCaptureServerMap_001
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, ProcessScreenCaptureServerMap_001, TestSize.Level2)
{
    int32_t sessionId = ScreenCaptureServer::gIdGenerator.GetNewID();
    std::shared_ptr<ScreenCaptureServer> server = std::make_shared<ScreenCaptureServer>();
    server->SetSessionId(sessionId);
    int32_t sizeBefore = ScreenCaptureServer::serverMap.size();
    ScreenCaptureServer::AddScreenCaptureServerMap(sessionId, server);
    ASSERT_EQ(ScreenCaptureServer::serverMap.size(), sizeBefore + 1);
    ScreenCaptureServer::RemoveScreenCaptureServerMap(sessionId);
}

/**
* @tc.name: ProcessScreenCaptureServerMap_002
* @tc.desc: ProcessScreenCaptureServerMap_002
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, ProcessScreenCaptureServerMap_002, TestSize.Level2)
{
    int32_t sessionId = ScreenCaptureServer::gIdGenerator.GetNewID();
    std::shared_ptr<ScreenCaptureServer> server = std::make_shared<ScreenCaptureServer>();
    server->SetSessionId(sessionId);
    int32_t sizeBefore = ScreenCaptureServer::serverMap.size();
    ScreenCaptureServer::AddScreenCaptureServerMap(sessionId, server);
    ScreenCaptureServer::RemoveScreenCaptureServerMap(sessionId);
    ASSERT_EQ(ScreenCaptureServer::serverMap.size(), sizeBefore);
}

/**
* @tc.name: CheckGetScreenCaptureServerById_001
* @tc.desc: CheckGetScreenCaptureServerById_001
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CheckGetScreenCaptureServerById_001, TestSize.Level2)
{
    int32_t sessionId = ScreenCaptureServer::gIdGenerator.GetNewID();
    std::shared_ptr<ScreenCaptureServer> server = std::make_shared<ScreenCaptureServer>();
    server->SetSessionId(sessionId);
    ScreenCaptureServer::AddScreenCaptureServerMap(sessionId, server);
    ASSERT_NE(ScreenCaptureServer::GetScreenCaptureServerByIdWithLock(sessionId), nullptr);
    ScreenCaptureServer::RemoveScreenCaptureServerMap(sessionId);
}

/**
* @tc.name: CheckGetScreenCaptureServerById_002
* @tc.desc: CheckGetScreenCaptureServerById_002
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CheckGetScreenCaptureServerById_002, TestSize.Level2)
{
    ScreenCaptureServer::serverMap.clear();
    int32_t sessionId = ScreenCaptureServer::gIdGenerator.GetNewID();
    ASSERT_EQ(ScreenCaptureServer::GetScreenCaptureServerByIdWithLock(sessionId), nullptr);
    ScreenCaptureServer::gIdGenerator.ReturnID(sessionId);
}

/**
* @tc.name: CountStartedSCSNumByPid_001
* @tc.desc: CountStartedSCSNumByPid_001
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CountStartedSCSNumByPid_001, TestSize.Level2)
{
    ScreenCaptureServer::serverMap.clear();
    int32_t sessionId = ScreenCaptureServer::gIdGenerator.GetNewID();
    std::shared_ptr<ScreenCaptureServer> server = std::make_shared<ScreenCaptureServer>();
    server->SetSessionId(sessionId);
    server->appInfo_.appPid = 1;
    ScreenCaptureServer::AddScreenCaptureServerMap(sessionId, server);
    ScreenCaptureServer::AddStartedSessionIdList(sessionId);
    MEDIA_LOGD("mapSize: %{public}d", static_cast<int32_t>(ScreenCaptureServer::serverMap.size()));
    ASSERT_EQ(ScreenCaptureServer::CountStartedScreenCaptureServerNumByPid(server->appInfo_.appPid), 1);

    ScreenCaptureServer::RemoveStartedSessionIdList(sessionId);
    ScreenCaptureServer::RemoveScreenCaptureServerMap(sessionId);
}

/**
* @tc.name: CheckScreenCaptureSessionIdLimit_001
* @tc.desc: CheckScreenCaptureSessionIdLimit_001
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CheckScreenCaptureSessionIdLimit_001, TestSize.Level2)
{
    ScreenCaptureServer::serverMap.clear();
    std::shared_ptr<ScreenCaptureServer> server = std::make_shared<ScreenCaptureServer>();
    server->appInfo_.appUid = 1;
    ASSERT_EQ(ScreenCaptureServer::CheckScreenCaptureSessionIdLimit(server->appInfo_.appUid), true);
}

/**
* @tc.name: CheckScreenCaptureSessionIdLimit_002
* @tc.desc: CheckScreenCaptureSessionIdLimit_002
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CheckScreenCaptureSessionIdLimit_002, TestSize.Level2)
{
    ScreenCaptureServer::serverMap.clear();
    std::vector<std::shared_ptr<ScreenCaptureServer>> serverList;
    for (int32_t i = 0; i < ScreenCaptureServer::maxSessionPerUid; i++) {
        std::shared_ptr<ScreenCaptureServer> server = std::make_shared<ScreenCaptureServer>();
        serverList.push_back(server);
        int32_t sessionId = i + 1;
        server->SetSessionId(sessionId);
        server->appInfo_.appUid = 0;
        ASSERT_EQ(ScreenCaptureServer::CheckScreenCaptureSessionIdLimit(server->appInfo_.appUid), true);
        ScreenCaptureServer::AddScreenCaptureServerMap(sessionId, server);
    }
    std::shared_ptr<ScreenCaptureServer> server = std::make_shared<ScreenCaptureServer>();
    int32_t sessionId = ScreenCaptureServer::maxSessionPerUid + 1;
    server->SetSessionId(sessionId);
    server->appInfo_.appUid = 0;
    ASSERT_EQ(ScreenCaptureServer::CheckScreenCaptureSessionIdLimit(server->appInfo_.appUid), false);
    ScreenCaptureServer::serverMap.clear();
}

/**
* @tc.name: ProcessStartedSessionIdList_001
* @tc.desc: ProcessStartedSessionIdList_001
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, ProcessStartedSessionIdList_001, TestSize.Level2)
{
    int32_t beforeSize = ScreenCaptureServer::startedSessionIDList_.size();
    int32_t sessionId = ScreenCaptureServer::gIdGenerator.GetNewID();
    ScreenCaptureServer::AddStartedSessionIdList(sessionId);
    ASSERT_EQ(ScreenCaptureServer::startedSessionIDList_.size(), beforeSize + 1);
    ScreenCaptureServer::RemoveStartedSessionIdList(sessionId);
    ScreenCaptureServer::gIdGenerator.ReturnID(sessionId);
}

/**
* @tc.name: ProcessStartedSessionIdList_002
* @tc.desc: ProcessStartedSessionIdList_002
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, ProcessStartedSessionIdList_002, TestSize.Level2)
{
    int32_t beforeSize = ScreenCaptureServer::startedSessionIDList_.size();
    int32_t sessionId = ScreenCaptureServer::gIdGenerator.GetNewID();
    ScreenCaptureServer::AddStartedSessionIdList(sessionId);
    ScreenCaptureServer::RemoveStartedSessionIdList(sessionId);
    ASSERT_EQ(ScreenCaptureServer::startedSessionIDList_.size(), beforeSize);
    ScreenCaptureServer::gIdGenerator.ReturnID(sessionId);
}

/**
* @tc.name: GetStartedSCSPidList_001
* @tc.desc: GetStartedSCSPidList_001
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, GetStartedSCSPidList_001, TestSize.Level2)
{
    std::shared_ptr<ScreenCaptureServer> server = std::make_shared<ScreenCaptureServer>();
    int32_t sessionId = ScreenCaptureServer::gIdGenerator.GetNewID();
    server->SetSessionId(sessionId);
    ScreenCaptureServer::AddScreenCaptureServerMap(sessionId, server);
    ScreenCaptureServer::AddStartedSessionIdList(sessionId);
    MEDIA_LOGD("GetStartedSCSPidList_001 listSize: %{public}d, mapSize: %{public}d",
        static_cast<int32_t>(ScreenCaptureServer::GetStartedScreenCaptureServerPidList().size()),
        static_cast<int32_t>(ScreenCaptureServer::serverMap.size()));
    ASSERT_EQ(ScreenCaptureServer::GetStartedScreenCaptureServerPidList().size()
        <= ScreenCaptureServer::serverMap.size(), true);
    ScreenCaptureServer::RemoveStartedSessionIdList(sessionId);
    ScreenCaptureServer::RemoveScreenCaptureServerMap(sessionId);
}

/**
* @tc.name: GetStartedSCSPidList_002
* @tc.desc: GetStartedSCSPidList_002
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, GetStartedSCSPidList_002, TestSize.Level2)
{
    std::shared_ptr<ScreenCaptureServer> server = std::make_shared<ScreenCaptureServer>();
    int32_t sessionId = ScreenCaptureServer::gIdGenerator.GetNewID();
    server->SetSessionId(sessionId);
    ScreenCaptureServer::AddScreenCaptureServerMap(sessionId, server);
    ScreenCaptureServer::AddStartedSessionIdList(sessionId);
    ASSERT_EQ(ScreenCaptureServer::GetAllStartedSessionIdList().size() <= ScreenCaptureServer::serverMap.size(), true);
    ScreenCaptureServer::RemoveStartedSessionIdList(sessionId);
    ScreenCaptureServer::RemoveScreenCaptureServerMap(sessionId);
}

/**
* @tc.name: GetStartedSCSPidList_003
* @tc.desc: GetStartedSCSPidList_003
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, GetStartedSCSPidList_003, TestSize.Level2)
{
    std::shared_ptr<ScreenCaptureServer> server = std::make_shared<ScreenCaptureServer>();
    int32_t sessionId = ScreenCaptureServer::gIdGenerator.GetNewID();
    server->SetSessionId(sessionId);
    ScreenCaptureServer::AddScreenCaptureServerMap(sessionId, server);
    ScreenCaptureServer::AddStartedSessionIdList(sessionId);
    std::list<int32_t> pidList{};
    ASSERT_EQ(ScreenCaptureServer::GetRunningScreenCaptureInstancePid(pidList), MSERR_OK);
}

/**
* @tc.name: CheckCanSCInstanceBeCreate_001
* @tc.desc: CheckCanSCInstanceBeCreate_001
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CheckCanSCInstanceBeCreate_001, TestSize.Level2)
{
    ScreenCaptureServer::serverMap.clear();
    ASSERT_EQ(ScreenCaptureServer::CanScreenCaptureInstanceBeCreate(), true);
}

/**
* @tc.name: CheckCanSCInstanceBeCreate_002
* @tc.desc: CheckCanSCInstanceBeCreate_002
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CheckCanSCInstanceBeCreate_002, TestSize.Level2)
{
    ScreenCaptureServer::serverMap.clear();
    std::vector<std::shared_ptr<ScreenCaptureServer>> serverList;
    for (int32_t i = 0; i < ScreenCaptureServer::maxSessionPerUid; i++) {
        std::shared_ptr<ScreenCaptureServer> server = std::make_shared<ScreenCaptureServer>();
        serverList.push_back(server);
        int32_t sessionId = ScreenCaptureServer::gIdGenerator.GetNewID();
        server->SetSessionId(sessionId);
        server->appInfo_.appUid = 0;
        ASSERT_EQ(ScreenCaptureServer::CanScreenCaptureInstanceBeCreate(), true);
        ScreenCaptureServer::AddScreenCaptureServerMap(sessionId, server);
    }
    ASSERT_EQ(ScreenCaptureServer::CanScreenCaptureInstanceBeCreate(), false);
    ScreenCaptureServer::serverMap.clear();
}

/**
* @tc.name: CreateSCNewInstance_001
* @tc.desc: CreateSCNewInstance_001
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CreateSCNewInstance_001, TestSize.Level2)
{
    ASSERT_NE(ScreenCaptureServer::CreateScreenCaptureNewInstance(), nullptr);
}

/**
* @tc.name: CreateSCNewInstance_002
* @tc.desc: CreateSCNewInstance_002
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CreateSCNewInstance_002, TestSize.Level2)
{
    std::queue<int32_t> tmpQ;
    while (!ScreenCaptureServer::gIdGenerator.availableIDs.empty()) {
        tmpQ.push(ScreenCaptureServer::gIdGenerator.availableIDs.front());
        ScreenCaptureServer::gIdGenerator.availableIDs.pop();
    }
    ASSERT_EQ(ScreenCaptureServer::CreateScreenCaptureNewInstance(), nullptr);

    while (!tmpQ.empty()) {
        ScreenCaptureServer::gIdGenerator.availableIDs.push(tmpQ.front());
        tmpQ.pop();
    }
}

/**
* @tc.name: CreateSCNewInstance_003
* @tc.desc: CreateSCNewInstance_003
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CreateSCNewInstance_003, TestSize.Level2)
{
    ScreenCaptureServer::serverMap.clear();
    ASSERT_NE(ScreenCaptureServer::Create(), nullptr);
}

/**
* @tc.name: CheckFirstStartPidInstance_001
* @tc.desc: CheckFirstStartPidInstance_001
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CheckFirstStartPidInstance_001, TestSize.Level2)
{
    ScreenCaptureServer::serverMap.clear();
    ScreenCaptureServer::startedSessionIDList_.clear();
    screenCaptureServer_->appInfo_.appPid = 1;
    ASSERT_EQ(screenCaptureServer_->IsFirstStartPidInstance(screenCaptureServer_->appInfo_.appPid), true);
    ASSERT_EQ(screenCaptureServer_->IsLastStartedPidInstance(screenCaptureServer_->appInfo_.appPid), false);
}

/**
* @tc.name: CheckFirstStartPidInstance_002
* @tc.desc: CheckFirstStartPidInstance_002
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CheckFirstStartPidInstance_002, TestSize.Level2)
{
    ScreenCaptureServer::serverMap.clear();
    ScreenCaptureServer::startedSessionIDList_.clear();
    std::shared_ptr<ScreenCaptureServer> server = std::make_shared<ScreenCaptureServer>();
    int32_t sessionId = ScreenCaptureServer::gIdGenerator.GetNewID();
    server->SetSessionId(sessionId);
    server->appInfo_.appPid = 1;
    ScreenCaptureServer::AddScreenCaptureServerMap(sessionId, server);
    ScreenCaptureServer::AddStartedSessionIdList(sessionId);
    ASSERT_EQ(server->IsFirstStartPidInstance(server->appInfo_.appPid), false);
    ASSERT_EQ(server->FirstPidUpdatePrivacyUsingPermissionState(server->appInfo_.appPid), true);
    ASSERT_EQ(server->IsLastStartedPidInstance(server->appInfo_.appPid), true);

    ScreenCaptureServer::RemoveScreenCaptureServerMap(sessionId);
    ScreenCaptureServer::serverMap.clear();
    ScreenCaptureServer::startedSessionIDList_.clear();
}

/**
* @tc.name: CheckFirstPidUpdatePrivacyUsingPermissionState_001
* @tc.desc: CheckFirstPidUpdatePrivacyUsingPermissionState_001
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CheckFirstPidUpdatePrivacyUsingPermissionState_001, TestSize.Level2)
{
    ScreenCaptureServer::serverMap.clear();
    ScreenCaptureServer::startedSessionIDList_.clear();
    std::shared_ptr<ScreenCaptureServer> server = std::make_shared<ScreenCaptureServer>();
    server->appInfo_.appUid = ROOT_UID;
    server->appInfo_.appPid = 1;
    ASSERT_EQ(server->IsFirstStartPidInstance(server->appInfo_.appPid), true);
    ASSERT_EQ(server->FirstPidUpdatePrivacyUsingPermissionState(server->appInfo_.appPid), true);
}

/**
* @tc.name: CheckLastStartedPidInstance_001
* @tc.desc: CheckLastStartedPidInstance_001
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CheckLastStartedPidInstance_001, TestSize.Level2)
{
    ScreenCaptureServer::serverMap.clear();
    ScreenCaptureServer::startedSessionIDList_.clear();
    std::vector<std::shared_ptr<ScreenCaptureServer>> serverList;
    for (int32_t i = 0; i < ScreenCaptureServer::maxSessionPerUid; i++) {
        std::shared_ptr<ScreenCaptureServer> server = std::make_shared<ScreenCaptureServer>();
        serverList.push_back(server);
        int32_t sessionId = ScreenCaptureServer::gIdGenerator.GetNewID();
        server->SetSessionId(sessionId);
        server->appInfo_.appPid = 1;
        ScreenCaptureServer::AddScreenCaptureServerMap(sessionId, server);
        ScreenCaptureServer::AddStartedSessionIdList(sessionId);
    }
    screenCaptureServer_->appInfo_.appPid = 1;
    ASSERT_EQ(screenCaptureServer_->IsLastStartedPidInstance(screenCaptureServer_->appInfo_.appPid), false);
    ASSERT_EQ(screenCaptureServer_->LastPidUpdatePrivacyUsingPermissionState(screenCaptureServer_->appInfo_.appPid),
        true);
    
    ScreenCaptureServer::serverMap.clear();
    ScreenCaptureServer::startedSessionIDList_.clear();
}

/**
* @tc.name: CheckLastPidUpdatePrivacyUsingPermissionState_001
* @tc.desc: CheckLastPidUpdatePrivacyUsingPermissionState_001
* @tc.type: FUNC
*/
HWTEST_F(ScreenCaptureServerFunctionTest, CheckLastPidUpdatePrivacyUsingPermissionState_001, TestSize.Level2)
{
    ScreenCaptureServer::serverMap.clear();
    ScreenCaptureServer::startedSessionIDList_.clear();
    std::shared_ptr<ScreenCaptureServer> server = std::make_shared<ScreenCaptureServer>();
    int32_t sessionId = ScreenCaptureServer::gIdGenerator.GetNewID();
    server->SetSessionId(sessionId);
    server->appInfo_.appUid = ROOT_UID;
    server->appInfo_.appPid = 1;
    ScreenCaptureServer::AddScreenCaptureServerMap(sessionId, server);
    ScreenCaptureServer::AddStartedSessionIdList(sessionId);
    ASSERT_EQ(server->IsLastStartedPidInstance(server->appInfo_.appPid), true);
    ASSERT_EQ(server->LastPidUpdatePrivacyUsingPermissionState(server->appInfo_.appPid), true);
}

} // Media
} // OHOS