/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef SCREEN_CAPTURE_SERVER_MANAGER_H
#define SCREEN_CAPTURE_SERVER_MANAGER_H

#include <list>
#include <map>
#include <memory>
#include <shared_mutex>

#include "limitIdGenerator.h"
#include "nocopyable.h"
#include "screen_capture.h"

namespace OHOS {
namespace Media {

class ScreenCaptureServer;

class ScreenCaptureServerManager : public NoCopyable {
public:
    static ScreenCaptureServerManager &GetInstance();

    int32_t GetNewSessionId();
    void RegisterServer(int32_t sessionId, std::weak_ptr<ScreenCaptureServer> server, int32_t appUid);
    void RemoveScreenCaptureServerMap(int32_t sessionId);
    void UpdateServerAppUid(int32_t sessionId, int32_t appUid);
    void UpdateServerDataType(int32_t sessionId, DataType dataType);
    bool CheckSCServerSpecifiedDataTypeNum(int32_t curAppUid, DataType dataType);
    std::weak_ptr<ScreenCaptureServer> GetScreenCaptureServerById(int32_t id);
    bool CanScreenCaptureInstanceBeCreate(int32_t appUid);
    void AddSaAppInfoMap(int32_t saUid, int32_t curAppUid);
    void RemoveSaAppInfoMap(int32_t saUid);
    bool IsSAUidValid(int32_t saUid, int32_t appUid);

private:
    ScreenCaptureServerManager();
    ~ScreenCaptureServerManager() = default;

    struct ServerEntry {
        std::weak_ptr<ScreenCaptureServer> server;
        int32_t appUid = 0;
        DataType dataType = DataType::INVAILD;
    };

    std::shared_mutex mutex_;
    std::map<int32_t, ServerEntry> serverMap_;
    std::map<int32_t, std::pair<int32_t, int32_t>> saUidAppUidMap_;
    UniqueIDGenerator idGenerator_;
    static constexpr int32_t maxSessionId_ = 16;
    static constexpr int32_t maxAppLimit_ = 4;
    static constexpr int32_t maxSessionPerUid_ = 4;
    static constexpr int32_t maxSCServerDataTypePerUid_ = 2;
};
} // namespace Media
} // namespace OHOS
#endif // SCREEN_CAPTURE_SERVER_MANAGER_H
