 /*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
 
#ifndef DFX_AGENT_H
#define DFX_AGENT_H

#include <unordered_set>

#include "osal/task/task.h"
#include "filter/filter.h"
#include "common/performance_utils.h"
 
namespace OHOS {
namespace Media {
 
enum class PlayerDfxSourceType : uint8_t {
    DFX_SOURCE_TYPE_URL_FILE = 0,
    DFX_SOURCE_TYPE_URL_FD = 1,
    DFX_SOURCE_TYPE_URL_NETWORK = 2,
    DFX_SOURCE_TYPE_DATASRC = 3,
    DFX_SOURCE_TYPE_MEDIASOURCE_LOCAL = 4,
    DFX_SOURCE_TYPE_MEDIASOURCE_NETWORK = 5,
    DFX_SOURCE_TYPE_UNKNOWN = 127,
};

class DfxAgent;
using DfxEventHandleFunc = std::function<void(std::weak_ptr<DfxAgent> ptr, const DfxEvent&)>;
 
class DfxAgent : public std::enable_shared_from_this<DfxAgent> {
public:
    DfxAgent(const std::string& groupId, const std::string& appName);
    ~DfxAgent();
    void SetSourceType(PlayerDfxSourceType type);
    void OnDfxEvent(const DfxEvent &event);
    void SetInstanceId(const std::string& instanceId);
    void ResetAgent();
    void SetMetricsCallback(DfxEventHandleFunc cb);
    void GetTotalStallingDuration(int64_t* duration);
    void GetTotalStallingTimes(int64_t* times);

    struct AVMetricsEvent {
        int32_t metricsEventType = 0;
        int64_t timeStamp = 0;
        int64_t playbackPosition = 0;
        std::map<std::string, int64_t> details;
    };

private:
    void ReportLagEvent(int64_t lagDuration, const std::string& eventMsg);
    void ReportEosSeek0Event(int32_t appUid);
    void UpdateDfxInfo(const DfxEvent &event);
    void ReportMetricsEvent(const DfxEvent &event);
    std::string GetPerfStr(const bool needWaitAllData);
    static void ProcessVideoLagEvent(std::weak_ptr<DfxAgent> ptr, const DfxEvent &event);
    static void ProcessAudioLagEvent(std::weak_ptr<DfxAgent> ptr, const DfxEvent &event);
    static void ProcessStreamLagEvent(std::weak_ptr<DfxAgent> ptr, const DfxEvent &event);
    static void ProcessEosSeekEvent(std::weak_ptr<DfxAgent> ptr, const DfxEvent &event);
    static void ProcessPerfInfoEvent(std::weak_ptr<DfxAgent> ptr, const DfxEvent &event);
    static void ProcessMetricsEvent(std::weak_ptr<DfxAgent> ptr, const DfxEvent &event);
    int64_t CalculateEventTimestamp(int64_t steadyMs);
    DfxEventHandleFunc metricsCallback_;
    std::string groupId_ {};
    std::string instanceId_ {};
    std::string appName_ {};
    PlayerDfxSourceType sourceType_ {PlayerDfxSourceType::DFX_SOURCE_TYPE_UNKNOWN};
    std::unique_ptr<Task> dfxTask_ {nullptr};
    bool hasReported_ {false};
    bool needPrintPerfLog_ { false };
    std::unordered_map<std::string, MainPerfData> perfDataMap_ {};
    std::atomic<int64_t> totalStallingDuration_{0};
    std::atomic<int64_t> totalStallingTimes_{0};

    static const std::map<DfxEventType, DfxEventHandleFunc> DFX_EVENT_HANDLERS_;
};

class ConcurrentUidSet {
public:
    bool IsAppFirstEvent(int32_t uid)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (set_.find(uid) == set_.end()) {
            set_.insert(uid);
            return true;
        }
        return false;
    }

private:
    std::mutex mutex_{};
    std::unordered_set<int32_t> set_{};
};
 
} // namespace Media
} // namespace OHOS
#endif // DFX_AGENT_H