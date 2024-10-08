 /*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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
 
#include "osal/task/task.h"
#include "demuxer_filter.h"
 
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
 
class DfxAgent : public std::enable_shared_from_this<DfxAgent> {
public:
    DfxAgent(const std::string& groupId, const std::string& appName);
    ~DfxAgent();
    void SetDemuxer(std::weak_ptr<Pipeline::DemuxerFilter> demuxer);
    void SetSourceType(PlayerDfxSourceType type);
    void SetInstanceId(const std::string& instanceId);
    void OnAudioLagEvent(int64_t lagDuration);
    void OnVideoLagEvent(int64_t lagDuration);
    void OnStreamLagEvent(int64_t lagDuration);
    void ResetAgent();
private:
    void ReportLagEvent(int64_t lagDuration, const std::string& eventMsg);
    bool GetNetworkInfo(std::string& networkInfo);
    std::string groupId_ {};
    std::string instanceId_ {};
    std::string appName_ {};
    PlayerDfxSourceType sourceType_ {PlayerDfxSourceType::DFX_SOURCE_TYPE_UNKNOWN};
    std::unique_ptr<Task> dfxTask_ {nullptr};
    bool hasReported_ {false};
    std::weak_ptr<Pipeline::DemuxerFilter> demuxer_ {};
};
 
} // namespace Media
} // namespace OHOS
#endif // DFX_AGENT_H