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

#include <random>
#include "hiappevent_agent.h"
#include "app_event.h"
#include "app_event_processor_mgr.h"
#include "media_log.h"
#include "media_errors.h"

namespace {
constexpr auto KNAME = "ha_app_event";
constexpr auto KAPPID = "com_hw_hmos_avplayer";
constexpr auto SDKNAME = "MediaKit";
constexpr auto APINAME = "HMOS_MEDIA_SERVICE";
constexpr int32_t KTIMEOUT = 90;
constexpr int32_t KCONDROW = 30;
}

namespace OHOS {
namespace Media {

using namespace OHOS::HiviewDFX;
using namespace OHOS::HiviewDFX::HiAppEvent;

void HiAppEventAgent::WriteEndEvent(const std::string &transId,
    const int errCode, const std::string& message, time_t startTime, HiviewDFX::HiTraceId traceId)
{
    int result = errCode == MSERR_OK ? API_RESULT_SUCCESS : API_RESULT_FAILED;
    Event event("api_diagnostic", "api_exec_end", OHOS::HiviewDFX::HiAppEvent::BEHAVIOR);
    event.AddParam("trans_id", transId);
    event.AddParam("api_name", std::string(APINAME));
    event.AddParam("sdk_name", std::string(SDKNAME));
    event.AddParam("begin_time", startTime);
    event.AddParam("end_time", time(nullptr));
    event.AddParam("result", result);
    event.AddParam("error_code", errCode);
    event.AddParam("message", message);
    if (traceId.IsValid()) {
        event.AddParam("traceId", static_cast<int64_t>(traceId.GetChainId()));
    }
    Write(event);
}

int64_t HiAppEventAgent::AddProcessor()
{
    ReportConfig config;
    config.name = KNAME;
    config.appId = KAPPID;
    config.routeInfo = "AUTO";
    config.triggerCond.timeout = KTIMEOUT;
    config.triggerCond.row = KCONDROW;
    config.eventConfigs.clear();
    {
        EventConfig event1;
        event1.domain = "api_diagnostic";
        event1.name = "api_exec_end";
        event1.isRealTime = false;
        config.eventConfigs.push_back(event1);
    }
    {
        EventConfig event2;
        event2.domain = "api_diagnostic";
        event2.name = "api_called_stat";
        event2.isRealTime = true;
        config.eventConfigs.push_back(event2);
    }
    {
        EventConfig event3;
        event3.domain = "api_diagnostic";
        event3.name = "api_called_stat_cnt";
        event3.isRealTime = true;
        config.eventConfigs.push_back(event3);
    }
    return AppEventProcessorMgr::AddProcessor(config);
}

void HiAppEventAgent::TraceApiEvent(
    int errCode, const std::string& message, time_t startTime, HiviewDFX::HiTraceId traceId)
{
    CHECK_AND_RETURN_NOLOG(errCode != MSERR_OK);
    {
        std::lock_guard<std::mutex> lock(processorMutex);
        if (processorId_ == -1) {
            processorId_ = AddProcessor();
        }
        if (processorId_ < 0) {
            return;
        }
    }

    std::string transId = GenerateTransId();
    WriteEndEvent(transId, errCode, message, startTime, traceId);
}

std::string HiAppEventAgent::GenerateTransId()
{
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int64_t> dist(0, 1e12);
 
    return "transId_" + std::to_string(dist(gen));
}

} // namespace Media
} // namespace OHOS
