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

#ifndef HIAPPEVENT_AGENT_H
#define HIAPPEVENT_AGENT_H

#include <string>
#include <mutex>
#include "hitrace/tracechain.h"
#include "osal/task/task.h"

#define API_RESULT_SUCCESS 0
#define API_RESULT_FAILED 1

namespace OHOS {
namespace Media {

class HiAppEventAgent : public std::enable_shared_from_this<HiAppEventAgent> {
public:
    HiAppEventAgent();
    ~HiAppEventAgent();
    void TraceApiEvent(int errCode,
        const std::string& apiName, time_t startTime, HiviewDFX::HiTraceId traceId = HiviewDFX::HiTraceId());

private:
    std::string GenerateTransId();
#ifdef SUPPORT_HIAPPEVENT
    void TraceApiEventAsync(int errCode,
        const std::string& apiName, time_t startTime, HiviewDFX::HiTraceId traceId);
    int64_t AddProcessor();
    void WriteEndEvent(const std::string& transId,
        const int errCode, const std::string& apiName, time_t startTime, HiviewDFX::HiTraceId traceId);

    std::unique_ptr<Task> hiAppEventTask_;
    std::unordered_map<std::string, time_t> lastReportTime_;
#endif
};

} // namespace Media
} // namespace OHOS

#endif // HIAPPEVENT_AGENT_H
