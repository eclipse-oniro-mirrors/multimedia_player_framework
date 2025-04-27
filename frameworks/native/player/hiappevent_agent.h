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

#define API_RESULT_SUCCESS 0
#define API_RESULT_FAILED 1

namespace OHOS {
namespace Media {

class HiAppEventAgent {
public:
    void TraceApiEvent(int errCode,
        const std::string& message, time_t startTime, HiviewDFX::HiTraceId traceId = HiviewDFX::HiTraceId());

private:
    int64_t AddProcessor();
    std::string GenerateTransId();
    void WriteEndEvent(const std::string& transId, const int result,
        const int errCode, const std::string& message, time_t startTime, HiviewDFX::HiTraceId traceId);
    int64_t processorId_ = -1;
    std::mutex processorMutex;
};

} // namespace Media
} // namespace OHOS

#endif // HIAPPEVENT_AGENT_H
