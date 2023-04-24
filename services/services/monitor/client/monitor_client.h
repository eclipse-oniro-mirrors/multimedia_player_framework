/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef MONITOR_CLIENT_H
#define MONITOR_CLIENT_H

#include <thread>
#include <mutex>
#include <set>
#include "monitor_client_object.h"
#include "i_standard_monitor_service.h"
namespace OHOS {
namespace Media {
class MonitorClient {
public:
    MonitorClient();
    ~MonitorClient();

    static MonitorClient &GetInstance();
    int32_t StartClick(MonitorClientObject *obj);
    int32_t StopClick(MonitorClientObject *obj);
    void MediaServerDied();

private:
    bool IsVaildProxy();
    void ClickThread();

    sptr<IStandardMonitorService> monitorProxy_ = nullptr;
    bool enableThread_ = false;
    std::mutex cmdMutex_;
    std::mutex threadMutex_;
    std::condition_variable clickCond_;
    std::unique_ptr<std::thread> clickThread_ = nullptr;
    std::set<MonitorClientObject *> objSet_;
};
} // namespace Media
} // namespace OHOS
#endif // MONITOR_CLIENT_H