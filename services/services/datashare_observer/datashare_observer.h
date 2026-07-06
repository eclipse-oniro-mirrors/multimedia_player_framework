/*
* Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef DATASHARE_OBSERVER_H
#define DATASHARE_OBSERVER_H

#include "common_event_subscriber.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "nocopyable.h"
#include <cstdlib>
#include <string>

namespace OHOS {
namespace Media {
class MediaDatashareObserver : public EventFwk::CommonEventSubscriber {
public:
    explicit MediaDatashareObserver(const EventFwk::CommonEventSubscribeInfo &subscribeInfo)
        : EventFwk::CommonEventSubscriber(subscribeInfo)
    {}
    ~MediaDatashareObserver() = default;
    void OnReceiveEvent(const EventFwk::CommonEventData &data) override;
};

class MediaDatashareObserverRegister {
public:
    static MediaDatashareObserverRegister &GetInstance();
    bool Subscribe();
    void UnSubscribe();

private:
    MediaDatashareObserverRegister() = default;
    ~MediaDatashareObserverRegister();
    DISALLOW_COPY_AND_MOVE(MediaDatashareObserverRegister);
    std::mutex mutex_;
    std::shared_ptr<DatashareObserver> datashareObserver_ = nullptr;
};

int32_t UpdateSettingsValue(const std::string &key, const std::string &value);
} // namespace Media
} // namespace OHOS
#endif // DATASHARE_OBSERVER_H