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

#ifndef MEDIA_SERVER_SUBSCRIBER_H
#define MEDIA_SERVER_SUBSCRIBER_H

#include "common_event_subscriber.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "nocopyable.h"
#include <cstdlib>
#include <string>

namespace OHOS {
namespace Media {
class MediaServerSubscriber : public EventFwk::CommonEventSubscriber {
public:
    explicit MediaServerSubscriber(const EventFwk::CommonEventSubscribeInfo &subscribeInfo)
        : EventFwk::CommonEventSubscriber(subscribeInfo)
    {}
    ~MediaServerSubscriber() = default;
    void OnReceiveEvent(const EventFwk::CommonEventData &data) override;
};

class MediaServerSubscriberRegister {
public:
    static MediaServerSubscriberRegister &GetInstance();
    bool Subscribe();
    void UnSubscribe();

private:
    MediaServerSubscriberRegister() = default;
    ~MediaServerSubscriberRegister();
    DISALLOW_COPY_AND_MOVE(MediaServerSubscriberRegister);
    std::mutex mutex_;
    std::shared_ptr<MediaServerSubscriber> subscriber_ = nullptr;
};

int32_t UpdateSettingsValue(const std::string &key, const std::string &value);
} // namespace Media
} // namespace OHOS
#endif // MEDIA_SERVER_SUBSCRIBER_H