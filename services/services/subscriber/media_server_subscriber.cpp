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

#include "media_server_subscriber.h"
#include "media_server_datashare.h"
#include "media_log.h"

namespace {
static const std::string SHOW_TOUCH_HINT_KEY = "settings.app.show_touch_hint";
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "MediaServerSubscriber"};
}

namespace OHOS {
namespace Media {
void MediaServerSubscriber::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    auto const &want = data.GetWant();
    std::string action = want.GetAction();
    MEDIA_LOGI("MediaServerSubscriber::OnReceiveEvent action: %{public}s", action.c_str());
    CHECK_AND_RETURN(action == EventFwk::CommonEventSupport::COMMON_EVENT_DATA_SHARE_READY);
    MEDIA_LOGI("MediaServerSubscriber::HandleDataShareReadyEvent");
    int32_t ret = UpdateSettingsValue(SHOW_TOUCH_HINT_KEY, "");
    MEDIA_LOGI("MediaServerSubscriber::HandleDataShareReadyEvent update result: %{public}d", ret);
}

MediaServerSubscriberRegister &MediaServerSubscriberRegister::GetInstance()
{
    static MediaServerSubscriberRegister instance;
    return instance;
}

MediaServerSubscriberRegister::~MediaServerSubscriberRegister()
{
    MEDIA_LOGI("MediaServerSubscriberRegister::~MediaServerSubscriberRegister");
    UnSubscribe();
}

bool MediaServerSubscriberRegister::Subscribe()
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("MediaServerSubscriberRegister::Subscribe");
    if (subscriber_ != nullptr) {
        MEDIA_LOGI("MediaServerSubscriberRegister already subscribed");
        return true;
    }
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_DATA_SHARE_READY);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    auto *tempSubscriber = new (std::nothrow) MediaServerSubscriber(subscribeInfo);
    CHECK_AND_RETURN_RET_LOG(tempSubscriber != nullptr, false,
        "MediaServerSubscriberRegister::Subscribe failed to create subscriber");
    subscriber_ = std::shared_ptr<MediaServerSubscriber>(tempSubscriber);
    bool result = EventFwk::CommonEventManager::SubscribeCommonEvent(subscriber_);
    MEDIA_LOGI("MediaServerSubscriberRegister::Subscribe result: %{public}d", result);
    return result;
}

void MediaServerSubscriberRegister::UnSubscribe()
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("MediaServerSubscriberRegister::UnSubscribe");
    CHECK_AND_RETURN_LOG(subscriber_ != nullptr, "MediaServerSubscriberRegister::UnSubscribe subscriber_ is null");
    bool result = EventFwk::CommonEventManager::UnSubscribeCommonEvent(subscriber_);
    MEDIA_LOGI("MediaServerSubscriberRegister::UnSubscribe result: %{public}d", result);
    subscriber_ = nullptr;
}
} // namespace Media
} // namespace OHOS