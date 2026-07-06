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

#include "datashare_observer.h"
#include "media_log.h"
#include "media_utils.h"
#include "media_log.h"
#include "datashare_helper.h"
#include "uri.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace {
static const std::string SHOW_TOUCH_HINT_KEY = "settings.app.show_touch_hint";
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "DatashareObserver"};
static const int32_t MEDIA_SERVICE_SA_ID = 3002;
static const std::string SETTINGS_DATA_BASE_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true";
static const std::string SETTINGS_DATA_EXT_URI = "datashare:///com.ohos.settingsdata.DataAbility";
static const std::string SETTINGS_DATA_FIELD_KEYWORD = "KEYWORD";
static const std::string SETTINGS_DATA_FIELD_VALUE = "VALUE";
}

namespace OHOS {
namespace Media {
void MediaDatashareObserver::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    auto const &want = data.GetWant();
    std::string action = want.GetAction();
    MEDIA_LOGI("MediaDatashareObserver::OnReceiveEvent action: %{public}s", action.c_str());
    CHECK_AND_RETURN(action == EventFwk::CommonEventSupport::COMMON_EVENT_DATA_SHARE_READY);
    MEDIA_LOGI("MediaDatashareObserver::HandleDataShareReadyEvent");
    int32_t ret = UpdateSettingsValue(SHOW_TOUCH_HINT_KEY, "");
    MEDIA_LOGI("MediaDatashareObserver::HandleDataShareReadyEvent update result: %{public}d", ret);
}

MediaDatashareObserverRegister &MediaDatashareObserverRegister::GetInstance()
{
    static MediaDatashareObserverRegister instance;
    return instance;
}

MediaDatashareObserverRegister::~MediaDatashareObserverRegister()
{
    MEDIA_LOGI("MediaDatashareObserverRegister::~MediaDatashareObserverRegister");
    UnSubscribe();
}

bool MediaDatashareObserverRegister::Subscribe()
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("MediaDatashareObserverRegister::Subscribe");
    if (datashareObserver_ != nullptr) {
        MEDIA_LOGI("MediaDatashareObserverRegister already subscribed");
        return true;
    }
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_DATA_SHARE_READY);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    auto *tempObserver = new (std::nothrow) MediaDatashareObserver(subscribeInfo);
    CHECK_AND_RETURN_RET_LOG(tempObserver != nullptr, false,
        "MediaDatashareObserverRegister::Subscribe failed to create observer");
    datashareObserver_ = std::shared_ptr<DatashareObserver>(tempObserver);
    bool result = EventFwk::CommonEventManager::SubscribeCommonEvent(datashareObserver_);
    MEDIA_LOGI("MediaDatashareObserverRegister::Subscribe result: %{public}d", result);
    return result;
}

void MediaDatashareObserverRegister::UnSubscribe()
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("MediaDatashareObserverRegister::UnSubscribe");
    CHECK_AND_RETURN_LOG(datashareObserver_ != nullptr,
        "MediaDatashareObserverRegister::UnSubscribe datashareObserver_ is null");
    bool result = EventFwk::CommonEventManager::UnSubscribeCommonEvent(datashareObserver_);
    MEDIA_LOGI("MediaDatashareObserverRegister::UnSubscribe result: %{public}d", result);
    datashareObserver_ = nullptr;
}

std::shared_ptr<DataShare::DataShareHelper> CreateDataShareHelper()
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_AND_RETURN_RET_LOG(samgr != nullptr, nullptr, "GetSystemAbilityManager failed");
    sptr<IRemoteObject> remoteObj = samgr->GetSystemAbility(MEDIA_SERVICE_SA_ID);
    CHECK_AND_RETURN_RET_LOG(remoteObj != nullptr, nullptr, "GetSystemAbility service failed");
    return DataShare::DataShareHelper::Creator(remoteObj, SETTINGS_DATA_BASE_URI, SETTINGS_DATA_EXT_URI);
}

int32_t UpdateSettingsValue(const std::string &key, const std::string &value)
{
    MEDIA_LOGI("UpdateSettingsValue start key: %{public}s", key.c_str());
    auto dataShareHelper = CreateDataShareHelper();
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, MSERR_INVALID_VAL, "dataShareHelper is nullptr");
    Uri uri(SETTINGS_DATA_BASE_URI + "&key=" + key);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SETTINGS_DATA_FIELD_KEYWORD, key);
    DataShare::DataShareValuesBucket bucket;
    DataShare::DataShareValueObject keyObj(key);
    DataShare::DataShareValueObject valueObj(value);
    bucket.Put(SETTINGS_DATA_FIELD_KEYWORD, keyObj);
    bucket.Put(SETTINGS_DATA_FIELD_VALUE, valueObj);
    int32_t updateResult = dataShareHelper->Update(uri, predicates, bucket);
    MEDIA_LOGI("UpdateSettingsValue update %{public}d", updateResult);
    dataShareHelper->NotifyChange(uri);
    dataShareHelper->Release();
    return updateResult;
}
} // namespace Media
} // namespace OHOS