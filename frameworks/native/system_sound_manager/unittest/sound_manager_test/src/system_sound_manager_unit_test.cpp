/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "system_sound_manager_unit_test.h"

using namespace OHOS::AbilityRuntime;
using namespace testing::ext;

namespace OHOS {
namespace Media {
const int ERROR = -1;
const int SUCCESS = 0;
constexpr int32_t TONE_CATEGORY_DEFAULT = 8;
void SystemSoundManagerUnitTest::SetUpTestCase(void) {}
void SystemSoundManagerUnitTest::TearDownTestCase(void) {}
void SystemSoundManagerUnitTest::SetUp(void) {}
void SystemSoundManagerUnitTest::TearDown(void) {}

const int STORAGE_MANAGER_MANAGER_ID = 5003;
static std::shared_ptr<DataShare::DataShareHelper> CreateDataShareHelper(int32_t systemAbilityId)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        return nullptr;
    }
    auto remoteObj = saManager->GetSystemAbility(systemAbilityId);
    if (remoteObj == nullptr) {
        return nullptr;
    }
    return DataShare::DataShareHelper::Creator(remoteObj, RINGTONE_URI);
}

/**
 * @tc.name  : Test GetDefaultRingtoneAttrs API
 * @tc.number: Media_SoundManager_GetDefaultRingtoneAttrs_001
 * @tc.desc  : Test GetDefaultRingtoneAttrs interface. Returns attributes of the default ringtone on success.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_GetDefaultRingtoneAttrs_001, TestSize.Level2)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<AbilityRuntime::Context> context_ = std::make_shared<ContextImpl>();
    std::shared_ptr<ToneAttrs> toneAttrs_ = systemSoundManager_->GetDefaultRingtoneAttrs(context_,
        RingtoneType::RINGTONE_TYPE_SIM_CARD_0);
    EXPECT_NE(systemSoundManager_, nullptr);
}

/**
 * @tc.name  : Test GetRingtoneAttrList API
 * @tc.number: Media_SoundManager_GetRingtoneAttrList_001
 * @tc.desc  : Test GetRingtoneAttrList interface. Returns attribute list of ringtones on success.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_GetRingtoneAttrList_001, TestSize.Level2)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<AbilityRuntime::Context> context_ = std::make_shared<ContextImpl>();
    auto ringtoneAttrsArray_ = systemSoundManager_->GetRingtoneAttrList(context_,
        RingtoneType::RINGTONE_TYPE_SIM_CARD_0);
    EXPECT_NE(systemSoundManager_, nullptr);
}

/**
 * @tc.name  : Test GetDefaultSystemToneAttrs API
 * @tc.number: Media_SoundManager_GetDefaultSystemToneAttrs_001
 * @tc.desc  : Test GetDefaultSystemToneAttrs interface. Returns attributes of the default system tone.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_GetDefaultSystemToneAttrs_001, TestSize.Level2)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<AbilityRuntime::Context> context_ = std::make_shared<ContextImpl>();
    auto toneAttrs_ = systemSoundManager_->GetDefaultSystemToneAttrs(context_,
        SystemToneType::SYSTEM_TONE_TYPE_SIM_CARD_0);
    EXPECT_NE(systemSoundManager_, nullptr);
}

/**
 * @tc.name  : Test GetDefaultSystemToneAttrs API
 * @tc.number: Media_SoundManager_GetDefaultSystemToneAttrs_002
 * @tc.desc  : Test GetDefaultSystemToneAttrs interface. Returns attributes of the default system tone.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_GetDefaultSystemToneAttrs_002, TestSize.Level2)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<AbilityRuntime::Context> context_ = std::make_shared<ContextImpl>();
    auto toneAttrs_ = systemSoundManager_->GetDefaultSystemToneAttrs(context_,
        SystemToneType::SYSTEM_TONE_TYPE_SIM_CARD_1);
    EXPECT_NE(systemSoundManager_, nullptr);
}

/**
 * @tc.name  : Test GetDefaultSystemToneAttrs API
 * @tc.number: Media_SoundManager_GetDefaultSystemToneAttrs_003
 * @tc.desc  : Test GetDefaultSystemToneAttrs interface. Returns attributes of the default system tone.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_GetDefaultSystemToneAttrs_003, TestSize.Level2)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<AbilityRuntime::Context> context_ = std::make_shared<ContextImpl>();
    auto toneAttrs_ = systemSoundManager_->GetDefaultSystemToneAttrs(context_,
        SystemToneType::SYSTEM_TONE_TYPE_NOTIFICATION);
    EXPECT_NE(systemSoundManager_, nullptr);
}

/**
 * @tc.name  : Test GetSystemToneAttrList API
 * @tc.number: Media_SoundManager_GetSystemToneAttrList_001
 * @tc.desc  : Test GetSystemToneAttrList interface. Returns attributes of the default system tone.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_GetSystemToneAttrList_001, TestSize.Level2)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<AbilityRuntime::Context> context_ = std::make_shared<ContextImpl>();
    auto ringtoneAttrsArray_ = systemSoundManager_->GetSystemToneAttrList(context_,
        SystemToneType::SYSTEM_TONE_TYPE_SIM_CARD_0);
    EXPECT_NE(systemSoundManager_, nullptr);
}

/**
 * @tc.name  : Test GetSystemToneAttrList API
 * @tc.number: Media_SoundManager_GetSystemToneAttrList_002
 * @tc.desc  : Test GetSystemToneAttrList interface. Returns attributes of the default system tone.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_GetSystemToneAttrList_002, TestSize.Level2)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<AbilityRuntime::Context> context_ = std::make_shared<ContextImpl>();
    auto ringtoneAttrsArray_ = systemSoundManager_->GetSystemToneAttrList(context_,
        SystemToneType::SYSTEM_TONE_TYPE_SIM_CARD_1);
    EXPECT_NE(systemSoundManager_, nullptr);
}

/**
 * @tc.name  : Test GetSystemToneAttrList API
 * @tc.number: Media_SoundManager_GetSystemToneAttrList_003
 * @tc.desc  : Test GetSystemToneAttrList interface. Returns attributes of the default system tone.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_GetSystemToneAttrList_003, TestSize.Level2)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<AbilityRuntime::Context> context_ = std::make_shared<ContextImpl>();
    auto ringtoneAttrsArray_ = systemSoundManager_->GetSystemToneAttrList(context_,
        SystemToneType::SYSTEM_TONE_TYPE_NOTIFICATION);
    EXPECT_NE(systemSoundManager_, nullptr);
}

/**
 * @tc.name  : Test GetDefaultAlarmToneAttrs API
 * @tc.number: Media_SoundManager_GetDefaultAlarmToneAttrs_001
 * @tc.desc  : Test GetDefaultAlarmToneAttrs interface. Returns attributes of the default system tone.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_GetDefaultAlarmToneAttrs_001, TestSize.Level2)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<AbilityRuntime::Context> context_ = std::make_shared<ContextImpl>();
    std::shared_ptr<ToneAttrs> toneAttrs_ = systemSoundManager_->GetDefaultAlarmToneAttrs(context_);
    EXPECT_NE(systemSoundManager_, nullptr);
}

/**
 * @tc.name  : Test GetAlarmToneAttrList API
 * @tc.number: Media_SoundManager_GetAlarmToneAttrList_001
 * @tc.desc  : Test GetAlarmToneAttrList interface. Returns attributes of the default system tone.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_GetAlarmToneAttrList_001, TestSize.Level2)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<AbilityRuntime::Context> context_ = std::make_shared<ContextImpl>();
    auto alarmtoneAttrsArray_ = systemSoundManager_->GetAlarmToneAttrList(context_);
    EXPECT_NE(systemSoundManager_, nullptr);
}

/**
 * @tc.name  : Test GetAlarmToneUri API
 * @tc.number: Media_SoundManager_GetAlarmToneUri_001
 * @tc.desc  : Test GetAlarmToneUri interface. Returns attributes of the default system tone.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_GetAlarmToneUri_001, TestSize.Level2)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<AbilityRuntime::Context> context_ = std::make_shared<ContextImpl>();
    std::string uri = systemSoundManager_->GetAlarmToneUri(context_);
    EXPECT_NE(systemSoundManager_, nullptr);
}

/**
 * @tc.name  : Test SetAlarmToneUri API
 * @tc.number: Media_SoundManager_SetAlarmToneUri_001
 * @tc.desc  : Test SetAlarmToneUri interface. Returns attributes of the default system tone.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_SetAlarmToneUri_001, TestSize.Level2)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<AbilityRuntime::Context> context_ = std::make_shared<ContextImpl>();
    std::string srcUri, dstUri;

    auto vec = systemSoundManager_->GetAlarmToneAttrList(context_);
    if (vec.size() > 0) {
        srcUri = vec[0]->GetUri();
    }

    systemSoundManager_->SetAlarmToneUri(context_, srcUri);
    dstUri = systemSoundManager_->GetAlarmToneUri(context_);
    EXPECT_EQ(srcUri, dstUri);
}

/**
 * @tc.name  : Test OpenAlarmTone API
 * @tc.number: Media_SoundManager_OpenAlarmTone_001
 * @tc.desc  : Test OpenAlarmTone interface. Returns attributes of the default system tone.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_OpenAlarmTone_001, TestSize.Level2)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<AbilityRuntime::Context> context_ = std::make_shared<ContextImpl>();
    int fd = systemSoundManager_->OpenAlarmTone(context_, "test");
    EXPECT_LT(fd, 0);
    auto vec = systemSoundManager_->GetAlarmToneAttrList(context_);
    if (vec.size() > 0) {
        std::string uri = vec[0]->GetUri();
        fd = systemSoundManager_->OpenAlarmTone(context_, uri);
    }
    EXPECT_NE(systemSoundManager_, nullptr);
}

/**
 * @tc.name  : Test AddCustomizedToneByExternalUri API
 * @tc.number: Media_SoundManager_AddCustomizedToneByExternalUri_001
 * @tc.desc  : Test AddCustomizedToneByExternalUri interface. Returns attributes of the default system tone.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_AddCustomizedToneByExternalUri_001, TestSize.Level2)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<AbilityRuntime::Context> context_ = std::make_shared<ContextImpl>();
    std::shared_ptr<ToneAttrs> toneAttrs_ = std::make_shared<ToneAttrs>("default",
        "default", "default", CUSTOMISED, TONE_CATEGORY_RINGTONE);
    auto vec = systemSoundManager_->GetAlarmToneAttrList(context_);
    std::string uri = "";
    if (vec.size() > 0) {
        uri = vec[0]->GetUri();
    }

    std::string res = systemSoundManager_->AddCustomizedToneByExternalUri(context_, toneAttrs_, "test");
    EXPECT_EQ(res.empty(), true);
    toneAttrs_->SetTitle("06171");
    toneAttrs_->SetFileName("06171");
    res = systemSoundManager_->AddCustomizedToneByExternalUri(context_, toneAttrs_, uri);
    EXPECT_EQ(res.empty(), true);
}

/**
 * @tc.name  : Test AddCustomizedToneByFdAndOffset API
 * @tc.number: Media_SoundManager_AddCustomizedToneByFdAndOffset_001
 * @tc.desc  : Test AddCustomizedToneByFdAndOffset interface. Returns attributes of the default system tone.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_AddCustomizedToneByFdAndOffset_001, TestSize.Level2)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<AbilityRuntime::Context> context_ = std::make_shared<ContextImpl>();
    std::shared_ptr<ToneAttrs> toneAttrs_ = std::make_shared<ToneAttrs>("default",
        "default", "default", CUSTOMISED, TONE_CATEGORY_RINGTONE);
    auto vec = systemSoundManager_->GetAlarmToneAttrList(context_);
    std::string uri = "";
    if (vec.size() > 0) {
        uri = vec[0]->GetUri();
    }

    std::string res;
    toneAttrs_->SetTitle("06172");
    toneAttrs_->SetFileName("06172");
    res = systemSoundManager_->AddCustomizedToneByFdAndOffset(context_, toneAttrs_, 1, 10, 0);
    EXPECT_EQ(res.empty(), true);

    int fd = systemSoundManager_->OpenAlarmTone(context_, uri);
    toneAttrs_->SetTitle("06173");
    toneAttrs_->SetFileName("06173");
    res = systemSoundManager_->AddCustomizedToneByFdAndOffset(context_, toneAttrs_, fd, 10, 0);

    toneAttrs_->SetTitle("06174");
    toneAttrs_->SetFileName("06174");
    res = systemSoundManager_->AddCustomizedToneByFdAndOffset(context_, toneAttrs_, fd, 10, 1);
    EXPECT_NE(systemSoundManager_, nullptr);
    systemSoundManager_->Close(fd);
}

/**
 * @tc.name  : Test RemoveCustomizedTone API
 * @tc.number: Media_SoundManager_RemoveCustomizedTone_001
 * @tc.desc  : Test RemoveCustomizedTone interface. Returns attributes of the default system tone.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_RemoveCustomizedTone_001, TestSize.Level2)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<AbilityRuntime::Context> context_ = std::make_shared<ContextImpl>();
    std::shared_ptr<ToneAttrs> toneAttrs_ = std::make_shared<ToneAttrs>("default",
        "default", "default", CUSTOMISED, TONE_CATEGORY_RINGTONE);
    int res;
    auto vec = systemSoundManager_->GetAlarmToneAttrList(context_);
    std::string uri = "";
    if (vec.size() > 0) {
        uri = vec[0]->GetUri();
    }
    toneAttrs_->SetTitle("06175");
    toneAttrs_->SetFileName("06175");
    systemSoundManager_->AddCustomizedToneByExternalUri(context_, toneAttrs_, uri);
    res = systemSoundManager_->RemoveCustomizedTone(context_, uri);
    EXPECT_NE(systemSoundManager_, nullptr);
}

/**
 * @tc.name  : Test GetToneHapticsSettings API
 * @tc.number: Media_SoundManager_GetToneHapticsSettings_001
 * @tc.desc  : Test GetToneHapticsSettings interface. Returns vibration setting of the ringtone.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_GetToneHapticsSettings_001, TestSize.Level2)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<AbilityRuntime::Context> context_ = std::make_shared<ContextImpl>();
    ToneHapticsSettings settings;
    systemSoundManager_->GetToneHapticsSettings(context_, CALL_SIM_CARD_0, settings);
    EXPECT_NE(systemSoundManager_, nullptr);
}

/**
 * @tc.name  : Test GetToneHapticsSettings API
 * @tc.number: Media_SoundManager_GetToneHapticsSettings_002
 * @tc.desc  : Test GetToneHapticsSettings interface. Returns vibration setting of the ringtone.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_GetToneHapticsSettings_002, TestSize.Level2)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<AbilityRuntime::Context> context_ = std::make_shared<ContextImpl>();
    ToneHapticsSettings settings;
    systemSoundManager_->GetToneHapticsSettings(context_, CALL_SIM_CARD_1, settings);
    EXPECT_NE(systemSoundManager_, nullptr);
}

/**
 * @tc.name  : Test GetToneHapticsSettings API
 * @tc.number: Media_SoundManager_GetToneHapticsSettings_003
 * @tc.desc  : Test GetToneHapticsSettings interface. Returns vibration setting of the system tone.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_GetToneHapticsSettings_003, TestSize.Level2)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<AbilityRuntime::Context> context_ = std::make_shared<ContextImpl>();
    ToneHapticsSettings settings;
    systemSoundManager_->GetToneHapticsSettings(context_, TEXT_MESSAGE_SIM_CARD_0, settings);
    EXPECT_NE(systemSoundManager_, nullptr);
}

/**
 * @tc.name  : Test GetToneHapticsSettings API
 * @tc.number: Media_SoundManager_GetToneHapticsSettings_004
 * @tc.desc  : Test GetToneHapticsSettings interface. Returns vibration setting of the system tone.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_GetToneHapticsSettings_004, TestSize.Level2)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<AbilityRuntime::Context> context_ = std::make_shared<ContextImpl>();
    ToneHapticsSettings settings;
    systemSoundManager_->GetToneHapticsSettings(context_, TEXT_MESSAGE_SIM_CARD_1, settings);
    EXPECT_NE(systemSoundManager_, nullptr);
}

/**
 * @tc.name  : Test GetToneHapticsSettings API
 * @tc.number: Media_SoundManager_GetToneHapticsSettings_005
 * @tc.desc  : Test GetToneHapticsSettings interface. Returns vibration setting of the notification.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_GetToneHapticsSettings_005, TestSize.Level2)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<AbilityRuntime::Context> context_ = std::make_shared<ContextImpl>();

    ToneHapticsSettings settings;
    int32_t result = systemSoundManager_->GetToneHapticsSettings(context_, NOTIFICATION,
        settings);

    std::vector<std::shared_ptr<ToneHapticsAttrs>> toneHapticsAttrsArray;
    result = systemSoundManager_->GetToneHapticsList(context_, false, toneHapticsAttrsArray);
    if (result == 0 && toneHapticsAttrsArray.size() > 0) {
        settings.hapticsUri = toneHapticsAttrsArray[0]->GetUri();
        settings.mode = ToneHapticsMode::NON_SYNC;
        result = systemSoundManager_->SetToneHapticsSettings(context_, NOTIFICATION, settings);
        EXPECT_EQ(result, 0);
        result = systemSoundManager_->GetToneHapticsSettings(context_, NOTIFICATION, settings);
        EXPECT_EQ(result, 0);

        auto ringtoneAttrsArray_ = systemSoundManager_->GetSystemToneAttrList(context_, SYSTEM_TONE_TYPE_NOTIFICATION);
        EXPECT_GT(ringtoneAttrsArray_.size(), 1);
        std::string oldToneUri = systemSoundManager_->GetSystemToneUri(context_, SYSTEM_TONE_TYPE_NOTIFICATION);
        EXPECT_EQ(oldToneUri.empty(), false);
        int32_t index = oldToneUri != ringtoneAttrsArray_[0]->GetUri() ? 0 : 1;
        std::string newToneUri = ringtoneAttrsArray_[index]->GetUri();
        result = systemSoundManager_->SetSystemToneUri(context_, newToneUri, SYSTEM_TONE_TYPE_NOTIFICATION);
        EXPECT_EQ(result, 0);
        result = systemSoundManager_->GetToneHapticsSettings(context_, NOTIFICATION, settings);
        EXPECT_EQ(result, 0);
    }
    EXPECT_NE(systemSoundManager_, nullptr);
}

/**
 * @tc.name  : Test SetToneHapticsSettings API
 * @tc.number: Media_SoundManager_SetToneHapticsSettings_001
 * @tc.desc  : Test SetToneHapticsSettings interface. Set notification ring vibration.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_SetToneHapticsSettings_001, TestSize.Level2)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<AbilityRuntime::Context> context_ = std::make_shared<ContextImpl>();

    std::vector<std::shared_ptr<ToneHapticsAttrs>> toneHapticsAttrsArray;
    int32_t result = systemSoundManager_->GetToneHapticsList(context_, false, toneHapticsAttrsArray);
    if (result == 0 && toneHapticsAttrsArray.size() > 0) {
        ToneHapticsSettings srcSetting;
        srcSetting.hapticsUri = toneHapticsAttrsArray[0]->GetUri();
        srcSetting.mode = ToneHapticsMode::NON_SYNC;
        result = systemSoundManager_->SetToneHapticsSettings(context_,
            ToneHapticsType::NOTIFICATION, srcSetting);
        EXPECT_EQ(result, 0);

        ToneHapticsSettings dstSetting;
        result = systemSoundManager_->GetToneHapticsSettings(context_,
            ToneHapticsType::NOTIFICATION, dstSetting);
        EXPECT_EQ(result, 0);
        EXPECT_EQ(srcSetting.hapticsUri, dstSetting.hapticsUri);
        EXPECT_EQ(srcSetting.mode, dstSetting.mode);
    }
    EXPECT_NE(systemSoundManager_, nullptr);
}

/**
 * @tc.name  : Test GetToneHapticsList API
 * @tc.number: Media_SoundManager_GetToneHapticsList_001
 * @tc.desc  : Test GetToneHapticsList interface. Returns a list of sync tone vibrations.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_GetToneHapticsList_001, TestSize.Level2)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<AbilityRuntime::Context> context_ = std::make_shared<ContextImpl>();

    std::vector<std::shared_ptr<ToneHapticsAttrs>> toneHapticsAttrsArray;
    systemSoundManager_->GetToneHapticsList(context_, false, toneHapticsAttrsArray);
    EXPECT_NE(systemSoundManager_, nullptr);
}

/**
 * @tc.name  : Test GetToneHapticsList API
 * @tc.number: Media_SoundManager_GetToneHapticsList_002
 * @tc.desc  : Test GetToneHapticsList interface. Returns a list of non sync tone vibrations.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_GetToneHapticsList_002, TestSize.Level2)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<AbilityRuntime::Context> context_ = std::make_shared<ContextImpl>();

    std::vector<std::shared_ptr<ToneHapticsAttrs>> toneHapticsAttrsArray;
    systemSoundManager_->GetToneHapticsList(context_, false, toneHapticsAttrsArray);
    EXPECT_NE(systemSoundManager_, nullptr);
}

/**
 * @tc.name  : Test OpenToneHaptics API
 * @tc.number: Media_SoundManager_OpenToneHaptics_001
 * @tc.desc  : Test OpenToneHaptics interface. Returns handle of the tone haptics.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_OpenToneHaptics_001, TestSize.Level2)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<AbilityRuntime::Context> context_ = std::make_shared<ContextImpl>();
    int32_t fd = systemSoundManager_->OpenToneHaptics(context_, "test");
    EXPECT_LT(fd, 0);

    std::vector<std::shared_ptr<ToneHapticsAttrs>> toneHapticsAttrsArray;
    int32_t result = systemSoundManager_->GetToneHapticsList(context_, true, toneHapticsAttrsArray);
    if (result == 0 && toneHapticsAttrsArray.size() > 0) {
        std::string uri = toneHapticsAttrsArray[0]->GetUri();
        fd = systemSoundManager_->OpenToneHaptics(context_, uri);
        EXPECT_GT(fd, 0);
    }
    EXPECT_NE(systemSoundManager_, nullptr);
}

/**
 * @tc.name  : Test GetHapticsUriByStyle API
 * @tc.number: Media_SoundManager_GetHapticsUriByStyle_001
 * @tc.desc  : Test GetHapticsUriByStyle interface. Returns haptics of the specified style.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_GetHapticsUriByStyle_001, TestSize.Level2)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<AbilityRuntime::Context> context_ = std::make_shared<ContextImpl>();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    EXPECT_NE(systemSoundManagerImpl_, nullptr);

    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    EXPECT_NE(dataShareHelper, nullptr);

    std::string hapticsUri = systemSoundManagerImpl_->GetHapticsUriByStyle(dataShareHelper, "test",
        HapticsStyle::HAPTICS_STYLE_GENTLE);
    EXPECT_EQ(hapticsUri.empty(), true);

    std::vector<std::shared_ptr<ToneHapticsAttrs>> toneHapticsAttrsArray;
    int32_t result = systemSoundManagerImpl_->GetToneHapticsList(context_, false, toneHapticsAttrsArray);
    if (result == 0 && toneHapticsAttrsArray.size() > 0) {
        hapticsUri = systemSoundManagerImpl_->GetHapticsUriByStyle(dataShareHelper, toneHapticsAttrsArray[0]->GetUri(),
            HapticsStyle::HAPTICS_STYLE_GENTLE);
        EXPECT_EQ(hapticsUri.empty(), false);
    }
    dataShareHelper->Release();
}

/**
 * @tc.name  : Test IsSystemToneType API
 * @tc.number: Media_SoundManager_IsSystemToneType_001
 * @tc.desc  : Test IsSystemToneType interface.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_IsSystemToneType_001, TestSize.Level2)
{
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    std::unique_ptr<RingtoneAsset> ringtoneAsset = std::make_unique<RingtoneAsset>();
    EXPECT_TRUE(systemSoundManager_->IsSystemToneType(ringtoneAsset,
         SystemToneType::SYSTEM_TONE_TYPE_SIM_CARD_0));
}

/**
 * @tc.name  : Test IsSystemToneType API
 * @tc.number: Media_SoundManager_IsSystemToneType_002
 * @tc.desc  : Test IsSystemToneType interface.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_IsSystemToneType_002, TestSize.Level2)
{
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    std::unique_ptr<RingtoneAsset> ringtoneAsset = std::make_unique<RingtoneAsset>();
    EXPECT_TRUE(systemSoundManager_->IsSystemToneType(ringtoneAsset,
        SystemToneType::SYSTEM_TONE_TYPE_NOTIFICATION));
}

/**
 * @tc.name  : Test IsToneHapticsTypeValid API
 * @tc.number: Media_SoundManager_IsToneHapticsTypeValid_001
 * @tc.desc  : Test IsToneHapticsTypeValid interface.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_IsToneHapticsTypeValid_001, TestSize.Level2)
{
    auto systemSoundManager_ =std::make_shared<SystemSoundManagerImpl>();
    EXPECT_TRUE(systemSoundManager_->IsToneHapticsTypeValid(ToneHapticsType::CALL_SIM_CARD_0));

    int defaultToneHapticsType = 4;
    ToneHapticsType toneHapticsType = static_cast<ToneHapticsType>(defaultToneHapticsType);
    EXPECT_FALSE(systemSoundManager_->IsToneHapticsTypeValid(toneHapticsType));
}

/**
 * @tc.name  : Test InitDefaultRingtoneUriMap API
 * @tc.number: Media_SoundManager_InitDefaultRingtoneUriMap_001
 * @tc.desc  : Test InitDefaultRingtoneUriMap interface.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_InitDefaultRingtoneUriMap_001, TestSize.Level2)
{
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    systemSoundManager_->InitDefaultRingtoneUriMap("test");
    EXPECT_NE(systemSoundManager_, nullptr);

    std::shared_ptr<AbilityRuntime::Context> context_ = std::make_shared<ContextImpl>();
    auto vec = systemSoundManager_->GetAlarmToneAttrList(context_);
    std::string uri = "";
    if (vec.size() > 0) {
        uri = vec[0]->GetUri();
    }

    systemSoundManager_->InitDefaultRingtoneUriMap(uri);
    EXPECT_NE(systemSoundManager_, nullptr);
}

/**
 * @tc.name  : Test GetDefaultRingtoneUri API
 * @tc.number: Media_SoundManager_GetDefaultRingtoneUri_001
 * @tc.desc  : Test GetDefaultRingtoneUri interface.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_GetDefaultRingtoneUri_001, TestSize.Level2)
{
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    EXPECT_NO_THROW(
        systemSoundManager_->GetDefaultRingtoneUri(RingtoneType::RINGTONE_TYPE_SIM_CARD_0);
    );
}

/**
 * @tc.name  : Test GetDefaultSystemToneUri API
 * @tc.number: Media_SoundManager_GetDefaultSystemToneUri_001
 * @tc.desc  : Test GetDefaultSystemToneUri interface.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_GetDefaultSystemToneUri_001, TestSize.Level2)
{
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    EXPECT_NO_THROW(
        systemSoundManager_->GetDefaultSystemToneUri(SystemToneType::SYSTEM_TONE_TYPE_SIM_CARD_0);
    );
}

/**
 * @tc.name  : Test WriteUriToDatabase API
 * @tc.number: Media_SoundManager_WriteUriToDatabase_001
 * @tc.desc  : Test WriteUriToDatabase/GetUriFromDatabase interface.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_Get_WriteUriToDatabase_001, TestSize.Level2)
{
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    std::shared_ptr<AbilityRuntime::Context> context_ = std::make_shared<ContextImpl>();
    std::string uri;
    auto vec = systemSoundManager_->GetAlarmToneAttrList(context_);
    if (vec.size() > 0) {
        uri = vec[0]->GetUri();
    }

    systemSoundManager_->WriteUriToDatabase("test", uri);
    EXPECT_NE(systemSoundManager_, nullptr);

    std::string key = "test";
    EXPECT_NO_THROW(
        systemSoundManager_->GetUriFromDatabase(key);
    );
}

/**
 * @tc.name  : Test GetKeyForDatabase API
 * @tc.number: Media_SoundManager_GetKeyForDatabase_001
 * @tc.desc  : Test GetKeyForDatabase interface.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_GetKeyForDatabase_001, TestSize.Level2)
{
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    std::string Ring_Tone = "ring_tone";
    int32_t Ringtone_Type_Sim_Card_0 = 0;
    int32_t Ringtone_Type_Sim_Card_1 = 1;

    std::string result = systemSoundManager_->GetKeyForDatabase(Ring_Tone, Ringtone_Type_Sim_Card_0);
    EXPECT_EQ(result, "ringtone_for_sim_card_0");

    result = systemSoundManager_->GetKeyForDatabase(Ring_Tone, Ringtone_Type_Sim_Card_1);
    EXPECT_EQ(result, "ringtone_for_sim_card_1");

    int32_t Ringtone_Type_Sim_Card = 2;
    result = systemSoundManager_->GetKeyForDatabase(Ring_Tone, Ringtone_Type_Sim_Card);
    EXPECT_EQ(result, "");
}

/**
 * @tc.name  : Test GetKeyForDatabase API
 * @tc.number: Media_SoundManager_GetKeyForDatabase_002
 * @tc.desc  : Test GetKeyForDatabase interface.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_GetKeyForDatabase_002, TestSize.Level2)
{
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    std::string System_Tone = "system_tone";
    int32_t System_Tone_Type_Sim_Card_0 = 0;
    int32_t System_Tone_Type_Sim_Card_1 = 1;
    int32_t System_Tone_Type_Notification = 32;
    int32_t System_Tone_Type_Sim_Card = 3;

    std::string result = systemSoundManager_->GetKeyForDatabase(System_Tone, System_Tone_Type_Sim_Card_0);
    EXPECT_EQ(result, "system_tone_for_sim_card_0");

    result = systemSoundManager_->GetKeyForDatabase(System_Tone, System_Tone_Type_Sim_Card_1);
    EXPECT_EQ(result, "system_tone_for_sim_card_1");

    result = systemSoundManager_->GetKeyForDatabase(System_Tone, System_Tone_Type_Notification);
    EXPECT_EQ(result, "system_tone_for_notification");

    result = systemSoundManager_->GetKeyForDatabase(System_Tone, System_Tone_Type_Sim_Card);
    EXPECT_EQ(result, "");
}

/**
 * @tc.name  : Test GetKeyForDatabase API
 * @tc.number: Media_SoundManager_GetKeyForDatabase_003
 * @tc.desc  : Test GetKeyForDatabase interface.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_GetKeyForDatabase_003, TestSize.Level2)
{
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    std::string result = systemSoundManager_->GetKeyForDatabase("test", 0);
    EXPECT_EQ(result, "");
}

/**
 * @tc.name  : Test SetRingtoneUri API
 * @tc.number: Media_SoundManager_SetRingtoneUri_001
 * @tc.desc  : Test SetRingtoneUri interface.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_SetRingtoneUri_001, TestSize.Level2)
{
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    std::shared_ptr<Context> context_ = std::make_shared<ContextImpl>();
    std::string uri;
    auto vec = systemSoundManager_->GetAlarmToneAttrList(context_);
    if (vec.size() > 0) {
        uri = vec[0]->GetUri();
    }

    systemSoundManager_->SetRingtoneUri(context_, uri, RingtoneType::RINGTONE_TYPE_SIM_CARD_0);
    systemSoundManager_->GetRingtoneUri(context_, RingtoneType::RINGTONE_TYPE_SIM_CARD_0);
    EXPECT_NE(systemSoundManager_, nullptr);

    systemSoundManager_->SetRingtoneUri(context_, uri, RingtoneType::RINGTONE_TYPE_SIM_CARD_1);
    systemSoundManager_->GetRingtoneUri(context_, RingtoneType::RINGTONE_TYPE_SIM_CARD_1);
    EXPECT_NE(systemSoundManager_, nullptr);

    int RINGTONE_TYPE_SIM_CARD = 2;
    systemSoundManager_->SetRingtoneUri(context_, uri, static_cast<RingtoneType>(RINGTONE_TYPE_SIM_CARD));
    systemSoundManager_->GetRingtoneUri(context_, static_cast<RingtoneType>(RINGTONE_TYPE_SIM_CARD));
    EXPECT_NE(systemSoundManager_, nullptr);
}

/**
 * @tc.name  : Test GetRingtoneTitle API
 * @tc.number: Media_SoundManager_GetRingtoneTitle_001
 * @tc.desc  : Test GetRingtoneTitle interface.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundMnanager_GetRingtoneTitle_001, TestSize.Level2)
{
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    std::string ringtoneUri = "test";
    std::string result = systemSoundManager_->GetRingtoneTitle(ringtoneUri);
    EXPECT_EQ(result, "");
}

/**
 * @tc.name  : Test GetRingtonePlayer API
 * @tc.number: Media_SoundManager_GetRingtonePlayer_001
 * @tc.desc  : Test GetRingtonePlayer interface.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_GetRingtonePlayer_001, TestSize.Level2)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<Context> context_ = std::make_shared<ContextImpl>();
    std::shared_ptr<RingtonePlayer> result;
    result = systemSoundManager_->GetRingtonePlayer(context_, RingtoneType::RINGTONE_TYPE_SIM_CARD_0);
    EXPECT_NE(result, nullptr);

    result = systemSoundManager_->GetRingtonePlayer(context_, RingtoneType::RINGTONE_TYPE_SIM_CARD_1);
    EXPECT_NE(result, nullptr);

    int RINGTONE_TYPE_SIM_CARD_DEFAULT = 2;
    result = systemSoundManager_->GetRingtonePlayer(context_,
        static_cast<RingtoneType>(RINGTONE_TYPE_SIM_CARD_DEFAULT));
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name  : Test GetSystemtonePlayer API
 * @tc.number: Media_SoundManager_GetSystemtonePlayer_001
 * @tc.desc  : Test GetSystemtonePlayer interface.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_GetSystemtonePlayer_001, TestSize.Level2)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<AbilityRuntime::Context> context_ = std::make_shared<ContextImpl>();
    std::shared_ptr<SystemTonePlayer> result;
    result = systemSoundManager_->GetSystemTonePlayer(context_, SystemToneType::SYSTEM_TONE_TYPE_SIM_CARD_0);
    EXPECT_NE(result, nullptr);

    result = systemSoundManager_->GetSystemTonePlayer(context_, SystemToneType::SYSTEM_TONE_TYPE_SIM_CARD_1);
    EXPECT_NE(result, nullptr);

    result = systemSoundManager_->GetSystemTonePlayer(context_, SystemToneType::SYSTEM_TONE_TYPE_NOTIFICATION);
    EXPECT_NE(result, nullptr);

    int SYSTEM_TONE_TYPE_SIM_CARD_DEFAULT = 2;
    result = systemSoundManager_->GetSystemTonePlayer(context_,
        static_cast<SystemToneType>(SYSTEM_TONE_TYPE_SIM_CARD_DEFAULT));
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name  : Test SetSystemToneUri API
 * @tc.number: Media_SoundManager_SetSystemToneUri_001
 * @tc.desc  : Test SetSystemToneUri interface.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_SetSystemToneUri_001, TestSize.Level2)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<Context> context_ = std::make_shared<ContextImpl>();
    std::string uri;
    auto vec = systemSoundManager_->GetAlarmToneAttrList(context_);
    if (vec.size() > 0) {
        uri = vec[0]->GetUri();
    }
    systemSoundManager_->SetSystemToneUri(context_, uri, SystemToneType::SYSTEM_TONE_TYPE_SIM_CARD_0);
    EXPECT_NE(systemSoundManager_, nullptr);

    systemSoundManager_->SetSystemToneUri(context_, uri, SystemToneType::SYSTEM_TONE_TYPE_SIM_CARD_1);
    EXPECT_NE(systemSoundManager_, nullptr);

    systemSoundManager_->SetSystemToneUri(context_, uri, SystemToneType::SYSTEM_TONE_TYPE_NOTIFICATION);
    EXPECT_NE(systemSoundManager_, nullptr);

    int SYSTEM_TONE_TYPE_SIM_CARD_DEFAULT = 2;
    systemSoundManager_->SetSystemToneUri(context_, uri,
        static_cast<SystemToneType>(SYSTEM_TONE_TYPE_SIM_CARD_DEFAULT));
    EXPECT_NE(systemSoundManager_, nullptr);
}

/**
 * @tc.name  : Test GetSystemToneUri API
 * @tc.number: Media_SoundManager_GetSystemToneUri_001
 * @tc.desc  : Test GetSystemToneUri interface.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_GetSystemToneUri_001, TestSize.Level2)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<AbilityRuntime::Context> context_ = std::make_shared<ContextImpl>();
    systemSoundManager_->GetSystemToneUri(context_, SystemToneType::SYSTEM_TONE_TYPE_SIM_CARD_0);
    EXPECT_NE(systemSoundManager_, nullptr);

    systemSoundManager_->GetSystemToneUri(context_, SystemToneType::SYSTEM_TONE_TYPE_SIM_CARD_1);
    EXPECT_NE(systemSoundManager_, nullptr);

    systemSoundManager_->GetSystemToneUri(context_, SystemToneType::SYSTEM_TONE_TYPE_NOTIFICATION);
    EXPECT_NE(systemSoundManager_, nullptr);

    int SYSTEM_TONE_TYPE_SIM_CARD_DEFAULT = 2;
    systemSoundManager_->GetSystemToneUri(context_, static_cast<SystemToneType>(SYSTEM_TONE_TYPE_SIM_CARD_DEFAULT));
    EXPECT_NE(systemSoundManager_, nullptr);
}

/**
 * @tc.name  : Test AddCustomizedToneByFdAndOffset API
 * @tc.number: Media_SoundManager_AddCustomizedToneByFdAndOffset_002
 * @tc.desc  : Test AddCustomizedToneByFdAndOffset interface.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_AddCustomizedToneByFdAndOffset_002, TestSize.Level2)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<AbilityRuntime::Context> context_ = std::make_shared<ContextImpl>();
    std::shared_ptr<ToneAttrs> toneAttrs_ = std::make_shared<ToneAttrs>("default",
        "default", "default", CUSTOMISED, TONE_CATEGORY_INVALID);
    auto vec = systemSoundManager_->GetAlarmToneAttrList(context_);
    std::string uri = "";
    if (vec.size() > 0) {
        uri = vec[0]->GetUri();
    }

    std::string res;
    toneAttrs_->SetTitle("06172");
    toneAttrs_->SetFileName("06172");
    res = systemSoundManager_->AddCustomizedToneByFdAndOffset(context_, toneAttrs_, 1, 10, 0);
    EXPECT_EQ(res.empty(), true);

    int fd = systemSoundManager_->OpenAlarmTone(context_, uri);
    toneAttrs_->SetTitle("06173");
    toneAttrs_->SetFileName("06173");
    systemSoundManager_->AddCustomizedToneByFdAndOffset(context_, toneAttrs_, fd, 10, 0);
    EXPECT_NE(systemSoundManager_, nullptr);

    toneAttrs_->SetTitle("06174");
    toneAttrs_->SetFileName("06174");
    systemSoundManager_->AddCustomizedToneByFdAndOffset(context_, toneAttrs_, fd, 10, 1);
    EXPECT_NE(systemSoundManager_, nullptr);
    systemSoundManager_->Close(fd);
}

/**
 * @tc.name  : Test AddCustomizedToneByFdAndOffset API
 * @tc.number: Media_SoundManager_AddCustomizedToneByFdAndOffset_003
 * @tc.desc  : Test AddCustomizedToneByFdAndOffset interface.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_AddCustomizedToneByFdAndOffset_003, TestSize.Level2)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<AbilityRuntime::Context> context_ = std::make_shared<ContextImpl>();
    auto vec = systemSoundManager_->GetAlarmToneAttrList(context_);
    std::string uri = "";
    std::string title = "";
    std::string fileName = "";
    if (vec.size() > 0) {
        uri = vec[0]->GetUri();
        title = vec[0]->GetTitle();
        fileName = vec[0]->GetFileName();
    }

    std::shared_ptr<ToneAttrs> toneAttrs_ = std::make_shared<ToneAttrs>(title,
        fileName, uri, PRE_INSTALLED, TONE_CATEGORY_RINGTONE);
    std::string res;
    res = systemSoundManager_->AddCustomizedToneByFdAndOffset(context_, toneAttrs_, 1, 10, 0);
    EXPECT_NE(systemSoundManager_, nullptr);

    int fd = systemSoundManager_->OpenAlarmTone(context_, uri);
    systemSoundManager_->AddCustomizedToneByFdAndOffset(context_, toneAttrs_, fd, 10, 0);
    EXPECT_NE(systemSoundManager_, nullptr);

    systemSoundManager_->AddCustomizedToneByFdAndOffset(context_, toneAttrs_, fd, 10, 1);
    EXPECT_NE(systemSoundManager_, nullptr);
    systemSoundManager_->Close(fd);
}

/**
 * @tc.name  : Test AddCustomizedToneByFd API
 * @tc.number: Media_SoundManager_AddCustomizedToneByFd_001
 * @tc.desc  : Test AddCustomizedToneByFd interface.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_AddCustomizedToneByFd_001, TestSize.Level2)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<AbilityRuntime::Context> context_ = std::make_shared<ContextImpl>();
    std::shared_ptr<ToneAttrs> toneAttrs_ = std::make_shared<ToneAttrs>("default",
        "default", "default", CUSTOMISED, TONE_CATEGORY_INVALID);
    auto vec = systemSoundManager_->GetAlarmToneAttrList(context_);
    std::string uri = "";
    if (vec.size() > 0) {
        uri = vec[0]->GetUri();
    }
    int fd = systemSoundManager_->OpenAlarmTone(context_, uri);
    toneAttrs_->SetTitle("06172");
    toneAttrs_->SetFileName("06172");
    systemSoundManager_->AddCustomizedToneByFd(context_, toneAttrs_, fd);
    EXPECT_NE(systemSoundManager_, nullptr);
}

/**
 * @tc.name  : Test AddCustomizedToneByFd API
 * @tc.number: Media_SoundManager_AddCustomizedToneByFd_002
 * @tc.desc  : Test AddCustomizedToneByFd interface.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_AddCustomizedToneByFd_002, TestSize.Level2)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<AbilityRuntime::Context> context_ = std::make_shared<ContextImpl>();
    std::shared_ptr<ToneAttrs> toneAttrs_ = std::make_shared<ToneAttrs>("default",
        "default", "default", CUSTOMISED, TONE_CATEGORY_TEXT_MESSAGE);
    auto vec = systemSoundManager_->GetAlarmToneAttrList(context_);
    std::string uri = "";
    if (vec.size() > 0) {
        uri = vec[0]->GetUri();
    }
    int fd = systemSoundManager_->OpenAlarmTone(context_, uri);
    toneAttrs_->SetTitle("06172");
    toneAttrs_->SetFileName("06172");
    systemSoundManager_->AddCustomizedToneByFd(context_, toneAttrs_, fd);
    EXPECT_NE(systemSoundManager_, nullptr);

    toneAttrs_->SetCategory(TONE_CATEGORY_NOTIFICATION);
    systemSoundManager_->AddCustomizedToneByFd(context_, toneAttrs_, fd);
    EXPECT_NE(systemSoundManager_, nullptr);

    toneAttrs_->SetCategory(TONE_CATEGORY_ALARM);
    systemSoundManager_->AddCustomizedToneByFd(context_, toneAttrs_, fd);
    EXPECT_NE(systemSoundManager_, nullptr);
}

/**
 * @tc.name  : Test GetCustomizedTone API
 * @tc.number: Media_SoundManager_GetCustomizedTone_001
 * @tc.desc  : Test GetCustomizedTone interface.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_GetCustomizedTone_001, TestSize.Level2)
{
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    std::shared_ptr<ToneAttrs> toneAttrs_ = std::make_shared<ToneAttrs>("default",
        "default", "default", CUSTOMISED, TONE_CATEGORY_INVALID);
    toneAttrs_->SetTitle("06172");
    toneAttrs_->SetFileName("06172");
    systemSoundManager_->GetCustomizedTone(toneAttrs_);
    EXPECT_NE(systemSoundManager_, nullptr);
}

/**
 * @tc.name  : Test ConvertToSystemToneType API
 * @tc.number: Media_SoundManager_ConvertToSystemToneType_001
 * @tc.desc  : Test ConvertToSystemToneType interface.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_ConvertToSystemToneType_001, TestSize.Level2)
{
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    SystemToneType systemToneType;
    int HAPTICS_RINGTONE_TYPE_SIM_CARD_DEFAULT = 4;
    systemSoundManager_->ConvertToSystemToneType(static_cast<ToneHapticsType>(HAPTICS_RINGTONE_TYPE_SIM_CARD_DEFAULT),
        systemToneType);
    EXPECT_NE(systemSoundManager_, nullptr);
}

/**
 * @tc.name  : Test IntToToneHapticsMode API
 * @tc.number: Media_SoundManager_IntToToneHapticsMode_001
 * @tc.desc  : Test IntToToneHapticsMode interface.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_IntToToneHapticsMode_001, TestSize.Level2)
{
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    int32_t result = systemSoundManager_->IntToToneHapticsMode(ToneHapticsMode::NONE);
    EXPECT_EQ(result, 0);

    result = systemSoundManager_->IntToToneHapticsMode(ToneHapticsMode::SYNC);
    EXPECT_EQ(result, 1);

    result = systemSoundManager_->IntToToneHapticsMode(ToneHapticsMode::NON_SYNC);
    EXPECT_EQ(result, 2);

    int32_t DEFAULT_SYNC = 3;
    result = systemSoundManager_->IntToToneHapticsMode(static_cast<ToneHapticsMode>(DEFAULT_SYNC));
    EXPECT_EQ(result, 0);
}

/**
 * @tc.name  : Test SetRingerMode API
 * @tc.number: Media_SoundManager_SetRingerMode_001
 * @tc.desc  : Test SetRingerMode interface.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_SetRingerMode_001, TestSize.Level2)
{
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    int32_t result = systemSoundManager_->SetRingerMode(AudioStandard::AudioRingerMode::RINGER_MODE_NORMAL);
    EXPECT_EQ(result, 0);
}

/**
* @tc.name  : Test OnRingerModeUpdated API
* @tc.number: Media_SoundManager_OnRingerModeUpdated_001
* @tc.desc  : Test OnRingerModeUpdated interface.
*/
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_OnRingerModeUpdated_001, TestSize.Level2)
{
    auto systemSoundManager = std::make_shared<SystemSoundManagerImpl>();
    SystemSoundManagerImpl systemSoundManager_;
    RingerModeCallbackImpl ringerMode_(systemSoundManager_);
    ringerMode_.OnRingerModeUpdated(AudioStandard::AudioRingerMode::RINGER_MODE_SILENT);
    EXPECT_NE(systemSoundManager, nullptr);
}

/**
* @tc.name  : Test GetStandardVibrateType API
* @tc.number: Media_SoundManager_GetStandardVibrateType_001
* @tc.desc  : Test GetStandardVibrateType interface.
*/
 HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_GetStandardVibrateType_001, TestSize.Level2)
{
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    systemSoundManager_->GetStandardVibrateType(ToneType::TONE_TYPE_ALARM);
    EXPECT_NE(systemSoundManager_, nullptr);

    systemSoundManager_->GetStandardVibrateType(ToneType::TONE_TYPE_RINGTONE);
    EXPECT_NE(systemSoundManager_, nullptr);

    systemSoundManager_->GetStandardVibrateType(ToneType::TONE_TYPE_NOTIFICATION);
    EXPECT_NE(systemSoundManager_, nullptr);
    systemSoundManager_->GetStandardVibrateType(ToneType::TONE_TYPE_MAX);
    EXPECT_NE(systemSoundManager_, nullptr);
}

/**
* @tc.name  : Test GetDefaultToneHapticsSettings API
* @tc.number: Media_SoundManager_GetDefaultToneHapticsSettings_001
* @tc.desc  : Test GetDefaultToneHapticsSettings interface.
*/
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_GetDefaultToneHapticsSettings_001, TestSize.Level2)
{
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    std::shared_ptr<AbilityRuntime::Context> context_ = std::make_shared<ContextImpl>();
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    EXPECT_NE(dataShareHelper, nullptr);

    ToneHapticsSettings settings_;
    std::string currentToneUri;
    currentToneUri = systemSoundManager_->GetCurrentToneUri(context_,
        ToneHapticsType::CALL_SIM_CARD_0);
    systemSoundManager_->GetDefaultToneHapticsSettings(dataShareHelper, currentToneUri,
        ToneHapticsType::CALL_SIM_CARD_0, settings_);
    EXPECT_NE(systemSoundManager_, nullptr);

    currentToneUri = systemSoundManager_->GetCurrentToneUri(context_,
        ToneHapticsType::CALL_SIM_CARD_1);
    systemSoundManager_->GetDefaultToneHapticsSettings(dataShareHelper, currentToneUri,
        ToneHapticsType::CALL_SIM_CARD_1, settings_);
    EXPECT_NE(systemSoundManager_, nullptr);

    currentToneUri = systemSoundManager_->GetCurrentToneUri(context_,
        ToneHapticsType::NOTIFICATION);
    systemSoundManager_->GetDefaultToneHapticsSettings(dataShareHelper, currentToneUri,
        ToneHapticsType::NOTIFICATION, settings_);
    EXPECT_NE(systemSoundManager_, nullptr);

    currentToneUri = systemSoundManager_->GetCurrentToneUri(context_,
        ToneHapticsType::TEXT_MESSAGE_SIM_CARD_0);
    systemSoundManager_->GetDefaultToneHapticsSettings(dataShareHelper, currentToneUri,
        ToneHapticsType::TEXT_MESSAGE_SIM_CARD_0, settings_);
    EXPECT_NE(systemSoundManager_, nullptr);

    currentToneUri = systemSoundManager_->GetCurrentToneUri(context_,
        ToneHapticsType::TEXT_MESSAGE_SIM_CARD_1);
    systemSoundManager_->GetDefaultToneHapticsSettings(dataShareHelper, currentToneUri,
        ToneHapticsType::TEXT_MESSAGE_SIM_CARD_1, settings_);
    EXPECT_NE(systemSoundManager_, nullptr);

    dataShareHelper->Release();
}

/**
* @tc.name  : Test GetVibrateTypeByStyle API
* @tc.number: Media_SoundManager_GetVibrateTypeByStyle_001
* @tc.desc  : Test GetVibrateTypeByStyle interface.
*/
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_GetVibrateTypeByStyle_001, TestSize.Level2)
{
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    std::unique_ptr<VibrateAsset> vibrateAssetByUri = std::make_unique<VibrateAsset>();
    int vibrateType = 0;
    systemSoundManager_->GetVibrateTypeByStyle(vibrateAssetByUri->GetVibrateType(), HapticsStyle::HAPTICS_STYLE_GENTLE,
        vibrateType);
    EXPECT_NE(systemSoundManager_, nullptr);
    systemSoundManager_->GetVibrateTypeByStyle(vibrateAssetByUri->GetVibrateType(),
    HapticsStyle::HAPTICS_STYLE_STANDARD, vibrateType);
    EXPECT_NE(systemSoundManager_, nullptr);
}

/**
 * @tc.name  : Test SetSystemToneUri API
 * @tc.number: Media_SoundManager_SetSystemToneUri_002
 * @tc.desc  : Test SetSystemToneUri interface.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_SetSystemToneUri_002, TestSize.Level2)
{
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    std::shared_ptr<Context> context_ = std::make_shared<ContextImpl>();
    std::string uri = NO_SYSTEM_SOUND;

    int32_t result = systemSoundManager_->SetSystemToneUri(context_, uri,
        SystemToneType::SYSTEM_TONE_TYPE_NOTIFICATION);
    EXPECT_NE(systemSoundManager_, nullptr);

    result = systemSoundManager_->SetSystemToneUri(context_, uri,
        SystemToneType::SYSTEM_TONE_TYPE_SIM_CARD_0);
    EXPECT_NE(systemSoundManager_, nullptr);

    result = systemSoundManager_->SetSystemToneUri(context_, uri,
        SystemToneType::SYSTEM_TONE_TYPE_SIM_CARD_1);
    EXPECT_NE(systemSoundManager_, nullptr);
}

/**
 * @tc.name  : Test IsSystemToneTypeValid API
 * @tc.number: Media_SoundManager_IsSystemToneTypeValid_002
 * @tc.desc  : Test IsSystemToneTypeValid interface.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_IsSystemToneTypeValid_002, TestSize.Level2)
{
    bool result;
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    result = systemSoundManager_->IsSystemToneTypeValid(SystemToneType::SYSTEM_TONE_TYPE_SIM_CARD_1);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name  : Test GetDefaultRingtoneUri API
 * @tc.number: Media_SoundManager_GetDefaultRingtoneUri_002
 * @tc.desc  : Test GetDefaultRingtoneUri interface.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_GetDefaultRingtoneUri_002, TestSize.Level2)
{
    int32_t RINGTONE_TYPE_SIM_CARD_DEFAULT = 2;
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    systemSoundManager_->GetDefaultRingtoneUri(static_cast<OHOS::Media::RingtoneType>(RINGTONE_TYPE_SIM_CARD_DEFAULT));
    EXPECT_NE(systemSoundManager_, nullptr);
}

/**
 * @tc.name  : Test GetDefaultSystemToneUri API
 * @tc.number: Media_SoundManager_GetDefaultSystemToneUri_002
 * @tc.desc  : Test GetDefaultSystemToneUri interface.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_GetDefaultSystemToneUri_002, TestSize.Level2)
{
    int32_t SYSTEM_TONE_TYPE_SIM_CARD_DEFAULT = 2;
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    systemSoundManager_->GetDefaultSystemToneUri(static_cast<SystemToneType>(SYSTEM_TONE_TYPE_SIM_CARD_DEFAULT));
    EXPECT_NE(systemSoundManager_, nullptr);
}

/**
 * @tc.name  : Test OpenToneUri API
 * @tc.number: Media_SoundManager_OpenToneUri_001
 * @tc.desc  : Test OpenToneUri interface. Returns attributes of the default system tone.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_OpenToneUri_001, TestSize.Level2)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<AbilityRuntime::Context> context_ = std::make_shared<ContextImpl>();
    int fd = systemSoundManager_->OpenToneUri(context_, "test", ToneType::TONE_TYPE_ALARM);
    EXPECT_LT(fd, 0);
    auto vec = systemSoundManager_->GetAlarmToneAttrList(context_);
    if (vec.size() > 0) {
        std::string uri = vec[0]->GetUri();
        fd = systemSoundManager_->OpenToneUri(context_, uri, ToneType::TONE_TYPE_ALARM);
    }
    EXPECT_NE(systemSoundManager_, nullptr);
}

/**
 * @tc.name  : GetDefaultRingtoneUri_ShouldReturnUri_WhenTypeIsValid
 * @tc.number: GetDefaultRingtoneUri_ShouldReturnUri_WhenTypeIsValid_001
 * @tc.desc  : Test GetDefaultRingtoneUri method when ringtone type is valid.
 */
HWTEST(SystemSoundManagerUnitTest, GetDefaultRingtoneUri_ShouldReturnUri_WhenTypeIsValid_001, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    EXPECT_NE(systemSoundManagerImpl_, nullptr);

    // Arrange
    RingtoneType validType = static_cast<RingtoneType>(0);

    // Act
    std::string result = systemSoundManagerImpl_->GetDefaultRingtoneUri(validType);

    // Assert
    EXPECT_EQ(result, "");
}

/**
 * @tc.name  : GetDefaultRingtoneUri_ShouldReturnEmpty_WhenTypeIsInvalid
 * @tc.number: GetDefaultRingtoneUri_ShouldReturnEmpty_WhenTypeIsInvalid_001
 * @tc.desc  : Test GetDefaultRingtoneUri method when ringtone type is invalid.
 */
HWTEST(SystemSoundManagerUnitTest, GetDefaultRingtoneUri_ShouldReturnEmpty_WhenTypeIsInvalid_001, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    EXPECT_NE(systemSoundManagerImpl_, nullptr);

    // Arrange
    RingtoneType invalidType = static_cast<RingtoneType>(99); // Assuming 99 is an invalid type

    // Act
    std::string result = systemSoundManagerImpl_->GetDefaultRingtoneUri(invalidType);

    // Assert
    EXPECT_EQ(result, "");
}

/**
 * @tc.name  : GetDefaultSystemToneUri_ShouldReturnUri_WhenTypeIsRinging
 * @tc.number: GetDefaultSystemToneUri_001
 * @tc.desc  : Test GetDefaultSystemToneUri function when SystemToneType is Ringing
 */
HWTEST(SystemSoundManagerUnitTest, GetDefaultSystemToneUri_001, testing::ext::TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    EXPECT_NE(systemSoundManagerImpl_, nullptr);

    // Arrange
    SystemToneType systemToneType = SystemToneType::SYSTEM_TONE_TYPE_SIM_CARD_0;
    std::string expectedUri = "system_ringing_tone.mp3";

    // Act
    std::string actualUri = systemSoundManagerImpl_->GetDefaultSystemToneUri(systemToneType);

    // Assert
    EXPECT_NE(expectedUri, actualUri);
}

/**
 * @tc.name  : GetDefaultSystemToneUri_ShouldReturnUri_WhenTypeIsNotification
 * @tc.number: GetDefaultSystemToneUri_002
 * @tc.desc  : Test GetDefaultSystemToneUri function when SystemToneType is Notification
 */
HWTEST(SystemSoundManagerUnitTest, GetDefaultSystemToneUri_002, testing::ext::TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    EXPECT_NE(systemSoundManagerImpl_, nullptr);

    // Arrange
    SystemToneType systemToneType = SystemToneType::SYSTEM_TONE_TYPE_SIM_CARD_1;
    std::string expectedUri = "system_notification_tone.mp3";

    // Act
    std::string actualUri = systemSoundManagerImpl_->GetDefaultSystemToneUri(systemToneType);

    // Assert
    EXPECT_NE(expectedUri, actualUri);
}

/**
 * @tc.name  : GetDefaultSystemToneUri_ShouldReturnUri_WhenTypeIsAlarm
 * @tc.number: GetDefaultSystemToneUri_003
 * @tc.desc  : Test GetDefaultSystemToneUri function when SystemToneType is Alarm
 */
HWTEST(SystemSoundManagerUnitTest, GetDefaultSystemToneUri_003, testing::ext::TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    EXPECT_NE(systemSoundManagerImpl_, nullptr);

    // Arrange
    SystemToneType systemToneType = SystemToneType::SYSTEM_TONE_TYPE_NOTIFICATION;
    std::string expectedUri = "system_alarm_tone.mp3";

    // Act
    std::string actualUri = systemSoundManagerImpl_->GetDefaultSystemToneUri(systemToneType);

    // Assert
    EXPECT_NE(expectedUri, actualUri);
}

/**
 * @tc.name  : GetKeyForDatabase_ShouldReturnCorrectKey_WhenRingtoneTypeIsSimCard0
 * @tc.number: GetKeyForDatabase_RING_TONE_001
 * @tc.desc  : Test GetKeyForDatabase function when systemSoundType is RING_TONE and type is RINGTONE_TYPE_SIM_CARD_0
 */
HWTEST(SystemSoundManagerUnitTest, GetKeyForDatabase_RING_TONE_001, testing::ext::TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    EXPECT_NE(systemSoundManagerImpl_, nullptr);

    std::string result = systemSoundManagerImpl_->GetKeyForDatabase(RING_TONE, 0);
    EXPECT_EQ(result, "ringtone_for_sim_card_0");
    result = systemSoundManagerImpl_->GetKeyForDatabase(RING_TONE, 1);
    EXPECT_EQ(result, "ringtone_for_sim_card_1");
    result = systemSoundManagerImpl_->GetKeyForDatabase(RING_TONE, 100);
    EXPECT_EQ(result, "");
}


/**
 * @tc.name  : GetKeyForDatabase_SystemTone_SimCard0
 * @tc.number: GetKeyForDatabase_001
 * @tc.desc  : Test GetKeyForDatabase function with SYSTEM_TONE and SIM_CARD_0
 */
HWTEST(SystemSoundManagerUnitTest, GetKeyForDatabase_SystemTone_SimCard0, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    EXPECT_NE(systemSoundManagerImpl_, nullptr);

    std::string result = systemSoundManagerImpl_->GetKeyForDatabase(SYSTEM_TONE, 0);
    EXPECT_EQ(result, "system_tone_for_sim_card_0");
    result = systemSoundManagerImpl_->GetKeyForDatabase(SYSTEM_TONE, 1);
    EXPECT_EQ(result, "system_tone_for_sim_card_1");
    result = systemSoundManagerImpl_->GetKeyForDatabase(SYSTEM_TONE, 32);
    EXPECT_EQ(result, "system_tone_for_notification");
    result = systemSoundManagerImpl_->GetKeyForDatabase(SYSTEM_TONE, 100);
    EXPECT_EQ(result, "");
    result = systemSoundManagerImpl_->GetKeyForDatabase("unavailable_system_sound_type", 100);
    EXPECT_EQ(result, "");
}

/**
 * @tc.name  : UpdateRingtoneUri_UpdateOnly_Test
 * @tc.number: UpdateRingtoneUri_001
 * @tc.desc  : Test UpdateRingtoneUri method when only updateOnlyPredicates and updateOnlyValuesBucket are used.
 */
HWTEST(SystemSoundManagerUnitTest, UpdateRingtoneUri_UpdateOnly_Test, testing::ext::TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    EXPECT_NE(systemSoundManagerImpl_, nullptr);

    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    EXPECT_NE(dataShareHelper, nullptr);

    int32_t toneId = 1;
    RingtoneType ringtoneType = RingtoneType::RINGTONE_TYPE_SIM_CARD_1;
    int32_t num = 1;

    systemSoundManagerImpl_->UpdateRingtoneUri(dataShareHelper, toneId, ringtoneType, num);
}

/**
 * @tc.name  : UpdateRingtoneUri_UpdateBoth_Test
 * @tc.number: UpdateRingtoneUri_002
 * @tc.desc  : Test UpdateRingtoneUri method
 */
HWTEST(SystemSoundManagerUnitTest, UpdateRingtoneUri_UpdateBoth_Test, testing::ext::TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    EXPECT_NE(systemSoundManagerImpl_, nullptr);

    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    EXPECT_NE(dataShareHelper, nullptr);

    int32_t toneId = 1;
    RingtoneType ringtoneType = RingtoneType::RINGTONE_TYPE_SIM_CARD_1;
    int32_t num = 2;

    systemSoundManagerImpl_->UpdateRingtoneUri(dataShareHelper, toneId, ringtoneType, num);
}

/**
 * @tc.name  : UpdateRingtoneUri_UpdatePredicates_Test
 * @tc.number: UpdateRingtoneUri_003
 * @tc.desc  : Test UpdateRingtoneUri method when updatePredicates and updateValuesBucket are used.
 */
HWTEST(SystemSoundManagerUnitTest, UpdateRingtoneUri_UpdatePredicates_Test, testing::ext::TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    EXPECT_NE(systemSoundManagerImpl_, nullptr);

    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    EXPECT_NE(dataShareHelper, nullptr);

    int32_t toneId = 1;
    RingtoneType ringtoneType = RingtoneType::RINGTONE_TYPE_SIM_CARD_1;
    int32_t num = 1;

    systemSoundManagerImpl_->UpdateRingtoneUri(dataShareHelper, toneId, ringtoneType, num);
}

/**
 * @tc.name  : GetRingtoneTitle_ShouldReturnTitle_WhenDataShareHelperIsNotNull
 * @tc.number: GetRingtoneTitle_001
 * @tc.desc  : Test GetRingtoneTitle method when dataShareHelper is not null.
 */
HWTEST(SystemSoundManagerUnitTest, GetRingtoneTitle_ShouldReturnTitle_WhenDataShareHelperIsNotNull, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    EXPECT_NE(systemSoundManagerImpl_, nullptr);

    std::string ringtoneUri = "testUri";
    std::string ringtoneTitle = "";

    std::string result = systemSoundManagerImpl_->GetRingtoneTitle(ringtoneUri);
    EXPECT_EQ(result, ringtoneTitle);
}

/**
 * @tc.name  : UpdateShotToneUri_ShouldUpdate_WhenSystemToneTypeIsSimCard1AndNumIsSimCard1
 * @tc.number: UpdateShotToneUri_001
 * @tc.desc  : Test UpdateShotToneUri
 */
HWTEST(SystemSoundManagerUnitTest, UpdateShotToneUri_001, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    EXPECT_NE(systemSoundManagerImpl_, nullptr);

    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    EXPECT_NE(dataShareHelper, nullptr);
	
    int32_t toneId = 1;
    SystemToneType systemToneType = SystemToneType::SYSTEM_TONE_TYPE_SIM_CARD_0;
    int32_t num = SHOT_TONE_TYPE_SIM_CARD_1;

    int32_t result = systemSoundManagerImpl_->UpdateShotToneUri(dataShareHelper, toneId, systemToneType, num);

    EXPECT_NE(result, 1);
}

/**
 * @tc.name  : UpdateShotToneUri_ShouldUpdate_WhenSystemToneTypeIsSimCard2AndNumIsSimCard2
 * @tc.number: UpdateShotToneUri_002
 * @tc.desc  : Test UpdateShotToneUri method
 */
HWTEST(SystemSoundManagerUnitTest, UpdateShotToneUri_002, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    EXPECT_NE(systemSoundManagerImpl_, nullptr);

    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    EXPECT_NE(dataShareHelper, nullptr);
	
    int32_t toneId = 2;
    SystemToneType systemToneType = SystemToneType::SYSTEM_TONE_TYPE_SIM_CARD_1;
    int32_t num = SHOT_TONE_TYPE_SIM_CARD_2;

    int32_t result = systemSoundManagerImpl_->UpdateShotToneUri(dataShareHelper, toneId, systemToneType, num);

    EXPECT_NE(result, 1);
}

/**
 * @tc.name  : UpdateShotToneUri_ShouldUpdate_WhenSystemToneTypeIsSimCardBothAndNumIsSimCardBoth
 * @tc.number: UpdateShotToneUri_003
 * @tc.desc  : Test UpdateShotToneUri method
 */
HWTEST(SystemSoundManagerUnitTest, UpdateShotToneUri_003, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    EXPECT_NE(systemSoundManagerImpl_, nullptr);

    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    EXPECT_NE(dataShareHelper, nullptr);
	
    int32_t toneId = 3;
    SystemToneType systemToneType = SystemToneType::SYSTEM_TONE_TYPE_NOTIFICATION;
    int32_t num = SHOT_TONE_TYPE_SIM_CARD_BOTH;

    int32_t result = systemSoundManagerImpl_->UpdateShotToneUri(dataShareHelper, toneId, systemToneType, num);

    EXPECT_NE(result, 1);
}

/**
 * @tc.name  : RemoveSourceTypeForSystemTone
 * @tc.number: SystemSoundManagerImplTest_001
 * @tc.desc  : Test RemoveSourceTypeForSystemTone function test
 */
HWTEST(SystemSoundManagerUnitTest, RemoveSourceTypeForSystemTone_001, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    EXPECT_NE(systemSoundManagerImpl_, nullptr);

    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    EXPECT_NE(dataShareHelper, nullptr);
	
    SystemToneType systemToneType = SystemToneType::SYSTEM_TONE_TYPE_SIM_CARD_0;
    SourceType sourceType = SourceType::SOURCE_TYPE_CUSTOMISED;
    int32_t result =
        systemSoundManagerImpl_->RemoveSourceTypeForSystemTone(dataShareHelper, systemToneType, sourceType);
    systemToneType = SystemToneType::SYSTEM_TONE_TYPE_SIM_CARD_1;
    result = systemSoundManagerImpl_->RemoveSourceTypeForSystemTone(dataShareHelper, systemToneType, sourceType);
    systemToneType = SystemToneType::SYSTEM_TONE_TYPE_NOTIFICATION;
    result = systemSoundManagerImpl_->RemoveSourceTypeForSystemTone(dataShareHelper, systemToneType, sourceType);
    SystemToneType invalidType = static_cast<SystemToneType>(99); // 99 is an invalid type
    result = systemSoundManagerImpl_->RemoveSourceTypeForSystemTone(dataShareHelper, invalidType, sourceType);
    EXPECT_EQ(result, 0);
}

/**
 * @tc.name  : AddCustomizedTone_ShouldReturnError_WhenDataShareHelperIsNull
 * @tc.number: SystemSoundManagerImplTest_001
 * @tc.desc  : Test AddCustomizedTone method when dataShareHelper is null.
 */
HWTEST(SystemSoundManagerUnitTest, AddCustomizedTone_ShouldReturnError_WhenDataShareHelperIsNull, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    EXPECT_NE(systemSoundManagerImpl_, nullptr);

    std::shared_ptr<ToneAttrs> toneAttrs =
        std::make_shared<ToneAttrs>("default", "default", "default", CUSTOMISED, TONE_CATEGORY_RINGTONE);
    EXPECT_EQ(systemSoundManagerImpl_->AddCustomizedTone(nullptr, toneAttrs), ERROR);
}

/**
 * @tc.name  : AddCustomizedTone_ShouldReturnSuccess_WhenDataShareHelperIsNotNull
 * @tc.number: SystemSoundManagerImplTest_002
 * @tc.desc  : Test AddCustomizedTone method when dataShareHelper is not null.
 */
HWTEST(SystemSoundManagerUnitTest, AddCustomizedTone_ShouldReturnSuccess_WhenDataShareHelperIsNotNull, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    EXPECT_NE(systemSoundManagerImpl_, nullptr);
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    EXPECT_NE(dataShareHelper, nullptr);

    std::shared_ptr<ToneAttrs> toneAttrs =
        std::make_shared<ToneAttrs>("default", "default", "default", CUSTOMISED, TONE_CATEGORY_RINGTONE);
    EXPECT_NE(systemSoundManagerImpl_->AddCustomizedTone(dataShareHelper, toneAttrs), SUCCESS);
    toneAttrs->SetCategory(TONE_CATEGORY_TEXT_MESSAGE);
    EXPECT_NE(systemSoundManagerImpl_->AddCustomizedTone(dataShareHelper, toneAttrs), SUCCESS);
    toneAttrs->SetCategory(TONE_CATEGORY_NOTIFICATION);
    EXPECT_NE(systemSoundManagerImpl_->AddCustomizedTone(dataShareHelper, toneAttrs), SUCCESS);
    toneAttrs->SetCategory(TONE_CATEGORY_ALARM);
    EXPECT_NE(systemSoundManagerImpl_->AddCustomizedTone(dataShareHelper, toneAttrs), SUCCESS);
    toneAttrs->SetCategory(TONE_CATEGORY_DEFAULT);
    EXPECT_NE(systemSoundManagerImpl_->AddCustomizedTone(dataShareHelper, toneAttrs), SUCCESS);
}

/**
 * @tc.name  : AddCustomizedToneByFdAndOffset_TypeError_Test
 * @tc.number: 001
 * @tc.desc  : Test AddCustomizedToneByFdAndOffset when toneAttrs->GetCustomizedType() != CUSTOMISED
 */
HWTEST(SystemSoundManagerUnitTest, AddCustomizedToneByFdAndOffset_TypeError_Test, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<AbilityRuntime::Context> context_ = std::make_shared<ContextImpl>();
    std::shared_ptr<ToneAttrs> toneAttrs_ = std::make_shared<ToneAttrs>("default",
        "default", "default", PRE_INSTALLED, TONE_CATEGORY_RINGTONE);
    auto vec = systemSoundManager_->GetAlarmToneAttrList(context_);
    std::string uri = "";
    if (vec.size() > 0) {
        uri = vec[0]->GetUri();
    }
    int32_t fd = 1;
    int32_t offset = 0;
    int32_t length = 1024;
    toneAttrs_->SetTitle("06172");
    toneAttrs_->SetFileName("06172");
    EXPECT_EQ(
        systemSoundManager_->AddCustomizedToneByFdAndOffset(context_, toneAttrs_, fd, offset, length), "TYPEERROR");
    fd = -1;
    EXPECT_EQ(
        systemSoundManager_->AddCustomizedToneByFdAndOffset(context_, toneAttrs_, fd, offset, length), "TYPEERROR");
}

/**
 * @tc.name  : UpdateToneHapticsSettings_Success_WhenUpdateSuccess
 * @tc.number: UpdateToneHapticsSettings_Success_WhenUpdateSuccess_001
 * @tc.desc  : Test UpdateToneHapticsSettings when update success
 */
HWTEST(SystemSoundManagerUnitTest, UpdateToneHapticsSettings_Success_WhenUpdateSuccess_001, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    EXPECT_NE(systemSoundManagerImpl_, nullptr);
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    EXPECT_NE(dataShareHelper, nullptr);
    std::string toneUri = "toneUri";
    ToneHapticsType toneHapticsType = ToneHapticsType::CALL_SIM_CARD_0;
    ToneHapticsSettings settings;
    settings.hapticsUri = "hapticsUri";
    settings.mode = ToneHapticsMode::SYNC;
    int32_t result =
        systemSoundManagerImpl_->UpdateToneHapticsSettings(dataShareHelper, toneUri, toneHapticsType, settings);
    EXPECT_NE(result, SUCCESS);
}

/**
 * @tc.name  : GetDefaultNonSyncedHapticsUri_WhenTypeNotExist_ShouldReturnEmpty
 * @tc.number: SystemSoundManagerImplTest_001
 * @tc.desc  : Test GetDefaultNonSyncedHapticsUri when toneHapticsType not exist in map
 */
HWTEST(SystemSoundManagerUnitTest, GetDefaultNonSyncedHapticsUri_WhenTypeNotExist_ShouldReturnEmpty, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    EXPECT_NE(systemSoundManagerImpl_, nullptr);
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    EXPECT_NE(dataShareHelper, nullptr);

    // Arrange
    ToneHapticsType toneHapticsType = ToneHapticsType::CALL_SIM_CARD_0;

    // Act
    std::string result = systemSoundManagerImpl_->GetDefaultNonSyncedHapticsUri(dataShareHelper, toneHapticsType);
    toneHapticsType = ToneHapticsType::TEXT_MESSAGE_SIM_CARD_1;
    result = systemSoundManagerImpl_->GetDefaultNonSyncedHapticsUri(dataShareHelper, toneHapticsType);

    // Assert
    EXPECT_EQ(result, "");
}

/**
 * @tc.name  : GetDefaultNonSyncedHapticsUri_WhenDataShareHelperIsNull_ShouldReturnEmpty
 * @tc.number: GetDefaultNonSyncedHapticsUri_002
 * @tc.desc  : Test GetDefaultNonSyncedHapticsUri when dataShareHelper is null
 */
HWTEST(SystemSoundManagerUnitTest, GetDefaultNonSyncedHapticsUri_002, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    EXPECT_NE(systemSoundManagerImpl_, nullptr);
    // Arrange
    ToneHapticsType toneHapticsType = ToneHapticsType::CALL_SIM_CARD_1;

    // Act
    std::string result = systemSoundManagerImpl_->GetDefaultNonSyncedHapticsUri(nullptr, toneHapticsType);

    // Assert
    EXPECT_EQ(result, "");
}


/**
 * @tc.name  : GetDefaultNonSyncedHapticsUri_WhenTypeNotExist_ShouldReturnEmpty
 * @tc.number: GetDefaultNonSyncedHapticsUri_001
 * @tc.desc  : Test GetDefaultNonSyncedHapticsUri when toneHapticsType not exist in map
 */
HWTEST(SystemSoundManagerUnitTest, GetDefaultNonSyncedHapticsUri_001, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    EXPECT_NE(systemSoundManagerImpl_, nullptr);
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    EXPECT_NE(dataShareHelper, nullptr);
    // Arrange
    ToneHapticsType toneHapticsType = static_cast<ToneHapticsType>(100); // 100 is not in the map

    // Act
    std::string result = systemSoundManagerImpl_->GetDefaultNonSyncedHapticsUri(dataShareHelper, toneHapticsType);

    // Assert
    EXPECT_EQ(result, "");
}

/**
 * @tc.name  : GetDefaultNonSyncedHapticsUri_WhenDataShareHelperIsNull_ShouldReturnEmpty
 * @tc.number: GetDefaultNonSyncedHapticsUri_003
 * @tc.desc  : Test GetDefaultNonSyncedHapticsUri when dataShareHelper is null
 */
HWTEST(SystemSoundManagerUnitTest, GetDefaultNonSyncedHapticsUri_003, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    EXPECT_NE(systemSoundManagerImpl_, nullptr);
    // Arrange
    ToneHapticsType toneHapticsType = ToneHapticsType::CALL_SIM_CARD_1;

    // Act
    std::string result = systemSoundManagerImpl_->GetDefaultNonSyncedHapticsUri(nullptr, toneHapticsType);

    // Assert
    EXPECT_EQ(result, "");
}
} // namespace Media
} // namespace OHOS
