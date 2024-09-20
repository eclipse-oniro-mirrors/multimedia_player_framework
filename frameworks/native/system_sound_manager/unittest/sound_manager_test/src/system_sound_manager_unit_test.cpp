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
void SystemSoundManagerUnitTest::SetUpTestCase(void) {}
void SystemSoundManagerUnitTest::TearDownTestCase(void) {}
void SystemSoundManagerUnitTest::SetUp(void) {}
void SystemSoundManagerUnitTest::TearDown(void) {}

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
    systemSoundManager_->GetToneHapticsSettings(context_, HAPTICS_RINGTONE_TYPE_SIM_CARD_0, settings);
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
    systemSoundManager_->GetToneHapticsSettings(context_, HAPTICS_RINGTONE_TYPE_SIM_CARD_1, settings);
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
    systemSoundManager_->GetToneHapticsSettings(context_, HAPTICS_SYSTEM_TONE_TYPE_SIM_CARD_0, settings);
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
    systemSoundManager_->GetToneHapticsSettings(context_, HAPTICS_SYSTEM_TONE_TYPE_SIM_CARD_1, settings);
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
    int32_t result = systemSoundManager_->GetToneHapticsSettings(context_, HAPTICS_SYSTEM_TONE_TYPE_NOTIFICATION,
        settings);

    std::vector<std::shared_ptr<ToneHapticsAttrs>> toneHapticsAttrsArray;
    result = systemSoundManager_->GetToneHapticsList(context_, false, toneHapticsAttrsArray);
    if (result == 0 && toneHapticsAttrsArray.size() > 0) {
        settings.hapticsUri = toneHapticsAttrsArray[0]->GetUri();
        settings.mode = ToneHapticsMode::NON_SYNC;
        result = systemSoundManager_->SetToneHapticsSettings(context_, HAPTICS_SYSTEM_TONE_TYPE_NOTIFICATION, settings);
        EXPECT_EQ(result, 0);
        result = systemSoundManager_->GetToneHapticsSettings(context_, HAPTICS_SYSTEM_TONE_TYPE_NOTIFICATION, settings);
        EXPECT_EQ(result, 0);

        auto ringtoneAttrsArray_ = systemSoundManager_->GetSystemToneAttrList(context_, SYSTEM_TONE_TYPE_NOTIFICATION);
        EXPECT_GT(ringtoneAttrsArray_.size(), 1);
        std::string oldToneUri = systemSoundManager_->GetSystemToneUri(context_, SYSTEM_TONE_TYPE_NOTIFICATION);
        EXPECT_EQ(oldToneUri.empty(), false);
        int32_t index = oldToneUri != ringtoneAttrsArray_[0]->GetUri() ? 0 : 1;
        std::string newToneUri = ringtoneAttrsArray_[index]->GetUri();
        result = systemSoundManager_->SetSystemToneUri(context_, newToneUri, SYSTEM_TONE_TYPE_NOTIFICATION);
        EXPECT_EQ(result, 0);
        result = systemSoundManager_->GetToneHapticsSettings(context_, HAPTICS_SYSTEM_TONE_TYPE_NOTIFICATION, settings);
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
            ToneHapticsType::HAPTICS_SYSTEM_TONE_TYPE_NOTIFICATION, srcSetting);
        EXPECT_EQ(result, 0);

        ToneHapticsSettings dstSetting;
        result = systemSoundManager_->GetToneHapticsSettings(context_,
            ToneHapticsType::HAPTICS_SYSTEM_TONE_TYPE_NOTIFICATION, dstSetting);
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

    std::string hapticsUri = systemSoundManagerImpl_->GetHapticsUriByStyle("test", HapticsStyle::HAPTICS_STYLE_GENTLE);
    EXPECT_EQ(hapticsUri.empty(), true);

    std::vector<std::shared_ptr<ToneHapticsAttrs>> toneHapticsAttrsArray;
    int32_t result = systemSoundManagerImpl_->GetToneHapticsList(context_, false, toneHapticsAttrsArray);
    if (result == 0 && toneHapticsAttrsArray.size() > 0) {
        hapticsUri = systemSoundManagerImpl_->GetHapticsUriByStyle(toneHapticsAttrsArray[0]->GetUri(),
            HapticsStyle::HAPTICS_STYLE_GENTLE);
        EXPECT_EQ(hapticsUri.empty(), false);
    }
    EXPECT_NE(systemSoundManager_, nullptr);
}
} // namespace Media
} // namespace OHOS