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
#include "system_sound_manager_unit_next_test.h"
#include "mock_datashare_helper.h"
#include "mock_datashare_result_set.h"
#include "media_core.h"
#include "ringtone_db_const.h"
#include "ringtone_type.h"
#include <string>
#include <gmock/gmock.h>

using namespace OHOS::AbilityRuntime;
using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace Media {
const int ERROR = -1;
const int TYPEERROR = -2;
const int SUCCESS = 0;
const int32_t TONE_CATEGORY = -13;
const int32_t SYSPARA_SIZE = 128;
void SystemSoundManagerUnitNextTest::SetUpTestCase(void) {}
void SystemSoundManagerUnitNextTest::TearDownTestCase(void) {}
void SystemSoundManagerUnitNextTest::SetUp(void) {}
void SystemSoundManagerUnitNextTest::TearDown(void) {}

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
 * @tc.name  : IsValidRingtoneType
 * @tc.number: IsValidRingtoneType_001
 * @tc.desc  : Test IsValidRingtoneType when an invalid RingtoneType is passed
 */
HWTEST(SystemSoundManagerUnitNextTest, IsValidRingtoneType_001, TestSize.Level0)
{
    RingtoneType invalidType = static_cast<RingtoneType>(RINGTONE_TYPE_ESIM_CARD_1 + 1);
    bool result = IsValidRingtoneType(invalidType);
    EXPECT_FALSE(result);
}

/**
 * @tc.name  : IsValidRingtoneType_ESIM_CARD_0
 * @tc.number: IsValidRingtoneType_002
 * @tc.desc  : Test IsValidRingtoneType when RINGTONE_TYPE_ESIM_CARD_0 is passed (returns true)
 */
HWTEST(SystemSoundManagerUnitNextTest, IsValidRingtoneType_002, TestSize.Level0)
{
    bool result = IsValidRingtoneType(RINGTONE_TYPE_ESIM_CARD_0);
    EXPECT_TRUE(result);
}

/**
 * @tc.name  : IsValidRingtoneType_ESIM_CARD_1
 * @tc.number: IsValidRingtoneType_003
 * @tc.desc  : Test IsValidRingtoneType when RINGTONE_TYPE_ESIM_CARD_1 is passed (returns true)
 */
HWTEST(SystemSoundManagerUnitNextTest, IsValidRingtoneType_003, TestSize.Level0)
{
    bool result = IsValidRingtoneType(RINGTONE_TYPE_ESIM_CARD_1);
    EXPECT_TRUE(result);
}

/**
 * @tc.name  : IsValidRingtoneType_SIM_CARD_0
 * @tc.number: IsValidRingtoneType_004
 * @tc.desc  : Test IsValidRingtoneType when RINGTONE_TYPE_SIM_CARD_0 is passed (returns true)
 */
HWTEST(SystemSoundManagerUnitNextTest, IsValidRingtoneType_004, TestSize.Level0)
{
    bool result = IsValidRingtoneType(RINGTONE_TYPE_SIM_CARD_0);
    EXPECT_TRUE(result);
}

/**
 * @tc.name  : IsValidRingtoneType_SIM_CARD_1
 * @tc.number: IsValidRingtoneType_005
 * @tc.desc  : Test IsValidRingtoneType when RINGTONE_TYPE_SIM_CARD_1 is passed (returns true)
 */
HWTEST(SystemSoundManagerUnitNextTest, IsValidRingtoneType_005, TestSize.Level0)
{
    bool result = IsValidRingtoneType(RINGTONE_TYPE_SIM_CARD_1);
    EXPECT_TRUE(result);
}

/**
 * @tc.name  : IsValidSystemToneType
 * @tc.number: IsValidSystemToneType_001
 * @tc.desc  : Test IsValidSystemToneType when an invalid SystemToneType is passed
 */
HWTEST(SystemSoundManagerUnitNextTest, IsValidSystemToneType_001, TestSize.Level0)
{
    SystemToneType invalidType = static_cast<SystemToneType>(SYSTEM_TONE_TYPE_NOTIFICATION + 1);
    bool result = IsValidSystemToneType(invalidType);
    EXPECT_FALSE(result);
}

/**
 * @tc.name  : IsValidSystemToneType_ESIM_CARD_0
 * @tc.number: IsValidSystemToneType_002
 * @tc.desc  : Test IsValidSystemToneType when SYSTEM_TONE_TYPE_ESIM_CARD_0 is passed (returns true)
 */
HWTEST(SystemSoundManagerUnitNextTest, IsValidSystemToneType_002, TestSize.Level0)
{
    bool result = IsValidSystemToneType(SYSTEM_TONE_TYPE_ESIM_CARD_0);
    EXPECT_TRUE(result);
}

/**
 * @tc.name  : IsValidSystemToneType_ESIM_CARD_1
 * @tc.number: IsValidSystemToneType_003
 * @tc.desc  : Test IsValidSystemToneType when SYSTEM_TONE_TYPE_ESIM_CARD_1 is passed (returns true)
 */
HWTEST(SystemSoundManagerUnitNextTest, IsValidSystemToneType_003, TestSize.Level0)
{
    bool result = IsValidSystemToneType(SYSTEM_TONE_TYPE_ESIM_CARD_1);
    EXPECT_TRUE(result);
}

/**
 * @tc.name  : IsValidToneHapticsType_CALL_ESIM_CARD_0
 * @tc.number: IsValidToneHapticsType_002
 * @tc.desc  : Test IsValidToneHapticsType when CALL_ESIM_CARD_0 is passed (returns true)
 */
HWTEST(SystemSoundManagerUnitNextTest, IsValidToneHapticsType_002, TestSize.Level0)
{
    bool result = IsValidToneHapticsType(ToneHapticsType::CALL_ESIM_CARD_0);
    EXPECT_TRUE(result);
}

/**
 * @tc.name  : IsValidToneHapticsType_CALL_ESIM_CARD_1
 * @tc.number: IsValidToneHapticsType_003
 * @tc.desc  : Test IsValidToneHapticsType when CALL_ESIM_CARD_1 is passed (returns true)
 */
HWTEST(SystemSoundManagerUnitNextTest, IsValidToneHapticsType_003, TestSize.Level0)
{
    bool result = IsValidToneHapticsType(ToneHapticsType::CALL_ESIM_CARD_1);
    EXPECT_TRUE(result);
}

/**
 * @tc.name  : IsValidToneHapticsType_TEXT_MESSAGE_ESIM_CARD_0
 * @tc.number: IsValidToneHapticsType_004
 * @tc.desc  : Test IsValidToneHapticsType when TEXT_MESSAGE_ESIM_CARD_0 is passed (returns true)
 */
HWTEST(SystemSoundManagerUnitNextTest, IsValidToneHapticsType_004, TestSize.Level0)
{
    bool result = IsValidToneHapticsType(ToneHapticsType::TEXT_MESSAGE_ESIM_CARD_0);
    EXPECT_TRUE(result);
}

/**
 * @tc.name  : IsValidToneHapticsType_TEXT_MESSAGE_ESIM_CARD_1
 * @tc.number: IsValidToneHapticsType_005
 * @tc.desc  : Test IsValidToneHapticsType when TEXT_MESSAGE_ESIM_CARD_1 is passed (returns true)
 */
HWTEST(SystemSoundManagerUnitNextTest, IsValidToneHapticsType_005, TestSize.Level0)
{
    bool result = IsValidToneHapticsType(ToneHapticsType::TEXT_MESSAGE_ESIM_CARD_1);
    EXPECT_TRUE(result);
}

/**
 * @tc.name  : IsValidToneHapticsType_Invalid
 * @tc.number: IsValidToneHapticsType_006
 * @tc.desc  : Test IsValidToneHapticsType when invalid type is passed (returns false)
 */
HWTEST(SystemSoundManagerUnitNextTest, IsValidToneHapticsType_006, TestSize.Level0)
{
    ToneHapticsType invalidType = static_cast<ToneHapticsType>(999);
    bool result = IsValidToneHapticsType(invalidType);
    EXPECT_FALSE(result);
}

/**
 * @tc.name  : ReadDefaultToneHaptics
 * @tc.number: ReadDefaultToneHaptics_001
 * @tc.desc  : Test ReadDefaultToneHaptics when GetParameter returns empty string
 */
HWTEST(SystemSoundManagerUnitNextTest, ReadDefaultToneHaptics_001, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    systemSoundManagerImpl_->defaultToneHapticsUriMap_.clear();
    const char* paramName = "invalid_param";
    char paramValue[SYSPARA_SIZE] = {0};

    std::fill_n(paramValue, SYSPARA_SIZE, 0);
    ToneHapticsType toneHapticsType = CALL_SIM_CARD_0;
    systemSoundManagerImpl_->ReadDefaultToneHaptics(paramName, toneHapticsType);
    EXPECT_TRUE(systemSoundManagerImpl_->defaultToneHapticsUriMap_.empty());
}

/**
 * @tc.name  : ConvertToRingtoneType_CALL_ESIM_CARD_0
 * @tc.number: ConvertToRingtoneType_002
 * @tc.desc  : Test ConvertToRingtoneType when CALL_ESIM_CARD_0 is passed (returns RINGTONE_TYPE_ESIM_CARD_0)
 */
HWTEST(SystemSoundManagerUnitNextTest, ConvertToRingtoneType_002, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    RingtoneType ringtoneType;
    bool result = systemSoundManagerImpl_->ConvertToRingtoneType(ToneHapticsType::CALL_ESIM_CARD_0, ringtoneType);
    EXPECT_TRUE(result);
    EXPECT_EQ(ringtoneType, RINGTONE_TYPE_ESIM_CARD_0);
}

/**
 * @tc.name  : ConvertToRingtoneType_CALL_ESIM_CARD_1
 * @tc.number: ConvertToRingtoneType_003
 * @tc.desc  : Test ConvertToRingtoneType when CALL_ESIM_CARD_1 is passed (returns RINGTONE_TYPE_ESIM_CARD_1)
 */
HWTEST(SystemSoundManagerUnitNextTest, ConvertToRingtoneType_003, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    RingtoneType ringtoneType;
    bool result = systemSoundManagerImpl_->ConvertToRingtoneType(ToneHapticsType::CALL_ESIM_CARD_1, ringtoneType);
    EXPECT_TRUE(result);
    EXPECT_EQ(ringtoneType, RINGTONE_TYPE_ESIM_CARD_1);
}

/**
 * @tc.name  : ConvertToRingtoneType_Invalid
 * @tc.number: ConvertToRingtoneType_004
 * @tc.desc  : Test ConvertToRingtoneType when invalid type is passed (returns false)
 */
HWTEST(SystemSoundManagerUnitNextTest, ConvertToRingtoneType_004, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    RingtoneType ringtoneType;
    bool result = systemSoundManagerImpl_->ConvertToRingtoneType(static_cast<ToneHapticsType>(999), ringtoneType);
    EXPECT_FALSE(result);
}

/**
 * @tc.name  : ConvertToSystemToneType_Default
 * @tc.number: ConvertToSystemToneType_001
 * @tc.desc  : Test ConvertToSystemToneType when entering default branch
 */
HWTEST(SystemSoundManagerUnitNextTest, ConvertToSystemToneType_001, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    ToneHapticsType toneHapticsType = ToneHapticsType::CALL_SIM_CARD_0;
    SystemToneType systemToneType;
    bool result = systemSoundManagerImpl_->ConvertToSystemToneType(toneHapticsType, systemToneType);
    EXPECT_FALSE(result);
}

/**
 * @tc.name  : ConvertToSystemToneType_TEXT_MESSAGE_ESIM_CARD_0
 * @tc.number: ConvertToSystemToneType_002
 * @tc.desc  : Test ConvertToSystemToneType when TEXT_MESSAGE_ESIM_CARD_0 is passed
 */
HWTEST(SystemSoundManagerUnitNextTest, ConvertToSystemToneType_002, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    SystemToneType systemToneType;
    bool result = systemSoundManagerImpl_->ConvertToSystemToneType(
        ToneHapticsType::TEXT_MESSAGE_ESIM_CARD_0, systemToneType);
    EXPECT_TRUE(result);
    EXPECT_EQ(systemToneType, SYSTEM_TONE_TYPE_ESIM_CARD_0);
}

/**
 * @tc.name  : ConvertToSystemToneType_TEXT_MESSAGE_ESIM_CARD_1
 * @tc.number: ConvertToSystemToneType_003
 * @tc.desc  : Test ConvertToSystemToneType when TEXT_MESSAGE_ESIM_CARD_1 is passed
 */
HWTEST(SystemSoundManagerUnitNextTest, ConvertToSystemToneType_003, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    SystemToneType systemToneType;
    bool result = systemSoundManagerImpl_->ConvertToSystemToneType(
        ToneHapticsType::TEXT_MESSAGE_ESIM_CARD_1, systemToneType);
    EXPECT_TRUE(result);
    EXPECT_EQ(systemToneType, SYSTEM_TONE_TYPE_ESIM_CARD_1);
}

/**
 * @tc.name  : ConvertToSystemToneType_NOTIFICATION
 * @tc.number: ConvertToSystemToneType_004
 * @tc.desc  : Test ConvertToSystemToneType when NOTIFICATION is passed
 */
HWTEST(SystemSoundManagerUnitNextTest, ConvertToSystemToneType_004, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    SystemToneType systemToneType;
    bool result = systemSoundManagerImpl_->ConvertToSystemToneType(ToneHapticsType::NOTIFICATION, systemToneType);
    EXPECT_TRUE(result);
    EXPECT_EQ(systemToneType, SYSTEM_TONE_TYPE_NOTIFICATION);
}

/**
 * @tc.name  : IntToToneHapticsMode_None
 * @tc.number: IntToToneHapticsMode_001
 * @tc.desc  : Test IntToToneHapticsMode when value is NONE
 */
HWTEST(SystemSoundManagerUnitNextTest, IntToToneHapticsMode_001, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    int32_t value = NONE;
    ToneHapticsMode result = systemSoundManagerImpl_->IntToToneHapticsMode(value);
    EXPECT_EQ(result, NONE);
}

/**
 * @tc.name  : IntToToneHapticsMode_Sync
 * @tc.number: IntToToneHapticsMode_002
 * @tc.desc  : Test IntToToneHapticsMode when value is SYNC
 */
HWTEST(SystemSoundManagerUnitNextTest, IntToToneHapticsMode_002, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    int32_t value = SYNC;
    ToneHapticsMode result = systemSoundManagerImpl_->IntToToneHapticsMode(value);
    EXPECT_EQ(result, SYNC);
}

/**
 * @tc.name  : IntToToneHapticsMode_Default
 * @tc.number: IntToToneHapticsMode_003
 * @tc.desc  : Test IntToToneHapticsMode when entering default branch
 */
HWTEST(SystemSoundManagerUnitNextTest, IntToToneHapticsMode_003, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    int32_t value = 999;
    ToneHapticsMode result = systemSoundManagerImpl_->IntToToneHapticsMode(value);
    EXPECT_EQ(result, NONE);
}

/**
 * @tc.name  : SetSystemToneUri_NoSystemSound
 * @tc.number: SetSystemToneUri_001
 * @tc.desc  : Test SetSystemToneUri when uri is NO_SYSTEM_SOUND
 */
HWTEST(SystemSoundManagerUnitNextTest, SetSystemToneUri_001, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    std::shared_ptr<AbilityRuntime::Context> context = std::make_shared<ContextImpl>();
    ASSERT_NE(context, nullptr);

    std::string uri = NO_SYSTEM_SOUND;
    SystemToneType systemToneType = SYSTEM_TONE_TYPE_NOTIFICATION;
    int32_t result = systemSoundManagerImpl_->SetSystemToneUri(context, uri, systemToneType);
    EXPECT_EQ(result, SUCCESS);
}

/**
 * @tc.name  : SetSystemToneUri_ESIM_NoSystemSound
 * @tc.number: SetSystemToneUri_002
 * @tc.desc  : Test SetSystemToneUri with NO_SYSTEM_SOUND for eSIM card types
 */
HWTEST(SystemSoundManagerUnitNextTest, SetSystemToneUri_002, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    std::shared_ptr<AbilityRuntime::Context> context = std::make_shared<ContextImpl>();
    ASSERT_NE(context, nullptr);

    std::string uri = NO_SYSTEM_SOUND;
    int32_t result = systemSoundManagerImpl_->SetSystemToneUri(context, uri, SYSTEM_TONE_TYPE_ESIM_CARD_0);
    EXPECT_EQ(result, SUCCESS);
    result = systemSoundManagerImpl_->SetSystemToneUri(context, uri, SYSTEM_TONE_TYPE_ESIM_CARD_1);
    EXPECT_EQ(result, SUCCESS);
}

/**
 * @tc.name  : GetSpecificRingTonePlayer_NotEmptyUri
 * @tc.number: GetSpecificRingTonePlayer_001
 * @tc.desc  : Test GetSpecificRingTonePlayer when ringtoneUri is not empty
 */
HWTEST(SystemSoundManagerUnitNextTest, GetSpecificRingTonePlayer_001, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    std::shared_ptr<AbilityRuntime::Context> context = std::make_shared<ContextImpl>();
    ASSERT_NE(context, nullptr);
    RingtoneType ringtoneType = RINGTONE_TYPE_SIM_CARD_0;
    std::string ringtoneUri = "valid_uri";
    std::shared_ptr<RingtonePlayer> result = systemSoundManagerImpl_->GetSpecificRingTonePlayer(context,
        ringtoneType, ringtoneUri);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name  : GetSpecificRingTonePlayer_WithStreamUsage
 * @tc.number: GetSpecificRingTonePlayer_002
 * @tc.desc  : Test GetSpecificRingTonePlayer with custom StreamUsage
 */
HWTEST(SystemSoundManagerUnitNextTest, GetSpecificRingTonePlayer_002, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    std::shared_ptr<AbilityRuntime::Context> context = std::make_shared<ContextImpl>();
    RingtoneType ringtoneType = RINGTONE_TYPE_SIM_CARD_0;
    std::string ringtoneUri = "valid_uri";
    AudioStandard::StreamUsage usage = AudioStandard::StreamUsage::STREAM_USAGE_NOTIFICATION;
    std::shared_ptr<RingtonePlayer> result = systemSoundManagerImpl_->GetSpecificRingTonePlayer(context,
        ringtoneType, ringtoneUri, usage);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name  : SetRingtoneUri_NoRingSound
 * @tc.number: SetRingtoneUri_001
 * @tc.desc  : Test SetRingtoneUri when uri is NO_RING_SOUND
 */
HWTEST(SystemSoundManagerUnitNextTest, SetRingtoneUri_001, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    std::shared_ptr<AbilityRuntime::Context> context = std::make_shared<ContextImpl>();
    ASSERT_NE(context, nullptr);

    std::string uri = NO_RING_SOUND;
    RingtoneType ringtoneType = RINGTONE_TYPE_SIM_CARD_0;
    int32_t result = systemSoundManagerImpl_->SetRingtoneUri(context, uri, ringtoneType);
    EXPECT_EQ(result, SUCCESS);
}

/**
 * @tc.name  : SetRingtoneUri_ESIM_NoRingSound
 * @tc.number: SetRingtoneUri_002
 * @tc.desc  : Test SetRingtoneUri with NO_RING_SOUND for eSIM card types
 */
HWTEST(SystemSoundManagerUnitNextTest, SetRingtoneUri_002, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    std::shared_ptr<AbilityRuntime::Context> context = std::make_shared<ContextImpl>();
    ASSERT_NE(context, nullptr);

    std::string uri = NO_RING_SOUND;
    int32_t result = systemSoundManagerImpl_->SetRingtoneUri(context, uri, RINGTONE_TYPE_ESIM_CARD_0);
    EXPECT_EQ(result, SUCCESS);
    result = systemSoundManagerImpl_->SetRingtoneUri(context, uri, RINGTONE_TYPE_ESIM_CARD_1);
    EXPECT_EQ(result, SUCCESS);
}

/**
 * @tc.name  : GetSystemToneUri_NotInitialized
 * @tc.number: GetSystemToneAttrs_001
 * @tc.desc  : Test GetSystemToneUri when databaseTool is not initialized
 */
HWTEST(SystemSoundManagerUnitNextTest, GetSystemToneAttrs_001, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    DatabaseTool databaseTool;
    databaseTool.isInitialized = false;
    databaseTool.dataShareHelper = nullptr;
    SystemToneType systemToneType = SYSTEM_TONE_TYPE_SIM_CARD_0;
    ToneAttrs toneAttrs_ = systemSoundManagerImpl_->GetSystemToneAttrs(databaseTool, systemToneType);
    std::string result = toneAttrs_.GetUri();
    EXPECT_EQ(result, "");
}

/**
 * @tc.name  : GetSystemToneUri_DataShareHelperNull
 * @tc.number: GetSystemToneAttrs_002
 * @tc.desc  : Test GetSystemToneUri when dataShareHelper is null
 */
HWTEST(SystemSoundManagerUnitNextTest, GetSystemToneAttrs_002, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    DatabaseTool databaseTool;
    databaseTool.isInitialized = true;
    databaseTool.dataShareHelper = nullptr;
    SystemToneType systemToneType = SYSTEM_TONE_TYPE_SIM_CARD_0;
    ToneAttrs toneAttrs_ = systemSoundManagerImpl_->GetSystemToneAttrs(databaseTool, systemToneType);
    std::string result = toneAttrs_.GetUri();
    EXPECT_EQ(result, "");
}

/**
 * @tc.name  : AddCustomizedToneByExternalUri_ExternalUriWithFdHead
 * @tc.number: AddCustomizedToneByExternalUri_001
 * @tc.desc  : Test AddCustomizedToneByExternalUri when externalUri contains fdHead
 */
HWTEST(SystemSoundManagerUnitNextTest, AddCustomizedToneByExternalUri_001, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    std::shared_ptr<AbilityRuntime::Context> context = std::make_shared<ContextImpl>();
    ASSERT_NE(context, nullptr);

    std::shared_ptr<ToneAttrs> toneAttrs = std::make_shared<ToneAttrs>(
        "test_tone", "test_file", "test_uri", ToneCustomizedType::CUSTOMISED, 0);
    toneAttrs->SetTitle("test_tone");
    toneAttrs->SetCategory(0);
    std::string externalUri = "fd://123";
    std::string result = systemSoundManagerImpl_->AddCustomizedToneByExternalUri(context, toneAttrs, externalUri);
    EXPECT_NE(result, "vs");
}

/**
 * @tc.name  : GetCustomizedTone_WithFileType
 * @tc.number: GetCustomizedTone_001
 * @tc.desc  : Test GetCustomizedTone when file name contains a file type in RINGTONETYPE
 */
HWTEST(SystemSoundManagerUnitNextTest, GetCustomizedTone_001, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    std::shared_ptr<ToneAttrs> toneAttrs = std::make_shared<ToneAttrs>(
        "test_tone", "test_file.mp3", "test_uri", ToneCustomizedType::CUSTOMISED, 0);

    systemSoundManagerImpl_->displayName_ = "";
    systemSoundManagerImpl_->mimeType_ = "";
    systemSoundManagerImpl_->GetCustomizedTone(toneAttrs);
    EXPECT_EQ(systemSoundManagerImpl_->mimeType_, "mp3");
    EXPECT_EQ(systemSoundManagerImpl_->displayName_, "test_file.mp3");
}

/**
 * @tc.name  : GetCustomizedTone_WithoutFileType
 * @tc.number: GetCustomizedTone_002
 * @tc.desc  : Test GetCustomizedTone when file name does not contain any file type in RINGTONETYPE
 */
HWTEST(SystemSoundManagerUnitNextTest, GetCustomizedTone_002, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    std::shared_ptr<ToneAttrs> toneAttrs = std::make_shared<ToneAttrs>(
        "test_tone", "test_file", "test_uri", ToneCustomizedType::CUSTOMISED, 0);

    systemSoundManagerImpl_->displayName_ = "";
    systemSoundManagerImpl_->mimeType_ = "";
    systemSoundManagerImpl_->GetCustomizedTone(toneAttrs);
    EXPECT_EQ(systemSoundManagerImpl_->mimeType_, "ogg");
    EXPECT_EQ(systemSoundManagerImpl_->displayName_, "test_file.ogg");
}

/**
 * @tc.name  : AddCustomizedTone_ContactsCategory
 * @tc.number: AddCustomizedTone_001
 * @tc.desc  : Test AddCustomizedTone when entering TONE_CATEGORY_CONTACTS case
 */
HWTEST(SystemSoundManagerUnitNextTest, AddCustomizedTone_001, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(dataShareHelper, nullptr);

    std::shared_ptr<ToneAttrs> toneAttrs = std::make_shared<ToneAttrs>(
        "test_tone", "test_file", "test_uri", ToneCustomizedType::CUSTOMISED, TONE_CATEGORY_CONTACTS);
    int32_t length = 0;
    int32_t result = systemSoundManagerImpl_->AddCustomizedTone(dataShareHelper, toneAttrs, length);
    EXPECT_EQ(result, TONE_CATEGORY);
}

/**
 * @tc.name  : AddCustomizedTone_DefaultCategory
 * @tc.number: AddCustomizedTone_002
 * @tc.desc  : Test AddCustomizedTone when entering default case
 */
HWTEST(SystemSoundManagerUnitNextTest, AddCustomizedTone_002, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(dataShareHelper, nullptr);

    std::shared_ptr<ToneAttrs> toneAttrs = std::make_shared<ToneAttrs>(
        "test_tone", "test_file", "test_uri", ToneCustomizedType::CUSTOMISED, TONE_CATEGORY_INVALID);
    int32_t length = 0;
    int32_t result = systemSoundManagerImpl_->AddCustomizedTone(dataShareHelper, toneAttrs, length);
    EXPECT_EQ(result, TONE_CATEGORY);
}

/**
 * @tc.name  : AddCustomizedToneByFdAndOffset_LseekError
 * @tc.number: AddCustomizedToneByFdAndOffset_001
 * @tc.desc  : Test AddCustomizedToneByFdAndOffset when lseekResult is -1
 */
HWTEST(SystemSoundManagerUnitNextTest, AddCustomizedToneByFdAndOffset_001, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    std::shared_ptr<AbilityRuntime::Context> context = std::make_shared<ContextImpl>();
    ASSERT_NE(context, nullptr);
    std::shared_ptr<ToneAttrs> toneAttrs = std::make_shared<ToneAttrs>(
        "test_tone", "test_file", "test_uri", ToneCustomizedType::CUSTOMISED, TONE_CATEGORY_RINGTONE);

    int32_t fd = 123;
    int32_t offset = -1;
    int32_t length = 1024;
    ParamsForAddCustomizedTone paramsForAddCustomizedTone = { "", fd, length, offset, false };
    std::string result = systemSoundManagerImpl_->AddCustomizedToneByFdAndOffset(context,
        toneAttrs, paramsForAddCustomizedTone);
    EXPECT_EQ(result, "");
}

/**
 * @tc.name  : GetCurrentToneUri_NotInitialized
 * @tc.number: GetCurrentToneUri_001
 * @tc.desc  : Test GetCurrentToneUri when databaseTool is not initialized
 */
HWTEST(SystemSoundManagerUnitNextTest, GetCurrentToneUri_001, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    DatabaseTool databaseTool;
    databaseTool.isInitialized = false;
    databaseTool.dataShareHelper = nullptr;
    ToneHapticsType toneHapticsType = ToneHapticsType::CALL_SIM_CARD_0;
    std::string result = systemSoundManagerImpl_->GetCurrentToneUri(databaseTool, toneHapticsType);
    EXPECT_EQ(result, "");
}

/**
 * @tc.name  : GetCurrentToneUri_DataShareHelperNull
 * @tc.number: GetCurrentToneUri_002
 * @tc.desc  : Test GetCurrentToneUri when dataShareHelper is null
 */
HWTEST(SystemSoundManagerUnitNextTest, GetCurrentToneUri_002, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    DatabaseTool databaseTool;
    databaseTool.isInitialized = true;
    databaseTool.dataShareHelper = nullptr;
    ToneHapticsType toneHapticsType = ToneHapticsType::CALL_SIM_CARD_0;
    std::string result = systemSoundManagerImpl_->GetCurrentToneUri(databaseTool, toneHapticsType);
    EXPECT_EQ(result, "");
}

/**
 * @tc.name  : GetCurrentToneUri_InvalidType
 * @tc.number: GetCurrentToneUri_003
 * @tc.desc  : Test GetCurrentToneUri when entering the else branch
 */
HWTEST(SystemSoundManagerUnitNextTest, GetCurrentToneUri_003, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    DatabaseTool databaseTool;
    databaseTool.isInitialized = true;
    databaseTool.dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(databaseTool.dataShareHelper, nullptr);
    ToneHapticsType toneHapticsType = ToneHapticsType::NOTIFICATION;
    std::string result = systemSoundManagerImpl_->GetCurrentToneUri(databaseTool, toneHapticsType);
    EXPECT_EQ(result,  "no_system_sound");
}

/**
 * @tc.name  : GetSimcardSettingAssetByToneHapticsType_IsProxy
 * @tc.number: GetSimcardSettingAssetByToneHapticsType_001
 * @tc.desc  : Test GetSimcardSettingAssetByToneHapticsType when isProxy is true
 */
HWTEST(SystemSoundManagerUnitNextTest, GetSimcardSettingAssetByToneHapticsType_001, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    DatabaseTool databaseTool;
    databaseTool.isInitialized = true;
    databaseTool.isProxy = true;
    databaseTool.dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(databaseTool.dataShareHelper, nullptr);
    ToneHapticsType toneHapticsType = ToneHapticsType::CALL_SIM_CARD_0;
    std::unique_ptr<SimcardSettingAsset> result =
        systemSoundManagerImpl_->GetSimcardSettingAssetByToneHapticsType(databaseTool, toneHapticsType);
    ASSERT_NE(result, nullptr);
}

/**
 * @tc.name  : GetFirstNonSyncedHapticsUri_EnterIf
 * @tc.number: GetFirstNonSyncedHapticsUri_001
 * @tc.desc  : Test GetFirstNonSyncedHapticsUri when entering the if branch
 */
HWTEST(SystemSoundManagerUnitNextTest, GetFirstNonSyncedHapticsUri_001, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);
    std::string result = systemSoundManagerImpl_->GetFirstNonSyncedHapticsUri();
    EXPECT_EQ(result, "");
}

/**
 * @tc.name  : QueryToneAttrsByType_NotInitialized
 * @tc.number: QueryToneAttrsByType_001
 * @tc.desc  : Test QueryToneAttrsByType when databaseTool is not initialized
 */
HWTEST(SystemSoundManagerUnitNextTest, QueryToneAttrsByType_001, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    DatabaseTool databaseTool;
    databaseTool.isInitialized = false;
    databaseTool.dataShareHelper = nullptr;

    ToneAttrs result = systemSoundManagerImpl_->QueryToneAttrsByType(databaseTool,
        RINGTONE_COLUMN_RING_TONE_TYPE, 1, SOURCE_TYPE_CUSTOMISED, TONE_CATEGORY_RINGTONE);
    EXPECT_EQ(result.GetUri(), "");
    EXPECT_EQ(result.GetCategory(), TONE_CATEGORY_RINGTONE);
}

/**
 * @tc.name  : QueryToneAttrsByType_DataShareHelperNull
 * @tc.number: QueryToneAttrsByType_002
 * @tc.desc  : Test QueryToneAttrsByType when dataShareHelper is null
 */
HWTEST(SystemSoundManagerUnitNextTest, QueryToneAttrsByType_002, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    DatabaseTool databaseTool;
    databaseTool.isInitialized = true;
    databaseTool.dataShareHelper = nullptr;

    ToneAttrs result = systemSoundManagerImpl_->QueryToneAttrsByType(databaseTool,
        RINGTONE_COLUMN_RING_TONE_TYPE, 1, SOURCE_TYPE_CUSTOMISED, TONE_CATEGORY_RINGTONE);
    EXPECT_EQ(result.GetUri(), "");
}

/**
 * @tc.name  : QueryToneAttrsByType_InvalidTypeColumnName
 * @tc.number: QueryToneAttrsByType_003
 * @tc.desc  : Test QueryToneAttrsByType when typeColumnName is invalid (returns default toneAttrs)
 */
HWTEST(SystemSoundManagerUnitNextTest, QueryToneAttrsByType_003, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    DatabaseTool databaseTool;
    databaseTool.isInitialized = true;
    databaseTool.isProxy = false;
    databaseTool.dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(databaseTool.dataShareHelper, nullptr);

    ToneAttrs result = systemSoundManagerImpl_->QueryToneAttrsByType(databaseTool,
        "invalid_column_name", 1, SOURCE_TYPE_CUSTOMISED, TONE_CATEGORY_RINGTONE);
    EXPECT_EQ(result.GetUri(), "");
}

/**
 * @tc.name  : QueryToneAttrsByType_RingtoneType_IsProxy
 * @tc.number: QueryToneAttrsByType_004
 * @tc.desc  : Test QueryToneAttrsByType with RINGTONE_COLUMN_RING_TONE_TYPE and isProxy=true
 */
HWTEST(SystemSoundManagerUnitNextTest, QueryToneAttrsByType_004, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    DatabaseTool databaseTool;
    databaseTool.isInitialized = true;
    databaseTool.isProxy = true;
    databaseTool.dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(databaseTool.dataShareHelper, nullptr);

    int32_t targetToneType = 1 << (RINGTONE_TYPE_SIM_CARD_0 - RINGTONE_TYPE_SIM_CARD_0);
    ToneAttrs result = systemSoundManagerImpl_->QueryToneAttrsByType(databaseTool,
        RINGTONE_COLUMN_RING_TONE_TYPE, targetToneType, SOURCE_TYPE_CUSTOMISED, TONE_CATEGORY_RINGTONE);
    EXPECT_EQ(result.GetCategory(), TONE_CATEGORY_RINGTONE);
}

/**
 * @tc.name  : QueryToneAttrsByType_ShotToneType
 * @tc.number: QueryToneAttrsByType_005
 * @tc.desc  : Test QueryToneAttrsByType with RINGTONE_COLUMN_SHOT_TONE_TYPE and isProxy=true
 */
HWTEST(SystemSoundManagerUnitNextTest, QueryToneAttrsByType_005, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    DatabaseTool databaseTool;
    databaseTool.isInitialized = true;
    databaseTool.isProxy = true;
    databaseTool.dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(databaseTool.dataShareHelper, nullptr);

    int32_t targetToneType = 1 << (SYSTEM_TONE_TYPE_SIM_CARD_0 - SYSTEM_TONE_TYPE_SIM_CARD_0);
    ToneAttrs result = systemSoundManagerImpl_->QueryToneAttrsByType(databaseTool,
        RINGTONE_COLUMN_SHOT_TONE_TYPE, targetToneType, SOURCE_TYPE_CUSTOMISED, TONE_CATEGORY_TEXT_MESSAGE);
    EXPECT_EQ(result.GetCategory(), TONE_CATEGORY_TEXT_MESSAGE);
}

/**
 * @tc.name  : QueryToneAttrsByType_ESIM_Ringtone
 * @tc.number: QueryToneAttrsByType_006
 * @tc.desc  : Test QueryToneAttrsByType with eSIM ringtone bitmask target
 */
HWTEST(SystemSoundManagerUnitNextTest, QueryToneAttrsByType_006, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    DatabaseTool databaseTool;
    databaseTool.isInitialized = true;
    databaseTool.isProxy = true;
    databaseTool.dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(databaseTool.dataShareHelper, nullptr);

    int32_t esim0Target = 1 << (RINGTONE_TYPE_ESIM_CARD_0 - RINGTONE_TYPE_SIM_CARD_0);
    ToneAttrs result = systemSoundManagerImpl_->QueryToneAttrsByType(databaseTool,
        RINGTONE_COLUMN_RING_TONE_TYPE, esim0Target, SOURCE_TYPE_CUSTOMISED, TONE_CATEGORY_RINGTONE);
    EXPECT_EQ(result.GetCategory(), TONE_CATEGORY_RINGTONE);
}

/**
 * @tc.name  : QueryNotificationToneAttrs_NotInitialized
 * @tc.number: QueryNotificationToneAttrs_001
 * @tc.desc  : Test QueryNotificationToneAttrs when databaseTool is not initialized
 */
HWTEST(SystemSoundManagerUnitNextTest, QueryNotificationToneAttrs_001, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    DatabaseTool databaseTool;
    databaseTool.isInitialized = false;
    databaseTool.dataShareHelper = nullptr;

    ToneAttrs result = systemSoundManagerImpl_->QueryNotificationToneAttrs(databaseTool,
        RINGTONE_COLUMN_NOTIFICATION_TONE_TYPE, to_string(NOTIFICATION_TONE_TYPE), SOURCE_TYPE_CUSTOMISED);
    EXPECT_EQ(result.GetUri(), "");
    EXPECT_EQ(result.GetCategory(), TONE_CATEGORY_NOTIFICATION);
}

/**
 * @tc.name  : QueryNotificationToneAttrs_InvalidTypeColumnName
 * @tc.number: QueryNotificationToneAttrs_002
 * @tc.desc  : Test QueryNotificationToneAttrs when typeColumnName is invalid
 */
HWTEST(SystemSoundManagerUnitNextTest, QueryNotificationToneAttrs_002, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    DatabaseTool databaseTool;
    databaseTool.isInitialized = true;
    databaseTool.dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(databaseTool.dataShareHelper, nullptr);

    ToneAttrs result = systemSoundManagerImpl_->QueryNotificationToneAttrs(databaseTool,
        RINGTONE_COLUMN_RING_TONE_TYPE, to_string(NOTIFICATION_TONE_TYPE), SOURCE_TYPE_CUSTOMISED);
    EXPECT_EQ(result.GetUri(), "");
}

/**
 * @tc.name  : QueryNotificationToneAttrs_IsProxy
 * @tc.number: QueryNotificationToneAttrs_003
 * @tc.desc  : Test QueryNotificationToneAttrs with isProxy=true and valid column name
 */
HWTEST(SystemSoundManagerUnitNextTest, QueryNotificationToneAttrs_003, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    DatabaseTool databaseTool;
    databaseTool.isInitialized = true;
    databaseTool.isProxy = true;
    databaseTool.dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(databaseTool.dataShareHelper, nullptr);

    ToneAttrs result = systemSoundManagerImpl_->QueryNotificationToneAttrs(databaseTool,
        RINGTONE_COLUMN_NOTIFICATION_TONE_TYPE, to_string(NOTIFICATION_TONE_TYPE), SOURCE_TYPE_CUSTOMISED);
    EXPECT_EQ(result.GetCategory(), TONE_CATEGORY_NOTIFICATION);
}

/**
 * @tc.name  : ClearBitFromToneTypeColumn_NullResults
 * @tc.number: ClearBitFromToneTypeColumn_001
 * @tc.desc  : Test ClearBitFromToneTypeColumn when query returns null results
 */
HWTEST(SystemSoundManagerUnitNextTest, ClearBitFromToneTypeColumn_001, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    auto dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(dataShareHelper, nullptr);

    int32_t targetToneType = 1 << (RINGTONE_TYPE_SIM_CARD_0 - RINGTONE_TYPE_SIM_CARD_0);
    int32_t result = systemSoundManagerImpl_->ClearBitFromToneTypeColumn(dataShareHelper,
        RINGTONE_COLUMN_RING_TONE_TYPE, RINGTONE_COLUMN_RING_TONE_SOURCE_TYPE,
        targetToneType, SOURCE_TYPE_CUSTOMISED);
    EXPECT_GE(result, 0);
}

/**
 * @tc.name  : ClearBitFromToneTypeColumn_ShotToneColumn
 * @tc.number: ClearBitFromToneTypeColumn_002
 * @tc.desc  : Test ClearBitFromToneTypeColumn with shot tone type column
 */
HWTEST(SystemSoundManagerUnitNextTest, ClearBitFromToneTypeColumn_002, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    auto dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(dataShareHelper, nullptr);

    int32_t targetToneType = 1 << (SYSTEM_TONE_TYPE_SIM_CARD_0 - SYSTEM_TONE_TYPE_SIM_CARD_0);
    int32_t result = systemSoundManagerImpl_->ClearBitFromToneTypeColumn(dataShareHelper,
        RINGTONE_COLUMN_SHOT_TONE_TYPE, RINGTONE_COLUMN_SHOT_TONE_SOURCE_TYPE,
        targetToneType, SOURCE_TYPE_CUSTOMISED);
    EXPECT_GE(result, 0);
}

/**
 * @tc.name  : ClearBitFromToneTypeColumn_ESIM
 * @tc.number: ClearBitFromToneTypeColumn_003
 * @tc.desc  : Test ClearBitFromToneTypeColumn with eSIM target bitmask
 */
HWTEST(SystemSoundManagerUnitNextTest, ClearBitFromToneTypeColumn_003, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    auto dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(dataShareHelper, nullptr);

    int32_t esim0Target = 1 << (RINGTONE_TYPE_ESIM_CARD_0 - RINGTONE_TYPE_SIM_CARD_0);
    int32_t result = systemSoundManagerImpl_->ClearBitFromToneTypeColumn(dataShareHelper,
        RINGTONE_COLUMN_RING_TONE_TYPE, RINGTONE_COLUMN_RING_TONE_SOURCE_TYPE,
        esim0Target, SOURCE_TYPE_CUSTOMISED);
    EXPECT_GE(result, 0);
}

/**
 * @tc.name  : ClearNotificationToneType_Basic
 * @tc.number: ClearNotificationToneType_001
 * @tc.desc  : Test ClearNotificationToneType with DataShareHelper
 */
HWTEST(SystemSoundManagerUnitNextTest, ClearNotificationToneType_001, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    auto dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(dataShareHelper, nullptr);

    int32_t result = systemSoundManagerImpl_->ClearNotificationToneType(dataShareHelper, SOURCE_TYPE_CUSTOMISED);
    EXPECT_GE(result, 0);
}

/**
 * @tc.name  : UpdateToneTypeUri_SIMCard0_TargetBit1
 * @tc.number: UpdateToneTypeUri_001
 * @tc.desc  : Test UpdateToneTypeUri with new params structure - SIM_CARD_0 target
 */
HWTEST(SystemSoundManagerUnitNextTest, UpdateToneTypeUri_001, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    auto dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(dataShareHelper, nullptr);

    UpdateToneTypeParams params = {
        1,
        RINGTONE_COLUMN_RING_TONE_TYPE,
        RINGTONE_COLUMN_RING_TONE_SOURCE_TYPE,
        1 << (RINGTONE_TYPE_SIM_CARD_0 - RINGTONE_TYPE_SIM_CARD_0),
        1
    };

    int32_t result = systemSoundManagerImpl_->UpdateToneTypeUri(dataShareHelper, params);
    EXPECT_GE(result, 0);
}

/**
 * @tc.name  : UpdateToneTypeUri_SIMCard1_TargetBit2
 * @tc.number: UpdateToneTypeUri_002
 * @tc.desc  : Test UpdateToneTypeUri with SIM_CARD_1 target (bit=2)
 */
HWTEST(SystemSoundManagerUnitNextTest, UpdateToneTypeUri_002, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    auto dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(dataShareHelper, nullptr);

    UpdateToneTypeParams params = {
        1,
        RINGTONE_COLUMN_RING_TONE_TYPE,
        RINGTONE_COLUMN_RING_TONE_SOURCE_TYPE,
        1 << (RINGTONE_TYPE_SIM_CARD_1 - RINGTONE_TYPE_SIM_CARD_0),
        2
    };

    int32_t result = systemSoundManagerImpl_->UpdateToneTypeUri(dataShareHelper, params);
    EXPECT_GE(result, 0);
}

/**
 * @tc.name  : UpdateToneTypeUri_ESIMCard0_TargetBit4
 * @tc.number: UpdateToneTypeUri_003
 * @tc.desc  : Test UpdateToneTypeUri with ESIM_CARD_0 target (bit=4)
 */
HWTEST(SystemSoundManagerUnitNextTest, UpdateToneTypeUri_003, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    auto dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(dataShareHelper, nullptr);

    UpdateToneTypeParams params = {
        1,
        RINGTONE_COLUMN_RING_TONE_TYPE,
        RINGTONE_COLUMN_RING_TONE_SOURCE_TYPE,
        1 << (RINGTONE_TYPE_ESIM_CARD_0 - RINGTONE_TYPE_SIM_CARD_0),
        4
    };

    int32_t result = systemSoundManagerImpl_->UpdateToneTypeUri(dataShareHelper, params);
    EXPECT_GE(result, 0);
}

/**
 * @tc.name  : UpdateToneTypeUri_ESIMCard1_TargetBit8
 * @tc.number: UpdateToneTypeUri_004
 * @tc.desc  : Test UpdateToneTypeUri with ESIM_CARD_1 target (bit=8)
 */
HWTEST(SystemSoundManagerUnitNextTest, UpdateToneTypeUri_004, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    auto dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(dataShareHelper, nullptr);

    UpdateToneTypeParams params = {
        1,
        RINGTONE_COLUMN_RING_TONE_TYPE,
        RINGTONE_COLUMN_RING_TONE_SOURCE_TYPE,
        1 << (RINGTONE_TYPE_ESIM_CARD_1 - RINGTONE_TYPE_SIM_CARD_0),
        8
    };

    int32_t result = systemSoundManagerImpl_->UpdateToneTypeUri(dataShareHelper, params);
    EXPECT_GE(result, 0);
}

/**
 * @tc.name  : UpdateToneTypeUri_ShotTone_SIMCard0
 * @tc.number: UpdateToneTypeUri_005
 * @tc.desc  : Test UpdateToneTypeUri for shot tone with SIM_CARD_0 target
 */
HWTEST(SystemSoundManagerUnitNextTest, UpdateToneTypeUri_005, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    auto dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(dataShareHelper, nullptr);

    UpdateToneTypeParams params = {
        1,
        RINGTONE_COLUMN_SHOT_TONE_TYPE,
        RINGTONE_COLUMN_SHOT_TONE_SOURCE_TYPE,
        1 << (SYSTEM_TONE_TYPE_SIM_CARD_0 - SYSTEM_TONE_TYPE_SIM_CARD_0),
        1
    };

    int32_t result = systemSoundManagerImpl_->UpdateToneTypeUri(dataShareHelper, params);
    EXPECT_GE(result, 0);
}

/**
 * @tc.name  : UpdateToneTypeUri_ShotTone_ESIMCard0
 * @tc.number: UpdateToneTypeUri_006
 * @tc.desc  : Test UpdateToneTypeUri for shot tone with ESIM_CARD_0 target (bit=4)
 */
HWTEST(SystemSoundManagerUnitNextTest, UpdateToneTypeUri_006, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    auto dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(dataShareHelper, nullptr);

    UpdateToneTypeParams params = {
        1,
        RINGTONE_COLUMN_SHOT_TONE_TYPE,
        RINGTONE_COLUMN_SHOT_TONE_SOURCE_TYPE,
        1 << (SYSTEM_TONE_TYPE_ESIM_CARD_0 - SYSTEM_TONE_TYPE_SIM_CARD_0),
        4
    };

    int32_t result = systemSoundManagerImpl_->UpdateToneTypeUri(dataShareHelper, params);
    EXPECT_GE(result, 0);
}

/**
 * @tc.name  : UpdateToneTypeUri_ShotTone_ESIMCard1
 * @tc.number: UpdateToneTypeUri_007
 * @tc.desc  : Test UpdateToneTypeUri for shot tone with ESIM_CARD_1 target (bit=8)
 */
HWTEST(SystemSoundManagerUnitNextTest, UpdateToneTypeUri_007, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    auto dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(dataShareHelper, nullptr);

    UpdateToneTypeParams params = {
        1,
        RINGTONE_COLUMN_SHOT_TONE_TYPE,
        RINGTONE_COLUMN_SHOT_TONE_SOURCE_TYPE,
        1 << (SYSTEM_TONE_TYPE_ESIM_CARD_1 - SYSTEM_TONE_TYPE_SIM_CARD_0),
        8
    };

    int32_t result = systemSoundManagerImpl_->UpdateToneTypeUri(dataShareHelper, params);
    EXPECT_GE(result, 0);
}

/**
 * @tc.name  : UpdateToneTypeUri_BitwiseOR_FinalType
 * @tc.number: UpdateToneTypeUri_008
 * @tc.desc  : Test UpdateToneTypeUri where finalType = targetToneType | storedToneType (bitwise OR)
 */
HWTEST(SystemSoundManagerUnitNextTest, UpdateToneTypeUri_008, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    auto dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(dataShareHelper, nullptr);

    UpdateToneTypeParams params = {
        1,
        RINGTONE_COLUMN_RING_TONE_TYPE,
        RINGTONE_COLUMN_RING_TONE_SOURCE_TYPE,
        1 << (RINGTONE_TYPE_SIM_CARD_1 - RINGTONE_TYPE_SIM_CARD_0),
        3
    };

    int32_t result = systemSoundManagerImpl_->UpdateToneTypeUri(dataShareHelper, params);
    EXPECT_GE(result, 0);
}

/**
 * @tc.name  : UpdateRingtoneUri_SIMCard0
 * @tc.number: UpdateRingtoneUri_001
 * @tc.desc  : Test UpdateRingtoneUri with SIM_CARD_0 ringtone type
 */
HWTEST(SystemSoundManagerUnitNextTest, UpdateRingtoneUri_001, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    auto dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(dataShareHelper, nullptr);

    RingtoneType ringtoneType = RingtoneType::RINGTONE_TYPE_SIM_CARD_0;
    int32_t toneId = 1;
    int32_t storedToneType = 1;

    int32_t result = systemSoundManagerImpl_->UpdateRingtoneUri(
        dataShareHelper, toneId, ringtoneType, storedToneType);
    EXPECT_GE(result, 0);
}

/**
 * @tc.name  : UpdateRingtoneUri_SIMCard1
 * @tc.number: UpdateRingtoneUri_002
 * @tc.desc  : Test UpdateRingtoneUri with SIM_CARD_1 ringtone type
 */
HWTEST(SystemSoundManagerUnitNextTest, UpdateRingtoneUri_002, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    auto dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(dataShareHelper, nullptr);

    RingtoneType ringtoneType = RingtoneType::RINGTONE_TYPE_SIM_CARD_1;
    int32_t toneId = 1;
    int32_t storedToneType = 2;

    int32_t result = systemSoundManagerImpl_->UpdateRingtoneUri(
        dataShareHelper, toneId, ringtoneType, storedToneType);
    EXPECT_GE(result, 0);
}

/**
 * @tc.name  : UpdateRingtoneUri_ESIMCard0
 * @tc.number: UpdateRingtoneUri_003
 * @tc.desc  : Test UpdateRingtoneUri with ESIM_CARD_0 ringtone type (targetToneType=4)
 */
HWTEST(SystemSoundManagerUnitNextTest, UpdateRingtoneUri_003, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    auto dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(dataShareHelper, nullptr);

    RingtoneType ringtoneType = RingtoneType::RINGTONE_TYPE_ESIM_CARD_0;
    int32_t toneId = 1;
    int32_t storedToneType = 4;

    int32_t result = systemSoundManagerImpl_->UpdateRingtoneUri(
        dataShareHelper, toneId, ringtoneType, storedToneType);
    EXPECT_GE(result, 0);
}

/**
 * @tc.name  : UpdateRingtoneUri_ESIMCard1
 * @tc.number: UpdateRingtoneUri_004
 * @tc.desc  : Test UpdateRingtoneUri with ESIM_CARD_1 ringtone type (targetToneType=8)
 */
HWTEST(SystemSoundManagerUnitNextTest, UpdateRingtoneUri_004, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    auto dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(dataShareHelper, nullptr);

    RingtoneType ringtoneType = RingtoneType::RINGTONE_TYPE_ESIM_CARD_1;
    int32_t toneId = 1;
    int32_t storedToneType = 8;

    int32_t result = systemSoundManagerImpl_->UpdateRingtoneUri(
        dataShareHelper, toneId, ringtoneType, storedToneType);
    EXPECT_GE(result, 0);
}

/**
 * @tc.name  : UpdateShotToneUri_SIMCard1
 * @tc.number: UpdateShotToneUri_001
 * @tc.desc  : Test UpdateShotToneUri with SIM_CARD_1 system tone type
 */
HWTEST(SystemSoundManagerUnitNextTest, UpdateShotToneUri_001, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    auto dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(dataShareHelper, nullptr);

    SystemToneType systemToneType = SystemToneType::SYSTEM_TONE_TYPE_SIM_CARD_1;
    int32_t toneId = 1;
    int32_t storedToneType = 2;

    int32_t result = systemSoundManagerImpl_->UpdateShotToneUri(
        dataShareHelper, toneId, systemToneType, storedToneType);
    EXPECT_GE(result, 0);
}

/**
 * @tc.name  : UpdateShotToneUri_Notification
 * @tc.number: UpdateShotToneUri_002
 * @tc.desc  : Test UpdateShotToneUri for notification type
 */
HWTEST(SystemSoundManagerUnitNextTest, UpdateShotToneUri_002, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    auto dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(dataShareHelper, nullptr);

    SystemToneType systemToneType = SystemToneType::SYSTEM_TONE_TYPE_NOTIFICATION;
    int32_t toneId = 1;
    int32_t storedToneType = 32;

    int32_t result = systemSoundManagerImpl_->UpdateShotToneUri(
        dataShareHelper, toneId, systemToneType, storedToneType);
    EXPECT_GE(result, 0);
}

/**
 * @tc.name  : UpdateShotToneUri_ESIMCard0
 * @tc.number: UpdateShotToneUri_003
 * @tc.desc  : Test UpdateShotToneUri with ESIM_CARD_0 system tone type (targetToneType=4)
 */
HWTEST(SystemSoundManagerUnitNextTest, UpdateShotToneUri_003, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    auto dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(dataShareHelper, nullptr);

    SystemToneType systemToneType = SystemToneType::SYSTEM_TONE_TYPE_ESIM_CARD_0;
    int32_t toneId = 1;
    int32_t storedToneType = 4;

    int32_t result = systemSoundManagerImpl_->UpdateShotToneUri(
        dataShareHelper, toneId, systemToneType, storedToneType);
    EXPECT_GE(result, 0);
}

/**
 * @tc.name  : UpdateShotToneUri_ESIMCard1
 * @tc.number: UpdateShotToneUri_004
 * @tc.desc  : Test UpdateShotToneUri with ESIM_CARD_1 system tone type (targetToneType=8)
 */
HWTEST(SystemSoundManagerUnitNextTest, UpdateShotToneUri_004, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    auto dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(dataShareHelper, nullptr);

    SystemToneType systemToneType = SystemToneType::SYSTEM_TONE_TYPE_ESIM_CARD_1;
    int32_t toneId = 1;
    int32_t storedToneType = 8;

    int32_t result = systemSoundManagerImpl_->UpdateShotToneUri(
        dataShareHelper, toneId, systemToneType, storedToneType);
    EXPECT_GE(result, 0);
}

/**
 * @tc.name  : SetNoRingToneUri_ESIMCard0
 * @tc.number: SetNoRingToneUri_001
 * @tc.desc  : Test SetNoRingToneUri with eSIM card ringtone type
 */
HWTEST(SystemSoundManagerUnitNextTest, SetNoRingToneUri_001, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    auto dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(dataShareHelper, nullptr);

    int32_t result = systemSoundManagerImpl_->SetNoRingToneUri(dataShareHelper, RINGTONE_TYPE_ESIM_CARD_0);
    EXPECT_GE(result, 0);
}

/**
 * @tc.name  : SetNoRingToneUri_ESIMCard1
 * @tc.number: SetNoRingToneUri_002
 * @tc.desc  : Test SetNoRingToneUri with ESIM_CARD_1 ringtone type
 */
HWTEST(SystemSoundManagerUnitNextTest, SetNoRingToneUri_002, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    auto dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(dataShareHelper, nullptr);

    int32_t result = systemSoundManagerImpl_->SetNoRingToneUri(dataShareHelper, RINGTONE_TYPE_ESIM_CARD_1);
    EXPECT_GE(result, 0);
}

/**
 * @tc.name  : SetNoSystemToneUri_Notification
 * @tc.number: SetNoSystemToneUri_001
 * @tc.desc  : Test SetNoSystemToneUri with NOTIFICATION type (uses ClearNotificationToneType)
 */
HWTEST(SystemSoundManagerUnitNextTest, SetNoSystemToneUri_001, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    auto dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(dataShareHelper, nullptr);

    int32_t result = systemSoundManagerImpl_->SetNoSystemToneUri(
        dataShareHelper, SYSTEM_TONE_TYPE_NOTIFICATION);
    EXPECT_GE(result, 0);
}

/**
 * @tc.name  : SetNoSystemToneUri_ESIMCard0
 * @tc.number: SetNoSystemToneUri_002
 * @tc.desc  : Test SetNoSystemToneUri with ESIM_CARD_0 type (uses ClearBitFromToneTypeColumn)
 */
HWTEST(SystemSoundManagerUnitNextTest, SetNoSystemToneUri_002, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    auto dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(dataShareHelper, nullptr);

    int32_t result = systemSoundManagerImpl_->SetNoSystemToneUri(
        dataShareHelper, SYSTEM_TONE_TYPE_ESIM_CARD_0);
    EXPECT_GE(result, 0);
}

/**
 * @tc.name  : SetNoSystemToneUri_ESIMCard1
 * @tc.number: SetNoSystemToneUri_003
 * @tc.desc  : Test SetNoSystemToneUri with ESIM_CARD_1 type
 */
HWTEST(SystemSoundManagerUnitNextTest, SetNoSystemToneUri_003, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    auto dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(dataShareHelper, nullptr);

    int32_t result = systemSoundManagerImpl_->SetNoSystemToneUri(
        dataShareHelper, SYSTEM_TONE_TYPE_ESIM_CARD_1);
    EXPECT_GE(result, 0);
}

/**
 * @tc.name  : GetRingtoneAttrs_ESIMCard0
 * @tc.number: GetRingtoneAttrs_001
 * @tc.desc  : Test GetRingtoneAttrs with ESIM_CARD_0 ringtone type
 */
HWTEST(SystemSoundManagerUnitNextTest, GetRingtoneAttrs_001, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    DatabaseTool databaseTool;
    databaseTool.isInitialized = false;
    databaseTool.dataShareHelper = nullptr;

    ToneAttrs result = systemSoundManagerImpl_->GetRingtoneAttrs(databaseTool, RINGTONE_TYPE_ESIM_CARD_0);
    EXPECT_EQ(result.GetUri(), "");
}

/**
 * @tc.name  : GetRingtoneAttrs_ESIMCard1
 * @tc.number: GetRingtoneAttrs_002
 * @tc.desc  : Test GetRingtoneAttrs with ESIM_CARD_1 ringtone type via DataShareHelper
 */
HWTEST(SystemSoundManagerUnitNextTest, GetRingtoneAttrs_002, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    DatabaseTool databaseTool;
    databaseTool.isInitialized = true;
    databaseTool.isProxy = true;
    databaseTool.dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(databaseTool.dataShareHelper, nullptr);

    ToneAttrs result = systemSoundManagerImpl_->GetRingtoneAttrs(databaseTool, RINGTONE_TYPE_ESIM_CARD_1);
    EXPECT_EQ(result.GetCategory(), TONE_CATEGORY_RINGTONE);
}

/**
 * @tc.name  : GetSystemToneAttrs_ESIMCard0
 * @tc.number: GetSystemToneAttrs_003
 * @tc.desc  : Test GetSystemToneAttrs with ESIM_CARD_0 system tone type (non-notification branch)
 */
HWTEST(SystemSoundManagerUnitNextTest, GetSystemToneAttrs_003, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    DatabaseTool databaseTool;
    databaseTool.isInitialized = true;
    databaseTool.isProxy = true;
    databaseTool.dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(databaseTool.dataShareHelper, nullptr);

    ToneAttrs result = systemSoundManagerImpl_->GetSystemToneAttrs(databaseTool, SYSTEM_TONE_TYPE_ESIM_CARD_0);
    EXPECT_EQ(result.GetCategory(), TONE_CATEGORY_TEXT_MESSAGE);
}

/**
 * @tc.name  : GetSystemToneAttrs_ESIMCard1
 * @tc.number: GetSystemToneAttrs_004
 * @tc.desc  : Test GetSystemToneAttrs with ESIM_CARD_1 system tone type
 */
HWTEST(SystemSoundManagerUnitNextTest, GetSystemToneAttrs_004, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    DatabaseTool databaseTool;
    databaseTool.isInitialized = true;
    databaseTool.isProxy = true;
    databaseTool.dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(databaseTool.dataShareHelper, nullptr);

    ToneAttrs result = systemSoundManagerImpl_->GetSystemToneAttrs(databaseTool, SYSTEM_TONE_TYPE_ESIM_CARD_1);
    EXPECT_EQ(result.GetCategory(), TONE_CATEGORY_TEXT_MESSAGE);
}

/**
 * @tc.name  : GetSystemToneAttrs_Notification
 * @tc.number: GetSystemToneAttrs_005
 * @tc.desc  : Test GetSystemToneAttrs with NOTIFICATION type (notification branch)
 */
HWTEST(SystemSoundManagerUnitNextTest, GetSystemToneAttrs_005, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    DatabaseTool databaseTool;
    databaseTool.isInitialized = true;
    databaseTool.isProxy = true;
    databaseTool.dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(databaseTool.dataShareHelper, nullptr);

    ToneAttrs result = systemSoundManagerImpl_->GetSystemToneAttrs(databaseTool, SYSTEM_TONE_TYPE_NOTIFICATION);
    EXPECT_EQ(result.GetCategory(), TONE_CATEGORY_NOTIFICATION);
}

/**
 * @tc.name  : Test SetRingtoneUri with valid URI (Success Path)
 * @tc.number: Media_SoundManager_SetRingtoneUri_Refactor_001
 * @tc.desc  : Test SetRingtoneUri returns SUCCESS for valid URI with matching toneType.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_SetRingtoneUri_Refactor_001, TestSize.Level2)
{
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    std::shared_ptr<Context> context_ = std::make_shared<ContextImpl>();
    EXPECT_NE(systemSoundManager_, nullptr);

    auto vec = systemSoundManager_->GetRingtoneAttrList(context_,
        RingtoneType::RINGTONE_TYPE_SIM_CARD_0);
    if (vec.size() > 0) {
        std::string uri = vec[0]->GetUri();
        EXPECT_FALSE(uri.empty());

        int32_t result = systemSoundManager_->SetRingtoneUri(context_, uri,
            RingtoneType::RINGTONE_TYPE_SIM_CARD_0);
        EXPECT_EQ(result, SUCCESS);

        std::string getUri = systemSoundManager_->GetRingtoneUri(context_,
            RingtoneType::RINGTONE_TYPE_SIM_CARD_0);
        EXPECT_FALSE(getUri.empty());
    }
}

/**
 * @tc.name  : Test SetRingtoneUri with NO_RING_SOUND
 * @tc.number: Media_SoundManager_SetRingtoneUri_Refactor_002
 * @tc.desc  : Test SetRingtoneUri handles NO_RING_SOUND correctly.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_SetRingtoneUri_Refactor_002, TestSize.Level2)
{
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    std::shared_ptr<Context> context_ = std::make_shared<ContextImpl>();
    EXPECT_NE(systemSoundManager_, nullptr);

    int32_t result = systemSoundManager_->SetRingtoneUri(context_, NO_RING_SOUND,
        RingtoneType::RINGTONE_TYPE_SIM_CARD_0);
    EXPECT_EQ(result, SUCCESS);
}

/**
 * @tc.name  : Test SetRingtoneUri with all ringtone types including eSIM
 * @tc.number: Media_SoundManager_SetRingtoneUri_Refactor_003
 * @tc.desc  : Test SetRingtoneUri works correctly with all RingtoneType values including eSIM.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_SetRingtoneUri_Refactor_003, TestSize.Level2)
{
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    std::shared_ptr<Context> context_ = std::make_shared<ContextImpl>();
    EXPECT_NE(systemSoundManager_, nullptr);

    auto vec = systemSoundManager_->GetRingtoneAttrList(context_,
        RingtoneType::RINGTONE_TYPE_SIM_CARD_0);
    if (vec.size() > 0) {
        std::string uri = vec[0]->GetUri();

        std::vector<RingtoneType> ringtoneTypes = {
            RingtoneType::RINGTONE_TYPE_SIM_CARD_0,
            RingtoneType::RINGTONE_TYPE_SIM_CARD_1,
            RingtoneType::RINGTONE_TYPE_ESIM_CARD_0,
            RingtoneType::RINGTONE_TYPE_ESIM_CARD_1
        };

        for (auto type : ringtoneTypes) {
            int32_t result = systemSoundManager_->SetRingtoneUri(context_, uri, type);
            EXPECT_EQ(result, SUCCESS);
        }
    }
}

/**
 * @tc.name  : Test SetSystemToneUri with notification type
 * @tc.number: Media_SoundManager_SetSystemToneUri_Refactor_001
 * @tc.desc  : Test SetSystemToneUri with SYSTEM_TONE_TYPE_NOTIFICATION.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_SetSystemToneUri_Refactor_001, TestSize.Level2)
{
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    std::shared_ptr<Context> context_ = std::make_shared<ContextImpl>();
    EXPECT_NE(systemSoundManager_, nullptr);

    auto vec = systemSoundManager_->GetSystemToneAttrList(context_,
        SystemToneType::SYSTEM_TONE_TYPE_NOTIFICATION);
    if (vec.size() > 0) {
        std::string uri = vec[0]->GetUri();
        EXPECT_FALSE(uri.empty());

        int32_t result = systemSoundManager_->SetSystemToneUri(context_, uri,
            SystemToneType::SYSTEM_TONE_TYPE_NOTIFICATION);
        EXPECT_EQ(result, SUCCESS);

        std::string getUri = systemSoundManager_->GetSystemToneUri(context_,
            SystemToneType::SYSTEM_TONE_TYPE_NOTIFICATION);
        EXPECT_FALSE(getUri.empty());
    }
}

/**
 * @tc.name  : Test SetSystemToneUri with shot tone types including eSIM
 * @tc.number: Media_SoundManager_SetSystemToneUri_Refactor_002
 * @tc.desc  : Test SetSystemToneUri with SIM and eSIM shot tone types.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_SetSystemToneUri_Refactor_002, TestSize.Level2)
{
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    std::shared_ptr<Context> context_ = std::make_shared<ContextImpl>();
    EXPECT_NE(systemSoundManager_, nullptr);

    auto vec = systemSoundManager_->GetSystemToneAttrList(context_,
        SystemToneType::SYSTEM_TONE_TYPE_SIM_CARD_0);
    if (vec.size() > 0) {
        std::string uri = vec[0]->GetUri();

        std::vector<SystemToneType> systemToneTypes = {
            SystemToneType::SYSTEM_TONE_TYPE_SIM_CARD_0,
            SystemToneType::SYSTEM_TONE_TYPE_SIM_CARD_1,
            SystemToneType::SYSTEM_TONE_TYPE_ESIM_CARD_0,
            SystemToneType::SYSTEM_TONE_TYPE_ESIM_CARD_1
        };

        for (auto type : systemToneTypes) {
            int32_t result = systemSoundManager_->SetSystemToneUri(context_, uri, type);
            EXPECT_EQ(result, SUCCESS);
        }
    }
}

/**
 * @tc.name  : Test SetSystemToneUri with NO_SYSTEM_SOUND
 * @tc.number: Media_SoundManager_SetSystemToneUri_Refactor_003
 * @tc.desc  : Test SetSystemToneUri handles NO_SYSTEM_SOUND correctly.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_SetSystemToneUri_Refactor_003, TestSize.Level2)
{
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    std::shared_ptr<Context> context_ = std::make_shared<ContextImpl>();
    EXPECT_NE(systemSoundManager_, nullptr);

    int32_t result = systemSoundManager_->SetSystemToneUri(context_, NO_SYSTEM_SOUND,
        SystemToneType::SYSTEM_TONE_TYPE_NOTIFICATION);
    EXPECT_EQ(result, SUCCESS);
}

/**
 * @tc.name  : Test SetRingtoneUri with invalid URI
 * @tc.number: Media_SoundManager_SetRingtoneUri_Refactor_004
 * @tc.desc  : Test SetRingtoneUri returns ERROR for non-existent URI.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_SetRingtoneUri_Refactor_004, TestSize.Level2)
{
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    std::shared_ptr<Context> context_ = std::make_shared<ContextImpl>();
    EXPECT_NE(systemSoundManager_, nullptr);

    std::string invalidUri = "file:///data/storage/el2/base/files/nonexistent_ringtone.ogg";
    int32_t result = systemSoundManager_->SetRingtoneUri(context_, invalidUri,
        RingtoneType::RINGTONE_TYPE_SIM_CARD_0);
    EXPECT_EQ(result, ERROR);
}

/**
 * @tc.name  : Test SetSystemToneUri with invalid URI
 * @tc.number: Media_SoundManager_SetSystemToneUri_Refactor_005
 * @tc.desc  : Test SetSystemToneUri returns ERROR for non-existent URI.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_SetSystemToneUri_Refactor_005, TestSize.Level2)
{
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    std::shared_ptr<Context> context_ = std::make_shared<ContextImpl>();
    EXPECT_NE(systemSoundManager_, nullptr);

    std::string invalidUri = "file:///data/storage/el2/base/files/nonexistent_tone.ogg";
    int32_t result = systemSoundManager_->SetSystemToneUri(context_, invalidUri,
        SystemToneType::SYSTEM_TONE_TYPE_NOTIFICATION);
    EXPECT_EQ(result, ERROR);
}

/**
 * @tc.name  : Test SetRingtoneUri and SetSystemToneUri consistency
 * @tc.number: Media_SoundManager_SetToneUri_Refactor_006
 * @tc.desc  : Test that both refactored methods work consistently.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_SetToneUri_Refactor_006, TestSize.Level2)
{
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    std::shared_ptr<Context> context_ = std::make_shared<ContextImpl>();
    EXPECT_NE(systemSoundManager_, nullptr);

    auto ringtoneVec = systemSoundManager_->GetRingtoneAttrList(context_,
        RingtoneType::RINGTONE_TYPE_SIM_CARD_0);
    auto notificationVec = systemSoundManager_->GetSystemToneAttrList(context_,
        SystemToneType::SYSTEM_TONE_TYPE_NOTIFICATION);

    if (ringtoneVec.size() > 0) {
        std::string uri = ringtoneVec[0]->GetUri();
        EXPECT_FALSE(uri.empty());

        int32_t result1 = systemSoundManager_->SetRingtoneUri(context_, uri,
            RingtoneType::RINGTONE_TYPE_SIM_CARD_0);
        EXPECT_EQ(result1, SUCCESS);

        int32_t result2 = systemSoundManager_->SetSystemToneUri(context_, uri,
            SystemToneType::SYSTEM_TONE_TYPE_SIM_CARD_0);
        EXPECT_EQ(result2, TYPEERROR);
    }

    if (notificationVec.size() > 0) {
        std::string uri = notificationVec[0]->GetUri();
        EXPECT_FALSE(uri.empty());

        int32_t result3 = systemSoundManager_->SetSystemToneUri(context_, uri,
            SystemToneType::SYSTEM_TONE_TYPE_NOTIFICATION);
        EXPECT_EQ(result3, SUCCESS);
    }
}

/**
 * @tc.name  : Test resource management in refactored code
 * @tc.number: Media_SoundManager_SetToneUri_Refactor_007
 * @tc.desc  : Test that dataShareHelper is properly released after SetToneUriInternal.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_SetToneUri_Refactor_007, TestSize.Level2)
{
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    std::shared_ptr<Context> context_ = std::make_shared<ContextImpl>();
    EXPECT_NE(systemSoundManager_, nullptr);

    auto ringtoneVec = systemSoundManager_->GetRingtoneAttrList(context_,
        RingtoneType::RINGTONE_TYPE_SIM_CARD_0);
    auto notificationVec = systemSoundManager_->GetSystemToneAttrList(context_,
        SystemToneType::SYSTEM_TONE_TYPE_NOTIFICATION);

    if (ringtoneVec.size() > 0) {
        std::string uri = ringtoneVec[0]->GetUri();

        for (int i = 0; i < 10; i++) {
            int32_t result = systemSoundManager_->SetRingtoneUri(context_, uri,
                RingtoneType::RINGTONE_TYPE_SIM_CARD_0);
            EXPECT_EQ(result, SUCCESS);
        }
    }

    if (notificationVec.size() > 0) {
        std::string uri = notificationVec[0]->GetUri();

        for (int i = 0; i < 10; i++) {
            int32_t result = systemSoundManager_->SetSystemToneUri(context_, uri,
                SystemToneType::SYSTEM_TONE_TYPE_NOTIFICATION);
            EXPECT_EQ(result, SUCCESS);
        }
    }
}

/**
 * @tc.name  : Test return value semantics preservation
 * @tc.number: Media_SoundManager_SetToneUri_Refactor_008
 * @tc.desc  : Test that ERROR vs TYPEERROR return values are correctly preserved.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_SetToneUri_Refactor_008, TestSize.Level2)
{
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    std::shared_ptr<Context> context_ = std::make_shared<ContextImpl>();
    EXPECT_NE(systemSoundManager_, nullptr);

    std::string nonExistentUri = "file:///data/storage/el2/base/files/nonexistent_file_12345.ogg";
    int32_t result1 = systemSoundManager_->SetRingtoneUri(context_, nonExistentUri,
        RingtoneType::RINGTONE_TYPE_SIM_CARD_0);
    EXPECT_EQ(result1, ERROR);

    RingtoneType invalidType = static_cast<RingtoneType>(999);
    std::string validUri = "test_uri";
    int32_t result2 = systemSoundManager_->SetRingtoneUri(context_, validUri, invalidType);
    EXPECT_EQ(result2, MSERR_INVALID_VAL);
}

/**
 * @tc.name  : Test SetToneUriParams with all ringtone types including eSIM
 * @tc.number: Media_SoundManager_SetToneUri_Refactor_009
 * @tc.desc  : Test SetToneUriInternal with all ringtone types including eSIM.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_SetToneUri_Refactor_009, TestSize.Level2)
{
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    std::shared_ptr<Context> context_ = std::make_shared<ContextImpl>();
    EXPECT_NE(systemSoundManager_, nullptr);

    auto vec = systemSoundManager_->GetRingtoneAttrList(context_,
        RingtoneType::RINGTONE_TYPE_SIM_CARD_0);
    ASSERT_GT(vec.size(), 0u);
    std::string uri = vec[0]->GetUri();
    EXPECT_FALSE(uri.empty());

    std::vector<RingtoneType> ringtoneTypes = {
        RingtoneType::RINGTONE_TYPE_SIM_CARD_0,
        RingtoneType::RINGTONE_TYPE_SIM_CARD_1,
        RingtoneType::RINGTONE_TYPE_ESIM_CARD_0,
        RingtoneType::RINGTONE_TYPE_ESIM_CARD_1
    };

    for (auto ringtoneType : ringtoneTypes) {
        int32_t result = systemSoundManager_->SetRingtoneUri(context_, uri, ringtoneType);
        EXPECT_EQ(result, SUCCESS);

        std::string retrievedUri = systemSoundManager_->GetRingtoneUri(context_, ringtoneType);
        EXPECT_FALSE(retrievedUri.empty());
    }
}

/**
 * @tc.name  : Test SetRingtoneUri with invalid eSIM type
 * @tc.number: Media_SoundManager_SetRingtoneUri_ESIM_Invalid_001
 * @tc.desc  : Test SetRingtoneUri with invalid RingtoneType beyond eSIM range
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_SetRingtoneUri_ESIM_Invalid_001, TestSize.Level2)
{
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    std::shared_ptr<Context> context_ = std::make_shared<ContextImpl>();
    EXPECT_NE(systemSoundManager_, nullptr);

    RingtoneType invalidType = static_cast<RingtoneType>(RINGTONE_TYPE_ESIM_CARD_1 + 1);
    int32_t result = systemSoundManager_->SetRingtoneUri(context_, "test_uri", invalidType);
    EXPECT_EQ(result, MSERR_INVALID_VAL);
}

/**
 * @tc.name  : Test SetSystemToneUri with invalid eSIM type
 * @tc.number: Media_SoundManager_SetSystemToneUri_ESIM_Invalid_001
 * @tc.desc  : Test SetSystemToneUri with invalid SystemToneType beyond eSIM range
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_SetSystemToneUri_ESIM_Invalid_001, TestSize.Level2)
{
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    std::shared_ptr<Context> context_ = std::make_shared<ContextImpl>();
    EXPECT_NE(systemSoundManager_, nullptr);

    SystemToneType invalidType = static_cast<SystemToneType>(4);
    int32_t result = systemSoundManager_->SetSystemToneUri(context_, "test_uri", invalidType);
    EXPECT_EQ(result, MSERR_INVALID_VAL);
}

/**
 * @tc.name  : Test NO_RING_SOUND for eSIM ringtone types
 * @tc.number: Media_SoundManager_SetRingtoneUri_ESIM_NoRingSound_001
 * @tc.desc  : Test SetRingtoneUri with NO_RING_SOUND for all eSIM types
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_SetRingtoneUri_ESIM_NoRingSound_001, TestSize.Level2)
{
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    std::shared_ptr<Context> context_ = std::make_shared<ContextImpl>();
    EXPECT_NE(systemSoundManager_, nullptr);

    std::vector<RingtoneType> esimTypes = {
        RingtoneType::RINGTONE_TYPE_ESIM_CARD_0,
        RingtoneType::RINGTONE_TYPE_ESIM_CARD_1
    };

    for (auto type : esimTypes) {
        int32_t result = systemSoundManager_->SetRingtoneUri(context_, NO_RING_SOUND, type);
        EXPECT_EQ(result, SUCCESS);
    }
}

/**
 * @tc.name  : Test NO_SYSTEM_SOUND for eSIM system tone types
 * @tc.number: Media_SoundManager_SetSystemToneUri_ESIM_NoSystemSound_001
 * @tc.desc  : Test SetSystemToneUri with NO_SYSTEM_SOUND for eSIM card types
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_SetSystemToneUri_ESIM_NoSystemSound_001, TestSize.Level2)
{
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    std::shared_ptr<Context> context_ = std::make_shared<ContextImpl>();
    EXPECT_NE(systemSoundManager_, nullptr);

    std::vector<SystemToneType> esimTypes = {
        SystemToneType::SYSTEM_TONE_TYPE_ESIM_CARD_0,
        SystemToneType::SYSTEM_TONE_TYPE_ESIM_CARD_1
    };

    for (auto type : esimTypes) {
        int32_t result = systemSoundManager_->SetSystemToneUri(context_, NO_SYSTEM_SOUND, type);
        EXPECT_EQ(result, SUCCESS);
    }
}

/**
 * @tc.name  : Test SetToneUriInternal default branch
 * @tc.number: Media_SoundManager_SetToneUriInternal_Default_001
 * @tc.desc  : Test SetToneUriInternal with invalid toneTypeQuery triggers default branch.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_SetToneUriInternal_Default_001, TestSize.Level2)
{
    auto systemSoundManager = std::make_shared<SystemSoundManagerImpl>();
    std::shared_ptr<Context> context = std::make_shared<ContextImpl>();
    ASSERT_NE(systemSoundManager, nullptr);

    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(dataShareHelper, nullptr);

    SetToneUriParams params = {
        TONE_TYPE_RINGTONE + TONE_TYPE_NOTIFICATION,
        RINGTONE_TYPE_SIM_CARD_0,
        TONE_TYPE_RINGTONE
    };

    int32_t result = systemSoundManager->SetToneUriInternal(dataShareHelper, "test_uri", params);
    EXPECT_EQ(result, ERROR);

    dataShareHelper->Release();
}

namespace {

using namespace testing;

struct MockResultSetConfig {
    int32_t toneId = 0;
    int32_t sourceType = SOURCE_TYPE_INVALID;
    int32_t toneType = TONE_TYPE_INVALID;
    int32_t ringtoneType = RING_TONE_TYPE_NOT;
    int32_t shottoneType = SHOT_TONE_TYPE_NOT;
    int32_t notificationToneType = NOTIFICATION_TONE_TYPE_NOT;
    int32_t notificationToneSourceType = SOURCE_TYPE_INVALID;
    int32_t shotToneSourceType = SOURCE_TYPE_INVALID;
    int32_t ringtoneSourceType = SOURCE_TYPE_INVALID;
    bool hasRows = true;
};

std::unordered_map<std::string, int> BuildColumnIndexMap()
{
    std::unordered_map<std::string, int> columnIndexMap;
    int idx = 0;
    columnIndexMap[RINGTONE_COLUMN_TONE_ID] = idx++;
    columnIndexMap[RINGTONE_COLUMN_DATA] = idx++;
    columnIndexMap[RINGTONE_COLUMN_DISPLAY_NAME] = idx++;
    columnIndexMap[RINGTONE_COLUMN_TITLE] = idx++;
    columnIndexMap[RINGTONE_COLUMN_TONE_TYPE] = idx++;
    columnIndexMap[RINGTONE_COLUMN_MEDIA_TYPE] = idx++;
    columnIndexMap[RINGTONE_COLUMN_SOURCE_TYPE] = idx++;
    columnIndexMap[RINGTONE_COLUMN_SHOT_TONE_TYPE] = idx++;
    columnIndexMap[RINGTONE_COLUMN_SHOT_TONE_SOURCE_TYPE] = idx++;
    columnIndexMap[RINGTONE_COLUMN_NOTIFICATION_TONE_TYPE] = idx++;
    columnIndexMap[RINGTONE_COLUMN_NOTIFICATION_TONE_SOURCE_TYPE] = idx++;
    columnIndexMap[RINGTONE_COLUMN_RING_TONE_TYPE] = idx++;
    columnIndexMap[RINGTONE_COLUMN_RING_TONE_SOURCE_TYPE] = idx++;
    columnIndexMap[RINGTONE_COLUMN_ALARM_TONE_TYPE] = idx++;
    columnIndexMap[RINGTONE_COLUMN_ALARM_TONE_SOURCE_TYPE] = idx++;
    columnIndexMap[RINGTONE_COLUMN_MIME_TYPE] = idx++;
    columnIndexMap[RINGTONE_COLUMN_SIZE] = idx++;
    columnIndexMap[RINGTONE_COLUMN_DATE_ADDED] = idx++;
    columnIndexMap[RINGTONE_COLUMN_DATE_MODIFIED] = idx++;
    columnIndexMap[RINGTONE_COLUMN_DURATION] = idx++;
    columnIndexMap[RINGTONE_COLUMN_SCANNER_FLAG] = idx++;
    return columnIndexMap;
}

std::unordered_map<int, int> BuildIntValueMap(
    const std::unordered_map<std::string, int>& columnIndexMap,
    const MockResultSetConfig& config)
{
    std::unordered_map<int, int> intValueMap;
    intValueMap[columnIndexMap.at(RINGTONE_COLUMN_TONE_ID)] = config.toneId;
    intValueMap[columnIndexMap.at(RINGTONE_COLUMN_TONE_TYPE)] = config.toneType;
    intValueMap[columnIndexMap.at(RINGTONE_COLUMN_MEDIA_TYPE)] = RINGTONE_MEDIA_TYPE_AUDIO;
    intValueMap[columnIndexMap.at(RINGTONE_COLUMN_SOURCE_TYPE)] = config.sourceType;
    intValueMap[columnIndexMap.at(RINGTONE_COLUMN_SHOT_TONE_TYPE)] = config.shottoneType;
    intValueMap[columnIndexMap.at(RINGTONE_COLUMN_SHOT_TONE_SOURCE_TYPE)] = config.shotToneSourceType;
    intValueMap[columnIndexMap.at(RINGTONE_COLUMN_NOTIFICATION_TONE_TYPE)] = config.notificationToneType;
    intValueMap[columnIndexMap.at(RINGTONE_COLUMN_NOTIFICATION_TONE_SOURCE_TYPE)] = config.notificationToneSourceType;
    intValueMap[columnIndexMap.at(RINGTONE_COLUMN_RING_TONE_TYPE)] = config.ringtoneType;
    intValueMap[columnIndexMap.at(RINGTONE_COLUMN_RING_TONE_SOURCE_TYPE)] = config.ringtoneSourceType;
    intValueMap[columnIndexMap.at(RINGTONE_COLUMN_ALARM_TONE_TYPE)] = ALARM_TONE_TYPE_NOT;
    intValueMap[columnIndexMap.at(RINGTONE_COLUMN_ALARM_TONE_SOURCE_TYPE)] = SOURCE_TYPE_INVALID;
    intValueMap[columnIndexMap.at(RINGTONE_COLUMN_DURATION)] = 0;
    intValueMap[columnIndexMap.at(RINGTONE_COLUMN_SCANNER_FLAG)] = 0;
    return intValueMap;
}

void SetupResultSetON_CALL(std::shared_ptr<OHOS::Media::MockDataShareResultSet> resultSet,
    const std::unordered_map<std::string, int>& columnIndexMap,
    const std::unordered_map<int, int>& intValueMap)
{
    ON_CALL(*resultSet, GetColumnIndex(_, _))
        .WillByDefault(Invoke([columnIndexMap](const std::string& name, int& outIdx) -> int {
            auto it = columnIndexMap.find(name);
            if (it != columnIndexMap.end()) {
                outIdx = it->second;
                return 0;
            }
            outIdx = -1;
            return -1;
        }));

    ON_CALL(*resultSet, GetInt(_, _))
        .WillByDefault(Invoke([intValueMap](int colIdx, int& val) -> int {
            auto it = intValueMap.find(colIdx);
            if (it != intValueMap.end()) {
                val = it->second;
                return 0;
            }
            val = 0;
            return 0;
        }));

    ON_CALL(*resultSet, GetString(_, _))
        .WillByDefault(Invoke([](int colIdx, std::string& val) -> int {
            val = "test_value";
            return 0;
        }));

    ON_CALL(*resultSet, GetLong(_, _))
        .WillByDefault(Invoke([](int colIdx, int64_t& val) -> int {
            val = 0;
            return 0;
        }));

    ON_CALL(*resultSet, IsColumnNull(_, _))
        .WillByDefault(Invoke([](int colIdx, bool& isNull) -> int {
            isNull = false;
            return 0;
        }));

    ON_CALL(*resultSet, GetAllColumnNames(_))
        .WillByDefault(Invoke([columnIndexMap](std::vector<std::string>& columnNames) -> int {
            columnNames.clear();
            std::vector<std::pair<std::string, int>> sorted(columnIndexMap.begin(), columnIndexMap.end());
            std::sort(sorted.begin(), sorted.end(),
                [](const auto& a, const auto& b) { return a.second < b.second; });
            for (auto& [name, idx] : sorted) {
                columnNames.push_back(name);
            }
            return 0;
        }));
}

std::shared_ptr<OHOS::Media::MockDataShareResultSet> CreateMockResultSet(const MockResultSetConfig& config)
{
    auto resultSet = std::make_shared<OHOS::Media::MockDataShareResultSet>();

    if (!config.hasRows) {
        ON_CALL(*resultSet, GoToFirstRow()).WillByDefault(Return(-1));
        ON_CALL(*resultSet, GoToNextRow()).WillByDefault(Return(-1));
        ON_CALL(*resultSet, GetRowCount(_)).WillByDefault(DoAll(SetArgReferee<0>(0), Return(0)));
        ON_CALL(*resultSet, GetColumnCount(_)).WillByDefault(DoAll(SetArgReferee<0>(0), Return(0)));
        return resultSet;
    }

    ON_CALL(*resultSet, GoToFirstRow()).WillByDefault(Return(0));
    ON_CALL(*resultSet, GoToNextRow()).WillByDefault(Return(-1));
    ON_CALL(*resultSet, GoToRow(_)).WillByDefault(Return(0));
    ON_CALL(*resultSet, GetRowCount(_)).WillByDefault(DoAll(SetArgReferee<0>(1), Return(0)));
    ON_CALL(*resultSet, GetColumnCount(_)).WillByDefault(DoAll(SetArgReferee<0>(16), Return(0)));
    ON_CALL(*resultSet, Close()).WillByDefault(Return(0));
    ON_CALL(*resultSet, IsClosed()).WillByDefault(Return(false));

    auto columnIndexMap = BuildColumnIndexMap();
    auto intValueMap = BuildIntValueMap(columnIndexMap, config);
    SetupResultSetON_CALL(resultSet, columnIndexMap, intValueMap);

    return resultSet;
}

std::shared_ptr<OHOS::Media::MockDataShareHelper> CreateMockHelperWithResultSet(
    std::shared_ptr<OHOS::Media::MockDataShareResultSet> resultSet)
{
    auto mockHelper = std::make_shared<OHOS::Media::MockDataShareHelper>();

    ON_CALL(*mockHelper, Query(_, _, _, _))
        .WillByDefault(Invoke([resultSet](Uri& uri, const DataShare::DataSharePredicates& predicates,
            std::vector<std::string>& columns, DataShare::DatashareBusinessError* businessError)
            -> std::shared_ptr<DataShare::DataShareResultSet> {
            return std::static_pointer_cast<DataShare::DataShareResultSet>(resultSet);
        }));

    ON_CALL(*mockHelper, Delete(_, _)).WillByDefault(Return(1));
    ON_CALL(*mockHelper, Update(_, _, _)).WillByDefault(Return(1));
    ON_CALL(*mockHelper, Release()).WillByDefault(Return(true));

    return mockHelper;
}

}

using namespace testing;

/**
 * @tc.name  : ClearNotificationToneType_NullResults
 * @tc.number: ClearNotificationToneType_002
 * @tc.desc  : Test ClearNotificationToneType when Query returns null result set (early return branch)
 */
HWTEST(SystemSoundManagerUnitNextTest, ClearNotificationToneType_002, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    auto mockHelper = std::make_shared<OHOS::Media::MockDataShareHelper>();
    ON_CALL(*mockHelper, Query(_, _, _, _))
        .WillByDefault(Return(std::shared_ptr<DataShare::DataShareResultSet>(nullptr)));

    int32_t result = systemSoundManagerImpl_->ClearNotificationToneType(
        std::static_pointer_cast<DataShare::DataShareHelper>(mockHelper), SOURCE_TYPE_CUSTOMISED);
    EXPECT_EQ(result, 0);
}

/**
 * @tc.name  : ClearNotificationToneType_CustomisedNotification
 * @tc.number: ClearNotificationToneType_003
 * @tc.desc  : Test ClearNotificationToneType with customised notification tone (Delete branch)
 */
HWTEST(SystemSoundManagerUnitNextTest, ClearNotificationToneType_003, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    MockResultSetConfig config;
    config.toneId = 1;
    config.sourceType = SOURCE_TYPE_CUSTOMISED;
    config.toneType = TONE_TYPE_NOTIFICATION;
    config.notificationToneType = NOTIFICATION_TONE_TYPE;
    config.notificationToneSourceType = SOURCE_TYPE_CUSTOMISED;
    auto resultSet = CreateMockResultSet(config);
    auto mockHelper = CreateMockHelperWithResultSet(resultSet);

    EXPECT_CALL(*mockHelper, Delete(_, _)).Times(AtLeast(1));
    EXPECT_CALL(*mockHelper, Update(_, _, _)).Times(0);

    int32_t result = systemSoundManagerImpl_->ClearNotificationToneType(
        std::static_pointer_cast<DataShare::DataShareHelper>(mockHelper), SOURCE_TYPE_CUSTOMISED);
    EXPECT_GT(result, 0);
}

/**
 * @tc.name  : ClearNotificationToneType_PresetTone
 * @tc.number: ClearNotificationToneType_004
 * @tc.desc  : Test ClearNotificationToneType with preset tone (Update branch, else condition)
 */
HWTEST(SystemSoundManagerUnitNextTest, ClearNotificationToneType_004, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    MockResultSetConfig config;
    config.toneId = 2;
    config.sourceType = SOURCE_TYPE_PRESET;
    config.toneType = TONE_TYPE_RINGTONE;
    config.notificationToneType = NOTIFICATION_TONE_TYPE;
    config.notificationToneSourceType = SOURCE_TYPE_PRESET;
    auto resultSet = CreateMockResultSet(config);
    auto mockHelper = CreateMockHelperWithResultSet(resultSet);

    EXPECT_CALL(*mockHelper, Delete(_, _)).Times(0);
    EXPECT_CALL(*mockHelper, Update(_, _, _)).Times(AtLeast(1));

    int32_t result = systemSoundManagerImpl_->ClearNotificationToneType(
        std::static_pointer_cast<DataShare::DataShareHelper>(mockHelper), SOURCE_TYPE_PRESET);
    EXPECT_GT(result, 0);
}

/**
 * @tc.name  : ClearNotificationToneType_EmptyResults
 * @tc.number: ClearNotificationToneType_005
 * @tc.desc  : Test ClearNotificationToneType when Query returns empty result set (no rows, Close branch)
 */
HWTEST(SystemSoundManagerUnitNextTest, ClearNotificationToneType_005, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    MockResultSetConfig config;
    config.hasRows = false;
    auto resultSet = CreateMockResultSet(config);
    auto mockHelper = CreateMockHelperWithResultSet(resultSet);

    EXPECT_CALL(*mockHelper, Delete(_, _)).Times(0);
    EXPECT_CALL(*mockHelper, Update(_, _, _)).Times(0);

    int32_t result = systemSoundManagerImpl_->ClearNotificationToneType(
        std::static_pointer_cast<DataShare::DataShareHelper>(mockHelper), SOURCE_TYPE_CUSTOMISED);
    EXPECT_EQ(result, 0);
}

/**
 * @tc.name  : ClearBitFromToneTypeColumn_NullResults
 * @tc.number: ClearBitFromToneTypeColumn_004
 * @tc.desc  : Test ClearBitFromToneTypeColumn when Query returns null result set (early return branch)
 */
HWTEST(SystemSoundManagerUnitNextTest, ClearBitFromToneTypeColumn_004, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    auto mockHelper = std::make_shared<OHOS::Media::MockDataShareHelper>();
    ON_CALL(*mockHelper, Query(_, _, _, _))
        .WillByDefault(Return(std::shared_ptr<DataShare::DataShareResultSet>(nullptr)));

    int32_t targetToneType = 1;
    int32_t result = systemSoundManagerImpl_->ClearBitFromToneTypeColumn(
        std::static_pointer_cast<DataShare::DataShareHelper>(mockHelper),
        RINGTONE_COLUMN_RING_TONE_TYPE, RINGTONE_COLUMN_RING_TONE_SOURCE_TYPE,
        targetToneType, SOURCE_TYPE_CUSTOMISED);
    EXPECT_EQ(result, 0);
}

/**
 * @tc.name  : ClearBitFromToneTypeColumn_RemainingZeroCustomised
 * @tc.number: ClearBitFromToneTypeColumn_005
 * @tc.desc  : Test ClearBitFromToneTypeColumn with remaining==0 and customised source type (Delete branch)
 */
HWTEST(SystemSoundManagerUnitNextTest, ClearBitFromToneTypeColumn_005, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    MockResultSetConfig config;
    config.toneId = 3;
    config.sourceType = SOURCE_TYPE_CUSTOMISED;
    config.toneType = TONE_TYPE_RINGTONE;
    config.ringtoneType = 1;
    config.ringtoneSourceType = SOURCE_TYPE_CUSTOMISED;
    auto resultSet = CreateMockResultSet(config);
    auto mockHelper = CreateMockHelperWithResultSet(resultSet);

    EXPECT_CALL(*mockHelper, Delete(_, _)).Times(AtLeast(1));
    EXPECT_CALL(*mockHelper, Update(_, _, _)).Times(0);

    int32_t targetToneType = 1;
    int32_t result = systemSoundManagerImpl_->ClearBitFromToneTypeColumn(
        std::static_pointer_cast<DataShare::DataShareHelper>(mockHelper),
        RINGTONE_COLUMN_RING_TONE_TYPE, RINGTONE_COLUMN_RING_TONE_SOURCE_TYPE,
        targetToneType, SOURCE_TYPE_CUSTOMISED);
    EXPECT_GT(result, 0);
}

/**
 * @tc.name  : ClearBitFromToneTypeColumn_RemainingZeroPreset
 * @tc.number: ClearBitFromToneTypeColumn_006
 * @tc.desc  : Test ClearBitFromToneTypeColumn with remaining==0 and preset source type (Update reset branch)
 */
HWTEST(SystemSoundManagerUnitNextTest, ClearBitFromToneTypeColumn_006, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    MockResultSetConfig config;
    config.toneId = 4;
    config.sourceType = SOURCE_TYPE_PRESET;
    config.toneType = TONE_TYPE_RINGTONE;
    config.ringtoneType = 1;
    config.ringtoneSourceType = SOURCE_TYPE_PRESET;
    auto resultSet = CreateMockResultSet(config);
    auto mockHelper = CreateMockHelperWithResultSet(resultSet);

    EXPECT_CALL(*mockHelper, Delete(_, _)).Times(0);
    EXPECT_CALL(*mockHelper, Update(_, _, _)).Times(AtLeast(1));

    int32_t targetToneType = 1;
    int32_t result = systemSoundManagerImpl_->ClearBitFromToneTypeColumn(
        std::static_pointer_cast<DataShare::DataShareHelper>(mockHelper),
        RINGTONE_COLUMN_RING_TONE_TYPE, RINGTONE_COLUMN_RING_TONE_SOURCE_TYPE,
        targetToneType, SOURCE_TYPE_PRESET);
    EXPECT_GT(result, 0);
}

/**
 * @tc.name  : ClearBitFromToneTypeColumn_RemainingNonZero
 * @tc.number: ClearBitFromToneTypeColumn_007
 * @tc.desc  : Test ClearBitFromToneTypeColumn with remaining!=0 (Update remaining branch)
 */
HWTEST(SystemSoundManagerUnitNextTest, ClearBitFromToneTypeColumn_007, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    MockResultSetConfig config;
    config.toneId = 5;
    config.sourceType = SOURCE_TYPE_CUSTOMISED;
    config.toneType = TONE_TYPE_RINGTONE;
    config.ringtoneType = 3;
    config.ringtoneSourceType = SOURCE_TYPE_CUSTOMISED;
    auto resultSet = CreateMockResultSet(config);
    auto mockHelper = CreateMockHelperWithResultSet(resultSet);

    EXPECT_CALL(*mockHelper, Delete(_, _)).Times(0);
    EXPECT_CALL(*mockHelper, Update(_, _, _)).Times(AtLeast(1));

    int32_t targetToneType = 1;
    int32_t result = systemSoundManagerImpl_->ClearBitFromToneTypeColumn(
        std::static_pointer_cast<DataShare::DataShareHelper>(mockHelper),
        RINGTONE_COLUMN_RING_TONE_TYPE, RINGTONE_COLUMN_RING_TONE_SOURCE_TYPE,
        targetToneType, SOURCE_TYPE_CUSTOMISED);
    EXPECT_GT(result, 0);
}

/**
 * @tc.name  : ClearBitFromToneTypeColumn_ShotToneColumn
 * @tc.number: ClearBitFromToneTypeColumn_008
 * @tc.desc  : Test ClearBitFromToneTypeColumn with shot tone column name (GetShottoneType branch)
 */
HWTEST(SystemSoundManagerUnitNextTest, ClearBitFromToneTypeColumn_008, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    MockResultSetConfig config;
    config.toneId = 6;
    config.sourceType = SOURCE_TYPE_PRESET;
    config.toneType = TONE_TYPE_RINGTONE;
    config.shottoneType = 1;
    config.shotToneSourceType = SOURCE_TYPE_PRESET;
    auto resultSet = CreateMockResultSet(config);
    auto mockHelper = CreateMockHelperWithResultSet(resultSet);

    EXPECT_CALL(*mockHelper, Update(_, _, _)).Times(AtLeast(1));

    int32_t targetToneType = 1;
    int32_t result = systemSoundManagerImpl_->ClearBitFromToneTypeColumn(
        std::static_pointer_cast<DataShare::DataShareHelper>(mockHelper),
        RINGTONE_COLUMN_SHOT_TONE_TYPE, RINGTONE_COLUMN_SHOT_TONE_SOURCE_TYPE,
        targetToneType, SOURCE_TYPE_PRESET);
    EXPECT_GT(result, 0);
}
} // namespace Media
} // namespace OHOS
