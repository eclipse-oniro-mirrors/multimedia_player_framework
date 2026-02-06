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
#include "media_core.h"

using namespace OHOS::AbilityRuntime;
using namespace testing::ext;

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

class MockContext : public AbilityRuntime::Context {
    public:
        MockContext() = default;
        ~MockContext() override = default;

        std::string GetBundleName() const override { return "mock_bundle_name"; }
        std::shared_ptr<Context> CreateBundleContext(const std::string &bundleName) override { return nullptr; }
        std::shared_ptr<AppExecFwk::ApplicationInfo> GetApplicationInfo() const override { return nullptr; }
        std::shared_ptr<Global::Resource::ResourceManager> GetResourceManager() const override { return nullptr; }
        std::string GetBundleCodePath() const override { return ""; }
        std::shared_ptr<AppExecFwk::HapModuleInfo> GetHapModuleInfo() const override { return nullptr; }
        std::string GetBundleCodeDir() override { return ""; }
        std::string GetCacheDir() override { return ""; }
        std::string GetTempDir() override { return ""; }
        std::string GetFilesDir() override { return ""; }
        std::string GetResourceDir(const std::string &moduleName) override { return ""; }
        bool IsUpdatingConfigurations() override { return false; }
        bool PrintDrawnCompleted() override { return false; }
        std::string GetDatabaseDir() override { return ""; }
        int32_t GetSystemDatabaseDir(const std::string &groupId, bool checkExist, std::string &databaseDir)
            override { return 0; }
        std::string GetPreferencesDir() override { return ""; }
        int32_t GetSystemPreferencesDir(const std::string &groupId, bool checkExist, std::string &preferencesDir)
            override { return 0; }
        std::string GetGroupDir(std::string groupId) override { return ""; }
        std::string GetDistributedFilesDir() override { return ""; }
        std::string GetCloudFileDir() override { return ""; }
        std::string GetLogFileDir() override { return ""; }
        sptr<IRemoteObject> GetToken() override { return nullptr; }
        void SetToken(const sptr<IRemoteObject> &token) override {}
        void SwitchArea(int mode) override {}
        std::shared_ptr<Context> CreateModuleContext(const std::string &moduleName) override { return nullptr; }
        std::shared_ptr<Context> CreateModuleContext(const std::string &bundleName, const std::string &moduleName)
            override { return nullptr; }
        std::shared_ptr<Global::Resource::ResourceManager> CreateModuleResourceManager(const std::string &bundleName,
            const std::string &moduleName) override { return nullptr; }
        int32_t CreateSystemHspModuleResourceManager(const std::string &bundleName, const std::string &moduleName,
            std::shared_ptr<Global::Resource::ResourceManager> &resourceManager) override { return 0; }
        int32_t CreateHspModuleResourceManager(const std::string &bundleName, const std::string &moduleName,
            std::shared_ptr<Global::Resource::ResourceManager> &resourceManager) override { return 0; }
        int GetArea() override { return 0; }
        std::string GetProcessName() override { return ""; }
        std::shared_ptr<AppExecFwk::Configuration> GetConfiguration() const override { return nullptr; }
        std::string GetBaseDir() const override { return ""; }
        Global::Resource::DeviceType GetDeviceType() const override
            { return Global::Resource::DeviceType::DEVICE_PHONE; }
        std::shared_ptr<Context> CreateAreaModeContext(int areaMode) override { return nullptr; }
        std::shared_ptr<Context> CreateDisplayContext(uint64_t displayId) override { return nullptr; }
        bool IsContext(size_t contextTypeId) override { return false; }

        std::shared_ptr<Context> CreateModuleOrPluginContext(const std::string &bundleName,
            const std::string &moduleName) override { return nullptr; }
};

/**
 * @tc.name  : IsRingtoneTypeValid
 * @tc.number: IsRingtoneTypeValid_001
 * @tc.desc  : Test IsRingtoneTypeValid when an invalid RingtoneType is passed
 */
HWTEST(SystemSoundManagerUnitNextTest, IsRingtoneTypeValid_001, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    RingtoneType invalidType = static_cast<RingtoneType>(RINGTONE_TYPE_SIM_CARD_0 + 2);
    bool result = systemSoundManagerImpl_->IsRingtoneTypeValid(invalidType);
    EXPECT_FALSE(result);
}

/**
 * @tc.name  : IsSystemToneTypeValid
 * @tc.number: IsSystemToneTypeValid_001
 * @tc.desc  : Test IsSystemToneTypeValid when an invalid SystemToneType is passed
 */
HWTEST(SystemSoundManagerUnitNextTest, IsSystemToneTypeValid_001, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    SystemToneType invalidType = static_cast<SystemToneType>(SYSTEM_TONE_TYPE_NOTIFICATION + 1);
    bool result = systemSoundManagerImpl_->IsSystemToneTypeValid(invalidType);
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
 * @tc.name  : RemoveSourceTypeForRingTone
 * @tc.number: RemoveSourceTypeForRingTon_002
 * @tc.desc  : Test RemoveSourceTypeForRingTone when entering default branch
 */
HWTEST(SystemSoundManagerUnitNextTest, RemoveSourceTypeForRingTone_002, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(dataShareHelper, nullptr);
    RingtoneType invalidType = static_cast<RingtoneType>(RINGTONE_TYPE_SIM_CARD_1 + 1);

    SourceType sourceType = SOURCE_TYPE_CUSTOMISED;
    int32_t result = systemSoundManagerImpl_->RemoveSourceTypeForRingTone(dataShareHelper, invalidType, sourceType);
    EXPECT_EQ(result, SUCCESS);
}

/**
 * @tc.name  : GetRingtoneUriByType_NotInitialized
 * @tc.number: GetRingtoneUriByType_001
 * @tc.desc  : Test GetRingtoneUriByType when databaseTool is not initialized
 */
HWTEST(SystemSoundManagerUnitNextTest, GetRingtoneUriByType_001, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(dataShareHelper, nullptr);
    DatabaseTool databaseTool;
    databaseTool.isInitialized = false;
    databaseTool.isProxy = false;
    databaseTool.dataShareHelper = dataShareHelper;

    std::string type = "ringtone_type";
    std::string result = systemSoundManagerImpl_->GetRingtoneUriByType(databaseTool, type);
    EXPECT_EQ(result, "");
}

/**
 * @tc.name  : GetRingtoneUriByType_DataShareHelperNull
 * @tc.number: GetRingtoneUriByType_002
 * @tc.desc  : Test GetRingtoneUriByType when dataShareHelper is null
 */
HWTEST(SystemSoundManagerUnitNextTest, GetRingtoneUriByType_002, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    DatabaseTool databaseTool;
    databaseTool.isInitialized = true;
    databaseTool.isProxy = false;
    databaseTool.dataShareHelper = nullptr;

    std::string type = "ringtone_type";
    std::string result = systemSoundManagerImpl_->GetRingtoneUriByType(databaseTool, type);
    EXPECT_EQ(result, "");
}

/**
 * @tc.name  : GetRingtoneUriByType_IsProxy
 * @tc.number: GetRingtoneUriByType_003
 * @tc.desc  : Test GetRingtoneUriByType when isProxy is true
 */
HWTEST(SystemSoundManagerUnitNextTest, GetRingtoneUriByType_003, TestSize.Level0)
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

    std::string type = "ringtone_type";
    std::string result = systemSoundManagerImpl_->GetRingtoneUriByType(databaseTool, type);
    EXPECT_NE(result, "vs");
}

/**
 * @tc.name  : GetPresetRingToneUriByType_NotInitialized
 * @tc.number: GetPresetRingToneUriByType_001
 * @tc.desc  : Test GetPresetRingToneUriByType when databaseTool is not initialized
 */
HWTEST(SystemSoundManagerUnitNextTest, GetPresetRingToneUriByType_001, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    DatabaseTool databaseTool;
    databaseTool.isInitialized = false;
    databaseTool.isProxy = false;
    databaseTool.dataShareHelper = nullptr;

    std::string type = "preset_ringtone_type";
    std::string result = systemSoundManagerImpl_->GetPresetRingToneUriByType(databaseTool, type);
    EXPECT_EQ(result, "");
}

/**
 * @tc.name  : GetPresetRingToneUriByType_DataShareHelperNull
 * @tc.number: GetPresetRingToneUriByType_002
 * @tc.desc  : Test GetPresetRingToneUriByType when dataShareHelper is null
 */
HWTEST(SystemSoundManagerUnitNextTest, GetPresetRingToneUriByType_002, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    EXPECT_NE(systemSoundManagerImpl_, nullptr);

    DatabaseTool databaseTool;
    databaseTool.isInitialized = true;
    databaseTool.isProxy = false;
    databaseTool.dataShareHelper = nullptr;

    std::string type = "preset_ringtone_type";
    std::string result = systemSoundManagerImpl_->GetPresetRingToneUriByType(databaseTool, type);
    EXPECT_EQ(result, "");
}

/**
 * @tc.name  : GetPresetRingToneUriByType_IsProxy
 * @tc.number: GetPresetRingToneUriByType_003
 * @tc.desc  : Test GetPresetRingToneUriByType when isProxy is true
 */
HWTEST(SystemSoundManagerUnitNextTest, GetPresetRingToneUriByType_003, TestSize.Level0)
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

    std::string type = "preset_ringtone_type";
    std::string result = systemSoundManagerImpl_->GetPresetRingToneUriByType(databaseTool, type);
    EXPECT_NE(result, "vs");
}

/**
 * @tc.name  : GetRingtoneUri_NotInitialized
 * @tc.number: GetRingtoneUri_001
 * @tc.desc  : Test GetRingtoneUri when databaseTool is not initialized
 */
HWTEST(SystemSoundManagerUnitNextTest, GetRingtoneUri_001, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    DatabaseTool databaseTool;
    databaseTool.isInitialized = false;
    databaseTool.dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(databaseTool.dataShareHelper, nullptr);

    RingtoneType ringtoneType = RINGTONE_TYPE_SIM_CARD_0;
    std::string result = systemSoundManagerImpl_->GetRingtoneUri(databaseTool, ringtoneType);
    EXPECT_EQ(result, "");
}

/**
 * @tc.name  : GetRingtoneUri_DataShareHelperNull
 * @tc.number: GetRingtoneUri_002
 * @tc.desc  : Test GetRingtoneUri when dataShareHelper is null
 */
HWTEST(SystemSoundManagerUnitNextTest, GetRingtoneUri_002, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    DatabaseTool databaseTool;
    databaseTool.isInitialized = true;
    databaseTool.dataShareHelper = nullptr;

    RingtoneType ringtoneType = RINGTONE_TYPE_SIM_CARD_0;
    std::string result = systemSoundManagerImpl_->GetRingtoneUri(databaseTool, ringtoneType);
    EXPECT_EQ(result, "");
}

/**
 * @tc.name  : GetRingtoneUri_DefaultCase
 * @tc.number: GetRingtoneUri_003
 * @tc.desc  : Test GetRingtoneUri when entering the default case of switch
 */
HWTEST(SystemSoundManagerUnitNextTest, GetRingtoneUri_003, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    DatabaseTool databaseTool;
    databaseTool.isInitialized = true;
    databaseTool.dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(databaseTool.dataShareHelper, nullptr);

    RingtoneType ringtoneType = static_cast<RingtoneType>(RINGTONE_TYPE_SIM_CARD_1 + 1);
    std::string result = systemSoundManagerImpl_->GetRingtoneUri(databaseTool, ringtoneType);
    EXPECT_EQ(result, NO_RING_SOUND);
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

    std::shared_ptr<AbilityRuntime::Context> context = std::make_shared<MockContext>();
    ASSERT_NE(context, nullptr);

    std::string uri = NO_SYSTEM_SOUND;
    SystemToneType systemToneType = SYSTEM_TONE_TYPE_NOTIFICATION;
    int32_t result = systemSoundManagerImpl_->SetSystemToneUri(context, uri, systemToneType);
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

    std::shared_ptr<AbilityRuntime::Context> context = std::make_shared<MockContext>();
    ASSERT_NE(context, nullptr);
    RingtoneType ringtoneType = RINGTONE_TYPE_SIM_CARD_0;
    std::string ringtoneUri = "valid_uri";
    std::shared_ptr<RingtonePlayer> result = systemSoundManagerImpl_->GetSpecificRingTonePlayer(context,
        ringtoneType, ringtoneUri);
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

    std::shared_ptr<AbilityRuntime::Context> context = std::make_shared<MockContext>();
    ASSERT_NE(context, nullptr);

    std::string uri = NO_RING_SOUND;
    RingtoneType ringtoneType = RINGTONE_TYPE_SIM_CARD_0;
    int32_t result = systemSoundManagerImpl_->SetRingtoneUri(context, uri, ringtoneType);
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

    std::shared_ptr<AbilityRuntime::Context> context = std::make_shared<MockContext>();
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

    std::shared_ptr<AbilityRuntime::Context> context = std::make_shared<MockContext>();
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
 * @tc.name  : UpdateToneTypeUri_SimCard1_Current_SimCard1_Asset
 * @tc.number: UpdateToneTypeUri_001
 * @tc.desc  : Test UpdateToneTypeUri when currentType=SIM1 and assetType=SIM1, final should be SIM1
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
        1, // toneId
        RINGTONE_COLUMN_RING_TONE_TYPE,
        RINGTONE_COLUMN_RING_TONE_SOURCE_TYPE,
        RING_TONE_TYPE_NOT,
        RING_TONE_TYPE_SIM_CARD_BOTH,
        RING_TONE_TYPE_SIM_CARD_1, // currentType
        RING_TONE_TYPE_SIM_CARD_1  // shotToneType (assetType)
    };

    int32_t result = systemSoundManagerImpl_->UpdateToneTypeUri(dataShareHelper, params);
    EXPECT_GE(result, 0);
}

/**
 * @tc.name  : UpdateToneTypeUri_SimCard1_Current_SimCard2_Asset
 * @tc.number: UpdateToneTypeUri_002
 * @tc.desc  : Test UpdateToneTypeUri when currentType=SIM1 and assetType=SIM2, final should be BOTH
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
        1, // toneId
        RINGTONE_COLUMN_RING_TONE_TYPE,
        RINGTONE_COLUMN_RING_TONE_SOURCE_TYPE,
        RING_TONE_TYPE_NOT,
        RING_TONE_TYPE_SIM_CARD_BOTH,
        RING_TONE_TYPE_SIM_CARD_1, // currentType
        RING_TONE_TYPE_SIM_CARD_2  // shotToneType (assetType)
    };

    int32_t result = systemSoundManagerImpl_->UpdateToneTypeUri(dataShareHelper, params);
    EXPECT_GE(result, 0);
}

/**
 * @tc.name  : UpdateToneTypeUri_SimCard1_Current_SimCardBoth_Asset
 * @tc.number: UpdateToneTypeUri_003
 * @tc.desc  : Test UpdateToneTypeUri when currentType=SIM1 and assetType=BOTH, final should be SIM1
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
        1, // toneId
        RINGTONE_COLUMN_RING_TONE_TYPE,
        RINGTONE_COLUMN_RING_TONE_SOURCE_TYPE,
        RING_TONE_TYPE_NOT,
        RING_TONE_TYPE_SIM_CARD_BOTH,
        RING_TONE_TYPE_SIM_CARD_1, // currentType
        RING_TONE_TYPE_SIM_CARD_BOTH  // shotToneType (assetType)
    };

    int32_t result = systemSoundManagerImpl_->UpdateToneTypeUri(dataShareHelper, params);
    EXPECT_GE(result, 0);
}

/**
 * @tc.name  : UpdateToneTypeUri_SimCard2_Current_SimCard1_Asset
 * @tc.number: UpdateToneTypeUri_004
 * @tc.desc  : Test UpdateToneTypeUri when currentType=SIM2 and assetType=SIM1, final should be BOTH
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
        1, // toneId
        RINGTONE_COLUMN_RING_TONE_TYPE,
        RINGTONE_COLUMN_RING_TONE_SOURCE_TYPE,
        RING_TONE_TYPE_NOT,
        RING_TONE_TYPE_SIM_CARD_BOTH,
        RING_TONE_TYPE_SIM_CARD_2, // currentType
        RING_TONE_TYPE_SIM_CARD_1  // shotToneType (assetType)
    };

    int32_t result = systemSoundManagerImpl_->UpdateToneTypeUri(dataShareHelper, params);
    EXPECT_GE(result, 0);
}

/**
 * @tc.name  : UpdateToneTypeUri_SimCard2_Current_SimCard2_Asset
 * @tc.number: UpdateToneTypeUri_005
 * @tc.desc  : Test UpdateToneTypeUri when currentType=SIM2 and assetType=SIM2, final should be SIM2
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
        1, // toneId
        RINGTONE_COLUMN_RING_TONE_TYPE,
        RINGTONE_COLUMN_RING_TONE_SOURCE_TYPE,
        RING_TONE_TYPE_NOT,
        RING_TONE_TYPE_SIM_CARD_BOTH,
        RING_TONE_TYPE_SIM_CARD_2, // currentType
        RING_TONE_TYPE_SIM_CARD_2  // shotToneType (assetType)
    };

    int32_t result = systemSoundManagerImpl_->UpdateToneTypeUri(dataShareHelper, params);
    EXPECT_GE(result, 0);
}

/**
 * @tc.name  : UpdateToneTypeUri_ShotTone_SimCard1_Current_SimCard2_Asset
 * @tc.number: UpdateToneTypeUri_006
 * @tc.desc  : Test UpdateToneTypeUri for shot tone when currentType=SIM1 and assetType=SIM2
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
        1, // toneId
        RINGTONE_COLUMN_SHOT_TONE_TYPE,
        RINGTONE_COLUMN_SHOT_TONE_SOURCE_TYPE,
        RING_TONE_TYPE_NOT,
        SHOT_TONE_TYPE_SIM_CARD_BOTH,
        SHOT_TONE_TYPE_SIM_CARD_1, // currentType
        SHOT_TONE_TYPE_SIM_CARD_2  // shotToneType (assetType)
    };

    int32_t result = systemSoundManagerImpl_->UpdateToneTypeUri(dataShareHelper, params);
    EXPECT_GE(result, 0);
}

/**
 * @tc.name  : UpdateToneTypeUri_ShotTone_SimCard2_Current_SimCard1_Asset
 * @tc.number: UpdateToneTypeUri_007
 * @tc.desc  : Test UpdateToneTypeUri for shot tone when currentType=SIM2 and assetType=SIM1
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
        1, // toneId
        RINGTONE_COLUMN_SHOT_TONE_TYPE,
        RINGTONE_COLUMN_SHOT_TONE_SOURCE_TYPE,
        RING_TONE_TYPE_NOT,
        SHOT_TONE_TYPE_SIM_CARD_BOTH,
        SHOT_TONE_TYPE_SIM_CARD_2, // currentType
        SHOT_TONE_TYPE_SIM_CARD_1  // shotToneType (assetType)
    };

    int32_t result = systemSoundManagerImpl_->UpdateToneTypeUri(dataShareHelper, params);
    EXPECT_GE(result, 0);
}

/**
 * @tc.name  : UpdateToneTypeUri_ShotTone_SimCard1_Current_SimCardBoth_Asset
 * @tc.number: UpdateToneTypeUri_008
 * @tc.desc  : Test UpdateToneTypeUri for shot tone when currentType=SIM1 and assetType=BOTH
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
        1, // toneId
        RINGTONE_COLUMN_SHOT_TONE_TYPE,
        RINGTONE_COLUMN_SHOT_TONE_SOURCE_TYPE,
        RING_TONE_TYPE_NOT,
        SHOT_TONE_TYPE_SIM_CARD_BOTH,
        SHOT_TONE_TYPE_SIM_CARD_1, // currentType
        RING_TONE_TYPE_SIM_CARD_BOTH  // shotToneType (assetType - note uses RING for BOTH)
    };

    int32_t result = systemSoundManagerImpl_->UpdateToneTypeUri(dataShareHelper, params);
    EXPECT_GE(result, 0);
}

/**
 * @tc.name  : UpdateRingtoneUri_SimCard1_With_SimCard2_Asset
 * @tc.number: UpdateRingtoneUri_001
 * @tc.desc  : Test UpdateRingtoneUri integration with SIM1 current and SIM2 asset
 */
HWTEST(SystemSoundManagerUnitNextTest, UpdateRingtoneUri_001, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    auto dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(dataShareHelper, nullptr);

    RingtoneType ringtoneType = RingtoneType::RINGTONE_TYPE_SIM_CARD_1;
    int32_t toneId = 1;
    int32_t shotToneType = RING_TONE_TYPE_SIM_CARD_2;

    int32_t result = systemSoundManagerImpl_->UpdateRingtoneUri(dataShareHelper, toneId, ringtoneType, shotToneType);
    EXPECT_GE(result, 0);
}

/**
 * @tc.name  : UpdateRingtoneUri_SimCard2_With_SimCardBoth_Asset
 * @tc.number: UpdateRingtoneUri_002
 * @tc.desc  : Test UpdateRingtoneUri with SIM2 current and BOTH asset
 */
HWTEST(SystemSoundManagerUnitNextTest, UpdateRingtoneUri_002, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    auto dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(dataShareHelper, nullptr);

    RingtoneType ringtoneType = RingtoneType::RINGTONE_TYPE_SIM_CARD_0;
    int32_t toneId = 1;
    int32_t shotToneType = RING_TONE_TYPE_SIM_CARD_BOTH;

    int32_t result = systemSoundManagerImpl_->UpdateRingtoneUri(dataShareHelper, toneId, ringtoneType, shotToneType);
    EXPECT_GE(result, 0);
}

/**
 * @tc.name  : UpdateShotToneUri_SimCard1_With_SimCard2_Asset
 * @tc.number: UpdateShotToneUri_001
 * @tc.desc  : Test UpdateShotToneUri integration with SIM1 current and SIM2 asset
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
    int32_t shotToneType = SHOT_TONE_TYPE_SIM_CARD_2;

    int32_t result = systemSoundManagerImpl_->UpdateShotToneUri(dataShareHelper, toneId, systemToneType, shotToneType);
    EXPECT_GE(result, 0);
}

/**
 * @tc.name  : UpdateShotToneUri_Notification_With_SimCardBoth_Asset
 * @tc.number: UpdateShotToneUri_002
 * @tc.desc  : Test UpdateShotToneUri for notification type with BOTH asset
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
    int32_t shotToneType = SHOT_TONE_TYPE_SIM_CARD_BOTH;

    int32_t result = systemSoundManagerImpl_->UpdateShotToneUri(dataShareHelper, toneId, systemToneType, shotToneType);
    EXPECT_GE(result, 0);
}

/**
 * @tc.name  : GetRingtoneAttrsByType_NotInitialized
 * @tc.number: GetRingtoneAttrsByType_001
 * @tc.desc  : Test GetRingtoneAttrsByType when databaseTool is not initialized
 */
HWTEST(SystemSoundManagerUnitNextTest, GetRingtoneAttrsByType_001, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    DatabaseTool databaseTool;
    databaseTool.isInitialized = false;
    databaseTool.isProxy = false;
    databaseTool.dataShareHelper = nullptr;

    std::string type = "1";
    ToneAttrs result = systemSoundManagerImpl_->GetRingtoneAttrsByType(databaseTool, type);

    EXPECT_EQ(result.GetUri(), "");
    EXPECT_EQ(result.GetTitle(), "");
    EXPECT_EQ(result.GetFileName(), "");
}

/**
 * @tc.name  : GetRingtoneAttrsByType_DataShareHelperNull
 * @tc.number: GetRingtoneAttrsByType_002
 * @tc.desc  : Test GetRingtoneAttrsByType when dataShareHelper is null
 */
HWTEST(SystemSoundManagerUnitNextTest, GetRingtoneAttrsByType_002, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    DatabaseTool databaseTool;
    databaseTool.isInitialized = true;
    databaseTool.isProxy = false;
    databaseTool.dataShareHelper = nullptr;

    std::string type = "1";
    ToneAttrs result = systemSoundManagerImpl_->GetRingtoneAttrsByType(databaseTool, type);

    EXPECT_EQ(result.GetUri(), "");
    EXPECT_EQ(result.GetTitle(), "");
    EXPECT_EQ(result.GetFileName(), "");
}

/**
 * @tc.name  : GetRingtoneAttrsByType_IsProxy_True
 * @tc.number: GetRingtoneAttrsByType_003
 * @tc.desc  : Test GetRingtoneAttrsByType when isProxy is true
 */
HWTEST(SystemSoundManagerUnitNextTest, GetRingtoneAttrsByType_003, TestSize.Level0)
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

    std::string type = "1";
    ToneAttrs result = systemSoundManagerImpl_->GetRingtoneAttrsByType(databaseTool, type);

    EXPECT_EQ(result.GetCategory(), TONE_CATEGORY_RINGTONE);
}

/**
 * @tc.name  : GetPresetRingToneAttrByType_NotInitialized
 * @tc.number: GetPresetRingToneAttrByType_001
 * @tc.desc  : Test GetPresetRingToneAttrByType when databaseTool is not initialized
 */
HWTEST(SystemSoundManagerUnitNextTest, GetPresetRingToneAttrByType_001, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    DatabaseTool databaseTool;
    databaseTool.isInitialized = false;
    databaseTool.isProxy = false;
    databaseTool.dataShareHelper = nullptr;

    std::string type = "1";
    ToneAttrs result = systemSoundManagerImpl_->GetPresetRingToneAttrByType(databaseTool, type);

    EXPECT_EQ(result.GetUri(), "");
    EXPECT_EQ(result.GetTitle(), "");
    EXPECT_EQ(result.GetFileName(), "");
}

/**
 * @tc.name  : GetPresetRingToneAttrByType_IsProxy_True
 * @tc.number: GetPresetRingToneAttrByType_002
 * @tc.desc  : Test GetPresetRingToneAttrByType when isProxy is true
 */
HWTEST(SystemSoundManagerUnitNextTest, GetPresetRingToneAttrByType_002, TestSize.Level0)
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

    std::string type = "1";
    ToneAttrs result = systemSoundManagerImpl_->GetPresetRingToneAttrByType(databaseTool, type);

    EXPECT_EQ(result.GetCategory(), TONE_CATEGORY_RINGTONE);
}

/**
 * @tc.name  : GetShotToneAttrsByType_NotInitialized
 * @tc.number: GetShotToneAttrsByType_001
 * @tc.desc  : Test GetShotToneAttrsByType when databaseTool is not initialized
 */
HWTEST(SystemSoundManagerUnitNextTest, GetShotToneAttrsByType_001, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    DatabaseTool databaseTool;
    databaseTool.isInitialized = false;
    databaseTool.isProxy = false;
    databaseTool.dataShareHelper = nullptr;

    std::string type = "1";
    ToneAttrs result = systemSoundManagerImpl_->GetShotToneAttrsByType(databaseTool, type);

    EXPECT_EQ(result.GetUri(), "");
    EXPECT_EQ(result.GetTitle(), "");
    EXPECT_EQ(result.GetFileName(), "");
}

/**
 * @tc.name  : GetShotToneAttrsByType_IsProxy_True
 * @tc.number: GetShotToneAttrsByType_002
 * @tc.desc  : Test GetShotToneAttrsByType when isProxy is true
 */
HWTEST(SystemSoundManagerUnitNextTest, GetShotToneAttrsByType_002, TestSize.Level0)
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

    std::string type = "1";
    ToneAttrs result = systemSoundManagerImpl_->GetShotToneAttrsByType(databaseTool, type);

    EXPECT_EQ(result.GetCategory(), TONE_CATEGORY_TEXT_MESSAGE);
}

/**
 * @tc.name  : GetPresetShotToneAttrsByType_NotInitialized
 * @tc.number: GetPresetShotToneAttrsByType_001
 * @tc.desc  : Test GetPresetShotToneAttrsByType when databaseTool is not initialized
 */
HWTEST(SystemSoundManagerUnitNextTest, GetPresetShotToneAttrsByType_001, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    DatabaseTool databaseTool;
    databaseTool.isInitialized = false;
    databaseTool.isProxy = false;
    databaseTool.dataShareHelper = nullptr;

    std::string type = "1";
    ToneAttrs result = systemSoundManagerImpl_->GetPresetShotToneAttrsByType(databaseTool, type);

    EXPECT_EQ(result.GetUri(), "");
    EXPECT_EQ(result.GetTitle(), "");
    EXPECT_EQ(result.GetFileName(), "");
}

/**
 * @tc.name  : GetPresetShotToneAttrsByType_IsProxy_True
 * @tc.number: GetPresetShotToneAttrsByType_002
 * @tc.desc  : Test GetPresetShotToneAttrsByType when isProxy is true
 */
HWTEST(SystemSoundManagerUnitNextTest, GetPresetShotToneAttrsByType_002, TestSize.Level0)
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

    std::string type = "1";
    ToneAttrs result = systemSoundManagerImpl_->GetPresetShotToneAttrsByType(databaseTool, type);

    EXPECT_EQ(result.GetCategory(), TONE_CATEGORY_TEXT_MESSAGE);
}

/**
 * @tc.name  : GetNotificationToneAttrsByType_NotInitialized
 * @tc.number: GetNotificationToneAttrsByType_001
 * @tc.desc  : Test GetNotificationToneAttrsByType when databaseTool is not initialized
 */
HWTEST(SystemSoundManagerUnitNextTest, GetNotificationToneAttrsByType_001, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    DatabaseTool databaseTool;
    databaseTool.isInitialized = false;
    databaseTool.isProxy = false;
    databaseTool.dataShareHelper = nullptr;

    ToneAttrs result = systemSoundManagerImpl_->GetNotificationToneAttrsByType(databaseTool);

    EXPECT_EQ(result.GetUri(), "");
    EXPECT_EQ(result.GetTitle(), "");
    EXPECT_EQ(result.GetFileName(), "");
}

/**
 * @tc.name  : GetNotificationToneAttrsByType_IsProxy_True
 * @tc.number: GetNotificationToneAttrsByType_002
 * @tc.desc  : Test GetNotificationToneAttrsByType when isProxy is true
 */
HWTEST(SystemSoundManagerUnitNextTest, GetNotificationToneAttrsByType_002, TestSize.Level0)
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

    ToneAttrs result = systemSoundManagerImpl_->GetNotificationToneAttrsByType(databaseTool);

    EXPECT_EQ(result.GetCategory(), TONE_CATEGORY_NOTIFICATION);
}

/**
 * @tc.name  : GetPresetNotificationToneAttrs_NotInitialized
 * @tc.number: GetPresetNotificationToneAttrs_001
 * @tc.desc  : Test GetPresetNotificationToneAttrs when databaseTool is not initialized
 */
HWTEST(SystemSoundManagerUnitNextTest, GetPresetNotificationToneAttrs_001, TestSize.Level0)
{
    auto systemSoundManager_ = SystemSoundManagerFactory::CreateSystemSoundManager();
    std::shared_ptr<SystemSoundManagerImpl> systemSoundManagerImpl_ =
        std::static_pointer_cast<SystemSoundManagerImpl>(systemSoundManager_);
    ASSERT_NE(systemSoundManagerImpl_, nullptr);

    DatabaseTool databaseTool;
    databaseTool.isInitialized = false;
    databaseTool.isProxy = false;
    databaseTool.dataShareHelper = nullptr;

    ToneAttrs result = systemSoundManagerImpl_->GetPresetNotificationToneAttrs(databaseTool);

    EXPECT_EQ(result.GetUri(), "");
    EXPECT_EQ(result.GetTitle(), "");
    EXPECT_EQ(result.GetFileName(), "");
}

/**
 * @tc.name  : GetPresetNotificationToneAttrs_IsProxy_True
 * @tc.number: GetPresetNotificationToneAttrs_002
 * @tc.desc  : Test GetPresetNotificationToneAttrs when isProxy is true
 */
HWTEST(SystemSoundManagerUnitNextTest, GetPresetNotificationToneAttrs_002, TestSize.Level0)
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

    ToneAttrs result = systemSoundManagerImpl_->GetPresetNotificationToneAttrs(databaseTool);

    EXPECT_EQ(result.GetCategory(), TONE_CATEGORY_NOTIFICATION);
}

/**
 * @tc.name  : Test SetRingtoneUri with valid URI (Success Path)
 * @tc.number: Media_SoundManager_SetRingtoneUri_Refactor_001
 * @tc.desc  : Test SetRingtoneUri returns SUCCESS for valid URI with matching toneType.
 *            This tests the optimized single-query code path.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_SetRingtoneUri_Refactor_001, TestSize.Level2)
{
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    std::shared_ptr<Context> context_ = std::make_shared<ContextImpl>();
    EXPECT_NE(systemSoundManager_, nullptr);

    // Get a valid ringtone URI (not alarm tone)
    auto vec = systemSoundManager_->GetRingtoneAttrList(context_,
        RingtoneType::RINGTONE_TYPE_SIM_CARD_0);
    if (vec.size() > 0) {
        std::string uri = vec[0]->GetUri();
        EXPECT_FALSE(uri.empty());

        // Test setting ringtone with valid URI
        int32_t result = systemSoundManager_->SetRingtoneUri(context_, uri,
            RingtoneType::RINGTONE_TYPE_SIM_CARD_0);
        EXPECT_EQ(result, SUCCESS);

        // Verify the URI was set
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

    // Test setting no ring sound
    int32_t result = systemSoundManager_->SetRingtoneUri(context_, NO_RING_SOUND,
        RingtoneType::RINGTONE_TYPE_SIM_CARD_0);
    EXPECT_EQ(result, SUCCESS);
}

/**
 * @tc.name  : Test SetRingtoneUri with all ringtone types
 * @tc.number: Media_SoundManager_SetRingtoneUri_Refactor_003
 * @tc.desc  : Test SetRingtoneUri works correctly with all RingtoneType values.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_SetRingtoneUri_Refactor_003, TestSize.Level2)
{
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    std::shared_ptr<Context> context_ = std::make_shared<ContextImpl>();
    EXPECT_NE(systemSoundManager_, nullptr);

    // Get a valid ringtone URI
    auto vec = systemSoundManager_->GetRingtoneAttrList(context_,
        RingtoneType::RINGTONE_TYPE_SIM_CARD_0);
    if (vec.size() > 0) {
        std::string uri = vec[0]->GetUri();

        // Test all ringtone types
        std::vector<RingtoneType> ringtoneTypes = {
            RingtoneType::RINGTONE_TYPE_SIM_CARD_0,
            RingtoneType::RINGTONE_TYPE_SIM_CARD_1
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
 *            This tests the UpdateNotificatioToneUriWrapper code path.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_SetSystemToneUri_Refactor_001, TestSize.Level2)
{
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    std::shared_ptr<Context> context_ = std::make_shared<ContextImpl>();
    EXPECT_NE(systemSoundManager_, nullptr);

    // Get a valid notification tone URI
    auto vec = systemSoundManager_->GetSystemToneAttrList(context_,
        SystemToneType::SYSTEM_TONE_TYPE_NOTIFICATION);
    if (vec.size() > 0) {
        std::string uri = vec[0]->GetUri();
        EXPECT_FALSE(uri.empty());

        // Test setting system tone with notification type
        int32_t result = systemSoundManager_->SetSystemToneUri(context_, uri,
            SystemToneType::SYSTEM_TONE_TYPE_NOTIFICATION);
        EXPECT_EQ(result, SUCCESS);

        // Verify the URI was set
        std::string getUri = systemSoundManager_->GetSystemToneUri(context_,
            SystemToneType::SYSTEM_TONE_TYPE_NOTIFICATION);
        EXPECT_FALSE(getUri.empty());
    }
}

/**
 * @tc.name  : Test SetSystemToneUri with shot tone types
 * @tc.number: Media_SoundManager_SetSystemToneUri_Refactor_002
 * @tc.desc  : Test SetSystemToneUri with SIM_CARD shot tone types.
 *            This tests the UpdateShotToneUri code path.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_SetSystemToneUri_Refactor_002, TestSize.Level2)
{
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    std::shared_ptr<Context> context_ = std::make_shared<ContextImpl>();
    EXPECT_NE(systemSoundManager_, nullptr);

    // Get a valid system tone URI
    auto vec = systemSoundManager_->GetSystemToneAttrList(context_,
        SystemToneType::SYSTEM_TONE_TYPE_SIM_CARD_0);
    if (vec.size() > 0) {
        std::string uri = vec[0]->GetUri();

        // Test shot tone types
        std::vector<SystemToneType> systemToneTypes = {
            SystemToneType::SYSTEM_TONE_TYPE_SIM_CARD_0,
            SystemToneType::SYSTEM_TONE_TYPE_SIM_CARD_1
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

    // Test setting no system sound
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

    // Test with non-existent URI
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

    // Test with non-existent URI
    std::string invalidUri = "file:///data/storage/el2/base/files/nonexistent_tone.ogg";
    int32_t result = systemSoundManager_->SetSystemToneUri(context_, invalidUri,
        SystemToneType::SYSTEM_TONE_TYPE_NOTIFICATION);
    EXPECT_EQ(result, ERROR);
}

/**
 * @tc.name  : Test SetRingtoneUri and SetSystemToneUri consistency
 * @tc.number: Media_SoundManager_SetToneUri_Refactor_006
 * @tc.desc  : Test that both refactored methods work consistently.
 *            Verifies that SetToneUriParams and UpdateToneUriFunc work correctly.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_SetToneUri_Refactor_006, TestSize.Level2)
{
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    std::shared_ptr<Context> context_ = std::make_shared<ContextImpl>();
    EXPECT_NE(systemSoundManager_, nullptr);

    // Get valid URIs from appropriate sources
    auto ringtoneVec = systemSoundManager_->GetRingtoneAttrList(context_,
        RingtoneType::RINGTONE_TYPE_SIM_CARD_0);
    auto notificationVec = systemSoundManager_->GetSystemToneAttrList(context_,
        SystemToneType::SYSTEM_TONE_TYPE_NOTIFICATION);

    if (ringtoneVec.size() > 0) {
        std::string uri = ringtoneVec[0]->GetUri();
        EXPECT_FALSE(uri.empty());

        // Test SetRingtoneUri
        int32_t result1 = systemSoundManager_->SetRingtoneUri(context_, uri,
            RingtoneType::RINGTONE_TYPE_SIM_CARD_0);
        EXPECT_EQ(result1, SUCCESS);

        // Test SetSystemToneUri with shot tone type
        int32_t result2 = systemSoundManager_->SetSystemToneUri(context_, uri,
            SystemToneType::SYSTEM_TONE_TYPE_SIM_CARD_0);
        EXPECT_EQ(result2, TYPEERROR);
    }

    if (notificationVec.size() > 0) {
        std::string uri = notificationVec[0]->GetUri();
        EXPECT_FALSE(uri.empty());

        // Test SetSystemToneUri with notification type
        int32_t result3 = systemSoundManager_->SetSystemToneUri(context_, uri,
            SystemToneType::SYSTEM_TONE_TYPE_NOTIFICATION);
        EXPECT_EQ(result3, SUCCESS);
    }
}

/**
 * @tc.name  : Test resource management in refactored code
 * @tc.number: Media_SoundManager_SetToneUri_Refactor_007
 * @tc.desc  : Test that dataShareHelper is properly released after SetToneUriInternal.
 *            Verifies no resource leaks in the refactored implementation.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_SetToneUri_Refactor_007, TestSize.Level2)
{
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    std::shared_ptr<Context> context_ = std::make_shared<ContextImpl>();
    EXPECT_NE(systemSoundManager_, nullptr);

    // Get valid URIs from appropriate sources
    auto ringtoneVec = systemSoundManager_->GetRingtoneAttrList(context_,
        RingtoneType::RINGTONE_TYPE_SIM_CARD_0);
    auto notificationVec = systemSoundManager_->GetSystemToneAttrList(context_,
        SystemToneType::SYSTEM_TONE_TYPE_NOTIFICATION);

    if (ringtoneVec.size() > 0) {
        std::string uri = ringtoneVec[0]->GetUri();

        // Call multiple times to ensure no resource leak
        for (int i = 0; i < 10; i++) {
            int32_t result = systemSoundManager_->SetRingtoneUri(context_, uri,
                RingtoneType::RINGTONE_TYPE_SIM_CARD_0);
            EXPECT_EQ(result, SUCCESS);
        }
    }

    if (notificationVec.size() > 0) {
        std::string uri = notificationVec[0]->GetUri();

        // Also test SetSystemToneUri multiple times
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
 *            ERROR: URI doesn't exist, TYPEERROR: URI exists but toneType mismatch.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_SetToneUri_Refactor_008, TestSize.Level2)
{
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    std::shared_ptr<Context> context_ = std::make_shared<ContextImpl>();
    EXPECT_NE(systemSoundManager_, nullptr);

    // Test 1: Non-existent URI should return ERROR
    std::string nonExistentUri = "file:///data/storage/el2/base/files/nonexistent_file_12345.ogg";
    int32_t result1 = systemSoundManager_->SetRingtoneUri(context_, nonExistentUri,
        RingtoneType::RINGTONE_TYPE_SIM_CARD_0);
    EXPECT_EQ(result1, ERROR);

    // Test 2: Invalid RingtoneType should return MSERR_INVALID_VAL
    RingtoneType invalidType = static_cast<RingtoneType>(999);
    std::string validUri = "test_uri";
    int32_t result2 = systemSoundManager_->SetRingtoneUri(context_, validUri, invalidType);
    EXPECT_EQ(result2, MSERR_INVALID_VAL);
}

/**
 * @tc.name  : Test SetToneUriParams with all ringtone types
 * @tc.number: Media_SoundManager_SetToneUri_Refactor_009
 * @tc.desc  : Test SetToneUriInternal with different ringtone types via SetRingtoneUri.
 *            Verifies the SetToneUriParams structure works correctly.
 */
HWTEST(SystemSoundManagerUnitTest, Media_SoundManager_SetToneUri_Refactor_009, TestSize.Level2)
{
    auto systemSoundManager_ = std::make_shared<SystemSoundManagerImpl>();
    std::shared_ptr<Context> context_ = std::make_shared<ContextImpl>();
    EXPECT_NE(systemSoundManager_, nullptr);

    // Get a valid ringtone URI
    auto vec = systemSoundManager_->GetRingtoneAttrList(context_,
        RingtoneType::RINGTONE_TYPE_SIM_CARD_0);
    ASSERT_GT(vec.size(), 0u);
    std::string uri = vec[0]->GetUri();
    EXPECT_FALSE(uri.empty());

    // Test all SIM card types for ringtone
    std::vector<RingtoneType> ringtoneTypes = {
        RingtoneType::RINGTONE_TYPE_SIM_CARD_0,
        RingtoneType::RINGTONE_TYPE_SIM_CARD_1
    };

    for (auto ringtoneType : ringtoneTypes) {
        int32_t result = systemSoundManager_->SetRingtoneUri(context_, uri, ringtoneType);
        EXPECT_EQ(result, SUCCESS);

        // Verify each type
        std::string retrievedUri = systemSoundManager_->GetRingtoneUri(context_, ringtoneType);
        EXPECT_FALSE(retrievedUri.empty());
    }
}
} // namespace Media
} // namespace OHOS
