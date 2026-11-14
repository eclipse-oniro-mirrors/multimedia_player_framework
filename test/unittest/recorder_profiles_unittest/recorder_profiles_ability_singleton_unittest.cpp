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

#include <cstdio>
#include <memory>

#include "gtest/gtest.h"
#include "recorder_profiles_ability_singleton.h"

using namespace OHOS;
using namespace OHOS::Media;
using namespace testing::ext;

namespace {
constexpr char MISSING_CONFIG_PATH[] = "/data/test/recorder_profiles_missing_config.xml";
constexpr char DEFAULT_CONFIG_PATH[] = "/etc/recorder/recorder_configs.xml";
} // namespace

class RecorderProfilesAbilitySingletonUnitTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override
    {
        singleton_ = std::make_shared<RecorderProfilesAbilitySingleton>();
    }
    void TearDown() override
    {
        singleton_ = nullptr;
    }

protected:
    std::shared_ptr<RecorderProfilesAbilitySingleton> singleton_ = nullptr;
};

/**
 * @tc.name: ParseRecorderProfilesXml_MissingFile_001
 * @tc.desc: Parsing returns false and keeps the parsed flag unset when the configuration file cannot be loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderProfilesAbilitySingletonUnitTest, ParseRecorderProfilesXml_MissingFile_001, TestSize.Level2)
{
    singleton_->MEDIA_PROFILE_CONFIG_FILE = MISSING_CONFIG_PATH;

    EXPECT_FALSE(singleton_->ParseRecorderProfilesXml());
    EXPECT_FALSE(singleton_->isParsered_);
    EXPECT_TRUE(singleton_->capabilityDataArray_.empty());
}

/**
 * @tc.name: ParseRecorderProfilesXml_AlreadyParsed_001
 * @tc.desc: Parsing is skipped and returns true once the configuration has already been parsed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderProfilesAbilitySingletonUnitTest, ParseRecorderProfilesXml_AlreadyParsed_001, TestSize.Level2)
{
    singleton_->isParsered_ = true;

    EXPECT_TRUE(singleton_->ParseRecorderProfilesXml());
    // The early return must not rebuild the capability array
    EXPECT_TRUE(singleton_->capabilityDataArray_.empty());
}

/**
 * @tc.name: GetInstance_ParseFail_001
 * @tc.desc: GetInstance keeps returning the singleton instance when parsing its configuration fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderProfilesAbilitySingletonUnitTest, GetInstance_ParseFail_001, TestSize.Level2)
{
    RecorderProfilesAbilitySingleton &instance = RecorderProfilesAbilitySingleton::GetInstance();
    instance.isParsered_ = false;
    instance.MEDIA_PROFILE_CONFIG_FILE = MISSING_CONFIG_PATH;

    RecorderProfilesAbilitySingleton &parsedAgain = RecorderProfilesAbilitySingleton::GetInstance();
    EXPECT_EQ(&instance, &parsedAgain);
    EXPECT_FALSE(parsedAgain.isParsered_);

    // Restore the default configuration path so that other users of the singleton parse normally again
    parsedAgain.MEDIA_PROFILE_CONFIG_FILE = DEFAULT_CONFIG_PATH;
}

/**
 * @tc.name: GetInstance_SameInstance_001
 * @tc.desc: GetInstance returns the same instance for repeated calls
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderProfilesAbilitySingletonUnitTest, GetInstance_SameInstance_001, TestSize.Level2)
{
    RecorderProfilesAbilitySingleton &first = RecorderProfilesAbilitySingleton::GetInstance();
    RecorderProfilesAbilitySingleton &second = RecorderProfilesAbilitySingleton::GetInstance();

    EXPECT_EQ(&first, &second);
}
