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

#include "media_errors.h"
#include "hitranscode_unit_test.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing::ext;

void HitranscodeUnitTest::SetUpTestCase(void)
{
}

void HitranscodeUnitTest::TearDownTestCase(void)
{
}

void HitranscodeUnitTest::SetUp(void)
{
    transcode_ = std::make_unique<HiTransCoderImpl>(0, 0, 0, 0);
}

void HitranscodeUnitTest::TearDown(void)
{
    transcode_ = nullptr;
}

/**
* @tc.name    : Test ProcessMetaKey API
* @tc.number  : HitranscodeUnitTest_ProcessMetaKey001
* @tc.desc    : Test ProcessMetaKey interface, set metaKey to int32_t.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(HitranscodeUnitTest, HitranscodeUnitTest_ProcessMetaKey001, TestSize.Level0)
{
    // 1. Set up the test environment
    std::shared_ptr<Meta> innerMeta = std::make_shared<Meta>();
    std::shared_ptr<Meta> outputMeta = std::make_shared<Meta>();
    std::string metaKey = Tag::MEDIA_DURATION;
    int64_t intVal = 100;
    innerMeta->SetData(metaKey, intVal);

    // 2. Call the function to be tested
    bool result = transcode_->ProcessMetaKey(innerMeta, outputMeta, metaKey);

    // 3. Verify the result
    EXPECT_TRUE(result);
    int64_t outputIntVal;
    EXPECT_TRUE(outputMeta->GetData(metaKey, outputIntVal));
    EXPECT_EQ(intVal, outputIntVal);
}

/**
* @tc.name    : Test ProcessMetaKey API
* @tc.number  : HitranscodeUnitTest_ProcessMetaKey002
* @tc.desc    : Test ProcessMetaKey interface, set metaKey to std::string.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(HitranscodeUnitTest, HitranscodeUnitTest_ProcessMetaKey002, TestSize.Level0)
{
    // 1. Set up the test environment
    std::shared_ptr<Meta> innerMeta = std::make_shared<Meta>();
    std::shared_ptr<Meta> outputMeta = std::make_shared<Meta>();
    std::string metaKey = Tag::MEDIA_ALBUM;
    std::string strVal = "test";
    innerMeta->SetData(metaKey, strVal);

    // 2. Call the function to be tested
    bool result = transcode_->ProcessMetaKey(innerMeta, outputMeta, metaKey);

    // 3. Verify the result
    EXPECT_TRUE(result);
    std::string outputStrVal;
    EXPECT_TRUE(outputMeta->GetData(metaKey, outputStrVal));
    EXPECT_EQ(strVal, outputStrVal);
}

HWTEST_F(HitranscodeUnitTest, HitranscodeUnitTest_ProcessMetaKey003, TestSize.Level0)
{
    // 1. Set up the test environment
    std::shared_ptr<Meta> innerMeta = std::make_shared<Meta>();
    std::shared_ptr<Meta> outputMeta = std::make_shared<Meta>();
    std::string metaKey = Tag::VIDEO_HEIGHT;
    int32_t intVal = 100;
    innerMeta->SetData(metaKey, intVal);

    // 2. Call the function to be tested
    bool result = transcode_->ProcessMetaKey(innerMeta, outputMeta, metaKey);

    // 3. Verify the result
    EXPECT_TRUE(result);
    int32_t outputStrVal;
    EXPECT_TRUE(outputMeta->GetData(metaKey, outputStrVal));
    EXPECT_EQ(intVal, outputStrVal);
}

HWTEST_F(HitranscodeUnitTest, HitranscodeUnitTest_ProcessMetaKey004, TestSize.Level0)
{
    // 1. Set up the test environment
    std::shared_ptr<Meta> innerMeta = std::make_shared<Meta>();
    std::shared_ptr<Meta> outputMeta = std::make_shared<Meta>();
    std::string metaKey = Tag::VIDEO_CAPTURE_RATE;
    double doubleVal = 0.1;
    innerMeta->SetData(metaKey, doubleVal);

    // 2. Call the function to be tested
    bool result = transcode_->ProcessMetaKey(innerMeta, outputMeta, metaKey);

    // 3. Verify the result
    EXPECT_TRUE(result);
    double outputStrVal;
    EXPECT_TRUE(outputMeta->GetData(metaKey, outputStrVal));
    EXPECT_EQ(doubleVal, outputStrVal);
}

HWTEST_F(HitranscodeUnitTest, HitranscodeUnitTest_ProcessMetaKey005, TestSize.Level0)
{
    // 1. Set up the test environment
    std::shared_ptr<Meta> innerMeta = std::make_shared<Meta>();
    std::shared_ptr<Meta> outputMeta = std::make_shared<Meta>();
    std::string metaKey = Tag::VIDEO_ROTATION;
    Plugins::VideoRotation rotation = Plugins::VideoRotation::VIDEO_ROTATION_0;
    innerMeta->SetData(metaKey, rotation);

    // 2. Call the function to be tested
    bool result = transcode_->ProcessMetaKey(innerMeta, outputMeta, metaKey);

    // 3. Verify the result
    EXPECT_TRUE(result);
    Plugins::VideoRotation outputStrVal;
    EXPECT_TRUE(outputMeta->GetData(metaKey, outputStrVal));
    EXPECT_EQ(rotation, outputStrVal);
}

HWTEST_F(HitranscodeUnitTest, HitranscodeUnitTest_ProcessMetaKey006, TestSize.Level0)
{
    // 1. Set up the test environment
    std::shared_ptr<Meta> innerMeta = std::make_shared<Meta>();
    std::shared_ptr<Meta> outputMeta = std::make_shared<Meta>();
    std::string metaKey = Tag::VIDEO_COLOR_RANGE;
    bool boolVal = true;
    innerMeta->SetData(metaKey, boolVal);

    // 2. Call the function to be tested
    bool result = transcode_->ProcessMetaKey(innerMeta, outputMeta, metaKey);

    // 3. Verify the result
    EXPECT_TRUE(result);
    bool outputStrVal;
    EXPECT_TRUE(outputMeta->GetData(metaKey, outputStrVal));
    EXPECT_EQ(boolVal, outputStrVal);
}

HWTEST_F(HitranscodeUnitTest, HitranscodeUnitTest_ProcessMetaKey007, TestSize.Level0)
{
    // 1. Set up the test environment
    std::shared_ptr<Meta> innerMeta = std::make_shared<Meta>();
    std::shared_ptr<Meta> outputMeta = std::make_shared<Meta>();
    std::string metaKey = Tag::MEDIA_LATITUDE;
    float floatVal = 0.9;
    innerMeta->SetData(metaKey, floatVal);

    // 2. Call the function to be tested
    bool result = transcode_->ProcessMetaKey(innerMeta, outputMeta, metaKey);

    // 3. Verify the result
    EXPECT_TRUE(result);
    float outputStrVal;
    EXPECT_TRUE(outputMeta->GetData(metaKey, outputStrVal));
    EXPECT_EQ(floatVal, outputStrVal);
}

/**
* @tc.name    : Test SetValueByType API
* @tc.number  : SetValueByType_001
* @tc.desc    : Test SetValueByType interface, set innerMeta or outputMeta to nullptr.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(HitranscodeUnitTest, SetValueByType_001, TestSize.Level0)
{
    // 1. Set up the test environment
    std::shared_ptr<Meta> innerMeta = nullptr;
    std::shared_ptr<Meta> outputMeta = std::make_shared<Meta>();

    // 2. Call the function to be tested
    bool result = transcode_->SetValueByType(innerMeta, outputMeta);

    // 3. Verify the result
    EXPECT_FALSE(result);
}

/**
* @tc.name    : Test SetValueByType API
* @tc.number  : SetValueByType_002
* @tc.desc    : Test SetValueByType interface, set both innerMeta and outputMeta to nullptr.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(HitranscodeUnitTest, SetValueByType_002, TestSize.Level0)
{
    // 1. Set up the test environment
    std::shared_ptr<Meta> innerMeta = nullptr;
    std::shared_ptr<Meta> outputMeta = nullptr;

    // 2. Call the function to be tested
    bool result = transcode_->SetValueByType(innerMeta, outputMeta);

    // 3. Verify the result
    EXPECT_FALSE(result);
}

/**
* @tc.name    : Test SetValueByType API
* @tc.number  : SetValueByType_003
* @tc.desc    : Test SetValueByType interface, set valid innerMeta and outputMeta.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(HitranscodeUnitTest, SetValueByType_003, TestSize.Level0)
{
    // 1. Set up the test environment
    std::shared_ptr<Meta> innerMeta = std::make_shared<Meta>();
    std::shared_ptr<Meta> outputMeta = std::make_shared<Meta>();
    std::string metaKey = Tag::MEDIA_DURATION;
    int64_t intVal = 100;
    innerMeta->SetData(metaKey, intVal);

    bool result = transcode_->SetValueByType(innerMeta, outputMeta);

    EXPECT_TRUE(result);
}
} // namespace Media
} // namespace OHOS