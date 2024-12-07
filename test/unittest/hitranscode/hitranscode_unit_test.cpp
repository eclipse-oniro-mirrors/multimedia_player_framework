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
    transcoder_ = std::make_unique<HiTransCoderImpl>(0, 0, 0, 0);
    transcoder_->Init();
}

void HitranscodeUnitTest::TearDown(void)
{
    transcoder_ = nullptr;
}

/**
* @tc.name    : Test ProcessMetaKey API
* @tc.number  : HitranscodeUnitTest_ProcessMetaKey001
* @tc.desc    : Test ProcessMetaKey interface, set metaKey to int64_t.
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
    bool result = transcoder_->ProcessMetaKey(innerMeta, outputMeta, metaKey);

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
    bool result = transcoder_->ProcessMetaKey(innerMeta, outputMeta, metaKey);

    // 3. Verify the result
    EXPECT_TRUE(result);
    std::string outputStrVal;
    EXPECT_TRUE(outputMeta->GetData(metaKey, outputStrVal));
    EXPECT_EQ(strVal, outputStrVal);
}

/**
* @tc.name    : Test ProcessMetaKey API
* @tc.number  : HitranscodeUnitTest_ProcessMetaKey003
* @tc.desc    : Test ProcessMetaKey interface, set metaKey to int32_t.
* @tc.require :
*/
HWTEST_F(HitranscodeUnitTest, HitranscodeUnitTest_ProcessMetaKey003, TestSize.Level0)
{
    // 1. Set up the test environment
    std::shared_ptr<Meta> innerMeta = std::make_shared<Meta>();
    std::shared_ptr<Meta> outputMeta = std::make_shared<Meta>();
    std::string metaKey = Tag::VIDEO_HEIGHT;
    int32_t intVal = 100;
    innerMeta->SetData(metaKey, intVal);

    // 2. Call the function to be tested
    bool result = transcoder_->ProcessMetaKey(innerMeta, outputMeta, metaKey);

    // 3. Verify the result
    EXPECT_TRUE(result);
    int32_t outputStrVal;
    EXPECT_TRUE(outputMeta->GetData(metaKey, outputStrVal));
    EXPECT_EQ(intVal, outputStrVal);
}

/**
* @tc.name    : Test ProcessMetaKey API
* @tc.number  : HitranscodeUnitTest_ProcessMetaKey004
* @tc.desc    : Test ProcessMetaKey interface, set metaKey to double.
* @tc.require :
*/
HWTEST_F(HitranscodeUnitTest, HitranscodeUnitTest_ProcessMetaKey004, TestSize.Level0)
{
    // 1. Set up the test environment
    std::shared_ptr<Meta> innerMeta = std::make_shared<Meta>();
    std::shared_ptr<Meta> outputMeta = std::make_shared<Meta>();
    std::string metaKey = Tag::VIDEO_CAPTURE_RATE;
    double doubleVal = 0.1;
    innerMeta->SetData(metaKey, doubleVal);

    // 2. Call the function to be tested
    bool result = transcoder_->ProcessMetaKey(innerMeta, outputMeta, metaKey);

    // 3. Verify the result
    EXPECT_TRUE(result);
    double outputStrVal;
    EXPECT_TRUE(outputMeta->GetData(metaKey, outputStrVal));
    EXPECT_EQ(doubleVal, outputStrVal);
}

/**
* @tc.name    : Test ProcessMetaKey API
* @tc.number  : HitranscodeUnitTest_ProcessMetaKey005
* @tc.desc    : Test ProcessMetaKey interface, set metaKey to Plugins::VideoRotation.
* @tc.require :
*/
HWTEST_F(HitranscodeUnitTest, HitranscodeUnitTest_ProcessMetaKey005, TestSize.Level0)
{
    // 1. Set up the test environment
    std::shared_ptr<Meta> innerMeta = std::make_shared<Meta>();
    std::shared_ptr<Meta> outputMeta = std::make_shared<Meta>();
    std::string metaKey = Tag::VIDEO_ROTATION;
    Plugins::VideoRotation rotation = Plugins::VideoRotation::VIDEO_ROTATION_0;
    innerMeta->SetData(metaKey, rotation);

    // 2. Call the function to be tested
    bool result = transcoder_->ProcessMetaKey(innerMeta, outputMeta, metaKey);

    // 3. Verify the result
    EXPECT_TRUE(result);
    Plugins::VideoRotation outputStrVal;
    EXPECT_TRUE(outputMeta->GetData(metaKey, outputStrVal));
    EXPECT_EQ(rotation, outputStrVal);
}

/**
* @tc.name    : Test ProcessMetaKey API
* @tc.number  : HitranscodeUnitTest_ProcessMetaKey006
* @tc.desc    : Test ProcessMetaKey interface, set metaKey to bool.
* @tc.require :
*/
HWTEST_F(HitranscodeUnitTest, HitranscodeUnitTest_ProcessMetaKey006, TestSize.Level0)
{
    // 1. Set up the test environment
    std::shared_ptr<Meta> innerMeta = std::make_shared<Meta>();
    std::shared_ptr<Meta> outputMeta = std::make_shared<Meta>();
    std::string metaKey = Tag::VIDEO_COLOR_RANGE;
    bool boolVal = true;
    innerMeta->SetData(metaKey, boolVal);

    // 2. Call the function to be tested
    bool result = transcoder_->ProcessMetaKey(innerMeta, outputMeta, metaKey);

    // 3. Verify the result
    EXPECT_TRUE(result);
    bool outputStrVal;
    EXPECT_TRUE(outputMeta->GetData(metaKey, outputStrVal));
    EXPECT_EQ(boolVal, outputStrVal);
}

/**
* @tc.name    : Test ProcessMetaKey API
* @tc.number  : HitranscodeUnitTest_ProcessMetaKey007
* @tc.desc    : Test ProcessMetaKey interface, set metaKey to float.
* @tc.require :
*/
HWTEST_F(HitranscodeUnitTest, HitranscodeUnitTest_ProcessMetaKey007, TestSize.Level0)
{
    // 1. Set up the test environment
    std::shared_ptr<Meta> innerMeta = std::make_shared<Meta>();
    std::shared_ptr<Meta> outputMeta = std::make_shared<Meta>();
    std::string metaKey = Tag::MEDIA_LATITUDE;
    float floatVal = 0.9;
    innerMeta->SetData(metaKey, floatVal);

    // 2. Call the function to be tested
    bool result = transcoder_->ProcessMetaKey(innerMeta, outputMeta, metaKey);

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
    bool result = transcoder_->SetValueByType(innerMeta, outputMeta);

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
    bool result = transcoder_->SetValueByType(innerMeta, outputMeta);

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

    bool result = transcoder_->SetValueByType(innerMeta, outputMeta);

    EXPECT_TRUE(result);
}

/**
* @tc.name    : Test ConfigureVideoAudioMetaData API
* @tc.number  : ConfigureVideoAudioMetaData_001
* @tc.desc    : Test ConfigureVideoAudioMetaData interface, set demuxerFilter_ nulllptr.
* @tc.require :
*/
HWTEST_F(HitranscodeUnitTest, ConfigureVideoAudioMetaData_001, TestSize.Level0)
{
    transcoder_->demuxerFilter_ = nullptr;
    Status result = transcoder_->ConfigureVideoAudioMetaData();
    EXPECT_EQ(result, Status::ERROR_NULL_POINTER);
}

/**
* @tc.name    : Test Prepare API
* @tc.number  : Prepare_001
* @tc.desc    : Test Prepare interface, dont set width and height.
* @tc.require :
*/
HWTEST_F(HitranscodeUnitTest, Prepare_001, TestSize.Level0)
{
    transcoder_->isExistVideoTrack_ = true;
    int32_t ret = transcoder_->Prepare();
    EXPECT_EQ(ret, static_cast<int32_t>(Status::ERROR_INVALID_PARAMETER));
}

/**
* @tc.name    : Test Prepare API
* @tc.number  : Prepare_002
* @tc.desc    : Test Prepare interface, dont set height.
* @tc.require :
*/
HWTEST_F(HitranscodeUnitTest, Prepare_002, TestSize.Level0)
{
    transcoder_->isExistVideoTrack_ = true;
    std::string metaKey = Tag::VIDEO_WIDTH;
    int32_t width = 0;
    transcoder_->videoEncFormat_->SetData(metaKey, width);
    int32_t ret = transcoder_->Prepare();
    EXPECT_EQ(ret, static_cast<int32_t>(Status::ERROR_INVALID_PARAMETER));
}

/**
* @tc.name    : Test Prepare API
* @tc.number  : Prepare_003
* @tc.desc    : Test Prepare interface, dont set width.
* @tc.require :
*/
HWTEST_F(HitranscodeUnitTest, Prepare_003, TestSize.Level0)
{
    transcoder_->isExistVideoTrack_ = true;
    std::string metaKey = Tag::VIDEO_HEIGHT;
    int32_t height = 0;
    transcoder_->videoEncFormat_->SetData(metaKey, height);
    int32_t ret = transcoder_->Prepare();
    EXPECT_EQ(ret, static_cast<int32_t>(Status::ERROR_INVALID_PARAMETER));
}

/**
* @tc.name    : Test Prepare API
* @tc.number  : Prepare_004
* @tc.desc    : Test Prepare interface, set all and the condition is 001.
* @tc.require :
*/
HWTEST_F(HitranscodeUnitTest, Prepare_004, TestSize.Level0)
{
    transcoder_->isExistVideoTrack_ = true;
    std::string widthMetaKey = Tag::VIDEO_WIDTH;
    int32_t width = 100;
    transcoder_->videoEncFormat_->SetData(widthMetaKey, width);
    std::string heightMetaKey = Tag::VIDEO_HEIGHT;
    int32_t height = 100;
    transcoder_->videoEncFormat_->SetData(heightMetaKey, height);
    transcoder_->inputVideoWidth_ = 200;
    transcoder_->inputVideoHeight_ =200;
    int32_t ret = transcoder_->Prepare();
    EXPECT_EQ(ret, static_cast<int32_t>(Status::ERROR_INVALID_PARAMETER));
}

/**
* @tc.name    : Test Prepare API
* @tc.number  : Prepare_005
* @tc.desc    : Test Prepare interface, set all and the condition is 010.
* @tc.require :
*/
HWTEST_F(HitranscodeUnitTest, Prepare_005, TestSize.Level0)
{
    transcoder_->isExistVideoTrack_ = true;
    std::string widthMetaKey = Tag::VIDEO_WIDTH;
    int32_t width = 480;
    transcoder_->videoEncFormat_->SetData(widthMetaKey, width);
    std::string heightMetaKey = Tag::VIDEO_HEIGHT;
    int32_t height = 640;
    transcoder_->videoEncFormat_->SetData(heightMetaKey, height);
    transcoder_->inputVideoWidth_ = 640;
    transcoder_->inputVideoHeight_ = 480;
    int32_t ret = transcoder_->Prepare();
    EXPECT_EQ(ret, static_cast<int32_t>(Status::ERROR_INVALID_PARAMETER));
}

/**
* @tc.name    : Test Prepare API
* @tc.number  : Prepare_006
* @tc.desc    : Test Prepare interface, set all and the condition is 011.
* @tc.require :
*/
HWTEST_F(HitranscodeUnitTest, Prepare_006, TestSize.Level0)
{
    transcoder_->isExistVideoTrack_ = true;
    std::string widthMetaKey = Tag::VIDEO_WIDTH;
    int32_t width = 100;
    transcoder_->videoEncFormat_->SetData(widthMetaKey, width);
    std::string heightMetaKey = Tag::VIDEO_HEIGHT;
    int32_t height = 100;
    transcoder_->videoEncFormat_->SetData(heightMetaKey, height);
    transcoder_->inputVideoWidth_ = 200;
    transcoder_->inputVideoHeight_ = 50;
    int32_t ret = transcoder_->Prepare();
    EXPECT_EQ(ret, static_cast<int32_t>(Status::ERROR_INVALID_PARAMETER));
}

/**
* @tc.name    : Test Prepare API
* @tc.number  : Prepare_007
* @tc.desc    : Test Prepare interface, set all and the condition is 100.
* @tc.require :
*/
HWTEST_F(HitranscodeUnitTest, Prepare_007, TestSize.Level0)
{
    transcoder_->isExistVideoTrack_ = true;
    std::string widthMetaKey = Tag::VIDEO_WIDTH;
    int32_t width = 640;
    transcoder_->videoEncFormat_->SetData(widthMetaKey, width);
    std::string heightMetaKey = Tag::VIDEO_HEIGHT;
    int32_t height = 480;
    transcoder_->videoEncFormat_->SetData(heightMetaKey, height);
    transcoder_->inputVideoWidth_ = 480;
    transcoder_->inputVideoHeight_ = 640;
    int32_t ret = transcoder_->Prepare();
    EXPECT_EQ(ret, static_cast<int32_t>(Status::ERROR_INVALID_PARAMETER));
}

/**
* @tc.name    : Test Prepare API
* @tc.number  : Prepare_008
* @tc.desc    : Test Prepare interface, set all and the condition is 101.
* @tc.require :
*/
HWTEST_F(HitranscodeUnitTest, Prepare_008, TestSize.Level0)
{
    transcoder_->isExistVideoTrack_ = true;
    std::string widhtMetaKey = Tag::VIDEO_WIDTH;
    int32_t width = 100;
    transcoder_->videoEncFormat_->SetData(widhtMetaKey, width);
    std::string heightMetaKey = Tag::VIDEO_HEIGHT;
    int32_t height = 480;
    transcoder_->videoEncFormat_->SetData(heightMetaKey, height);
    transcoder_->inputVideoWidth_ = 50;
    transcoder_->inputVideoHeight_ = 640;
    int32_t ret = transcoder_->Prepare();
    EXPECT_EQ(ret, static_cast<int32_t>(Status::ERROR_INVALID_PARAMETER));
}

/**
* @tc.name    : Test Prepare API
* @tc.number  : Prepare_009
* @tc.desc    : Test Prepare interface, set all and the condition is 110.
* @tc.require :
*/
HWTEST_F(HitranscodeUnitTest, Prepare_009, TestSize.Level0)
{
    transcoder_->isExistVideoTrack_ = true;
    std::string widthMetaKey = Tag::VIDEO_WIDTH;
    int32_t width = 640;
    transcoder_->videoEncFormat_->SetData(widthMetaKey, width);
    std::string heightMetaKey = Tag::VIDEO_HEIGHT;
    int32_t height = 640;
    transcoder_->videoEncFormat_->SetData(heightMetaKey, height);
    transcoder_->inputVideoWidth_ = 480;
    transcoder_->inputVideoHeight_ = 480;
    int32_t ret = transcoder_->Prepare();
    EXPECT_EQ(ret, static_cast<int32_t>(Status::ERROR_INVALID_PARAMETER));
}

/**
* @tc.name    : Test Prepare API
* @tc.number  : Prepare_010
* @tc.desc    : Test Prepare interface, set all and the condition is 111.
* @tc.require :
*/
HWTEST_F(HitranscodeUnitTest, Prepare_010, TestSize.Level0)
{
    transcoder_->isExistVideoTrack_ = true;
    std::string widthMetaKey = Tag::VIDEO_WIDTH;
    int32_t width = 100;
    transcoder_->videoEncFormat_->SetData(widthMetaKey, width);
    std::string heightMetaKey = Tag::VIDEO_HEIGHT;
    int32_t height = 100;
    transcoder_->videoEncFormat_->SetData(heightMetaKey, height);
    transcoder_->inputVideoWidth_ = 50;
    transcoder_->inputVideoHeight_ = 50;
    int32_t ret = transcoder_->Prepare();
    EXPECT_EQ(ret, static_cast<int32_t>(Status::ERROR_INVALID_PARAMETER));
}

/**
* @tc.name    : Test GetRealPath API
* @tc.number  : GetRealPath_001
* @tc.desc    : Test GetRealPath interface, set url to "file://".
* @tc.require :
*/
HWTEST_F(HitranscodeUnitTest, GetRealPath_001, TestSize.Level0)
{
    // 1. Set up the test environment
    std::string url = "file://";
    std::string realUrlPath;

    // 2. Call the function to be tested
    int32_t ret = transcoder_->GetRealPath(url, realUrlPath);

    // 3. Verify the result
    EXPECT_EQ(ret, MSERR_OPEN_FILE_FAILED);
}

/**
* @tc.name    : Test GetRealPath API
* @tc.number  : GetRealPath_002
* @tc.desc    : Test GetRealPath interface, set url to "file".
* @tc.require :
*/
HWTEST_F(HitranscodeUnitTest, GetRealPath_002, TestSize.Level0)
{
    // 1. Set up the test environment
    std::string url = "file";
    std::string realUrlPath;

    // 2. Call the function to be tested
    int32_t ret = transcoder_->GetRealPath(url, realUrlPath);

    // 3. Verify the result
    EXPECT_EQ(ret, MSERR_OPEN_FILE_FAILED);
}

/**
* @tc.name    : Test GetRealPath API
* @tc.number  : GetRealPath_003
* @tc.desc    : Test GetRealPath interface, set url to "file:///storage/../test.mp3".
* @tc.require :
*/
HWTEST_F(HitranscodeUnitTest, GetRealPath_003, TestSize.Level0)
{
    // 1. Set up the test environment
    std::string url = "file:///storage/../test.mp3";
    std::string realUrlPath;

    // 2. Call the function to be tested
    int32_t ret = transcoder_->GetRealPath(url, realUrlPath);

    // 3. Verify the result
    EXPECT_EQ(ret, MSERR_FILE_ACCESS_FAILED);
}

/**
* @tc.name    : Test ProcessMetaKey API
* @tc.number  : HitranscodeUnitTest_ProcessMetaKey_008
* @tc.desc    : Test ProcessMetaKey interface, dont set int64_t to innerMeta.
* @tc.require :
*/
HWTEST_F(HitranscodeUnitTest, ProcessMetaKey_008, TestSize.Level0)
{
    // 1. Set up the test environment
    std::shared_ptr<Meta> innerMeta = std::make_shared<Meta>();
    std::shared_ptr<Meta> outputMeta = std::make_shared<Meta>();
    std::string metaKey = Tag::MEDIA_DURATION;

    // 2. Call the function to be tested
    bool result = transcoder_->ProcessMetaKey(innerMeta, outputMeta, metaKey);

    // 3. Verify the result
    EXPECT_TRUE(result);
    int64_t outputIntVal;
    EXPECT_FALSE(outputMeta->GetData(metaKey, outputIntVal));
}

/**
* @tc.name    : Test ProcessMetaKey API
* @tc.number  : HitranscodeUnitTest_ProcessMetaKey_009
* @tc.desc    : Test ProcessMetaKey interface, dont set string to innerMeta.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(HitranscodeUnitTest, ProcessMetaKey_009, TestSize.Level0)
{
    // 1. Set up the test environment
    std::shared_ptr<Meta> innerMeta = std::make_shared<Meta>();
    std::shared_ptr<Meta> outputMeta = std::make_shared<Meta>();
    std::string metaKey = Tag::MEDIA_ALBUM;

    // 2. Call the function to be tested
    bool result = transcoder_->ProcessMetaKey(innerMeta, outputMeta, metaKey);

    // 3. Verify the result
    EXPECT_TRUE(result);
    std::string outputStrVal;
    EXPECT_FALSE(outputMeta->GetData(metaKey, outputStrVal));
}

/**
* @tc.name    : Test ProcessMetaKey API
* @tc.number  : HitranscodeUnitTest_ProcessMetaKey_010
* @tc.desc    : Test ProcessMetaKey interface, dont set int32_t to innerMeta.
* @tc.require :
*/
HWTEST_F(HitranscodeUnitTest, ProcessMetaKey_010, TestSize.Level0)
{
    // 1. Set up the test environment
    std::shared_ptr<Meta> innerMeta = std::make_shared<Meta>();
    std::shared_ptr<Meta> outputMeta = std::make_shared<Meta>();
    std::string metaKey = Tag::VIDEO_HEIGHT;

    // 2. Call the function to be tested
    bool result = transcoder_->ProcessMetaKey(innerMeta, outputMeta, metaKey);

    // 3. Verify the result
    EXPECT_TRUE(result);
    int32_t outputStrVal;
    EXPECT_FALSE(outputMeta->GetData(metaKey, outputStrVal));
}

/**
* @tc.name    : Test ProcessMetaKey API
* @tc.number  : HitranscodeUnitTest_ProcessMetaKey_011
* @tc.desc    : Test ProcessMetaKey interface, dont set double to innerMeta.
* @tc.require :
*/
HWTEST_F(HitranscodeUnitTest, ProcessMetaKey_011, TestSize.Level0)
{
    // 1. Set up the test environment
    std::shared_ptr<Meta> innerMeta = std::make_shared<Meta>();
    std::shared_ptr<Meta> outputMeta = std::make_shared<Meta>();
    std::string metaKey = Tag::VIDEO_CAPTURE_RATE;

    // 2. Call the function to be tested
    bool result = transcoder_->ProcessMetaKey(innerMeta, outputMeta, metaKey);

    // 3. Verify the result
    EXPECT_TRUE(result);
    double outputStrVal;
    EXPECT_FALSE(outputMeta->GetData(metaKey, outputStrVal));
}

/**
* @tc.name    : Test ProcessMetaKey API
* @tc.number  : HitranscodeUnitTest_ProcessMetaKey_012
* @tc.desc    : Test ProcessMetaKey interface, dont set Plugins::VideoRotation to innerMeta.
* @tc.require :
*/
HWTEST_F(HitranscodeUnitTest, ProcessMetaKey_012, TestSize.Level0)
{
    // 1. Set up the test environment
    std::shared_ptr<Meta> innerMeta = std::make_shared<Meta>();
    std::shared_ptr<Meta> outputMeta = std::make_shared<Meta>();
    std::string metaKey = Tag::VIDEO_ROTATION;

    // 2. Call the function to be tested
    bool result = transcoder_->ProcessMetaKey(innerMeta, outputMeta, metaKey);

    // 3. Verify the result
    EXPECT_TRUE(result);
    Plugins::VideoRotation outputStrVal;
    EXPECT_FALSE(outputMeta->GetData(metaKey, outputStrVal));
}

/**
* @tc.name    : Test ProcessMetaKey API
* @tc.number  : HitranscodeUnitTest_ProcessMetaKey_013
* @tc.desc    : Test ProcessMetaKey interface, dont set bool to innerMeta.
* @tc.require :
*/
HWTEST_F(HitranscodeUnitTest, ProcessMetaKey_013, TestSize.Level0)
{
    // 1. Set up the test environment
    std::shared_ptr<Meta> innerMeta = std::make_shared<Meta>();
    std::shared_ptr<Meta> outputMeta = std::make_shared<Meta>();
    std::string metaKey = Tag::VIDEO_COLOR_RANGE;

    // 2. Call the function to be tested
    bool result = transcoder_->ProcessMetaKey(innerMeta, outputMeta, metaKey);

    // 3. Verify the result
    EXPECT_TRUE(result);
    bool outputStrVal;
    EXPECT_FALSE(outputMeta->GetData(metaKey, outputStrVal));
}

/**
* @tc.name    : Test ProcessMetaKey API
* @tc.number  : HitranscodeUnitTest_ProcessMetaKey_014
* @tc.desc    : Test ProcessMetaKey interface, dont set float to innerMeta.
* @tc.require :
*/
HWTEST_F(HitranscodeUnitTest, ProcessMetaKey_014, TestSize.Level0)
{
    // 1. Set up the test environment
    std::shared_ptr<Meta> innerMeta = std::make_shared<Meta>();
    std::shared_ptr<Meta> outputMeta = std::make_shared<Meta>();
    std::string metaKey = Tag::MEDIA_LATITUDE;

    // 2. Call the function to be tested
    bool result = transcoder_->ProcessMetaKey(innerMeta, outputMeta, metaKey);

    // 3. Verify the result
    EXPECT_TRUE(result);
    float outputStrVal;
    EXPECT_FALSE(outputMeta->GetData(metaKey, outputStrVal));
}

/**
* @tc.name    : Test ConfigureVideoEncoderFormat API
* @tc.number  : ConfigureVideoEncoderFormat_001
* @tc.desc    : Test ConfigureVideoEncoderFormat interface, set VideoCodecFormat::H264.
* @tc.require :
*/
HWTEST_F(HitranscodeUnitTest, ConfigureVideoEncoderFormat_001, TestSize.Level0)
{
    VideoEnc videoEnc(OHOS::Media::VideoCodecFormat::H264);
    Status ret = transcoder_->ConfigureVideoEncoderFormat(videoEnc);
    EXPECT_EQ(ret, Status::OK);
    
    std::string metaKey = Tag::MIME_TYPE;
    std::string strVal = "video/avc";
    std::string outputStrVal;
    EXPECT_TRUE(transcoder_->videoEncFormat_->GetData(metaKey, outputStrVal));
    EXPECT_EQ(strVal, outputStrVal);

    metaKey = Tag::VIDEO_H264_PROFILE;
    VideoH264Profile intVal = Plugins::VideoH264Profile::BASELINE;
    VideoH264Profile outputIntVal;
    EXPECT_TRUE(transcoder_->videoEncFormat_->GetData(metaKey, outputIntVal));
    EXPECT_EQ(intVal, outputIntVal);

    metaKey = Tag::VIDEO_H264_LEVEL;
    int32_t intVal2 = 32;
    int32_t outputIntVal2;
    EXPECT_TRUE(transcoder_->videoEncFormat_->GetData(metaKey, outputIntVal2));
    EXPECT_EQ(intVal2, outputIntVal2);
}

/**
* @tc.name    : Test ConfigureVideoEncoderFormat API
* @tc.number  : ConfigureVideoEncoderFormat_002
* @tc.desc    : Test ConfigureVideoEncoderFormat interface, set VideoCodecFormat::MPEG4.
* @tc.require :
*/
HWTEST_F(HitranscodeUnitTest, ConfigureVideoEncoderFormat_002, TestSize.Level0)
{
    VideoEnc videoEnc(OHOS::Media::VideoCodecFormat::MPEG4);
    Status ret = transcoder_->ConfigureVideoEncoderFormat(videoEnc);
    EXPECT_EQ(ret, Status::OK);
    
    std::string metaKey = Tag::MIME_TYPE;
    std::string strVal = "video/mp4v-es";
    std::string outputStrVal;
    EXPECT_TRUE(transcoder_->videoEncFormat_->GetData(metaKey, outputStrVal));
    EXPECT_EQ(strVal, outputStrVal);
}

/**
* @tc.name    : Test ConfigureVideoEncoderFormat API
* @tc.number  : ConfigureVideoEncoderFormat_003
* @tc.desc    : Test ConfigureVideoEncoderFormat interface, set VideoCodecFormat::H265.
* @tc.require :
*/
HWTEST_F(HitranscodeUnitTest, ConfigureVideoEncoderFormat_003, TestSize.Level0)
{
    VideoEnc videoEnc(OHOS::Media::VideoCodecFormat::H265);
    Status ret = transcoder_->ConfigureVideoEncoderFormat(videoEnc);
    EXPECT_EQ(ret, Status::OK);
    
    std::string metaKey = Tag::MIME_TYPE;
    std::string strVal = "video/hevc";
    std::string outputStrVal;
    EXPECT_TRUE(transcoder_->videoEncFormat_->GetData(metaKey, outputStrVal));
    EXPECT_EQ(strVal, outputStrVal);
}

/**
* @tc.name    : Test ConfigureVideoEncoderFormat API
* @tc.number  : ConfigureVideoEncoderFormat_004
* @tc.desc    : Test ConfigureVideoEncoderFormat interface, set VideoCodecFormat::VIDEO_DEFAULT.
* @tc.require :
*/
HWTEST_F(HitranscodeUnitTest, ConfigureVideoEncoderFormat_004, TestSize.Level0)
{
    VideoEnc videoEnc(OHOS::Media::VideoCodecFormat::VIDEO_DEFAULT);
    Status ret = transcoder_->ConfigureVideoEncoderFormat(videoEnc);
    EXPECT_EQ(ret, Status::OK);
    
    std::string metaKey = Tag::MIME_TYPE;
    std::string outputStrVal;
    EXPECT_FALSE(transcoder_->videoEncFormat_->GetData(metaKey, outputStrVal));
}

/**
* @tc.name    : Test SetTrackMime API
* @tc.number  : SetTrackMime_001
* @tc.desc    : Test SetTrackMime interface, dont set MIME_TYPE.
* @tc.require :
*/
HWTEST_F(HitranscodeUnitTest, SetTrackMime_001, TestSize.Level0)
{
    std::shared_ptr<Meta> inputMeta = std::make_shared<Meta>();
    std::vector<std::shared_ptr<Meta>> trackInfos;
    trackInfos.push_back(inputMeta);
    Status ret = transcoder_->SetTrackMime(trackInfos);
    EXPECT_EQ(ret, Status::OK);
}

/**
* @tc.name    : Test SetTrackMime API
* @tc.number  : SetTrackMime_002
* @tc.desc    : Test SetTrackMime interface, video condition 11.
* @tc.require :
*/
HWTEST_F(HitranscodeUnitTest, SetTrackMime_002, TestSize.Level0)
{
    std::shared_ptr<Meta> inputMeta = std::make_shared<Meta>();
    std::string metaKey = Tag::MIME_TYPE;
    std::string strVal = "video/263";
    inputMeta->SetData(metaKey, strVal);
    std::vector<std::shared_ptr<Meta>> trackInfos;
    trackInfos.push_back(inputMeta);

    Status ret = transcoder_->SetTrackMime(trackInfos);
    EXPECT_EQ(ret, Status::OK);

    std::string outputStrVal;
    EXPECT_TRUE(transcoder_->videoEncFormat_->GetData(metaKey, outputStrVal));
    EXPECT_EQ(strVal, outputStrVal);
}

/**
* @tc.name    : Test SetTrackMime API
* @tc.number  : SetTrackMime_003
* @tc.desc    : Test SetTrackMime interface, video condition 10.
* @tc.require :
*/
HWTEST_F(HitranscodeUnitTest, SetTrackMime_003, TestSize.Level0)
{
    std::shared_ptr<Meta> inputMeta = std::make_shared<Meta>();
    std::string metaKey = Tag::MIME_TYPE;
    std::string strVal = "video/263";
    inputMeta->SetData(metaKey, strVal);
    std::vector<std::shared_ptr<Meta>> trackInfos;
    trackInfos.push_back(inputMeta);

    transcoder_->videoEncFormat_->SetData(metaKey, strVal);

    Status ret = transcoder_->SetTrackMime(trackInfos);
    EXPECT_EQ(ret, Status::OK);
}

/**
* @tc.name    : Test SetTrackMime API
* @tc.number  : SetTrackMime_004
* @tc.desc    : Test SetTrackMime interface, audio condition 11.
* @tc.require :
*/
HWTEST_F(HitranscodeUnitTest, SetTrackMime_004, TestSize.Level0)
{
    std::shared_ptr<Meta> inputMeta = std::make_shared<Meta>();
    std::string metaKey = Tag::MIME_TYPE;
    std::string strVal = "audio/mp4a-latm";
    inputMeta->SetData(metaKey, strVal);
    std::vector<std::shared_ptr<Meta>> trackInfos;
    trackInfos.push_back(inputMeta);

    Status ret = transcoder_->SetTrackMime(trackInfos);
    EXPECT_EQ(ret, Status::OK);

    std::string outputStrVal;
    EXPECT_TRUE(transcoder_->audioEncFormat_->GetData(metaKey, outputStrVal));
    EXPECT_EQ(strVal, outputStrVal);
}

/**
* @tc.name    : Test SetTrackMime API
* @tc.number  : SetTrackMime_005
* @tc.desc    : Test SetTrackMime interface, audio condition 10.
* @tc.require :
*/
HWTEST_F(HitranscodeUnitTest, SetTrackMime_005, TestSize.Level0)
{
    std::shared_ptr<Meta> inputMeta = std::make_shared<Meta>();
    std::string metaKey = Tag::MIME_TYPE;
    std::string strVal = "audio/mp4a-latm";
    inputMeta->SetData(metaKey, strVal);
    std::vector<std::shared_ptr<Meta>> trackInfos;
    trackInfos.push_back(inputMeta);

    transcoder_->audioEncFormat_->SetData(metaKey, strVal);

    Status ret = transcoder_->SetTrackMime(trackInfos);
    EXPECT_EQ(ret, Status::OK);
}

/**
* @tc.name    : Test ConfigureMetaData API
* @tc.number  : ConfigureMetaData_001
* @tc.desc    : Test SetTrackMime interface, dont set MEDIA_TYPE.
* @tc.require :
*/
HWTEST_F(HitranscodeUnitTest, ConfigureMetaData_001, TestSize.Level0)
{
    std::shared_ptr<Meta> inputMeta = std::make_shared<Meta>();
    std::vector<std::shared_ptr<Meta>> trackInfos;
    trackInfos.push_back(inputMeta);

    Status ret = transcoder_->ConfigureMetaData(trackInfos);
    EXPECT_EQ(ret, Status::OK);
}

/**
* @tc.name    : Test ConfigureMetaData API
* @tc.number  : ConfigureMetaData_002
* @tc.desc    : Test SetTrackMime interface, dont set AUDIO_CHANNEL_COUNT and AUDIO_SAMPLE_RATE.
* @tc.require :
*/
HWTEST_F(HitranscodeUnitTest, ConfigureMetaData_002, TestSize.Level0)
{
    std::shared_ptr<Meta> inputMeta = std::make_shared<Meta>();
    std::string metaKey = Tag::MIME_TYPE;
    Plugins::MediaType mediaType = Plugins::MediaType::AUDIO;
    inputMeta->SetData(metaKey, mediaType);
    std::vector<std::shared_ptr<Meta>> trackInfos;
    trackInfos.push_back(inputMeta);
    Status ret = transcoder_->ConfigureMetaData(trackInfos);
    EXPECT_EQ(ret, Status::OK);
}

/**
* @tc.name    : Test ConfigureMetaData API
* @tc.number  : ConfigureMetaData_003
* @tc.desc    : Test SetTrackMime interface,  dont set AUDIO_CHANNEL_COUNT.
* @tc.require :
*/
HWTEST_F(HitranscodeUnitTest, ConfigureMetaData_003, TestSize.Level0)
{
    std::shared_ptr<Meta> inputMeta = std::make_shared<Meta>();
    std::string metaKey = Tag::MEDIA_TYPE;
    Plugins::MediaType mediaType = Plugins::MediaType::AUDIO;
    inputMeta->SetData(metaKey, mediaType);

    metaKey = Tag::AUDIO_SAMPLE_RATE;
    int32_t sampleRate = 0;
    inputMeta->SetData(metaKey, sampleRate);
    std::vector<std::shared_ptr<Meta>> trackInfos;
    trackInfos.push_back(inputMeta);
    Status ret = transcoder_->ConfigureMetaData(trackInfos);
    EXPECT_EQ(ret, Status::OK);
}

/**
* @tc.name    : Test ConfigureMetaData API
* @tc.number  : ConfigureMetaData_004
* @tc.desc    : Test SetTrackMime interface,  dont set AUDIO_SAMPLE_RATE.
* @tc.require :
*/
HWTEST_F(HitranscodeUnitTest, ConfigureMetaData_004, TestSize.Level0)
{
    std::shared_ptr<Meta> inputMeta = std::make_shared<Meta>();
    std::string metaKey = Tag::MEDIA_TYPE;
    Plugins::MediaType mediaType = Plugins::MediaType::AUDIO;
    inputMeta->SetData(metaKey, mediaType);

    metaKey = Tag::AUDIO_CHANNEL_COUNT;
    int32_t channels = 0;
    inputMeta->SetData(metaKey, channels);
    std::vector<std::shared_ptr<Meta>> trackInfos;
    trackInfos.push_back(inputMeta);
    Status ret = transcoder_->ConfigureMetaData(trackInfos);
    EXPECT_EQ(ret, Status::OK);
}
} // namespace Media
} // namespace OHOS