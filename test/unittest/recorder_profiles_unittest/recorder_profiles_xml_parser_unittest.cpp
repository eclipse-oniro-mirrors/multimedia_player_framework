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

#include "recorder_profiles_xml_parser_unittest.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing;
using namespace testing::ext;

void RecorderProfilesXmlParserUnitTest::SetUpTestCase(void)
{
}

void RecorderProfilesXmlParserUnitTest::TearDownTestCase(void)
{
}

void RecorderProfilesXmlParserUnitTest::SetUp(void)
{
    recorderProfilesXmlParser_ = std::make_shared<RecorderProfilesXmlParser>();
}

void RecorderProfilesXmlParserUnitTest::TearDown(void)
{
    recorderProfilesXmlParser_ = nullptr;
}

/**
 * @tc.name  : Test SetCapabilityIntData
 * @tc.number: SetCapabilityIntData_001
 * @tc.desc  : Test SetCapabilityIntData StrToInt(capabilityValue, value) = false
 */
HWTEST_F(RecorderProfilesXmlParserUnitTest, SetCapabilityIntData_001, TestSize.Level1)
{
    std::unordered_map<std::string, int32_t&> dataMap;
    const std::string capabilityKey = "invalid_key";
    const std::string capabilityValue = "invalid_value";
    recorderProfilesXmlParser_->SetCapabilityIntData(dataMap, capabilityKey, capabilityValue);
    EXPECT_TRUE(dataMap.empty());
}

/**
 * @tc.name  : Test SetCapabilityVectorData
 * @tc.number: SetCapabilityVectorData_001
 * @tc.desc  : Test SetCapabilityVectorData XmlParser::IsNumberArray(spilt) == false
 */
HWTEST_F(RecorderProfilesXmlParserUnitTest, SetCapabilityVectorData_001, TestSize.Level1)
{
    std::unordered_map<std::string, std::vector<int32_t>&> dataMap;
    const std::string capabilityKey = "invalid_key";
    const std::string capabilityValue = "123,abc,456";
    bool ret = recorderProfilesXmlParser_->SetCapabilityVectorData(dataMap, capabilityKey, capabilityValue);
    EXPECT_TRUE(!ret);
}

/**
 * @tc.name  : Test SetContainerFormat
 * @tc.number: SetContainerFormat_001
 * @tc.desc  : Test SetContainerFormat capabilityStringMap.find(capabilityKey) == capabilityStringMap.end()
 */
HWTEST_F(RecorderProfilesXmlParserUnitTest, SetContainerFormat_001, TestSize.Level1)
{
    ContainerFormatInfo data;
    const std::string capabilityKey = "invalid_key";
    const std::string capabilityValue = "invalid_value";
    bool ret = recorderProfilesXmlParser_->SetContainerFormat(data, capabilityKey, capabilityValue);
    EXPECT_TRUE(!ret);
}

/**
 * @tc.name  : Test SetVideoRecorderCaps
 * @tc.number: SetVideoRecorderCaps_001
 * @tc.desc  : Test SetVideoRecorderCaps capabilityRangeMap.find(capabilityKey) == capabilityRangeMap.end()
 */
HWTEST_F(RecorderProfilesXmlParserUnitTest, SetVideoRecorderCaps_001, TestSize.Level1)
{
    RecorderProfilesData data;
    const std::string capabilityKey = "invalid_key";
    const std::string capabilityValue = "invalid_value";
    bool ret = recorderProfilesXmlParser_->SetVideoRecorderCaps(data, capabilityKey, capabilityValue);
    EXPECT_TRUE(!ret);
}

/**
 * @tc.name  : Test SetAudioRecorderCaps
 * @tc.number: SetAudioRecorderCaps_001
 * @tc.desc  : Test SetAudioRecorderCaps capabilityVectorMap.find(capabilityKey) == capabilityVectorMap.end()
 */
HWTEST_F(RecorderProfilesXmlParserUnitTest, SetAudioRecorderCaps_001, TestSize.Level1)
{
    RecorderProfilesData data;
    const std::string capabilityKey = "invalid_key";
    const std::string capabilityValue = "invalid_value";
    bool ret = recorderProfilesXmlParser_->SetAudioRecorderCaps(data, capabilityKey, capabilityValue);
    EXPECT_TRUE(!ret);
}

/**
 * @tc.name  : Test PackageVideoRecorderCaps
 * @tc.number: PackageVideoRecorderCaps_001
 * @tc.desc  : Test CONTAINER_VIDEOCAPS_VIDEO_MAP.find(formatType) == CONTAINER_VIDEOCAPS_VIDEO_MAP.end()
 *             Test CONTAINER_VIDEOCAPS_AUDIO_MAP.find(formatType) == CONTAINER_VIDEOCAPS_AUDIO_MAP.end()
 *             Test itVideoCodec == CONTAINER_VIDEOCAPS_VIDEO_MAP.at(formatType).end()
 */
HWTEST_F(RecorderProfilesXmlParserUnitTest, PackageVideoRecorderCaps_001, TestSize.Level1)
{
    // Test CONTAINER_VIDEOCAPS_VIDEO_MAP.find(formatType) == CONTAINER_VIDEOCAPS_VIDEO_MAP.end()
    // Test CONTAINER_VIDEOCAPS_AUDIO_MAP.find(formatType) == CONTAINER_VIDEOCAPS_AUDIO_MAP.end()
    std::string formatType = "invalid_format";
    recorderProfilesXmlParser_->PackageVideoRecorderCaps(formatType);

    // Test itVideoCodec == CONTAINER_VIDEOCAPS_VIDEO_MAP.at(formatType).end()
    formatType = "mp4";
    RecorderProfilesData data;
    recorderProfilesXmlParser_->videoEncoderCapsArray_.push_back(data);
    recorderProfilesXmlParser_->PackageVideoRecorderCaps(formatType);
    EXPECT_TRUE(recorderProfilesXmlParser_->capabilityDataArray_.empty());
}

/**
 * @tc.name  : Test PaddingVideoCapsByAudioCaps
 * @tc.number: PaddingVideoCapsByAudioCaps_001
 * @tc.desc  : Test PaddingVideoCapsByAudioCaps itAudioCodec == CONTAINER_VIDEOCAPS_AUDIO_MAP.at(formatType).end()
 */
HWTEST_F(RecorderProfilesXmlParserUnitTest, PaddingVideoCapsByAudioCaps_001, TestSize.Level1)
{
    std::string formatType = "mp4";
    RecorderProfilesData data { .audioCaps.mimeType = "invalid_audio_mime" };
    recorderProfilesXmlParser_->audioEncoderCapsArray_.push_back(data);
    recorderProfilesXmlParser_->PaddingVideoCapsByAudioCaps(formatType, data);
    EXPECT_TRUE(recorderProfilesXmlParser_->capabilityDataArray_.empty());
}

/**
 * @tc.name  : Test PackageAudioRecorderCaps
 * @tc.number: PackageAudioRecorderCaps_001
 * @tc.desc  : Test CONTAINER_AUDIOCAPS_AUDIO_MAP.find(formatType) == CONTAINER_AUDIOCAPS_AUDIO_MAP.end()
 *             Test itAudioCodec == CONTAINER_AUDIOCAPS_AUDIO_MAP.at(formatType).end()
 */
HWTEST_F(RecorderProfilesXmlParserUnitTest, PackageAudioRecorderCaps_001, TestSize.Level1)
{
    // Test CONTAINER_AUDIOCAPS_AUDIO_MAP.find(formatType) == CONTAINER_AUDIOCAPS_AUDIO_MAP.end()
    std::string formatType = "invalid_format";
    recorderProfilesXmlParser_->PackageAudioRecorderCaps(formatType);

    // Test itAudioCodec == CONTAINER_AUDIOCAPS_AUDIO_MAP.at(formatType).end()
    formatType = "m4a";
    RecorderProfilesData data { .audioCaps.mimeType = "invalid_audio_mime" };
    recorderProfilesXmlParser_->audioEncoderCapsArray_.push_back(data);
    recorderProfilesXmlParser_->PackageAudioRecorderCaps(formatType);
    EXPECT_TRUE(recorderProfilesXmlParser_->capabilityDataArray_.empty());
}

/**
 * @tc.name  : Test SetVideoRecorderProfiles
 * @tc.number: SetVideoRecorderProfiles_001
 * @tc.desc  : Test SetVideoRecorderProfiles capabilityIntMap.find(capabilityKey) == capabilityIntMap.end()
 */
HWTEST_F(RecorderProfilesXmlParserUnitTest, SetVideoRecorderProfiles_001, TestSize.Level1)
{
    RecorderProfilesData data;
    const std::string capabilityKey = "invalid_key";
    const std::string capabilityValue = "invalid_value";
    bool ret = recorderProfilesXmlParser_->SetVideoRecorderProfiles(data, capabilityKey, capabilityValue);
    EXPECT_TRUE(!ret);
}

/**
 * @tc.name  : Test SetAudioRecorderProfiles
 * @tc.number: SetAudioRecorderProfiles_001
 * @tc.desc  : Test SetAudioRecorderProfiles capabilityIntMap.find(capabilityKey) == capabilityIntMap.end()
 */
HWTEST_F(RecorderProfilesXmlParserUnitTest, SetAudioRecorderProfiles_001, TestSize.Level1)
{
    RecorderProfilesData data;
    const std::string capabilityKey = "invalid_key";
    const std::string capabilityValue = "invalid_value";
    bool ret = recorderProfilesXmlParser_->SetAudioRecorderProfiles(data, capabilityKey, capabilityValue);
    EXPECT_TRUE(!ret);
}

/**
 * @tc.name  : Test GetNodeNameAsInt
 * @tc.number: GetNodeNameAsInt_001
 * @tc.desc  : Test !xmlStrcmp(node->name, reinterpret_cast<const xmlChar*>("RecorderProfiles")) == false
 */
HWTEST_F(RecorderProfilesXmlParserUnitTest, GetNodeNameAsInt_001, TestSize.Level1)
{
    xmlNode node { .name = reinterpret_cast<const xmlChar*>("test_node") };
    auto name = recorderProfilesXmlParser_->GetNodeNameAsInt(&node);
    EXPECT_EQ(name, RecorderProfilesNodeName::UNKNOWN);
}

/**
 * @tc.name  : Test ParseRecorderProfilesSourceData
 * @tc.number: ParseRecorderProfilesSourceData_001
 * @tc.desc  : Test xmlHasProp(node, reinterpret_cast<xmlChar*>(const_cast<char*>(property.c_str()))) == false
 */
HWTEST_F(RecorderProfilesXmlParserUnitTest, ParseRecorderProfilesSourceData_001, TestSize.Level1)
{
    std::string sourceType = "CameraRecorder";
    xmlNode node { .name = reinterpret_cast<const xmlChar*>("CameraRecorder") };
    node.properties = nullptr;
    bool ret = recorderProfilesXmlParser_->ParseRecorderProfilesSourceData(sourceType, &node);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name  : Test ParseRecorderProfilesSourceData
 * @tc.number: ParseRecorderProfilesSourceData_002
 * @tc.desc  : Test ParseRecorderProfilesSourceData propValue.get() == nullptr
 *             Test ParseRecorderProfilesSourceData SOURCE_TYPE_MAP.find(sourceType) != SOURCE_TYPE_MAP.end()
 */
HWTEST_F(RecorderProfilesXmlParserUnitTest, ParseRecorderProfilesSourceData_002, TestSize.Level1)
{
    // Test ParseRecorderProfilesSourceData propValue.get() == nullptr
    std::string sourceType = "CameraRecorder";
    xmlNode node { .name = reinterpret_cast<const xmlChar*>("CameraRecorder") };
    xmlAttr attr { .name = reinterpret_cast<const xmlChar*>("cameraId") };
    node.properties = &attr;
    bool ret = recorderProfilesXmlParser_->ParseRecorderProfilesSourceData(sourceType, &node);

    // Test ParseRecorderProfilesSourceData SOURCE_TYPE_MAP.find(sourceType) != SOURCE_TYPE_MAP.end()
    xmlNode node_child { .name = reinterpret_cast<const xmlChar*>("ProfileSettings") };
    attr.children = &node_child;
    ret = recorderProfilesXmlParser_->ParseRecorderProfilesSourceData(sourceType, &node);
    EXPECT_TRUE(ret);
}
} // namespace Media
} // namespace OHOS
