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
    EXPECT_TRUE(recorderProfilesXmlParser_->capabilityDataArray_.empty());

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
    EXPECT_TRUE(recorderProfilesXmlParser_->capabilityDataArray_.empty());

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

HWTEST_F(RecorderProfilesXmlParserUnitTest, SetCapabilityIntData_002, TestSize.Level1)
{
    int32_t value = 0;
    std::unordered_map<std::string, int32_t&> dataMap = {{"quality", value}};
    bool ret = recorderProfilesXmlParser_->SetCapabilityIntData(dataMap, "quality", "low");
    EXPECT_TRUE(ret);
    EXPECT_EQ(value, RECORDER_QUALITY_LOW);
}

HWTEST_F(RecorderProfilesXmlParserUnitTest, SetCapabilityIntData_003, TestSize.Level1)
{
    int32_t value = 0;
    std::unordered_map<std::string, int32_t&> dataMap = {{"bitrate", value}};
    bool ret = recorderProfilesXmlParser_->SetCapabilityIntData(dataMap, "bitrate", "96000");
    EXPECT_TRUE(ret);
    EXPECT_EQ(value, 96000);
}

HWTEST_F(RecorderProfilesXmlParserUnitTest, SetCapabilityVectorData_002, TestSize.Level1)
{
    std::vector<int32_t> vec;
    std::unordered_map<std::string, std::vector<int32_t>&> dataMap = {{"sampleRate", vec}};
    bool ret = recorderProfilesXmlParser_->SetCapabilityVectorData(dataMap, "sampleRate", "48000,44100");
    EXPECT_TRUE(ret);
    EXPECT_FALSE(vec.empty());
    EXPECT_EQ(vec[0], 48000);
    EXPECT_EQ(vec[1], 44100);
}

HWTEST_F(RecorderProfilesXmlParserUnitTest, SetCapabilityVectorData_003, TestSize.Level1)
{
    std::vector<int32_t> vec;
    std::unordered_map<std::string, std::vector<int32_t>&> dataMap = {{"sampleRate", vec}};
    bool ret = recorderProfilesXmlParser_->SetCapabilityVectorData(dataMap, "sampleRate", "");
    EXPECT_FALSE(ret);
}

HWTEST_F(RecorderProfilesXmlParserUnitTest, SetContainerFormat_002, TestSize.Level1)
{
    ContainerFormatInfo data;
    bool ret = recorderProfilesXmlParser_->SetContainerFormat(data, "name", "mp4");
    EXPECT_TRUE(ret);
    EXPECT_EQ(data.name, "mp4");

    ret = recorderProfilesXmlParser_->SetContainerFormat(data, "hasVideo", "true");
    EXPECT_TRUE(ret);
    EXPECT_EQ(data.hasVideo, "true");
}

HWTEST_F(RecorderProfilesXmlParserUnitTest, SetVideoRecorderCaps_002, TestSize.Level1)
{
    RecorderProfilesData data;
    bool ret = recorderProfilesXmlParser_->SetVideoRecorderCaps(data, "codecMime", "video/avc");
    EXPECT_TRUE(ret);
    EXPECT_EQ(data.videoCaps.videoEncoderMime, "video/avc");

    ret = recorderProfilesXmlParser_->SetVideoRecorderCaps(data, "bitrate", "1-1000000");
    EXPECT_TRUE(ret);

    ret = recorderProfilesXmlParser_->SetVideoRecorderCaps(data, "width", "128-1920");
    EXPECT_TRUE(ret);

    ret = recorderProfilesXmlParser_->SetVideoRecorderCaps(data, "height", "128-1080");
    EXPECT_TRUE(ret);

    ret = recorderProfilesXmlParser_->SetVideoRecorderCaps(data, "frameRate", "1-60");
    EXPECT_TRUE(ret);
}

HWTEST_F(RecorderProfilesXmlParserUnitTest, SetAudioRecorderCaps_002, TestSize.Level1)
{
    RecorderProfilesData data;
    bool ret = recorderProfilesXmlParser_->SetAudioRecorderCaps(data, "codecMime", "audio/mp4a-latm");
    EXPECT_TRUE(ret);
    EXPECT_EQ(data.audioCaps.mimeType, "audio/mp4a-latm");

    ret = recorderProfilesXmlParser_->SetAudioRecorderCaps(data, "bitrate", "1-320000");
    EXPECT_TRUE(ret);

    ret = recorderProfilesXmlParser_->SetAudioRecorderCaps(data, "channels", "1-2");
    EXPECT_TRUE(ret);

    ret = recorderProfilesXmlParser_->SetAudioRecorderCaps(data, "sampleRate", "8000,48000");
    EXPECT_TRUE(ret);
}

HWTEST_F(RecorderProfilesXmlParserUnitTest, SetVideoRecorderProfiles_002, TestSize.Level1)
{
    RecorderProfilesData data;
    bool ret = recorderProfilesXmlParser_->SetVideoRecorderProfiles(data, "format", "mp4");
    EXPECT_TRUE(ret);
    EXPECT_EQ(data.recorderProfile.containerFormatType, "mp4");

    ret = recorderProfilesXmlParser_->SetVideoRecorderProfiles(data, "codecMime", "video/avc");
    EXPECT_TRUE(ret);
    EXPECT_EQ(data.recorderProfile.videoCodec, "video/avc");

    ret = recorderProfilesXmlParser_->SetVideoRecorderProfiles(data, "duration", "60");
    EXPECT_TRUE(ret);
    EXPECT_EQ(data.recorderProfile.durationTime, 60);

    ret = recorderProfilesXmlParser_->SetVideoRecorderProfiles(data, "bitrate", "2000000");
    EXPECT_TRUE(ret);

    ret = recorderProfilesXmlParser_->SetVideoRecorderProfiles(data, "quality", "low");
    EXPECT_TRUE(ret);
    EXPECT_EQ(data.recorderProfile.qualityLevel, RECORDER_QUALITY_LOW);
}

HWTEST_F(RecorderProfilesXmlParserUnitTest, SetAudioRecorderProfiles_002, TestSize.Level1)
{
    RecorderProfilesData data;
    bool ret = recorderProfilesXmlParser_->SetAudioRecorderProfiles(data, "format", "m4a");
    EXPECT_TRUE(ret);
    EXPECT_EQ(data.recorderProfile.containerFormatType, "m4a");

    ret = recorderProfilesXmlParser_->SetAudioRecorderProfiles(data, "codecMime", "audio/mp4a-latm");
    EXPECT_TRUE(ret);
    EXPECT_EQ(data.recorderProfile.audioCodec, "audio/mp4a-latm");

    ret = recorderProfilesXmlParser_->SetAudioRecorderProfiles(data, "bitrate", "96000");
    EXPECT_TRUE(ret);

    ret = recorderProfilesXmlParser_->SetAudioRecorderProfiles(data, "sampleRate", "48000");
    EXPECT_TRUE(ret);

    ret = recorderProfilesXmlParser_->SetAudioRecorderProfiles(data, "channels", "2");
    EXPECT_TRUE(ret);
}

HWTEST_F(RecorderProfilesXmlParserUnitTest, GetNodeNameAsInt_002, TestSize.Level1)
{
    xmlNode node1 { .name = reinterpret_cast<const xmlChar*>("RecorderConfigurations") };
    EXPECT_EQ(recorderProfilesXmlParser_->GetNodeNameAsInt(&node1),
              RecorderProfilesNodeName::RECORDER_CONFIGURATIONS);

    xmlNode node2 { .name = reinterpret_cast<const xmlChar*>("RecorderCaps") };
    EXPECT_EQ(recorderProfilesXmlParser_->GetNodeNameAsInt(&node2),
              RecorderProfilesNodeName::RECORDER_CAPS);

    xmlNode node3 { .name = reinterpret_cast<const xmlChar*>("RecorderProfiles") };
    EXPECT_EQ(recorderProfilesXmlParser_->GetNodeNameAsInt(&node3),
              RecorderProfilesNodeName::RECORDER_PROFILES);
}

HWTEST_F(RecorderProfilesXmlParserUnitTest, LoadAndParse_001, TestSize.Level1)
{
    bool ret = recorderProfilesXmlParser_->LoadConfiguration("/etc/recorder/recorder_configs.xml");
    EXPECT_TRUE(ret);
    ret = recorderProfilesXmlParser_->Parse();
    EXPECT_TRUE(ret);
    auto data = recorderProfilesXmlParser_->GetRecorderProfileDataArray();
    EXPECT_FALSE(data.empty());
}

HWTEST_F(RecorderProfilesXmlParserUnitTest, LoadAndParse_002, TestSize.Level1)
{
    bool ret = recorderProfilesXmlParser_->LoadConfiguration("/invalid/path/no_file.xml");
    EXPECT_FALSE(ret);
}

HWTEST_F(RecorderProfilesXmlParserUnitTest, AbilitySingleton_GetInstance_001, TestSize.Level1)
{
    auto& instance = RecorderProfilesAbilitySingleton::GetInstance();
    auto data = instance.GetCapabilityDataArray();
    EXPECT_FALSE(data.empty());
}

HWTEST_F(RecorderProfilesXmlParserUnitTest, AbilitySingleton_GetInstance_002, TestSize.Level1)
{
    auto& instance1 = RecorderProfilesAbilitySingleton::GetInstance();
    auto& instance2 = RecorderProfilesAbilitySingleton::GetInstance();
    EXPECT_EQ(&instance1, &instance2);
    auto data = instance2.GetCapabilityDataArray();
    EXPECT_FALSE(data.empty());
}

HWTEST_F(RecorderProfilesXmlParserUnitTest, SetCapabilityIntData_004, TestSize.Level1)
{
    int32_t value = 0;
    std::unordered_map<std::string, int32_t&> dataMap = {{"bitrate", value}};
    bool ret = recorderProfilesXmlParser_->SetCapabilityIntData(dataMap, "bitrate", "abc");
    EXPECT_FALSE(ret);
}

HWTEST_F(RecorderProfilesXmlParserUnitTest, PackageVideoRecorderCaps_002, TestSize.Level1)
{
    recorderProfilesXmlParser_->capabilityDataArray_.clear();
    recorderProfilesXmlParser_->videoEncoderCapsArray_.clear();
    recorderProfilesXmlParser_->audioEncoderCapsArray_.clear();
    std::string formatType = "mp4";
    RecorderProfilesData videoData;
    videoData.videoCaps.videoEncoderMime = "video/avc";
    recorderProfilesXmlParser_->videoEncoderCapsArray_.push_back(videoData);
    RecorderProfilesData audioData;
    audioData.audioCaps.mimeType = "audio/mp4a-latm";
    recorderProfilesXmlParser_->audioEncoderCapsArray_.push_back(audioData);
    recorderProfilesXmlParser_->PackageVideoRecorderCaps(formatType);
    EXPECT_FALSE(recorderProfilesXmlParser_->capabilityDataArray_.empty());
}

HWTEST_F(RecorderProfilesXmlParserUnitTest, PackageAudioRecorderCaps_002, TestSize.Level1)
{
    recorderProfilesXmlParser_->capabilityDataArray_.clear();
    recorderProfilesXmlParser_->audioEncoderCapsArray_.clear();
    std::string formatType = "m4a";
    RecorderProfilesData audioData;
    audioData.audioCaps.mimeType = "audio/mp4a-latm";
    recorderProfilesXmlParser_->audioEncoderCapsArray_.push_back(audioData);
    recorderProfilesXmlParser_->PackageAudioRecorderCaps(formatType);
    EXPECT_FALSE(recorderProfilesXmlParser_->capabilityDataArray_.empty());
}

HWTEST_F(RecorderProfilesXmlParserUnitTest, PackageRecorderCaps_001, TestSize.Level1)
{
    recorderProfilesXmlParser_->containerFormatArray_.clear();
    recorderProfilesXmlParser_->capabilityDataArray_.clear();
    recorderProfilesXmlParser_->videoEncoderCapsArray_.clear();
    recorderProfilesXmlParser_->audioEncoderCapsArray_.clear();
    ContainerFormatInfo info;
    info.hasVideo = "true";
    info.name = "mp4";
    recorderProfilesXmlParser_->containerFormatArray_.push_back(info);
    RecorderProfilesData videoData;
    videoData.videoCaps.videoEncoderMime = "video/avc";
    recorderProfilesXmlParser_->videoEncoderCapsArray_.push_back(videoData);
    RecorderProfilesData audioData;
    audioData.audioCaps.mimeType = "audio/mp4a-latm";
    recorderProfilesXmlParser_->audioEncoderCapsArray_.push_back(audioData);
    recorderProfilesXmlParser_->PackageRecorderCaps();
    EXPECT_FALSE(recorderProfilesXmlParser_->capabilityDataArray_.empty());
}

HWTEST_F(RecorderProfilesXmlParserUnitTest, PackageRecorderCaps_002, TestSize.Level1)
{
    recorderProfilesXmlParser_->containerFormatArray_.clear();
    recorderProfilesXmlParser_->capabilityDataArray_.clear();
    recorderProfilesXmlParser_->audioEncoderCapsArray_.clear();
    ContainerFormatInfo info;
    info.hasVideo = "false";
    info.name = "m4a";
    recorderProfilesXmlParser_->containerFormatArray_.push_back(info);
    RecorderProfilesData audioData;
    audioData.audioCaps.mimeType = "audio/mp4a-latm";
    recorderProfilesXmlParser_->audioEncoderCapsArray_.push_back(audioData);
    recorderProfilesXmlParser_->PackageRecorderCaps();
    EXPECT_FALSE(recorderProfilesXmlParser_->capabilityDataArray_.empty());
}

HWTEST_F(RecorderProfilesXmlParserUnitTest, PaddingVideoCapsByAudioCaps_002, TestSize.Level1)
{
    recorderProfilesXmlParser_->capabilityDataArray_.clear();
    recorderProfilesXmlParser_->audioEncoderCapsArray_.clear();
    std::string formatType = "mp4";
    RecorderProfilesData videoData;
    videoData.videoCaps.videoEncoderMime = "video/avc";
    RecorderProfilesData audioData;
    audioData.audioCaps.mimeType = "audio/mp4a-latm";
    recorderProfilesXmlParser_->audioEncoderCapsArray_.push_back(audioData);
    recorderProfilesXmlParser_->PaddingVideoCapsByAudioCaps(formatType, videoData);
    EXPECT_FALSE(recorderProfilesXmlParser_->capabilityDataArray_.empty());
}

HWTEST_F(RecorderProfilesXmlParserUnitTest, SetContainerFormat_003, TestSize.Level1)
{
    ContainerFormatInfo data;
    bool ret = recorderProfilesXmlParser_->SetContainerFormat(data, "format", "mp4");
    EXPECT_FALSE(ret);
}

HWTEST_F(RecorderProfilesXmlParserUnitTest, SetVideoRecorderCaps_003, TestSize.Level1)
{
    RecorderProfilesData data;
    bool ret = recorderProfilesXmlParser_->SetVideoRecorderCaps(data, "format", "mp4");
    EXPECT_FALSE(ret);
}

HWTEST_F(RecorderProfilesXmlParserUnitTest, SetAudioRecorderCaps_003, TestSize.Level1)
{
    RecorderProfilesData data;
    bool ret = recorderProfilesXmlParser_->SetAudioRecorderCaps(data, "format", "mp4");
    EXPECT_FALSE(ret);
}

HWTEST_F(RecorderProfilesXmlParserUnitTest, SetVideoRecorderProfiles_003, TestSize.Level1)
{
    RecorderProfilesData data;
    bool ret = recorderProfilesXmlParser_->SetVideoRecorderProfiles(data, "sampleRate", "48000");
    EXPECT_FALSE(ret);
}

HWTEST_F(RecorderProfilesXmlParserUnitTest, SetAudioRecorderProfiles_003, TestSize.Level1)
{
    RecorderProfilesData data;
    bool ret = recorderProfilesXmlParser_->SetAudioRecorderProfiles(data, "duration", "60");
    EXPECT_FALSE(ret);
}


HWTEST_F(RecorderProfilesXmlParserUnitTest, ParseRecorderCapsData_005, TestSize.Level1)
{
    const char *xml = "<RecorderCaps><ContainerFormat format=\"mp4\"/></RecorderCaps>";
    auto doc = xmlReadMemory(xml, strlen(xml), "test.xml", nullptr, 0);
    EXPECT_NE(doc, nullptr);
    auto root = xmlDocGetRootElement(doc);
    bool ret = recorderProfilesXmlParser_->ParseRecorderCapsData(root);
    xmlFreeDoc(doc);
    EXPECT_FALSE(ret);
}

HWTEST_F(RecorderProfilesXmlParserUnitTest, ParseRecorderCapsData_006, TestSize.Level1)
{
    const char *xml = "<RecorderCaps><VideoEncoderCaps format=\"mp4\"/></RecorderCaps>";
    auto doc = xmlReadMemory(xml, strlen(xml), "test.xml", nullptr, 0);
    EXPECT_NE(doc, nullptr);
    auto root = xmlDocGetRootElement(doc);
    bool ret = recorderProfilesXmlParser_->ParseRecorderCapsData(root);
    xmlFreeDoc(doc);
    EXPECT_FALSE(ret);
}

HWTEST_F(RecorderProfilesXmlParserUnitTest, ParseRecorderCapsData_007, TestSize.Level1)
{
    const char *xml = "<RecorderCaps><AudioEncoderCaps format=\"mp4\"/></RecorderCaps>";
    auto doc = xmlReadMemory(xml, strlen(xml), "test.xml", nullptr, 0);
    EXPECT_NE(doc, nullptr);
    auto root = xmlDocGetRootElement(doc);
    bool ret = recorderProfilesXmlParser_->ParseRecorderCapsData(root);
    xmlFreeDoc(doc);
    EXPECT_FALSE(ret);
}

HWTEST_F(RecorderProfilesXmlParserUnitTest, ParseRecorderCapsData_008, TestSize.Level1)
{
    recorderProfilesXmlParser_->containerFormatArray_.clear();
    recorderProfilesXmlParser_->videoEncoderCapsArray_.clear();
    recorderProfilesXmlParser_->audioEncoderCapsArray_.clear();
    const char *xml =
        "<RecorderCaps>"
        "<ContainerFormat name=\"mp4\" hasVideo=\"true\"/>"
        "<VideoEncoderCaps codecMime=\"video/avc\" bitrate=\"1-1000000\" width=\"128-1920\"/>"
        "<AudioEncoderCaps codecMime=\"audio/mp4a-latm\" bitrate=\"1-320000\" "
        "channels=\"1-2\" sampleRate=\"8000,48000\"/>"
        "</RecorderCaps>";
    auto doc = xmlReadMemory(xml, strlen(xml), "test.xml", nullptr, 0);
    EXPECT_NE(doc, nullptr);
    auto root = xmlDocGetRootElement(doc);
    bool ret = recorderProfilesXmlParser_->ParseRecorderCapsData(root);
    EXPECT_TRUE(ret);
    EXPECT_FALSE(recorderProfilesXmlParser_->containerFormatArray_.empty());
    EXPECT_FALSE(recorderProfilesXmlParser_->videoEncoderCapsArray_.empty());
    xmlFreeDoc(doc);
    EXPECT_FALSE(recorderProfilesXmlParser_->audioEncoderCapsArray_.empty());
}

HWTEST_F(RecorderProfilesXmlParserUnitTest, ParseInternal_001, TestSize.Level1)
{
    const char *xml =
        "<RecorderConfigurations>"
        "<RecorderCaps>"
        "<ContainerFormat name=\"mp4\" hasVideo=\"true\"/>"
        "</RecorderCaps>"
        "</RecorderConfigurations>";
    auto doc = xmlReadMemory(xml, strlen(xml), "test.xml", nullptr, 0);
    EXPECT_NE(doc, nullptr);
    auto root = xmlDocGetRootElement(doc);
    bool ret = recorderProfilesXmlParser_->ParseInternal(root);
    EXPECT_TRUE(ret);
    xmlFreeDoc(doc);
    EXPECT_FALSE(recorderProfilesXmlParser_->containerFormatArray_.empty());
}

HWTEST_F(RecorderProfilesXmlParserUnitTest, ParseRecorderProfilesData_001, TestSize.Level1)
{
    const char *xml =
        "<RecorderProfiles>"
        "<CameraRecorder cameraId=\"0\">"
        "<ProfileSettings format=\"mp4\" codecMime=\"video/avc\" quality=\"low\"/>"
        "</CameraRecorder>"
        "</RecorderProfiles>";
    auto doc = xmlReadMemory(xml, strlen(xml), "test.xml", nullptr, 0);
    EXPECT_NE(doc, nullptr);
    auto root = xmlDocGetRootElement(doc);
    bool ret = recorderProfilesXmlParser_->ParseRecorderProfilesData(root);
    xmlFreeDoc(doc);
    EXPECT_TRUE(ret);
}

HWTEST_F(RecorderProfilesXmlParserUnitTest, ParseRecorderProfilesData_002, TestSize.Level1)
{
    const char *xml =
        "<RecorderProfiles>"
        "<CameraRecorder cameraId=\"0\">"
        "<ProfileSettings format=\"mp4\" codecMime=\"video/avc\"/>"
        "<Video codecMime=\"video/avc\" bitrate=\"2000000\"/>"
        "<Audio codecMime=\"audio/mp4a-latm\" bitrate=\"96000\" sampleRate=\"48000\" channels=\"2\"/>"
        "</CameraRecorder>"
        "</RecorderProfiles>";
    auto doc = xmlReadMemory(xml, strlen(xml), "test.xml", nullptr, 0);
    EXPECT_NE(doc, nullptr);
    auto root = xmlDocGetRootElement(doc);
    bool ret = recorderProfilesXmlParser_->ParseRecorderProfilesData(root);
    xmlFreeDoc(doc);
    EXPECT_TRUE(ret);
}

HWTEST_F(RecorderProfilesXmlParserUnitTest, ParseRecorderProfilesData_003, TestSize.Level1)
{
    const char *xml =
        "<RecorderProfiles>"
        "<CameraRecorder cameraId=\"0\">"
        "<ProfileSettings format=\"mp4\" codecMime=\"video/avc\"/>"
        "<UnknownChild/>"
        "</CameraRecorder>"
        "</RecorderProfiles>";
    auto doc = xmlReadMemory(xml, strlen(xml), "test.xml", nullptr, 0);
    EXPECT_NE(doc, nullptr);
    auto root = xmlDocGetRootElement(doc);
    bool ret = recorderProfilesXmlParser_->ParseRecorderProfilesData(root);
    xmlFreeDoc(doc);
    EXPECT_TRUE(ret);
}

HWTEST_F(RecorderProfilesXmlParserUnitTest, ParseRecorderProfilesSourceData_003, TestSize.Level1)
{
    const char *xml = "<CameraRecorder cameraId=\"abc\"/>";
    auto doc = xmlReadMemory(xml, strlen(xml), "test.xml", nullptr, 0);
    EXPECT_NE(doc, nullptr);
    auto root = xmlDocGetRootElement(doc);
    bool ret = recorderProfilesXmlParser_->ParseRecorderProfilesSourceData("CameraRecorder", root);
    xmlFreeDoc(doc);
    EXPECT_FALSE(ret);
}

HWTEST_F(RecorderProfilesXmlParserUnitTest, ParseRecorderProfilesSourceData_004, TestSize.Level1)
{
    const char *xml = "<VirtualDisplay displayId=\"0\"/>";
    auto doc = xmlReadMemory(xml, strlen(xml), "test.xml", nullptr, 0);
    EXPECT_NE(doc, nullptr);
    auto root = xmlDocGetRootElement(doc);
    bool ret = recorderProfilesXmlParser_->ParseRecorderProfilesSourceData("VirtualDisplay", root);
    EXPECT_TRUE(ret);
    xmlFreeDoc(doc);
    EXPECT_TRUE(ret);
}

HWTEST_F(RecorderProfilesXmlParserUnitTest, PackageVideoRecorderCaps_003, TestSize.Level1)
{
    recorderProfilesXmlParser_->capabilityDataArray_.clear();
    recorderProfilesXmlParser_->videoEncoderCapsArray_.clear();
    recorderProfilesXmlParser_->audioEncoderCapsArray_.clear();
    RecorderProfilesData videoData;
    videoData.videoCaps.videoEncoderMime = "video/mp4v-es";
    recorderProfilesXmlParser_->videoEncoderCapsArray_.push_back(videoData);
    RecorderProfilesData audioData;
    audioData.audioCaps.mimeType = "audio/mp4a-latm";
    recorderProfilesXmlParser_->audioEncoderCapsArray_.push_back(audioData);
    recorderProfilesXmlParser_->PackageVideoRecorderCaps("mp4");
    EXPECT_FALSE(recorderProfilesXmlParser_->capabilityDataArray_.empty());
    EXPECT_EQ(recorderProfilesXmlParser_->capabilityDataArray_[0].videoCaps.videoEncoderMime, "video/mp4v-es");
    EXPECT_EQ(recorderProfilesXmlParser_->capabilityDataArray_[0].videoCaps.containerFormatType, "mp4");
    EXPECT_EQ(recorderProfilesXmlParser_->capabilityDataArray_[0].videoCaps.audioEncoderMime, "audio/mp4a-latm");
}

HWTEST_F(RecorderProfilesXmlParserUnitTest, PackageAudioRecorderCaps_003, TestSize.Level1)
{
    recorderProfilesXmlParser_->capabilityDataArray_.clear();
    recorderProfilesXmlParser_->audioEncoderCapsArray_.clear();
    RecorderProfilesData audioData;
    audioData.audioCaps.mimeType = "audio/invalid";
    recorderProfilesXmlParser_->audioEncoderCapsArray_.push_back(audioData);
    recorderProfilesXmlParser_->PackageAudioRecorderCaps("m4a");
    EXPECT_TRUE(recorderProfilesXmlParser_->capabilityDataArray_.empty());
}

HWTEST_F(RecorderProfilesXmlParserUnitTest, PackageRecorderCaps_003, TestSize.Level1)
{
    recorderProfilesXmlParser_->containerFormatArray_.clear();
    recorderProfilesXmlParser_->capabilityDataArray_.clear();
    recorderProfilesXmlParser_->videoEncoderCapsArray_.clear();
    recorderProfilesXmlParser_->audioEncoderCapsArray_.clear();
    recorderProfilesXmlParser_->PackageRecorderCaps();
    EXPECT_TRUE(recorderProfilesXmlParser_->capabilityDataArray_.empty());
}

HWTEST_F(RecorderProfilesXmlParserUnitTest, PackageRecorderCaps_004, TestSize.Level1)
{
    recorderProfilesXmlParser_->containerFormatArray_.clear();
    recorderProfilesXmlParser_->capabilityDataArray_.clear();
    recorderProfilesXmlParser_->videoEncoderCapsArray_.clear();
    recorderProfilesXmlParser_->audioEncoderCapsArray_.clear();
    ContainerFormatInfo videoInfo;
    videoInfo.hasVideo = "true";
    videoInfo.name = "mp4";
    recorderProfilesXmlParser_->containerFormatArray_.push_back(videoInfo);
    ContainerFormatInfo audioInfo;
    audioInfo.hasVideo = "false";
    audioInfo.name = "m4a";
    recorderProfilesXmlParser_->containerFormatArray_.push_back(audioInfo);
    RecorderProfilesData videoData;
    videoData.videoCaps.videoEncoderMime = "video/avc";
    recorderProfilesXmlParser_->videoEncoderCapsArray_.push_back(videoData);
    RecorderProfilesData audioData;
    audioData.audioCaps.mimeType = "audio/mp4a-latm";
    recorderProfilesXmlParser_->audioEncoderCapsArray_.push_back(audioData);
    recorderProfilesXmlParser_->PackageRecorderCaps();
    EXPECT_FALSE(recorderProfilesXmlParser_->capabilityDataArray_.empty());
    EXPECT_GE(recorderProfilesXmlParser_->capabilityDataArray_.size(), 2u);
    bool hasVideoCaps = false;
    bool hasAudioCaps = false;
    for (const auto &cap : recorderProfilesXmlParser_->capabilityDataArray_) {
        if (cap.mediaProfileType == RECORDER_TYPE_VIDEO_CAPS) {
            hasVideoCaps = true;
        }
        if (cap.mediaProfileType == RECORDER_TYPE_AUDIO_CAPS) {
            hasAudioCaps = true;
        }
    }
    EXPECT_TRUE(hasVideoCaps);
    EXPECT_TRUE(hasAudioCaps);
}

HWTEST_F(RecorderProfilesXmlParserUnitTest, SetVideoRecorderCaps_004, TestSize.Level1)
{
    RecorderProfilesData data;
    bool ret = recorderProfilesXmlParser_->SetVideoRecorderCaps(data, "codecMime", "video/avc");
    EXPECT_TRUE(ret);
    ret = recorderProfilesXmlParser_->SetVideoRecorderCaps(data, "bitrate", "1-1000000");
    EXPECT_TRUE(ret);
    ret = recorderProfilesXmlParser_->SetVideoRecorderCaps(data, "width", "128-1920");
    EXPECT_TRUE(ret);
    ret = recorderProfilesXmlParser_->SetVideoRecorderCaps(data, "height", "128-1080");
    EXPECT_TRUE(ret);
    ret = recorderProfilesXmlParser_->SetVideoRecorderCaps(data, "frameRate", "1-60");
    EXPECT_TRUE(ret);
    ret = recorderProfilesXmlParser_->SetVideoRecorderCaps(data, "name", "test");
    EXPECT_FALSE(ret);
}

HWTEST_F(RecorderProfilesXmlParserUnitTest, SetAudioRecorderCaps_004, TestSize.Level1)
{
    RecorderProfilesData data;
    bool ret = recorderProfilesXmlParser_->SetAudioRecorderCaps(data, "codecMime", "audio/mp4a-latm");
    EXPECT_TRUE(ret);
    ret = recorderProfilesXmlParser_->SetAudioRecorderCaps(data, "bitrate", "1-320000");
    EXPECT_TRUE(ret);
    ret = recorderProfilesXmlParser_->SetAudioRecorderCaps(data, "channels", "1-2");
    EXPECT_TRUE(ret);
    ret = recorderProfilesXmlParser_->SetAudioRecorderCaps(data, "sampleRate", "8000,48000");
    EXPECT_TRUE(ret);
    ret = recorderProfilesXmlParser_->SetAudioRecorderCaps(data, "name", "test");
    EXPECT_FALSE(ret);
}

HWTEST_F(RecorderProfilesXmlParserUnitTest, SetVideoRecorderProfiles_004, TestSize.Level1)
{
    RecorderProfilesData data;
    bool ret = recorderProfilesXmlParser_->SetVideoRecorderProfiles(data, "format", "mp4");
    EXPECT_TRUE(ret);
    ret = recorderProfilesXmlParser_->SetVideoRecorderProfiles(data, "codecMime", "video/avc");
    EXPECT_TRUE(ret);
    ret = recorderProfilesXmlParser_->SetVideoRecorderProfiles(data, "duration", "60");
    EXPECT_TRUE(ret);
    ret = recorderProfilesXmlParser_->SetVideoRecorderProfiles(data, "bitrate", "2000000");
    EXPECT_TRUE(ret);
    ret = recorderProfilesXmlParser_->SetVideoRecorderProfiles(data, "width", "1920");
    EXPECT_TRUE(ret);
    ret = recorderProfilesXmlParser_->SetVideoRecorderProfiles(data, "height", "1080");
    EXPECT_TRUE(ret);
    ret = recorderProfilesXmlParser_->SetVideoRecorderProfiles(data, "frameRate", "30");
    EXPECT_TRUE(ret);
    ret = recorderProfilesXmlParser_->SetVideoRecorderProfiles(data, "quality", "high");
    EXPECT_TRUE(ret);
    ret = recorderProfilesXmlParser_->SetVideoRecorderProfiles(data, "sampleRate", "48000");
    EXPECT_FALSE(ret);
}

HWTEST_F(RecorderProfilesXmlParserUnitTest, SetAudioRecorderProfiles_004, TestSize.Level1)
{
    RecorderProfilesData data;
    bool ret = recorderProfilesXmlParser_->SetAudioRecorderProfiles(data, "format", "m4a");
    EXPECT_TRUE(ret);
    ret = recorderProfilesXmlParser_->SetAudioRecorderProfiles(data, "codecMime", "audio/mp4a-latm");
    EXPECT_TRUE(ret);
    ret = recorderProfilesXmlParser_->SetAudioRecorderProfiles(data, "bitrate", "96000");
    EXPECT_TRUE(ret);
    ret = recorderProfilesXmlParser_->SetAudioRecorderProfiles(data, "sampleRate", "48000");
    EXPECT_TRUE(ret);
    ret = recorderProfilesXmlParser_->SetAudioRecorderProfiles(data, "channels", "2");
    EXPECT_TRUE(ret);
    ret = recorderProfilesXmlParser_->SetAudioRecorderProfiles(data, "quality", "low");
    EXPECT_FALSE(ret);
}

HWTEST_F(RecorderProfilesXmlParserUnitTest, SetCapabilityIntData_005, TestSize.Level1)
{
    int32_t value = 0;
    std::unordered_map<std::string, int32_t&> dataMap = {{"quality", value}};
    bool ret = recorderProfilesXmlParser_->SetCapabilityIntData(dataMap, "quality", "high");
    EXPECT_TRUE(ret);
    EXPECT_EQ(value, RECORDER_QUALITY_HIGH);
    ret = recorderProfilesXmlParser_->SetCapabilityIntData(dataMap, "quality", "cif");
    EXPECT_TRUE(ret);
    EXPECT_EQ(value, RECORDER_QUALITY_CIF);
    ret = recorderProfilesXmlParser_->SetCapabilityIntData(dataMap, "quality", "abc");
    EXPECT_FALSE(ret);
}

HWTEST_F(RecorderProfilesXmlParserUnitTest, SetCapabilityVectorData_004, TestSize.Level1)
{
    std::vector<int32_t> vec;
    std::unordered_map<std::string, std::vector<int32_t>&> dataMap = {{"sampleRate", vec}};
    bool ret = recorderProfilesXmlParser_->SetCapabilityVectorData(dataMap, "sampleRate", "48000");
    EXPECT_TRUE(ret);
    EXPECT_EQ(vec.size(), 1);
    EXPECT_EQ(vec[0], 48000);
}
} // namespace Media
} // namespace OHOS
