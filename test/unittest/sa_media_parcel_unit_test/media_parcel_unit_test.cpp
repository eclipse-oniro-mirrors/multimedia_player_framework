/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
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

#include "media_parcel_unit_test.h"
#include <cstdint>
#include <limits>
#include <vector>

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing::ext;

namespace {
constexpr uint32_t MAX_PARCEL_SIZE_TEST = 256;
constexpr uint32_t INVALID_TYPE_VALUE = 999;
} // namespace

void MediaParcelUnitTest::SetUpTestCase(void) {}

void MediaParcelUnitTest::TearDownTestCase(void) {}

void MediaParcelUnitTest::SetUp(void) {}

void MediaParcelUnitTest::TearDown(void) {}

/**
 * @tc.name  : MediaParcel_Marshalling_Empty_001
 * @tc.number: MediaParcel_Marshalling_Empty_001
 * @tc.desc  : Test Marshalling and Unmarshalling with empty Format
 */
HWTEST_F(MediaParcelUnitTest, MediaParcel_Marshalling_Empty_001, TestSize.Level1)
{
    Format inFormat;
    MessageParcel parcel;
    EXPECT_TRUE(MediaParcel::Marshalling(parcel, inFormat));

    Format outFormat;
    EXPECT_TRUE(MediaParcel::Unmarshalling(parcel, outFormat));
    EXPECT_TRUE(outFormat.GetFormatMap().empty());
    EXPECT_TRUE(outFormat.GetFormatVectorMap().empty());
}

/**
 * @tc.name  : MediaParcel_Marshalling_AllTypes_001
 * @tc.number: MediaParcel_Marshalling_AllTypes_001
 * @tc.desc  : Test Marshalling and Unmarshalling with all supported Format data types
 */
HWTEST_F(MediaParcelUnitTest, MediaParcel_Marshalling_AllTypes_001, TestSize.Level1)
{
    Format inFormat;
    constexpr int32_t testInt32 = -12345;
    constexpr uint32_t testUint32 = 4000000000U;
    constexpr int64_t testInt64 = 9876543210123LL;
    constexpr float testFloat = 3.25F;
    constexpr double testDouble = 2.718281828;
    const std::string testString = "media_parcel_test_string";
    const std::vector<uint8_t> testBuf = {0x01, 0x02, 0x7F, 0xFF};

    ASSERT_TRUE(inFormat.PutIntValue("k_int32", testInt32));
    ASSERT_TRUE(inFormat.PutUintValue("k_uint32", testUint32));
    ASSERT_TRUE(inFormat.PutLongValue("k_int64", testInt64));
    ASSERT_TRUE(inFormat.PutFloatValue("k_float", testFloat));
    ASSERT_TRUE(inFormat.PutDoubleValue("k_double", testDouble));
    ASSERT_TRUE(inFormat.PutStringValue("k_string", testString));
    ASSERT_TRUE(inFormat.PutStringValue("k_empty_str", ""));
    ASSERT_TRUE(inFormat.PutBuffer("k_addr", testBuf.data(), testBuf.size()));

    MessageParcel parcel;
    ASSERT_TRUE(MediaParcel::Marshalling(parcel, inFormat));

    Format outFormat;
    ASSERT_TRUE(MediaParcel::Unmarshalling(parcel, outFormat));

    int32_t outInt32 = 0;
    uint32_t outUint32 = 0;
    int64_t outInt64 = 0;
    float outFloat = 0.0F;
    double outDouble = 0.0;
    std::string outString;
    std::string outEmptyStr = "non_empty";
    uint8_t *outAddr = nullptr;
    size_t outSize = 0;

    EXPECT_TRUE(outFormat.GetIntValue("k_int32", outInt32));
    EXPECT_EQ(outInt32, testInt32);
    EXPECT_TRUE(outFormat.GetUintValue("k_uint32", outUint32));
    EXPECT_EQ(outUint32, testUint32);
    EXPECT_TRUE(outFormat.GetLongValue("k_int64", outInt64));
    EXPECT_EQ(outInt64, testInt64);
    EXPECT_TRUE(outFormat.GetFloatValue("k_float", outFloat));
    EXPECT_FLOAT_EQ(outFloat, testFloat);
    EXPECT_TRUE(outFormat.GetDoubleValue("k_double", outDouble));
    EXPECT_DOUBLE_EQ(outDouble, testDouble);
    EXPECT_TRUE(outFormat.GetStringValue("k_string", outString));
    EXPECT_EQ(outString, testString);
    EXPECT_TRUE(outFormat.GetStringValue("k_empty_str", outEmptyStr));
    EXPECT_EQ(outEmptyStr, "");
    EXPECT_TRUE(outFormat.GetBuffer("k_addr", &outAddr, outSize));
    ASSERT_EQ(outSize, testBuf.size());
    ASSERT_NE(outAddr, nullptr);
    EXPECT_EQ(std::vector<uint8_t>(outAddr, outAddr + outSize), testBuf);
}

/**
 * @tc.name  : MediaParcel_Marshalling_FormatVector_001
 * @tc.number: MediaParcel_Marshalling_FormatVector_001
 * @tc.desc  : Test Marshalling and Unmarshalling with FormatVectorMap
 */
HWTEST_F(MediaParcelUnitTest, MediaParcel_Marshalling_FormatVector_001, TestSize.Level1)
{
    Format inFormat;
    EXPECT_TRUE(inFormat.PutIntValue("root_id", 7));

    Format item1;
    item1.PutIntValue("track_index", 0);
    item1.PutStringValue("mime", "video/avc");

    Format item2;
    item2.PutIntValue("track_index", 1);
    item2.PutStringValue("mime", "audio/mp4a-latm");

    std::vector<Format> vec = {item1, item2};
    ASSERT_TRUE(inFormat.PutFormatVector("tracks", vec));

    MessageParcel parcel;
    ASSERT_TRUE(MediaParcel::Marshalling(parcel, inFormat));

    Format outFormat;
    ASSERT_TRUE(MediaParcel::Unmarshalling(parcel, outFormat));

    int32_t rootId = 0;
    EXPECT_TRUE(outFormat.GetIntValue("root_id", rootId));
    EXPECT_EQ(rootId, 7);

    std::vector<Format> outVec;
    EXPECT_TRUE(outFormat.GetFormatVector("tracks", outVec));
    ASSERT_EQ(outVec.size(), 2U);

    int32_t trackIdx0 = -1;
    std::string mime0;
    EXPECT_TRUE(outVec[0].GetIntValue("track_index", trackIdx0));
    EXPECT_EQ(trackIdx0, 0);
    EXPECT_TRUE(outVec[0].GetStringValue("mime", mime0));
    EXPECT_EQ(mime0, "video/avc");

    int32_t trackIdx1 = -1;
    std::string mime1;
    EXPECT_TRUE(outVec[1].GetIntValue("track_index", trackIdx1));
    EXPECT_EQ(trackIdx1, 1);
    EXPECT_TRUE(outVec[1].GetStringValue("mime", mime1));
    EXPECT_EQ(mime1, "audio/mp4a-latm");
}

/**
 * @tc.name  : MediaParcel_Marshalling_EmptyFormatVector_001
 * @tc.number: MediaParcel_Marshalling_EmptyFormatVector_001
 * @tc.desc  : Test Marshalling and Unmarshalling when FormatVectorMap has an empty vector
 */
HWTEST_F(MediaParcelUnitTest, MediaParcel_Marshalling_EmptyFormatVector_001, TestSize.Level1)
{
    Format inFormat;
    inFormat.formatVecMap_["empty_tracks"] = {};

    MessageParcel parcel;
    ASSERT_TRUE(MediaParcel::Marshalling(parcel, inFormat));

    Format outFormat;
    EXPECT_TRUE(MediaParcel::Unmarshalling(parcel, outFormat));
    EXPECT_TRUE(outFormat.GetFormatVectorMap().empty());
}

/**
 * @tc.name  : MediaParcel_Marshalling_InvalidType_001
 * @tc.number: MediaParcel_Marshalling_InvalidType_001
 * @tc.desc  : Test Marshalling returns false when Format contains unsupported FormatDataType
 */
HWTEST_F(MediaParcelUnitTest, MediaParcel_Marshalling_InvalidType_001, TestSize.Level1)
{
    Format inFormat;
    FormatData invalidData;
    invalidData.type = FORMAT_TYPE_NONE;
    inFormat.formatMap_["invalid_key"] = invalidData;

    MessageParcel parcel;
    EXPECT_FALSE(MediaParcel::Marshalling(parcel, inFormat));
}

/**
 * @tc.name  : MediaParcel_Marshalling_InvalidTypeInVector_001
 * @tc.number: MediaParcel_Marshalling_InvalidTypeInVector_001
 * @tc.desc  : Test Marshalling returns false when FormatVector item has invalid FormatDataType
 */
HWTEST_F(MediaParcelUnitTest, MediaParcel_Marshalling_InvalidTypeInVector_001, TestSize.Level1)
{
    Format badItem;
    FormatData invalidData;
    invalidData.type = FORMAT_TYPE_NONE;
    badItem.formatMap_["invalid_key"] = invalidData;

    Format inFormat;
    std::vector<Format> vec = {badItem};
    ASSERT_TRUE(inFormat.PutFormatVector("tracks", vec));

    MessageParcel parcel;
    EXPECT_FALSE(MediaParcel::Marshalling(parcel, inFormat));
}

/**
 * @tc.name  : MediaParcel_Unmarshalling_Boundary_001
 * @tc.number: MediaParcel_Unmarshalling_Boundary_001
 * @tc.desc  : Test Unmarshalling rejects oversized counts, unknown types, and invalid buffers
 */
HWTEST_F(MediaParcelUnitTest, MediaParcel_Unmarshalling_Boundary_001, TestSize.Level1)
{
    // 1. DataMap size exceeds MAX_PARCEL_SIZE
    {
        MessageParcel parcel;
        parcel.WriteUint32(MAX_PARCEL_SIZE_TEST + 1);
        Format outFormat;
        EXPECT_FALSE(MediaParcel::Unmarshalling(parcel, outFormat));
    }
    // 2. Vector size exceeds MAX_PARCEL_SIZE
    {
        MessageParcel parcel;
        parcel.WriteUint32(0);
        parcel.WriteUint32(MAX_PARCEL_SIZE_TEST + 1);
        Format outFormat;
        EXPECT_FALSE(MediaParcel::Unmarshalling(parcel, outFormat));
    }
    // 3. Unknown FormatDataType
    {
        MessageParcel parcel;
        parcel.WriteUint32(1);
        parcel.WriteString("unknown_key");
        parcel.WriteUint32(INVALID_TYPE_VALUE);
        Format outFormat;
        EXPECT_FALSE(MediaParcel::Unmarshalling(parcel, outFormat));
    }
    // 4. FORMAT_TYPE_ADDR with empty buffer (PutBuffer fails)
    {
        MessageParcel parcel;
        parcel.WriteUint32(1);
        parcel.WriteString("empty_buf_key");
        parcel.WriteUint32(FORMAT_TYPE_ADDR);
        parcel.WriteUInt8Vector({});
        Format outFormat;
        EXPECT_FALSE(MediaParcel::Unmarshalling(parcel, outFormat));
    }
    // 5. Invalid item inside FormatVectorMap
    {
        MessageParcel parcel;
        parcel.WriteUint32(0);
        parcel.WriteUint32(1);
        parcel.WriteString("tracks");
        parcel.WriteUint32(MAX_PARCEL_SIZE_TEST + 1);
        Format outFormat;
        EXPECT_FALSE(MediaParcel::Unmarshalling(parcel, outFormat));
    }
}

/**
 * @tc.name  : MediaParcel_MetaMarshalling_001
 * @tc.number: MediaParcel_MetaMarshalling_001
 * @tc.desc  : Test MetaMarshalling and MetaUnmarshalling round-trip
 */
HWTEST_F(MediaParcelUnitTest, MediaParcel_MetaMarshalling_001, TestSize.Level1)
{
    Format inFormat;
    auto inMeta = std::make_shared<Meta>();
    ASSERT_NE(inMeta, nullptr);
    inMeta->Set<Tag::MEDIA_DURATION>(int64_t(120000));
    inMeta->Set<Tag::MEDIA_TITLE>(std::string("TestTitle"));
    ASSERT_TRUE(inFormat.SetMeta(inMeta));

    MessageParcel parcel;
    ASSERT_TRUE(MediaParcel::MetaMarshalling(parcel, inFormat));

    Format outFormat;
    ASSERT_TRUE(MediaParcel::MetaUnmarshalling(parcel, outFormat));
    auto outMeta = outFormat.GetMeta();
    ASSERT_NE(outMeta, nullptr);

    int64_t duration = 0;
    std::string title;
    EXPECT_TRUE(outMeta->Get<Tag::MEDIA_DURATION>(duration));
    EXPECT_EQ(duration, 120000);
    EXPECT_TRUE(outMeta->Get<Tag::MEDIA_TITLE>(title));
    EXPECT_EQ(title, "TestTitle");
}

/**
 * @tc.name  : MediaParcel_MetaMarshalling_EmptyAndInvalid_001
 * @tc.number: MediaParcel_MetaMarshalling_EmptyAndInvalid_001
 * @tc.desc  : Test MetaMarshalling with empty meta and MetaUnmarshalling with empty parcel
 */
HWTEST_F(MediaParcelUnitTest, MediaParcel_MetaMarshalling_EmptyAndInvalid_001, TestSize.Level1)
{
    Format inFormat;
    MessageParcel parcel;
    EXPECT_TRUE(MediaParcel::MetaMarshalling(parcel, inFormat));

    Format outFormat;
    EXPECT_TRUE(MediaParcel::MetaUnmarshalling(parcel, outFormat));

    MessageParcel emptyParcel;
    Format invalidOut;
    EXPECT_FALSE(MediaParcel::MetaUnmarshalling(emptyParcel, invalidOut));
}
} // namespace Media
} // namespace OHOS
