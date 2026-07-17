/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <cstring>
#include <securec.h>
#include "cache_mapping_format.h"
#include "path_validator.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {
namespace DownloadedCache {

class CacheMappingTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void) {}
    void TearDown(void) {}
};

HWTEST_F(CacheMappingTest, MagicNumber_Definition_001, TestSize.Level0)
{
    EXPECT_EQ(sizeof(CACHE_MAPPING_MAGIC), 4);
    EXPECT_EQ(CACHE_MAPPING_MAGIC[0], 'D');
    EXPECT_EQ(CACHE_MAPPING_MAGIC[1], 'C');
    EXPECT_EQ(CACHE_MAPPING_MAGIC[2], 'M');
    EXPECT_EQ(CACHE_MAPPING_MAGIC[3], 'H');
    EXPECT_EQ(CACHE_MAPPING_VERSION, 1);
    EXPECT_EQ(sizeof(CacheMappingHeader), 24);
    EXPECT_EQ(sizeof(CacheMappingEntryHeader), 52);
    EXPECT_EQ(SHA256_LEN, 32);
}

HWTEST_F(CacheMappingTest, HeaderFields_001, TestSize.Level0)
{
    CacheMappingHeader header;
    EXPECT_EQ(sizeof(header.magic), 4);
    EXPECT_EQ(sizeof(header.version), 4);
    EXPECT_EQ(sizeof(header.entryCount), 4);
    EXPECT_EQ(sizeof(header.reserved), 8);
    EXPECT_EQ(sizeof(header.headerChecksum), 4);
}

HWTEST_F(CacheMappingTest, EntryHeaderFields_001, TestSize.Level0)
{
    CacheMappingEntryHeader entryHeader;
    EXPECT_EQ(sizeof(entryHeader.urlHash), 32);
    EXPECT_EQ(sizeof(entryHeader.pathLength), 4);
    EXPECT_EQ(sizeof(entryHeader.fileSize), 8);
    EXPECT_EQ(sizeof(entryHeader.reserved), 8);
}

HWTEST_F(CacheMappingTest, Checksum_Calculate_001, TestSize.Level0)
{
    CacheMappingHeader header;
    (void)memcpy_s(header.magic, sizeof(CACHE_MAPPING_MAGIC), CACHE_MAPPING_MAGIC, sizeof(CACHE_MAPPING_MAGIC));
    header.version = CACHE_MAPPING_VERSION;
    header.entryCount = 1;
    (void)memset_s(header.reserved, 8, 0, 8);

    uint32_t checksum = CacheMappingSerializer::CalculateHeaderChecksum(header);
    EXPECT_NE(checksum, 0);
}

HWTEST_F(CacheMappingTest, Checksum_Consistent_001, TestSize.Level0)
{
    CacheMappingHeader header;
    (void)memcpy_s(header.magic, sizeof(CACHE_MAPPING_MAGIC), CACHE_MAPPING_MAGIC, sizeof(CACHE_MAPPING_MAGIC));
    header.version = CACHE_MAPPING_VERSION;
    header.entryCount = 5;
    (void)memset_s(header.reserved, 8, 0, 8);

    uint32_t checksum1 = CacheMappingSerializer::CalculateHeaderChecksum(header);
    uint32_t checksum2 = CacheMappingSerializer::CalculateHeaderChecksum(header);
    EXPECT_EQ(checksum1, checksum2);
}

HWTEST_F(CacheMappingTest, Checksum_Different_EntryCount_001, TestSize.Level0)
{
    CacheMappingHeader header1;
    (void)memcpy_s(header1.magic, sizeof(CACHE_MAPPING_MAGIC), CACHE_MAPPING_MAGIC, sizeof(CACHE_MAPPING_MAGIC));
    header1.version = CACHE_MAPPING_VERSION;
    header1.entryCount = 1;
    (void)memset_s(header1.reserved, 8, 0, 8);

    CacheMappingHeader header2;
    (void)memcpy_s(header2.magic, sizeof(CACHE_MAPPING_MAGIC), CACHE_MAPPING_MAGIC, sizeof(CACHE_MAPPING_MAGIC));
    header2.version = CACHE_MAPPING_VERSION;
    header2.entryCount = 2;
    (void)memset_s(header2.reserved, 8, 0, 8);

    uint32_t checksum1 = CacheMappingSerializer::CalculateHeaderChecksum(header1);
    uint32_t checksum2 = CacheMappingSerializer::CalculateHeaderChecksum(header2);
    EXPECT_NE(checksum1, checksum2);
}

HWTEST_F(CacheMappingTest, Checksum_Different_Version_001, TestSize.Level0)
{
    CacheMappingHeader header1;
    (void)memcpy_s(header1.magic, sizeof(CACHE_MAPPING_MAGIC), CACHE_MAPPING_MAGIC, sizeof(CACHE_MAPPING_MAGIC));
    header1.version = 1;
    header1.entryCount = 1;
    (void)memset_s(header1.reserved, 8, 0, 8);

    CacheMappingHeader header2;
    (void)memcpy_s(header2.magic, sizeof(CACHE_MAPPING_MAGIC), CACHE_MAPPING_MAGIC, sizeof(CACHE_MAPPING_MAGIC));
    header2.version = 2;
    header2.entryCount = 1;
    (void)memset_s(header2.reserved, 8, 0, 8);

    uint32_t checksum1 = CacheMappingSerializer::CalculateHeaderChecksum(header1);
    uint32_t checksum2 = CacheMappingSerializer::CalculateHeaderChecksum(header2);
    EXPECT_NE(checksum1, checksum2);
}

HWTEST_F(CacheMappingTest, Entry_GetTotalSize_001, TestSize.Level0)
{
    CacheMappingEntry entry;
    (void)memset_s(&entry.header, sizeof(entry.header), 0, sizeof(entry.header));
    entry.filePath = "videos/test.mp4";

    size_t totalSize = entry.GetTotalSize();
    EXPECT_EQ(totalSize, sizeof(CacheMappingEntryHeader) + entry.filePath.size());
}

HWTEST_F(CacheMappingTest, Entry_GetTotalSize_EmptyPath_001, TestSize.Level0)
{
    CacheMappingEntry entry;
    (void)memset_s(&entry.header, sizeof(entry.header), 0, sizeof(entry.header));
    entry.filePath = "";

    size_t totalSize = entry.GetTotalSize();
    EXPECT_EQ(totalSize, sizeof(CacheMappingEntryHeader));
}

HWTEST_F(CacheMappingTest, Header_Reserved_001, TestSize.Level0)
{
    CacheMappingHeader header;
    (void)memset_s(header.reserved, 8, 0xFF, 8);

    (void)memcpy_s(header.magic, sizeof(CACHE_MAPPING_MAGIC), CACHE_MAPPING_MAGIC, sizeof(CACHE_MAPPING_MAGIC));
    header.version = CACHE_MAPPING_VERSION;
    header.entryCount = 0;

    uint32_t checksum1 = CacheMappingSerializer::CalculateHeaderChecksum(header);

    (void)memset_s(header.reserved, 8, 0, 8);
    uint32_t checksum2 = CacheMappingSerializer::CalculateHeaderChecksum(header);

    EXPECT_NE(checksum1, checksum2);
}

HWTEST_F(CacheMappingTest, Header_MagicNotIncluded_001, TestSize.Level0)
{
    CacheMappingHeader header;
    (void)memcpy_s(header.magic, sizeof(CACHE_MAPPING_MAGIC), CACHE_MAPPING_MAGIC, sizeof(CACHE_MAPPING_MAGIC));
    header.version = 1;
    header.entryCount = 1;
    (void)memset_s(header.reserved, 8, 0, 8);
    header.headerChecksum = 0;

    uint32_t checksum = CacheMappingSerializer::CalculateHeaderChecksum(header);

    header.headerChecksum = checksum;
    uint32_t checksumWithChecksumField = CacheMappingSerializer::CalculateHeaderChecksum(header);

    EXPECT_EQ(checksum, checksumWithChecksumField);
}

HWTEST_F(CacheMappingTest, WriteHeader_FileNotOpen_001, TestSize.Level0)
{
    std::ofstream file;
    CacheMappingHeader header;
    (void)memcpy_s(header.magic, sizeof(CACHE_MAPPING_MAGIC), CACHE_MAPPING_MAGIC, sizeof(CACHE_MAPPING_MAGIC));
    header.version = CACHE_MAPPING_VERSION;
    header.entryCount = 0;
    (void)memset_s(header.reserved, 8, 0, 8);

    bool result = CacheMappingSerializer::WriteHeader(file, header);
    EXPECT_FALSE(result);
}

HWTEST_F(CacheMappingTest, ReadHeader_FileNotOpen_001, TestSize.Level0)
{
    std::ifstream file;
    CacheMappingHeader header;

    bool result = CacheMappingDeserializer::ReadHeader(file, header);
    EXPECT_FALSE(result);
}

HWTEST_F(CacheMappingTest, WriteEntry_FileNotOpen_001, TestSize.Level0)
{
    std::ofstream file;
    CacheMappingEntry entry;
    (void)memset_s(&entry.header, sizeof(entry.header), 0, sizeof(entry.header));
    entry.filePath = "test.mp4";

    bool result = CacheMappingSerializer::WriteEntry(file, entry, "/tmp/cache");
    EXPECT_FALSE(result);
}

HWTEST_F(CacheMappingTest, ReadEntry_FileNotOpen_001, TestSize.Level0)
{
    std::ifstream file;
    CacheMappingEntry entry;

    bool result = CacheMappingDeserializer::ReadEntry(file, entry, "/tmp/cache");
    EXPECT_FALSE(result);
}

HWTEST_F(CacheMappingTest, ValidateHeader_InvalidMagic_001, TestSize.Level0)
{
    CacheMappingHeader header;
    header.magic[0] = 'X';
    header.magic[1] = 'Y';
    header.magic[2] = 'Z';
    header.magic[3] = 'W';
    header.version = CACHE_MAPPING_VERSION;
    header.entryCount = 0;
    (void)memset_s(header.reserved, 8, 0, 8);
    header.headerChecksum = 0;

    bool result = CacheMappingDeserializer::ValidateHeader(header);
    EXPECT_FALSE(result);
}

HWTEST_F(CacheMappingTest, ValidateHeader_InvalidVersion_001, TestSize.Level0)
{
    CacheMappingHeader header;
    (void)memcpy_s(header.magic, sizeof(CACHE_MAPPING_MAGIC), CACHE_MAPPING_MAGIC, sizeof(CACHE_MAPPING_MAGIC));
    header.version = 999;
    header.entryCount = 0;
    (void)memset_s(header.reserved, 8, 0, 8);
    header.headerChecksum = CacheMappingSerializer::CalculateHeaderChecksum(header);

    bool result = CacheMappingDeserializer::ValidateHeader(header);
    EXPECT_FALSE(result);
}

HWTEST_F(CacheMappingTest, ValidateHeader_ChecksumMismatch_001, TestSize.Level0)
{
    CacheMappingHeader header;
    (void)memcpy_s(header.magic, sizeof(CACHE_MAPPING_MAGIC), CACHE_MAPPING_MAGIC, sizeof(CACHE_MAPPING_MAGIC));
    header.version = CACHE_MAPPING_VERSION;
    header.entryCount = 0;
    (void)memset_s(header.reserved, 8, 0, 8);
    header.headerChecksum = 12345678;

    bool result = CacheMappingDeserializer::ValidateHeader(header);
    EXPECT_FALSE(result);
}

HWTEST_F(CacheMappingTest, ValidateHeader_Valid_001, TestSize.Level0)
{
    CacheMappingHeader header;
    (void)memcpy_s(header.magic, sizeof(CACHE_MAPPING_MAGIC), CACHE_MAPPING_MAGIC, sizeof(CACHE_MAPPING_MAGIC));
    header.version = CACHE_MAPPING_VERSION;
    header.entryCount = 0;
    (void)memset_s(header.reserved, 8, 0, 8);
    header.headerChecksum = CacheMappingSerializer::CalculateHeaderChecksum(header);

    bool result = CacheMappingDeserializer::ValidateHeader(header);
    EXPECT_TRUE(result);
}

HWTEST_F(CacheMappingTest, WriteHeader_Success_001, TestSize.Level0)
{
    std::string testFile = "/data/test/test_mapping.bin";
    std::ofstream file(testFile, std::ios::binary | std::ios::trunc);

    CacheMappingHeader header;
    (void)memcpy_s(header.magic, sizeof(CACHE_MAPPING_MAGIC), CACHE_MAPPING_MAGIC, sizeof(CACHE_MAPPING_MAGIC));
    header.version = CACHE_MAPPING_VERSION;
    header.entryCount = 0;
    (void)memset_s(header.reserved, 8, 0, 8);

    bool result = CacheMappingSerializer::WriteHeader(file, header);
    EXPECT_TRUE(result);
    file.close();
}

HWTEST_F(CacheMappingTest, ReadHeader_Success_001, TestSize.Level0)
{
    std::string testFile = "/data/test/test_mapping.bin";

    CacheMappingHeader writeHeader;
    (void)memcpy_s(writeHeader.magic, sizeof(CACHE_MAPPING_MAGIC), CACHE_MAPPING_MAGIC, sizeof(CACHE_MAPPING_MAGIC));
    writeHeader.version = CACHE_MAPPING_VERSION;
    writeHeader.entryCount = 0;
    (void)memset_s(writeHeader.reserved, 8, 0, 8);
    writeHeader.headerChecksum = CacheMappingSerializer::CalculateHeaderChecksum(writeHeader);

    std::ofstream writeFile(testFile, std::ios::binary | std::ios::trunc);
    writeFile.write(reinterpret_cast<const char*>(writeHeader.magic), 4);
    writeFile.write(reinterpret_cast<const char*>(&writeHeader.version), 4);
    writeFile.write(reinterpret_cast<const char*>(&writeHeader.entryCount), 4);
    writeFile.write(reinterpret_cast<const char*>(writeHeader.reserved), 8);
    writeFile.write(reinterpret_cast<const char*>(&writeHeader.headerChecksum), 4);
    writeFile.close();

    std::ifstream readFile(testFile, std::ios::binary);
    CacheMappingHeader readHeader;
    bool result = CacheMappingDeserializer::ReadHeader(readFile, readHeader);
    EXPECT_TRUE(result);
    readFile.close();
}

HWTEST_F(CacheMappingTest, Checksum_DifferentReserved_001, TestSize.Level0)
{
    CacheMappingHeader header1;
    (void)memcpy_s(header1.magic, sizeof(CACHE_MAPPING_MAGIC), CACHE_MAPPING_MAGIC, sizeof(CACHE_MAPPING_MAGIC));
    header1.version = CACHE_MAPPING_VERSION;
    header1.entryCount = 1;
    (void)memset_s(header1.reserved, 8, 0, 8);

    CacheMappingHeader header2;
    (void)memcpy_s(header2.magic, sizeof(CACHE_MAPPING_MAGIC), CACHE_MAPPING_MAGIC, sizeof(CACHE_MAPPING_MAGIC));
    header2.version = CACHE_MAPPING_VERSION;
    header2.entryCount = 1;
    header2.reserved[0] = 1;
    header2.reserved[7] = 1;

    uint32_t checksum1 = CacheMappingSerializer::CalculateHeaderChecksum(header1);
    uint32_t checksum2 = CacheMappingSerializer::CalculateHeaderChecksum(header2);
    EXPECT_NE(checksum1, checksum2);
}

HWTEST_F(CacheMappingTest, EntryHeader_Packing_001, TestSize.Level0)
{
    CacheMappingEntryHeader entryHeader;
    (void)memset_s(&entryHeader, sizeof(entryHeader), 0, sizeof(entryHeader));

    uintptr_t urlHashOffset = reinterpret_cast<uintptr_t>(&entryHeader.urlHash);
    uintptr_t pathLengthOffset = reinterpret_cast<uintptr_t>(&entryHeader.pathLength);
    uintptr_t fileSizeOffset = reinterpret_cast<uintptr_t>(&entryHeader.fileSize);
    uintptr_t reservedOffset = reinterpret_cast<uintptr_t>(&entryHeader.reserved);

    EXPECT_EQ(pathLengthOffset - urlHashOffset, 32);
    EXPECT_EQ(fileSizeOffset - pathLengthOffset, 4);
    EXPECT_EQ(reservedOffset - fileSizeOffset, 8);
}

HWTEST_F(CacheMappingTest, Header_Packing_001, TestSize.Level0)
{
    CacheMappingHeader header;
    (void)memset_s(&header, sizeof(header), 0, sizeof(header));

    uintptr_t magicOffset = reinterpret_cast<uintptr_t>(&header.magic);
    uintptr_t versionOffset = reinterpret_cast<uintptr_t>(&header.version);
    uintptr_t entryCountOffset = reinterpret_cast<uintptr_t>(&header.entryCount);
    uintptr_t reservedOffset = reinterpret_cast<uintptr_t>(&header.reserved);
    uintptr_t checksumOffset = reinterpret_cast<uintptr_t>(&header.headerChecksum);

    EXPECT_EQ(versionOffset - magicOffset, 4);
    EXPECT_EQ(entryCountOffset - versionOffset, 4);
    EXPECT_EQ(reservedOffset - entryCountOffset, 4);
    EXPECT_EQ(checksumOffset - reservedOffset, 8);
}

HWTEST_F(CacheMappingTest, ZeroEntryCount_001, TestSize.Level0)
{
    CacheMappingHeader header;
    (void)memcpy_s(header.magic, sizeof(CACHE_MAPPING_MAGIC), CACHE_MAPPING_MAGIC, sizeof(CACHE_MAPPING_MAGIC));
    header.version = CACHE_MAPPING_VERSION;
    header.entryCount = 0;
    (void)memset_s(header.reserved, 8, 0, 8);

    uint32_t checksum = CacheMappingSerializer::CalculateHeaderChecksum(header);
    EXPECT_NE(checksum, 0);

    header.headerChecksum = checksum;
    bool valid = CacheMappingDeserializer::ValidateHeader(header);
    EXPECT_TRUE(valid);
}

HWTEST_F(CacheMappingTest, MaxEntryCount_001, TestSize.Level0)
{
    CacheMappingHeader header;
    (void)memcpy_s(header.magic, sizeof(CACHE_MAPPING_MAGIC), CACHE_MAPPING_MAGIC, sizeof(CACHE_MAPPING_MAGIC));
    header.version = CACHE_MAPPING_VERSION;
    header.entryCount = UINT32_MAX;
    (void)memset_s(header.reserved, 8, 0, 8);

    uint32_t checksum = CacheMappingSerializer::CalculateHeaderChecksum(header);
    EXPECT_NE(checksum, 0);
}

HWTEST_F(CacheMappingTest, ReadEntry_PathLengthTooLarge_001, TestSize.Level0)
{
    std::string testFile = "/data/test/test_pathlength_overflow.bin";

    CacheMappingHeader header;
    (void)memcpy_s(header.magic, sizeof(CACHE_MAPPING_MAGIC), CACHE_MAPPING_MAGIC, sizeof(CACHE_MAPPING_MAGIC));
    header.version = CACHE_MAPPING_VERSION;
    header.entryCount = 1;
    (void)memset_s(header.reserved, 8, 0, 8);
    header.headerChecksum = CacheMappingSerializer::CalculateHeaderChecksum(header);

    std::ofstream writeFile(testFile, std::ios::binary | std::ios::trunc);
    writeFile.write(reinterpret_cast<const char*>(header.magic), 4);
    writeFile.write(reinterpret_cast<const char*>(&header.version), 4);
    writeFile.write(reinterpret_cast<const char*>(&header.entryCount), 4);
    writeFile.write(reinterpret_cast<const char*>(header.reserved), 8);
    writeFile.write(reinterpret_cast<const char*>(&header.headerChecksum), 4);

    CacheMappingEntryHeader entryHeader;
    (void)memset_s(&entryHeader, sizeof(entryHeader), 0, sizeof(entryHeader));
    entryHeader.pathLength = static_cast<uint32_t>(PathValidator::MAX_PATH_LENGTH + 1);
    entryHeader.fileSize = 1024;

    writeFile.write(reinterpret_cast<const char*>(entryHeader.urlHash), SHA256_LEN);
    writeFile.write(reinterpret_cast<const char*>(&entryHeader.pathLength), 4);
    writeFile.write(reinterpret_cast<const char*>(&entryHeader.fileSize), 8);
    writeFile.write(reinterpret_cast<const char*>(entryHeader.reserved), 8);
    writeFile.close();

    std::ifstream readFile(testFile, std::ios::binary);
    CacheMappingHeader readHeader;
    (void)CacheMappingDeserializer::ReadHeader(readFile, readHeader);

    CacheMappingEntry entry;
    bool result = CacheMappingDeserializer::ReadEntry(readFile, entry, "/data/test");
    EXPECT_FALSE(result);
    readFile.close();
}

HWTEST_F(CacheMappingTest, ReadPlaybackParamData_LengthTooLarge_001, TestSize.Level0)
{
    std::string testFile = "/data/test/test_playback_param_overflow.bin";

    uint32_t overflowLength = 10 * 1024 * 1024 + 1;

    std::ofstream writeFile(testFile, std::ios::binary | std::ios::trunc);
    writeFile.write(reinterpret_cast<const char*>(&overflowLength), sizeof(overflowLength));
    writeFile.close();

    std::ifstream readFile(testFile, std::ios::binary);
    std::vector<uint8_t> playbackParamData;
    bool result = CacheMappingDeserializer::ReadPlaybackParamData(readFile, playbackParamData);
    EXPECT_FALSE(result);
    readFile.close();
}

HWTEST_F(CacheMappingTest, ReadPlaybackParamData_ZeroLength_001, TestSize.Level0)
{
    std::string testFile = "/data/test/test_playback_param_zero.bin";

    uint32_t zeroLength = 0;

    std::ofstream writeFile(testFile, std::ios::binary | std::ios::trunc);
    writeFile.write(reinterpret_cast<const char*>(&zeroLength), sizeof(zeroLength));
    writeFile.close();

    std::ifstream readFile(testFile, std::ios::binary);
    std::vector<uint8_t> playbackParamData;
    bool result = CacheMappingDeserializer::ReadPlaybackParamData(readFile, playbackParamData);
    EXPECT_TRUE(result);
    EXPECT_EQ(playbackParamData.size(), 0);
    readFile.close();
}

HWTEST_F(CacheMappingTest, WriteEntry_PathTraversal_001, TestSize.Level0)
{
    std::string testFile = "/data/test/test_write_entry_traversal.bin";
    std::ofstream file(testFile, std::ios::binary | std::ios::trunc);

    CacheMappingEntry entry;
    (void)memset_s(&entry.header, sizeof(entry.header), 0, sizeof(entry.header));
    entry.filePath = "../../etc/passwd";

    bool result = CacheMappingSerializer::WriteEntry(file, entry, "/data/test/cache");
    EXPECT_FALSE(result);
    file.close();
}

} // namespace DownloadedCache
} // namespace Media
} // namespace OHOS