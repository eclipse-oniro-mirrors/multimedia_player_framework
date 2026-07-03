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
#include <string>
#include <memory>
#include <vector>
#include <fstream>
#include <securec.h>
#include "downloaded_cache_test_common.h"
#include "cache_manager.h"
#include "cache_mapping_format.h"
#include "sha256_hasher.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {
namespace DownloadedCache {

class CacheManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void)
    {
        testCacheDir_ = TestCommon::GetTestCacheDir("cache_manager");
        TestCommon::SetupTestDirectory(testCacheDir_);
    }
    void TearDown(void)
    {
        TestCommon::CleanupTestDirectory(testCacheDir_);
    }
protected:
    std::string testCacheDir_;
};

HWTEST_F(CacheManagerTest, Constructor_001, TestSize.Level0)
{
    TestCommon::CreateTestMappingFile(testCacheDir_, {});
    auto manager = std::make_shared<DownloadedCacheManager>(testCacheDir_);
    ASSERT_NE(manager, nullptr);
    EXPECT_EQ(manager->GetCacheDir(), testCacheDir_);
}

HWTEST_F(CacheManagerTest, GetMediaCache_Success_001, TestSize.Level0)
{
    std::string testUrl = "http://example.com/test.mp4";
    std::string testPath = "videos/test.mp4";
    TestCommon::CreateTestCacheFile(testCacheDir_, testPath, std::vector<uint8_t>(1024, 'A'));
    TestCommon::CreateTestMappingFile(testCacheDir_, {{testUrl, testPath}});

    auto manager = std::make_shared<DownloadedCacheManager>(testCacheDir_);
    std::string result = manager->GetMediaCache(testUrl);
    EXPECT_NE(result, "");
    EXPECT_EQ(result, testCacheDir_ + "/" + testPath);
}

HWTEST_F(CacheManagerTest, GetMediaCache_NotFound_001, TestSize.Level0)
{
    std::string testUrl = "http://example.com/test.mp4";
    std::string testPath = "videos/test.mp4";
    TestCommon::CreateTestCacheFile(testCacheDir_, testPath, std::vector<uint8_t>(1024, 'A'));
    TestCommon::CreateTestMappingFile(testCacheDir_, {{testUrl, testPath}});

    auto manager = std::make_shared<DownloadedCacheManager>(testCacheDir_);
    std::string result = manager->GetMediaCache("http://example.com/nonexistent.mp4");
    EXPECT_EQ(result, "");
}

HWTEST_F(CacheManagerTest, GetMediaCache_EmptyUrl_001, TestSize.Level0)
{
    std::string testUrl = "http://example.com/test.mp4";
    std::string testPath = "videos/test.mp4";
    TestCommon::CreateTestCacheFile(testCacheDir_, testPath, std::vector<uint8_t>(1024, 'A'));
    TestCommon::CreateTestMappingFile(testCacheDir_, {{testUrl, testPath}});

    auto manager = std::make_shared<DownloadedCacheManager>(testCacheDir_);
    std::string result = manager->GetMediaCache("");
    EXPECT_EQ(result, "");
}

HWTEST_F(CacheManagerTest, GetCacheMetaData_Success_001, TestSize.Level0)
{
    std::string testUrl = "http://example.com/test.mp4";
    std::string testPath = "videos/test.mp4";
    TestCommon::CreateTestCacheFile(testCacheDir_, testPath, std::vector<uint8_t>(1024, 'A'));
    TestCommon::CreateTestMappingFile(testCacheDir_, {{testUrl, testPath}});

    auto manager = std::make_shared<DownloadedCacheManager>(testCacheDir_);
    CacheMetaData metadata;
    bool result = manager->GetCacheMetaData(testUrl, metadata);
    EXPECT_TRUE(result);
    EXPECT_EQ(metadata.url, testUrl);
    EXPECT_EQ(metadata.size, 1024);
    EXPECT_EQ(metadata.entry, testPath);
}

HWTEST_F(CacheManagerTest, GetCacheMetaData_NotFound_001, TestSize.Level0)
{
    std::string testUrl = "http://example.com/test.mp4";
    std::string testPath = "videos/test.mp4";
    TestCommon::CreateTestCacheFile(testCacheDir_, testPath, std::vector<uint8_t>(1024, 'A'));
    TestCommon::CreateTestMappingFile(testCacheDir_, {{testUrl, testPath}});

    auto manager = std::make_shared<DownloadedCacheManager>(testCacheDir_);
    CacheMetaData metadata;
    bool result = manager->GetCacheMetaData("http://example.com/nonexistent.mp4", metadata);
    EXPECT_FALSE(result);
}

HWTEST_F(CacheManagerTest, GetCacheMetaData_EmptyUrl_001, TestSize.Level0)
{
    std::string testUrl = "http://example.com/test.mp4";
    std::string testPath = "videos/test.mp4";
    TestCommon::CreateTestCacheFile(testCacheDir_, testPath, std::vector<uint8_t>(1024, 'A'));
    TestCommon::CreateTestMappingFile(testCacheDir_, {{testUrl, testPath}});

    auto manager = std::make_shared<DownloadedCacheManager>(testCacheDir_);
    CacheMetaData metadata;
    bool result = manager->GetCacheMetaData("", metadata);
    EXPECT_FALSE(result);
}

HWTEST_F(CacheManagerTest, BuildHttpHeaders_Success_001, TestSize.Level0)
{
    std::string testUrl = "http://example.com/test.mp4";
    std::string testPath = "videos/test.mp4";
    TestCommon::CreateTestCacheFile(testCacheDir_, testPath, std::vector<uint8_t>(1024, 'A'));
    TestCommon::CreateTestMappingFile(testCacheDir_, {{testUrl, testPath}});

    auto manager = std::make_shared<DownloadedCacheManager>(testCacheDir_);
    auto headers = manager->BuildHttpHeaders(testUrl, 1024);
    EXPECT_FALSE(headers.empty());
    EXPECT_EQ(headers["content-length"], "1024");
    EXPECT_EQ(headers["accept-ranges"], "bytes");
}

HWTEST_F(CacheManagerTest, BuildHttpHeaders_NotFound_001, TestSize.Level0)
{
    std::string testUrl = "http://example.com/test.mp4";
    std::string testPath = "videos/test.mp4";
    TestCommon::CreateTestCacheFile(testCacheDir_, testPath, std::vector<uint8_t>(1024, 'A'));
    TestCommon::CreateTestMappingFile(testCacheDir_, {{testUrl, testPath}});

    auto manager = std::make_shared<DownloadedCacheManager>(testCacheDir_);
    auto headers = manager->BuildHttpHeaders("http://example.com/nonexistent.mp4", 0);
    EXPECT_TRUE(headers.empty());
}

HWTEST_F(CacheManagerTest, MultiInstance_001, TestSize.Level0)
{
    std::string testUrl = "http://example.com/test.mp4";
    std::string testPath = "videos/test.mp4";
    TestCommon::CreateTestCacheFile(testCacheDir_, testPath, std::vector<uint8_t>(1024, 'A'));
    TestCommon::CreateTestMappingFile(testCacheDir_, {{testUrl, testPath}});

    auto manager1 = std::make_shared<DownloadedCacheManager>(testCacheDir_);
    auto manager2 = std::make_shared<DownloadedCacheManager>(testCacheDir_);
    ASSERT_NE(manager1, manager2);
    EXPECT_EQ(manager1->GetMediaCache(testUrl), manager2->GetMediaCache(testUrl));
}

HWTEST_F(CacheManagerTest, MultipleEntries_001, TestSize.Level0)
{
    std::vector<std::pair<std::string, std::string>> entries = {
        {"http://example.com/video1.mp4", "videos/video1.mp4"},
        {"http://example.com/video2.mp4", "videos/video2.mp4"},
        {"http://example.com/audio1.mp3", "audio/audio1.mp3"},
    };
    for (const auto& entry : entries) {
        TestCommon::CreateTestCacheFile(testCacheDir_, entry.second, std::vector<uint8_t>(1024, 'A'));
    }
    TestCommon::CreateTestMappingFile(testCacheDir_, entries);

    auto manager = std::make_shared<DownloadedCacheManager>(testCacheDir_);
    for (const auto& entry : entries) {
        std::string result = manager->GetMediaCache(entry.first);
        EXPECT_NE(result, "");
    }
}

HWTEST_F(CacheManagerTest, InvalidMagic_001, TestSize.Level0)
{
    std::vector<uint8_t> data = {'X', 'Y', 'Z', 'W'};
    data.resize(24, 0);
    TestCommon::CreateRawMappingFile(testCacheDir_, data);

    auto manager = std::make_shared<DownloadedCacheManager>(testCacheDir_);
    std::string result = manager->GetMediaCache("http://example.com/test.mp4");
    EXPECT_EQ(result, "");
}

HWTEST_F(CacheManagerTest, InvalidVersion_001, TestSize.Level0)
{
    std::vector<uint8_t> data;
    data.push_back('D'); data.push_back('C'); data.push_back('M'); data.push_back('H');
    uint32_t version = 999;
    uint32_t entryCount = 0;
    uint8_t reserved[8] = {0};
    uint32_t checksum = 0;
    data.insert(data.end(), reinterpret_cast<uint8_t*>(&version), reinterpret_cast<uint8_t*>(&version) + 4);
    data.insert(data.end(), reinterpret_cast<uint8_t*>(&entryCount), reinterpret_cast<uint8_t*>(&entryCount) + 4);
    data.insert(data.end(), reserved, reserved + 8);
    data.insert(data.end(), reinterpret_cast<uint8_t*>(&checksum), reinterpret_cast<uint8_t*>(&checksum) + 4);
    TestCommon::CreateRawMappingFile(testCacheDir_, data);

    auto manager = std::make_shared<DownloadedCacheManager>(testCacheDir_);
    std::string result = manager->GetMediaCache("http://example.com/test.mp4");
    EXPECT_EQ(result, "");
}

HWTEST_F(CacheManagerTest, ChecksumMismatch_001, TestSize.Level0)
{
    TestCommon::CreateTestMappingFileWithChecksum(testCacheDir_, {}, 12345678);

    auto manager = std::make_shared<DownloadedCacheManager>(testCacheDir_);
    std::string result = manager->GetMediaCache("http://example.com/test.mp4");
    EXPECT_EQ(result, "");
}

HWTEST_F(CacheManagerTest, TruncatedHeader_001, TestSize.Level0)
{
    std::vector<uint8_t> data = {'D', 'C'};
    TestCommon::CreateRawMappingFile(testCacheDir_, data);

    auto manager = std::make_shared<DownloadedCacheManager>(testCacheDir_);
    std::string result = manager->GetMediaCache("http://example.com/test.mp4");
    EXPECT_EQ(result, "");
}

HWTEST_F(CacheManagerTest, MappingFileTooLarge_001, TestSize.Level0)
{
    std::vector<uint8_t> largeData(11 * 1024 * 1024, 'A');
    TestCommon::CreateRawMappingFile(testCacheDir_, largeData);

    auto manager = std::make_shared<DownloadedCacheManager>(testCacheDir_);
    std::string result = manager->GetMediaCache("http://example.com/test.mp4");
    EXPECT_EQ(result, "");
}

HWTEST_F(CacheManagerTest, GetCacheDir_001, TestSize.Level0)
{
    auto manager = std::make_shared<DownloadedCacheManager>(testCacheDir_);
    EXPECT_EQ(manager->GetCacheDir(), testCacheDir_);
}

HWTEST_F(CacheManagerTest, SpecialUrl_001, TestSize.Level0)
{
    std::string testUrl = "http://example.com/test?param=value&foo=bar";
    std::string testPath = "videos/test_query.mp4";
    TestCommon::CreateTestCacheFile(testCacheDir_, testPath, std::vector<uint8_t>(1024, 'A'));
    TestCommon::CreateTestMappingFile(testCacheDir_, {{testUrl, testPath}});

    auto manager = std::make_shared<DownloadedCacheManager>(testCacheDir_);
    std::string result = manager->GetMediaCache(testUrl);
    EXPECT_NE(result, "");
}

HWTEST_F(CacheManagerTest, LongUrl_001, TestSize.Level0)
{
    std::string testUrl = "http://example.com/" + std::string(500, 'a') + ".mp4";
    std::string testPath = "videos/long.mp4";
    TestCommon::CreateTestCacheFile(testCacheDir_, testPath, std::vector<uint8_t>(1024, 'A'));
    TestCommon::CreateTestMappingFile(testCacheDir_, {{testUrl, testPath}});

    auto manager = std::make_shared<DownloadedCacheManager>(testCacheDir_);
    std::string result = manager->GetMediaCache(testUrl);
    EXPECT_NE(result, "");
}

HWTEST_F(CacheManagerTest, EmptyRelativePath_Entry_001, TestSize.Level0)
{
    std::string testUrl = "http://example.com/test.mp4";
    std::string testPath = "";
    TestCommon::CreateTestMappingFile(testCacheDir_, {{testUrl, testPath}});

    auto manager = std::make_shared<DownloadedCacheManager>(testCacheDir_);
    std::string result = manager->GetMediaCache(testUrl);
    EXPECT_EQ(result, "");
}

HWTEST_F(CacheManagerTest, EntryWithPathTraversal_001, TestSize.Level0)
{
    std::string mappingPath = testCacheDir_ + "/cache_mapping.txt";

    CacheMappingHeader header;
    (void)memcpy_s(header.magic, sizeof(CACHE_MAPPING_MAGIC), CACHE_MAPPING_MAGIC, sizeof(CACHE_MAPPING_MAGIC));
    header.version = CACHE_MAPPING_VERSION;
    header.entryCount = 1;
    (void)memset_s(header.reserved, 8, 0, 8);
    header.headerChecksum = CacheMappingSerializer::CalculateHeaderChecksum(header);

    std::ofstream file(mappingPath, std::ios::binary | std::ios::trunc);
    file.write(reinterpret_cast<const char*>(header.magic), 4);
    file.write(reinterpret_cast<const char*>(&header.version), 4);
    file.write(reinterpret_cast<const char*>(&header.entryCount), 4);
    file.write(reinterpret_cast<const char*>(header.reserved), 8);
    file.write(reinterpret_cast<const char*>(&header.headerChecksum), 4);

    CacheMappingEntry entry;
    auto hash = SHA256Hasher::GenerateHash("http://example.com/test.mp4");
    (void)memcpy_s(entry.header.urlHash, SHA256_LEN, hash.data(), SHA256_LEN);
    entry.header.pathLength = 13;
    entry.header.fileSize = 1024;
    (void)memset_s(entry.header.reserved, 8, 0, 8);
    std::string traversalPath = "../../../etc/passwd";
    entry.filePath = traversalPath;

    file.write(reinterpret_cast<const char*>(entry.header.urlHash), SHA256_LEN);
    file.write(reinterpret_cast<const char*>(&entry.header.pathLength), 4);
    file.write(reinterpret_cast<const char*>(&entry.header.fileSize), 8);
    file.write(reinterpret_cast<const char*>(entry.header.reserved), 8);
    file.write(traversalPath.c_str(), traversalPath.size());
    file.close();

    auto manager = std::make_shared<DownloadedCacheManager>(testCacheDir_);
    std::string result = manager->GetMediaCache("http://example.com/test.mp4");
    EXPECT_EQ(result, "");
}

HWTEST_F(CacheManagerTest, EntryWithInvalidPathLength_001, TestSize.Level0)
{
    std::string mappingPath = testCacheDir_ + "/cache_mapping.txt";

    CacheMappingHeader header;
    (void)memcpy_s(header.magic, sizeof(CACHE_MAPPING_MAGIC), CACHE_MAPPING_MAGIC, sizeof(CACHE_MAPPING_MAGIC));
    header.version = CACHE_MAPPING_VERSION;
    header.entryCount = 1;
    (void)memset_s(header.reserved, 8, 0, 8);
    header.headerChecksum = CacheMappingSerializer::CalculateHeaderChecksum(header);

    std::ofstream file(mappingPath, std::ios::binary | std::ios::trunc);
    file.write(reinterpret_cast<const char*>(header.magic), 4);
    file.write(reinterpret_cast<const char*>(&header.version), 4);
    file.write(reinterpret_cast<const char*>(&header.entryCount), 4);
    file.write(reinterpret_cast<const char*>(header.reserved), 8);
    file.write(reinterpret_cast<const char*>(&header.headerChecksum), 4);

    CacheMappingEntry entry;
    auto hash = SHA256Hasher::GenerateHash("http://example.com/test.mp4");
    (void)memcpy_s(entry.header.urlHash, SHA256_LEN, hash.data(), SHA256_LEN);
    entry.header.pathLength = 999999;
    entry.header.fileSize = 1024;
    (void)memset_s(entry.header.reserved, 8, 0, 8);

    file.write(reinterpret_cast<const char*>(entry.header.urlHash), SHA256_LEN);
    file.write(reinterpret_cast<const char*>(&entry.header.pathLength), 4);
    file.write(reinterpret_cast<const char*>(&entry.header.fileSize), 8);
    file.write(reinterpret_cast<const char*>(entry.header.reserved), 8);
    file.close();

    auto manager = std::make_shared<DownloadedCacheManager>(testCacheDir_);
    std::string result = manager->GetMediaCache("http://example.com/test.mp4");
    EXPECT_EQ(result, "");
}

HWTEST_F(CacheManagerTest, TruncatedEntry_001, TestSize.Level0)
{
    std::string mappingPath = testCacheDir_ + "/cache_mapping.txt";

    CacheMappingHeader header;
    (void)memcpy_s(header.magic, sizeof(CACHE_MAPPING_MAGIC), CACHE_MAPPING_MAGIC, sizeof(CACHE_MAPPING_MAGIC));
    header.version = CACHE_MAPPING_VERSION;
    header.entryCount = 1;
    (void)memset_s(header.reserved, 8, 0, 8);
    header.headerChecksum = CacheMappingSerializer::CalculateHeaderChecksum(header);

    std::ofstream file(mappingPath, std::ios::binary | std::ios::trunc);
    file.write(reinterpret_cast<const char*>(header.magic), 4);
    file.write(reinterpret_cast<const char*>(&header.version), 4);
    file.write(reinterpret_cast<const char*>(&header.entryCount), 4);
    file.write(reinterpret_cast<const char*>(header.reserved), 8);
    file.write(reinterpret_cast<const char*>(&header.headerChecksum), 4);

    auto hash = SHA256Hasher::GenerateHash("http://example.com/test.mp4");
    file.write(reinterpret_cast<const char*>(hash.data()), 10);
    file.close();

    auto manager = std::make_shared<DownloadedCacheManager>(testCacheDir_);
    std::string result = manager->GetMediaCache("http://example.com/test.mp4");
    EXPECT_EQ(result, "");
}

HWTEST_F(CacheManagerTest, RelativePathWithDoubleDot_001, TestSize.Level0)
{
    std::string testUrl = "http://example.com/test.mp4";
    std::string testPath = "videos/../test.mp4";
    TestCommon::CreateTestCacheFile(testCacheDir_, "test.mp4", std::vector<uint8_t>(1024, 'A'));
    TestCommon::CreateTestMappingFile(testCacheDir_, {{testUrl, testPath}});

    auto manager = std::make_shared<DownloadedCacheManager>(testCacheDir_);
    std::string result = manager->GetMediaCache(testUrl);
    EXPECT_NE(result, "");
}

HWTEST_F(CacheManagerTest, GetMediaCache_RelativePathContainsDoubleDot_001, TestSize.Level0)
{
    std::string testUrl = "http://example.com/test.mp4";
    std::string testPath = "videos/../../etc/passwd";
    TestCommon::CreateTestMappingFile(testCacheDir_, {{testUrl, testPath}});

    auto manager = std::make_shared<DownloadedCacheManager>(testCacheDir_);
    std::string result = manager->GetMediaCache(testUrl);
    EXPECT_EQ(result, "");
}

HWTEST_F(CacheManagerTest, GetMediaCache_NormalPath_AfterTraversal_001, TestSize.Level0)
{
    std::string testUrl = "http://example.com/test.mp4";
    std::string testPath = "videos/test.mp4";
    TestCommon::CreateTestCacheFile(testCacheDir_, testPath, std::vector<uint8_t>(1024, 'A'));
    TestCommon::CreateTestMappingFile(testCacheDir_, {{testUrl, testPath}});

    auto manager = std::make_shared<DownloadedCacheManager>(testCacheDir_);
    std::string result = manager->GetMediaCache(testUrl);
    EXPECT_NE(result, "");
    EXPECT_EQ(result, testCacheDir_ + "/" + testPath);
}

HWTEST_F(CacheManagerTest, LargeFileSize_001, TestSize.Level0)
{
    std::string testUrl = "http://example.com/test.mp4";
    std::string testPath = "videos/test.mp4";
    TestCommon::CreateTestCacheFile(testCacheDir_, testPath, std::vector<uint8_t>(1024, 'A'));

    std::string mappingPath = testCacheDir_ + "/cache_mapping.txt";
    CacheMappingHeader header;
    (void)memcpy_s(header.magic, sizeof(CACHE_MAPPING_MAGIC), CACHE_MAPPING_MAGIC, sizeof(CACHE_MAPPING_MAGIC));
    header.version = CACHE_MAPPING_VERSION;
    header.entryCount = 1;
    (void)memset_s(header.reserved, 8, 0, 8);
    header.headerChecksum = CacheMappingSerializer::CalculateHeaderChecksum(header);

    std::ofstream file(mappingPath, std::ios::binary | std::ios::trunc);
    file.write(reinterpret_cast<const char*>(header.magic), 4);
    file.write(reinterpret_cast<const char*>(&header.version), 4);
    file.write(reinterpret_cast<const char*>(&header.entryCount), 4);
    file.write(reinterpret_cast<const char*>(header.reserved), 8);
    file.write(reinterpret_cast<const char*>(&header.headerChecksum), 4);

    CacheMappingEntry entry;
    auto hash = SHA256Hasher::GenerateHash(testUrl);
    (void)memcpy_s(entry.header.urlHash, SHA256_LEN, hash.data(), SHA256_LEN);
    entry.header.pathLength = static_cast<uint32_t>(testPath.size());
    entry.header.fileSize = static_cast<uint64_t>(10ULL * 1024ULL * 1024ULL * 1024ULL);
    (void)memset_s(entry.header.reserved, 8, 0, 8);
    entry.filePath = testPath;

    file.write(reinterpret_cast<const char*>(entry.header.urlHash), SHA256_LEN);
    file.write(reinterpret_cast<const char*>(&entry.header.pathLength), 4);
    file.write(reinterpret_cast<const char*>(&entry.header.fileSize), 8);
    file.write(reinterpret_cast<const char*>(entry.header.reserved), 8);
    file.write(testPath.c_str(), testPath.size());
    file.close();

    auto manager = std::make_shared<DownloadedCacheManager>(testCacheDir_);
    CacheMetaData metadata;
    bool result = manager->GetCacheMetaData(testUrl, metadata);
    EXPECT_TRUE(result);
    EXPECT_EQ(metadata.size, static_cast<uint64_t>(10ULL * 1024ULL * 1024ULL * 1024ULL));
}

} // namespace DownloadedCache
} // namespace Media
} // namespace OHOS