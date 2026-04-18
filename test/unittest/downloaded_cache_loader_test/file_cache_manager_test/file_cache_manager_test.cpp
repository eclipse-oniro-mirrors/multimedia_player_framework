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
#include <vector>
#include "downloaded_cache_test_common.h"
#include "file_cache_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {
namespace DownloadedCache {

class FileCacheManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void) {
        testCacheDir_ = TestCommon::GetTestCacheDir("file_cache");
        TestCommon::SetupTestDirectory(testCacheDir_);
        testFilePath_ = testCacheDir_ + "/test.bin";
        testRelativePath_ = "test.bin";
        testData_ = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A};
        TestCommon::CreateTestCacheFile(testCacheDir_, testRelativePath_, testData_);
    }
    void TearDown(void) {
        TestCommon::CleanupTestDirectory(testCacheDir_);
    }
protected:
    std::string testCacheDir_;
    std::string testFilePath_;
    std::string testRelativePath_;
    std::vector<uint8_t> testData_;
};

HWTEST_F(FileCacheManagerTest, GetSize_Success_001, TestSize.Level0)
{
    auto fileManager = std::make_shared<DownloadedFileCacheManager>(testCacheDir_);
    int64_t size = fileManager->GetSize(testFilePath_);
    EXPECT_EQ(size, static_cast<int64_t>(testData_.size()));
}

HWTEST_F(FileCacheManagerTest, GetSize_FileNotExist_001, TestSize.Level0)
{
    auto fileManager = std::make_shared<DownloadedFileCacheManager>(testCacheDir_);
    int64_t size = fileManager->GetSize(testCacheDir_ + "/nonexistent.bin");
    EXPECT_LT(size, 0);
}

HWTEST_F(FileCacheManagerTest, Read_Success_001, TestSize.Level0)
{
    auto fileManager = std::make_shared<DownloadedFileCacheManager>(testCacheDir_);
    std::vector<uint8_t> buffer(testData_.size(), 0);
    int32_t result = fileManager->Read(testFilePath_, buffer.data(), 0, testData_.size());
    EXPECT_EQ(result, 0);
    EXPECT_EQ(buffer, testData_);
}

HWTEST_F(FileCacheManagerTest, Read_Offset_001, TestSize.Level0)
{
    auto fileManager = std::make_shared<DownloadedFileCacheManager>(testCacheDir_);
    std::vector<uint8_t> buffer(5, 0);
    int32_t result = fileManager->Read(testFilePath_, buffer.data(), 2, 5);
    EXPECT_EQ(result, 0);
    std::vector<uint8_t> expected = {0x03, 0x04, 0x05, 0x06, 0x07};
    EXPECT_EQ(buffer, expected);
}

HWTEST_F(FileCacheManagerTest, Read_FileNotExist_001, TestSize.Level0)
{
    auto fileManager = std::make_shared<DownloadedFileCacheManager>(testCacheDir_);
    std::vector<uint8_t> buffer(10, 0);
    int32_t result = fileManager->Read(testCacheDir_ + "/nonexistent.bin", buffer.data(), 0, 10);
    EXPECT_LT(result, 0);
}

HWTEST_F(FileCacheManagerTest, Read_InvalidPath_001, TestSize.Level0)
{
    auto fileManager = std::make_shared<DownloadedFileCacheManager>(testCacheDir_);
    std::vector<uint8_t> buffer(10, 0);
    int32_t result = fileManager->Read("/etc/passwd", buffer.data(), 0, 10);
    EXPECT_LT(result, 0);
}

HWTEST_F(FileCacheManagerTest, Read_PathTraversal_001, TestSize.Level0)
{
    auto fileManager = std::make_shared<DownloadedFileCacheManager>(testCacheDir_);
    std::vector<uint8_t> buffer(10, 0);
    int32_t result = fileManager->Read(testCacheDir_ + "/../etc/passwd", buffer.data(), 0, 10);
    EXPECT_LT(result, 0);
}

HWTEST_F(FileCacheManagerTest, Read_EmptyPath_001, TestSize.Level0)
{
    auto fileManager = std::make_shared<DownloadedFileCacheManager>(testCacheDir_);
    std::vector<uint8_t> buffer(10, 0);
    int32_t result = fileManager->Read("", buffer.data(), 0, 10);
    EXPECT_LT(result, 0);
}

HWTEST_F(FileCacheManagerTest, Read_PathTooLong_001, TestSize.Level0)
{
    auto fileManager = std::make_shared<DownloadedFileCacheManager>(testCacheDir_);
    std::vector<uint8_t> buffer(10, 0);
    std::string longPath(testCacheDir_ + "/" + std::string(5000, 'a'));
    int32_t result = fileManager->Read(longPath, buffer.data(), 0, 10);
    EXPECT_LT(result, 0);
}

HWTEST_F(FileCacheManagerTest, Read_Partial_001, TestSize.Level0)
{
    auto fileManager = std::make_shared<DownloadedFileCacheManager>(testCacheDir_);
    std::vector<uint8_t> buffer(3, 0);
    int32_t result = fileManager->Read(testFilePath_, buffer.data(), 0, 3);
    EXPECT_EQ(result, 0);
    std::vector<uint8_t> expected = {0x01, 0x02, 0x03};
    EXPECT_EQ(buffer, expected);
}

HWTEST_F(FileCacheManagerTest, Read_LastBytes_001, TestSize.Level0)
{
    auto fileManager = std::make_shared<DownloadedFileCacheManager>(testCacheDir_);
    std::vector<uint8_t> buffer(3, 0);
    int32_t result = fileManager->Read(testFilePath_, buffer.data(), 7, 3);
    EXPECT_EQ(result, 0);
    std::vector<uint8_t> expected = {0x08, 0x09, 0x0A};
    EXPECT_EQ(buffer, expected);
}

HWTEST_F(FileCacheManagerTest, GetSize_EmptyPath_001, TestSize.Level0)
{
    auto fileManager = std::make_shared<DownloadedFileCacheManager>(testCacheDir_);
    int64_t size = fileManager->GetSize("");
    EXPECT_LT(size, 0);
}

HWTEST_F(FileCacheManagerTest, GetSize_PathTraversal_001, TestSize.Level0)
{
    auto fileManager = std::make_shared<DownloadedFileCacheManager>(testCacheDir_);
    int64_t size = fileManager->GetSize(testCacheDir_ + "/../etc/passwd");
    EXPECT_LT(size, 0);
}

HWTEST_F(FileCacheManagerTest, LargeFile_001, TestSize.Level0)
{
    std::string largeRelativePath = "large.bin";
    std::vector<uint8_t> largeData(1024 * 1024, 0xAB);
    TestCommon::CreateTestCacheFile(testCacheDir_, largeRelativePath, largeData);

    auto fileManager = std::make_shared<DownloadedFileCacheManager>(testCacheDir_);
    std::string largePath = testCacheDir_ + "/" + largeRelativePath;
    int64_t size = fileManager->GetSize(largePath);
    EXPECT_EQ(size, static_cast<int64_t>(largeData.size()));

    std::vector<uint8_t> buffer(1024, 0);
    int32_t result = fileManager->Read(largePath, buffer.data(), 0, 1024);
    EXPECT_EQ(result, 0);
}

HWTEST_F(FileCacheManagerTest, ZeroOffset_001, TestSize.Level0)
{
    auto fileManager = std::make_shared<DownloadedFileCacheManager>(testCacheDir_);
    std::vector<uint8_t> buffer(testData_.size(), 0);
    int32_t result = fileManager->Read(testFilePath_, buffer.data(), 0, testData_.size());
    EXPECT_EQ(result, 0);
}

HWTEST_F(FileCacheManagerTest, ZeroLength_001, TestSize.Level0)
{
    auto fileManager = std::make_shared<DownloadedFileCacheManager>(testCacheDir_);
    std::vector<uint8_t> buffer(1, 0);
    int32_t result = fileManager->Read(testFilePath_, buffer.data(), 0, 0);
    EXPECT_EQ(result, 0);
}

HWTEST_F(FileCacheManagerTest, Read_BufferOverflow_001, TestSize.Level0)
{
    auto fileManager = std::make_shared<DownloadedFileCacheManager>(testCacheDir_);
    std::vector<uint8_t> buffer(5, 0);
    int32_t result = fileManager->Read(testFilePath_, buffer.data(), 0, 100);
    EXPECT_EQ(result, 0);
}

HWTEST_F(FileCacheManagerTest, Read_OffsetExceedsSize_001, TestSize.Level0)
{
    auto fileManager = std::make_shared<DownloadedFileCacheManager>(testCacheDir_);
    std::vector<uint8_t> buffer(5, 0);
    int32_t result = fileManager->Read(testFilePath_, buffer.data(), 100, 5);
    EXPECT_EQ(result, 0);
}

HWTEST_F(FileCacheManagerTest, Read_PathWithSlashPrefix_001, TestSize.Level0)
{
    auto fileManager = std::make_shared<DownloadedFileCacheManager>(testCacheDir_);
    std::vector<uint8_t> buffer(5, 0);
    std::string pathWithSlash = testCacheDir_ + "/" + testRelativePath_;
    int32_t result = fileManager->Read(pathWithSlash, buffer.data(), 0, 5);
    EXPECT_EQ(result, 0);
}

HWTEST_F(FileCacheManagerTest, Read_DifferentCacheDir_001, TestSize.Level0)
{
    std::string otherCacheDir = TestCommon::GetTestCacheDir("other_cache");
    TestCommon::SetupTestDirectory(otherCacheDir);

    auto fileManager = std::make_shared<DownloadedFileCacheManager>(testCacheDir_);
    std::vector<uint8_t> buffer(5, 0);
    int32_t result = fileManager->Read(otherCacheDir + "/test.bin", buffer.data(), 0, 5);
    EXPECT_LT(result, 0);

    TestCommon::CleanupTestDirectory(otherCacheDir);
}

HWTEST_F(FileCacheManagerTest, GetSize_PathWithSlashPrefix_001, TestSize.Level0)
{
    auto fileManager = std::make_shared<DownloadedFileCacheManager>(testCacheDir_);
    std::string pathWithSlash = testCacheDir_ + "/" + testRelativePath_;
    int64_t size = fileManager->GetSize(pathWithSlash);
    EXPECT_EQ(size, static_cast<int64_t>(testData_.size()));
}

HWTEST_F(FileCacheManagerTest, IsValidPath_CacheDirExactMatch_001, TestSize.Level0)
{
    auto fileManager = std::make_shared<DownloadedFileCacheManager>(testCacheDir_);
    int64_t size = fileManager->GetSize(testCacheDir_);
    EXPECT_LT(size, 0);
}

HWTEST_F(FileCacheManagerTest, Constructor_EmptyCacheDir_001, TestSize.Level0)
{
    auto fileManager = std::make_shared<DownloadedFileCacheManager>("");
    ASSERT_NE(fileManager, nullptr);
    int64_t size = fileManager->GetSize("/etc/passwd");
    EXPECT_LT(size, 0);
}

HWTEST_F(FileCacheManagerTest, Read_EntireFile_001, TestSize.Level0)
{
    auto fileManager = std::make_shared<DownloadedFileCacheManager>(testCacheDir_);
    std::vector<uint8_t> buffer(testData_.size(), 0);
    int32_t result = fileManager->Read(testFilePath_, buffer.data(), 0, testData_.size());
    EXPECT_EQ(result, 0);
    EXPECT_EQ(buffer, testData_);
}

HWTEST_F(FileCacheManagerTest, Read_MultipleTimes_001, TestSize.Level0)
{
    auto fileManager = std::make_shared<DownloadedFileCacheManager>(testCacheDir_);

    std::vector<uint8_t> buffer1(3, 0);
    int32_t result1 = fileManager->Read(testFilePath_, buffer1.data(), 0, 3);
    EXPECT_EQ(result1, 0);

    std::vector<uint8_t> buffer2(3, 0);
    int32_t result2 = fileManager->Read(testFilePath_, buffer2.data(), 3, 3);
    EXPECT_EQ(result2, 0);

    std::vector<uint8_t> expected1 = {0x01, 0x02, 0x03};
    std::vector<uint8_t> expected2 = {0x04, 0x05, 0x06};
    EXPECT_EQ(buffer1, expected1);
    EXPECT_EQ(buffer2, expected2);
}

HWTEST_F(FileCacheManagerTest, Read_ReadOnlyPath_001, TestSize.Level0)
{
    auto fileManager = std::make_shared<DownloadedFileCacheManager>(testCacheDir_);
    std::vector<uint8_t> buffer(10, 0);
    int32_t result = fileManager->Read(testFilePath_, buffer.data(), 0, 10);
    EXPECT_EQ(result, 0);
}

HWTEST_F(FileCacheManagerTest, GetSize_AfterCreate_001, TestSize.Level0)
{
    auto fileManager = std::make_shared<DownloadedFileCacheManager>(testCacheDir_);
    int64_t size1 = fileManager->GetSize(testFilePath_);
    EXPECT_EQ(size2, 10);

    std::string newFile = testCacheDir_ + "/new.bin";
    std::vector<uint8_t> newData(50, 0xFF);
    TestCommon::CreateTestCacheFile(testCacheDir_, "new.bin", newData);

    int64_t size2 = fileManager->GetSize(newFile);
    EXPECT_EQ(size2, 50);
}

} // namespace DownloadedCache
} // namespace Media
} // namespace OHOS