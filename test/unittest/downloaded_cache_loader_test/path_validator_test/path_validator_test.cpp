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
#include "../common/downloaded_cache_test_common.h"
#include "path_validator.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {
namespace DownloadedCache {

class PathValidatorTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void) {
        testCacheDir_ = TestCommon::GetTestCacheDir("path_validator");
        TestCommon::SetupTestDirectory(testCacheDir_);
    }
    void TearDown(void) {
        TestCommon::CleanupTestDirectory(testCacheDir_);
    }
protected:
    std::string testCacheDir_;
};

HWTEST_F(PathValidatorTest, ValidPath_001, TestSize.Level0)
{
    std::string relativePath = "videos/test.mp4";
    bool result = PathValidator::Validate(testCacheDir_, relativePath);
    EXPECT_TRUE(result);
}

HWTEST_F(PathValidatorTest, PathTraversal_001, TestSize.Level0)
{
    std::string relativePath = "../etc/passwd";
    bool result = PathValidator::Validate(testCacheDir_, relativePath);
    EXPECT_FALSE(result);
}

HWTEST_F(PathValidatorTest, DeepPathTraversal_001, TestSize.Level0)
{
    std::string relativePath = "videos/../../../etc/passwd";
    bool result = PathValidator::Validate(testCacheDir_, relativePath);
    EXPECT_FALSE(result);
}

HWTEST_F(PathValidatorTest, IllegalChar_Null_001, TestSize.Level0)
{
    std::string relativePath = "videos/\x00test.mp4";
    bool result = PathValidator::Validate(testCacheDir_, relativePath);
    EXPECT_FALSE(result);
}

HWTEST_F(PathValidatorTest, IllegalChar_Control_001, TestSize.Level0)
{
    std::string relativePath = "videos/\x01test.mp4";
    bool result = PathValidator::Validate(testCacheDir_, relativePath);
    EXPECT_FALSE(result);
}

HWTEST_F(PathValidatorTest, AllowedChar_Tab_001, TestSize.Level0)
{
    std::string relativePath = "videos/\ttest.mp4";
    bool result = PathValidator::Validate(testCacheDir_, relativePath);
    EXPECT_TRUE(result);
}

HWTEST_F(PathValidatorTest, AllowedChar_Newline_001, TestSize.Level0)
{
    std::string relativePath = "videos/\ntest.mp4";
    bool result = PathValidator::Validate(testCacheDir_, relativePath);
    EXPECT_TRUE(result);
}

HWTEST_F(PathValidatorTest, PathTooLong_001, TestSize.Level0)
{
    std::string relativePath(2000, 'a');
    bool result = PathValidator::Validate(testCacheDir_, relativePath);
    EXPECT_FALSE(result);
}

HWTEST_F(PathValidatorTest, PathWithDot_001, TestSize.Level0)
{
    std::string relativePath = "videos/./test.mp4";
    bool result = PathValidator::Validate(testCacheDir_, relativePath);
    EXPECT_TRUE(result);
}

HWTEST_F(PathValidatorTest, EmptyRelativePath_001, TestSize.Level0)
{
    std::string relativePath = "";
    bool result = PathValidator::Validate(testCacheDir_, relativePath);
    EXPECT_TRUE(result);
}

HWTEST_F(PathValidatorTest, SingleDot_001, TestSize.Level0)
{
    std::string relativePath = ".";
    bool result = PathValidator::Validate(testCacheDir_, relativePath);
    EXPECT_TRUE(result);
}

HWTEST_F(PathValidatorTest, DoubleDot_001, TestSize.Level0)
{
    std::string relativePath = "..";
    bool result = PathValidator::Validate(testCacheDir_, relativePath);
    EXPECT_FALSE(result);
}

HWTEST_F(PathValidatorTest, ValidMultiLevel_001, TestSize.Level0)
{
    std::string relativePath = "videos/hd/2024/test.mp4";
    bool result = PathValidator::Validate(testCacheDir_, relativePath);
    EXPECT_TRUE(result);
}

HWTEST_F(PathValidatorTest, PathTraversalInMiddle_001, TestSize.Level0)
{
    std::string relativePath = "videos/../audio/test.mp3";
    bool result = PathValidator::Validate(testCacheDir_, relativePath);
    EXPECT_TRUE(result);
}

HWTEST_F(PathValidatorTest, ExcessiveDotDot_001, TestSize.Level0)
{
    std::string relativePath = "../../../../../../../../etc/passwd";
    bool result = PathValidator::Validate(testCacheDir_, relativePath);
    EXPECT_FALSE(result);
}

HWTEST_F(PathValidatorTest, MixedTraversal_001, TestSize.Level0)
{
    std::string relativePath = "a/b/c/../../../d/e/../../../etc/passwd";
    bool result = PathValidator::Validate(testCacheDir_, relativePath);
    EXPECT_FALSE(result);
}

HWTEST_F(PathValidatorTest, CarriageReturn_001, TestSize.Level0)
{
    std::string relativePath = "videos/\rtest.mp4";
    bool result = PathValidator::Validate(testCacheDir_, relativePath);
    EXPECT_TRUE(result);
}

HWTEST_F(PathValidatorTest, MultipleDots_001, TestSize.Level0)
{
    std::string relativePath = "videos/...test.mp4";
    bool result = PathValidator::Validate(testCacheDir_, relativePath);
    EXPECT_TRUE(result);
}

HWTEST_F(PathValidatorTest, SlashOnly_001, TestSize.Level0)
{
    std::string relativePath = "/";
    bool result = PathValidator::Validate(testCacheDir_, relativePath);
    EXPECT_TRUE(result);
}

HWTEST_F(PathValidatorTest, EmptyRootPath_001, TestSize.Level0)
{
    std::string relativePath = "videos/test.mp4";
    bool result = PathValidator::Validate("", relativePath);
    EXPECT_TRUE(result);
}

HWTEST_F(PathValidatorTest, BothEmpty_001, TestSize.Level0)
{
    std::string relativePath = "";
    bool result = PathValidator::Validate("", relativePath);
    EXPECT_TRUE(result);
}

HWTEST_F(PathValidatorTest, RootPathWithSlash_001, TestSize.Level0)
{
    std::string rootPath = testCacheDir_ + "/";
    std::string relativePath = "videos/test.mp4";
    bool result = PathValidator::Validate(rootPath, relativePath);
    EXPECT_TRUE(result);
}

HWTEST_F(PathValidatorTest, RelativePathStartingWithSlash_001, TestSize.Level0)
{
    std::string relativePath = "/videos/test.mp4";
    bool result = PathValidator::Validate(testCacheDir_, relativePath);
    EXPECT_TRUE(result);
}

HWTEST_F(PathValidatorTest, ConsecutiveSlash_001, TestSize.Level0)
{
    std::string relativePath = "videos//test.mp4";
    bool result = PathValidator::Validate(testCacheDir_, relativePath);
    EXPECT_TRUE(result);
}

HWTEST_F(PathValidatorTest, Backslash_001, TestSize.Level0)
{
    std::string relativePath = "videos\\test.mp4";
    bool result = PathValidator::Validate(testCacheDir_, relativePath);
    EXPECT_TRUE(result);
}

HWTEST_F(PathValidatorTest, SpecialChars_001, TestSize.Level0)
{
    std::string relativePath = "videos/test-file_123.mp4";
    bool result = PathValidator::Validate(testCacheDir_, relativePath);
    EXPECT_TRUE(result);
}

HWTEST_F(PathValidatorTest, UnicodePath_001, TestSize.Level0)
{
    std::string relativePath = "videos/\xe4\xb8\xad\xe6\x96\x87.mp4";
    bool result = PathValidator::Validate(testCacheDir_, relativePath);
    EXPECT_TRUE(result);
}

HWTEST_F(PathValidatorTest, AllControlChars_001, TestSize.Level0)
{
    for (int i = 1; i < 32; i++) {
        if (i == 9 || i == 10 || i == 13) continue;
        std::string relativePath = "videos/test";
        relativePath += static_cast<char>(i);
        relativePath += ".mp4";
        bool result = PathValidator::Validate(testCacheDir_, relativePath);
        EXPECT_FALSE(result);
    }
}

HWTEST_F(PathValidatorTest, NormalizePath_001, TestSize.Level0)
{
    std::string relativePath = "a/b/../c/./d";
    bool result = PathValidator::Validate(testCacheDir_, relativePath);
    EXPECT_TRUE(result);
}

HWTEST_F(PathValidatorTest, RootPathEscaped_001, TestSize.Level0)
{
    std::string rootPath = testCacheDir_ + "/subdir";
    TestCommon::SetupTestDirectory(rootPath);
    std::string relativePath = "..";
    bool result = PathValidator::Validate(rootPath, relativePath);
    EXPECT_FALSE(result);
    TestCommon::CleanupTestDirectory(rootPath);
}

} // namespace DownloadedCache
} // namespace Media
} // namespace OHOS