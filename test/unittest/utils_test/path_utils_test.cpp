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
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include "path_utils.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {
namespace MediaSourceUtils {

class PathUtilsTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void)
    {
        testDir_ = "/data/test/path_utils_test_" + std::to_string(getpid());
        mkdir(testDir_.c_str(), S_IRWXU);
        subDir_ = testDir_ + "/subdir";
        mkdir(subDir_.c_str(), S_IRWXU);
    }
    void TearDown(void)
    {
        std::string cmd = "rm -rf " + testDir_;
        (void)system(cmd.c_str());
    }
protected:
    std::string testDir_;
    std::string subDir_;
};

HWTEST_F(PathUtilsTest, IsPathTraversalSafe_SafePath_001, TestSize.Level0)
{
    EXPECT_TRUE(PathUtils::IsPathTraversalSafe("/data/test/normal/path"));
}

HWTEST_F(PathUtilsTest, IsPathTraversalSafe_EmptyPath_001, TestSize.Level0)
{
    EXPECT_TRUE(PathUtils::IsPathTraversalSafe(""));
}

HWTEST_F(PathUtilsTest, IsPathTraversalSafe_DotDot_001, TestSize.Level0)
{
    EXPECT_FALSE(PathUtils::IsPathTraversalSafe("/data/../etc/passwd"));
}

HWTEST_F(PathUtilsTest, IsPathTraversalSafe_DotDotInMiddle_001, TestSize.Level0)
{
    EXPECT_FALSE(PathUtils::IsPathTraversalSafe("/data/test/../../etc/passwd"));
}

HWTEST_F(PathUtilsTest, IsPathTraversalSafe_DotDotAtEnd_001, TestSize.Level0)
{
    EXPECT_FALSE(PathUtils::IsPathTraversalSafe("/data/test/.."));
}

HWTEST_F(PathUtilsTest, ValidateAndNormalizePath_Empty_001, TestSize.Level0)
{
    std::string normalized;
    auto ret = PathUtils::ValidateAndNormalizePath("", normalized);
    EXPECT_EQ(ret, PATH_VALIDATE_ERROR_EMPTY);
}

HWTEST_F(PathUtilsTest, ValidateAndNormalizePath_Traversal_001, TestSize.Level0)
{
    std::string normalized;
    auto ret = PathUtils::ValidateAndNormalizePath("/data/../etc/passwd", normalized);
    EXPECT_EQ(ret, PATH_VALIDATE_ERROR_TRAVERSAL);
}

HWTEST_F(PathUtilsTest, ValidateAndNormalizePath_NotAbsolute_001, TestSize.Level0)
{
    std::string normalized;
    auto ret = PathUtils::ValidateAndNormalizePath("relative/path", normalized);
    EXPECT_EQ(ret, PATH_VALIDATE_ERROR_NOT_ABSOLUTE);
}

HWTEST_F(PathUtilsTest, ValidateAndNormalizePath_ExistingFile_001, TestSize.Level0)
{
    std::string filePath = subDir_ + "/test.txt";
    FILE* fp = fopen(filePath.c_str(), "w");
    ASSERT_NE(fp, nullptr);
    fclose(fp);

    std::string normalized;
    auto ret = PathUtils::ValidateAndNormalizePath(filePath, normalized);
    EXPECT_EQ(ret, PATH_VALIDATE_OK);
    EXPECT_EQ(normalized, filePath);
    unlink(filePath.c_str());
}

HWTEST_F(PathUtilsTest, ValidateAndNormalizePath_ExistingDir_001, TestSize.Level0)
{
    std::string normalized;
    auto ret = PathUtils::ValidateAndNormalizePath(subDir_, normalized);
    EXPECT_EQ(ret, PATH_VALIDATE_OK);
    EXPECT_FALSE(normalized.empty());
    EXPECT_EQ(normalized[0], '/');
}

HWTEST_F(PathUtilsTest, ValidateAndNormalizePath_NewFileInExistingDir_001, TestSize.Level0)
{
    std::string filePath = subDir_ + "/newfile.txt";

    std::string normalized;
    auto ret = PathUtils::ValidateAndNormalizePath(filePath, normalized);
    EXPECT_EQ(ret, PATH_VALIDATE_OK);
    EXPECT_FALSE(normalized.empty());
    EXPECT_EQ(normalized[0], '/');
}

HWTEST_F(PathUtilsTest, ValidateAndNormalizePath_NewFileInNonExistingDir_001, TestSize.Level0)
{
    std::string filePath = "/nonexistent/dir/file.txt";

    std::string normalized;
    auto ret = PathUtils::ValidateAndNormalizePath(filePath, normalized);
    EXPECT_EQ(ret, PATH_VALIDATE_ERROR_REALPATH_FAILED);
}

HWTEST_F(PathUtilsTest, ValidateAndNormalizePath_SlashRoot_001, TestSize.Level0)
{
    std::string filePath = "/newfile_in_root.txt";

    std::string normalized;
    auto ret = PathUtils::ValidateAndNormalizePath(filePath, normalized);
    EXPECT_EQ(ret, PATH_VALIDATE_OK);
    EXPECT_EQ(normalized.substr(0, 1), "/");
}

HWTEST_F(PathUtilsTest, ValidateAndNormalizePath_SymlinkResolved_001, TestSize.Level0)
{
    std::string filePath = subDir_ + "/real.txt";
    FILE* fp = fopen(filePath.c_str(), "w");
    ASSERT_NE(fp, nullptr);
    fclose(fp);

    std::string linkPath = testDir_ + "/link.txt";
    symlink(filePath.c_str(), linkPath.c_str());

    std::string normalized;
    auto ret = PathUtils::ValidateAndNormalizePath(linkPath, normalized);
    EXPECT_EQ(ret, PATH_VALIDATE_OK);
    EXPECT_NE(normalized, linkPath);
    EXPECT_EQ(normalized, filePath);

    unlink(linkPath.c_str());
    unlink(filePath.c_str());
}

HWTEST_F(PathUtilsTest, ValidateAndNormalizePath_ValidAbsolute_001, TestSize.Level0)
{
    std::string normalized;
    auto ret = PathUtils::ValidateAndNormalizePath(testDir_, normalized);
    EXPECT_EQ(ret, PATH_VALIDATE_OK);
    EXPECT_EQ(normalized[0], '/');
}

HWTEST_F(PathUtilsTest, ValidateAndNormalizePath_MultipleTraversal_001, TestSize.Level0)
{
    std::string normalized;
    auto ret = PathUtils::ValidateAndNormalizePath("/a/b/../../../etc", normalized);
    EXPECT_EQ(ret, PATH_VALIDATE_ERROR_TRAVERSAL);
}

HWTEST_F(PathUtilsTest, ValidateAndNormalizePath_TraversalAtStart_001, TestSize.Level0)
{
    std::string normalized;
    auto ret = PathUtils::ValidateAndNormalizePath("/../etc/passwd", normalized);
    EXPECT_EQ(ret, PATH_VALIDATE_ERROR_TRAVERSAL);
}

} // namespace MediaSourceUtils
} // namespace Media
} // namespace OHOS
