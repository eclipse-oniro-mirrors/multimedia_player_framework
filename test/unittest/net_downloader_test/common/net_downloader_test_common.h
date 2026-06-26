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

#ifndef NET_DOWNLOADER_TEST_COMMON_H
#define NET_DOWNLOADER_TEST_COMMON_H

#include <string>
#include <memory>
#include <iostream>
#include <vector>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>

namespace OHOS {
namespace Media {
namespace MediaDownload {

class NetDownloaderTestCommon {
public:
    static std::string GetTestCacheDir(const std::string &subDir)
    {
        char tmpDir[] = "/data/test/net_downloader_test_XXXXXX";
        char *dir = mkdtemp(tmpDir);
        if (dir == nullptr) {
            return "";
        }
        std::string testDir = std::string(dir) + "/" + subDir;
        mkdir(testDir.c_str(), S_IRWXU);
        return testDir;
    }

    static void SetupTestDirectory(const std::string &dir)
    {
        mkdir(dir.c_str(), S_IRWXU);
    }

    static void CleanupTestDirectory(const std::string &dir)
    {
        if (dir.empty()) {
            return;
        }
        std::string cmd = "rm -rf " + dir;
        (void)system(cmd.c_str());
    }

    static bool CreateTestFile(const std::string &path, const std::vector<uint8_t> &content)
    {
        FILE *fp = fopen(path.c_str(), "wb");
        if (fp == nullptr) {
            return false;
        }
        if (!content.empty()) {
            fwrite(content.data(), 1, content.size(), fp);
        }
        fclose(fp);
        return true;
    }

    static bool FileExists(const std::string &path)
    {
        struct stat st;
        return stat(path.c_str(), &st) == 0;
    }

    static int64_t GetFileSize(const std::string &path)
    {
        struct stat st;
        if (stat(path.c_str(), &st) == 0) {
            return st.st_size;
        }
        return -1;
    }
};

using TestCommon = NetDownloaderTestCommon;

} // namespace MediaDownload
} // namespace Media
} // namespace OHOS

#endif // NET_DOWNLOADER_TEST_COMMON_H