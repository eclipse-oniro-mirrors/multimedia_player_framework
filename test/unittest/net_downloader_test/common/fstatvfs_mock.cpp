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

#include "fstatvfs_mock.h"

extern "C" int __real_fstatvfs(int fd, struct statvfs* buf);

namespace {
struct statvfs g_mockInfo;
int g_mockRet = 0;
bool g_mockEnabled = false;
}

extern "C" int __wrap_fstatvfs(int fd, struct statvfs* buf)
{
    if (g_mockEnabled) {
        if (g_mockRet == 0 && buf != nullptr) {
            *buf = g_mockInfo;
        }
        return g_mockRet;
    }
    return __real_fstatvfs(fd, buf);
}

namespace OHOS {
namespace Media {
namespace MediaDownload {
namespace MockUtil {

void SetFstatvfsResult(const struct statvfs& info, int ret)
{
    g_mockInfo = info;
    g_mockRet = ret;
    g_mockEnabled = true;
}

void ResetFstatvfsMock()
{
    g_mockEnabled = false;
    g_mockRet = 0;
}

} // namespace MockUtil
} // namespace MediaDownload
} // namespace Media
} // namespace OHOS
