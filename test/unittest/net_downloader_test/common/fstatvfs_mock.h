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

#ifndef FSTATVFS_MOCK_H
#define FSTATVFS_MOCK_H

#include <sys/statvfs.h>

namespace OHOS {
namespace Media {
namespace MediaDownload {
namespace MockUtil {

void SetFstatvfsResult(const struct statvfs& info, int ret);
void ResetFstatvfsMock();

class FstatvfsMockGuard {
public:
    FstatvfsMockGuard(const struct statvfs& info, int ret)
    {
        SetFstatvfsResult(info, ret);
    }
    ~FstatvfsMockGuard()
    {
        ResetFstatvfsMock();
    }
};

} // namespace MockUtil
} // namespace MediaDownload
} // namespace Media
} // namespace OHOS

#endif // FSTATVFS_MOCK_H
