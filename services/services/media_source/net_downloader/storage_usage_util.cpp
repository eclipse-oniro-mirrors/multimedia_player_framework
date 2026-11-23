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

#include <sys/statvfs.h>
#include <cstdint>
#include <cinttypes>
#include <cerrno>
#include <limits>

#include "storage_usage_util.h"
#include "common/log.h"

#ifndef MEDIA_LOGI
#define MEDIA_LOGI MEDIA_LOG_I
#endif
#ifndef MEDIA_LOGW
#define MEDIA_LOGW MEDIA_LOG_W
#endif

namespace OHOS {
namespace Media {
namespace MediaDownload {

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SYSTEM_PLAYER, "NetDownloaderStorageUsageUtil"};
constexpr double DOUBLE_TO_INT64_SAFE_MAX = 9.0e15;
constexpr int64_t STORAGE_THRESHOLD_500G = 500LL * 1000 * 1000 * 1000;
constexpr int64_t STORAGE_EXTRA_2G = 2LL * 1000 * 1000 * 1000;
constexpr double STORAGE_PERCENT_THRESHOLD_OVER_500G = 0.05;
constexpr double STORAGE_PERCENT_THRESHOLD = 0.1;
} // namespace

int64_t ComputeStorageFreeSize(struct statvfs &diskInfo)
{
    uint64_t result = static_cast<uint64_t>(diskInfo.f_bsize) * diskInfo.f_bfree;
    if (result > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
        return std::numeric_limits<int64_t>::max();
    }
    return static_cast<int64_t>(result);
}

int64_t ComputeStorageTotalSize(struct statvfs &diskInfo)
{
    uint64_t result = static_cast<uint64_t>(diskInfo.f_bsize) * diskInfo.f_blocks;
    if (result > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
        return std::numeric_limits<int64_t>::max();
    }
    return static_cast<int64_t>(result);
}

bool HasEnoughStorageImpl(int64_t freesize, int64_t totalSize)
{
    MEDIA_LOGI("HasEnoughStorageImpl freesize:%{public}" PRId64 "; totalsize:%{public}" PRId64,
        freesize, totalSize);
    auto safeThreshold = [](int64_t total, double percent) -> int64_t {
        double r = static_cast<double>(total) * percent;
        if (r >= DOUBLE_TO_INT64_SAFE_MAX) {
            return std::numeric_limits<int64_t>::max() - STORAGE_EXTRA_2G;
        }
        return static_cast<int64_t>(r);
    };
    if (totalSize > STORAGE_THRESHOLD_500G) {
        return freesize > (safeThreshold(totalSize, STORAGE_PERCENT_THRESHOLD_OVER_500G) + STORAGE_EXTRA_2G);
    }
    return freesize > (safeThreshold(totalSize, STORAGE_PERCENT_THRESHOLD) + STORAGE_EXTRA_2G);
}

bool HasEnoughStorageForWrite(int fd)
{
    struct statvfs diskInfo;
    int ret = fstatvfs(fd, &diskInfo);
    if (ret != 0) {
        MEDIA_LOGW("fstatvfs failed, skip storage check, errno:%{public}d", errno);
        return true;
    }
    int64_t freesize = ComputeStorageFreeSize(diskInfo);
    int64_t totalSize = ComputeStorageTotalSize(diskInfo);
    return HasEnoughStorageImpl(freesize, totalSize);
}

} // namespace MediaDownload
} // namespace Media
} // namespace OHOS
