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

#ifndef STORAGE_USAGE_UTIL_H
#define STORAGE_USAGE_UTIL_H

#include <cstdint>
#include <sys/statvfs.h>

namespace OHOS {
namespace Media {
namespace MediaDownload {

int64_t ComputeStorageFreeSize(struct statvfs &diskInfo);
int64_t ComputeStorageTotalSize(struct statvfs &diskInfo);
bool HasEnoughStorageImpl(int64_t freesize, int64_t totalSize);
bool HasEnoughStorageForWrite(int fd);

} // namespace MediaDownload
} // namespace Media
} // namespace OHOS

#endif // STORAGE_USAGE_UTIL_H
