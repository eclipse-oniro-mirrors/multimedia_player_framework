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

#ifndef MEDIA_SOURCE_FD_SAN_H
#define MEDIA_SOURCE_FD_SAN_H

#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <cstdint>

namespace OHOS {
namespace Media {
namespace MediaSource {

inline constexpr uint32_t FDSAN_TAG_ID_DOWNLOADED_CACHE = 19;
inline constexpr uint32_t FDSAN_TAG_ID_NET_DOWNLOADER = 20;
inline constexpr uint64_t FDSAN_TAG_DOWNLOADED_CACHE = (0xD002B23ULL << 32) | FDSAN_TAG_ID_DOWNLOADED_CACHE;
inline constexpr uint64_t FDSAN_TAG_NET_DOWNLOADER = (0xD002B23ULL << 32) | FDSAN_TAG_ID_NET_DOWNLOADER;

template <uint64_t FdsanTag>
inline int FdSanOpen(const char *path, int flags)
{
    int fd = open(path, flags);
    if (fd == -1) {
        return -1;
    }
    fdsan_exchange_owner_tag(fd, 0, FdsanTag);
    return fd;
}

template <uint64_t FdsanTag>
inline int FdSanOpen(const char *path, int flags, mode_t mode)
{
    int fd = open(path, flags, mode);
    if (fd == -1) {
        return -1;
    }
    fdsan_exchange_owner_tag(fd, 0, FdsanTag);
    return fd;
}

template <uint64_t FdsanTag>
inline void FdSanClose(int fd)
{
    if (fd < 0) {
        return;
    }
    fdsan_close_with_tag(fd, FdsanTag);
}

} // namespace MediaSource
} // namespace Media
} // namespace OHOS

#endif // MEDIA_SOURCE_FD_SAN_H
