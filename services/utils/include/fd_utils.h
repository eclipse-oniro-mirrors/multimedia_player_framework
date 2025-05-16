/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef FD_UTILS_H
#define FD_UTILS_H
 
#include <sstream>
#include <sys/ioctl.h>
#include "common/fdsan_fd.h"
 
namespace OHOS {
namespace Media {

class FdUtils {
public:
    // This method is prohibited from being used on the server side.
    static FdsanFd ReOpenFd(int32_t fd)
    {
#ifdef __linux__
        int loc;
        int ioResult = ioctl(fd, HMDFS_IOC_GET_LOCATION, &loc);
        if (ioResult != 0 && loc != IOCTL_CLOUD) {
            std::stringstream ss;
            ss << "/proc/self/fd/" << fd;
            std::string fdPathStr = ss.str();
            char realPath[PATH_MAX_REAL];
            ssize_t result = readlink(fdPathStr.c_str(), realPath, sizeof(realPath));
            if (result == RESULT_ERROR) {
                MEDIA_LOGW("invailed fd: %{public}d, error: %{public}s", fd, std::strerror(errno));
                return FdsanFd();
            }
            auto newFd = open(fdPathStr.c_str(), O_RDONLY);
            if (newFd < 0) {
                MEDIA_LOGW("invailed fd: %{public}d, error: %{public}s", fd, std::strerror(errno));
                return FdsanFd();
            }
            return FdsanFd(newFd);
        }
#endif
        return FdsanFd();
    }

private:
    // The HMDFS I/O control code
    static constexpr unsigned int HMDFS_IOC = 0xf2;
    // The I/O control code for retrieving the HMDFS location
    static constexpr unsigned int HMDFS_IOC_GET_LOCATION = _IOR(HMDFS_IOC, 7, __u32);
    // The I/O control code for cloud operations
    static constexpr int IOCTL_CLOUD = 2;
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "FdUtils"};
    static constexpr ssize_t RESULT_ERROR = -1;
    static constexpr int PATH_MAX_REAL = PATH_MAX + 1;
};
} // namespace media
} // namespace OHOS
#endif // FD_UTILS_H