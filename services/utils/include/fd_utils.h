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
#ifdef __linux__
#include <sys/xattr.h>
#endif

namespace OHOS {
namespace Media {

#ifdef __linux__
namespace {
constexpr size_t MAX_ATTR_NAME = 64;
const std::string CLOUD_LOCATION_ATTR = "user.cloud.location";
}
#endif

class FdUtils {
public:
    // This method is prohibited from being used on the server side.
    static FdsanFd ReOpenFd(int32_t fd)
    {
#ifdef __linux__
        if (LocalFd(fd)) {
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
        MEDIA_LOGW("=== fd is cloud");
        return FdsanFd();
    }

#if __linux__
    static bool LocalFd(int32_t fd)
    {
        char value[MAX_ATTR_NAME + 1] = {0};
        ssize_t size = fgetxattr(fd, CLOUD_LOCATION_ATTR.c_str(), value, MAX_ATTR_NAME);
        int32_t defaultLocation = INVALID;
        if (size <= 0) {
            MEDIA_LOGW("Getxattr value failed, errno is %{public}s", std::strerror(errno));
            return false;
        }
        value[size] = '\0';
        std::string location(value);
        MEDIA_LOGD("Getxattr value, location is %{public}s", location.c_str());

        if (!std::all_of(location.begin(), location.end(), ::isdigit)) {
            return false;
        }
        int fileLocation = atoi(location.c_str());
        return fileLocation == LOCAL;
    }
#endif

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
    static constexpr int32_t LOCAL = 1;
};
} // namespace Media
} // namespace OHOS
#endif // FD_UTILS_H