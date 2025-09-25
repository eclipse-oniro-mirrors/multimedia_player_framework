/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
 
namespace ANI {
namespace Media {

class FdUtils {
private:
    static constexpr unsigned int HMDFS_IOC = 0xf2;
    static constexpr unsigned int HMDFS_IOC_GET_LOCATION = _IOR(HMDFS_IOC, 7, __u32);
    static constexpr int IOCTL_CLOUD = 2;

public:
    static int32_t ReOpenFd(int32_t fd, FILE *&reopenFile)
    {
        int loc;
        int ioResult = ioctl(fd, HMDFS_IOC_GET_LOCATION, &loc);
        if (ioResult != 0 || loc != IOCTL_CLOUD) {
            std::stringstream ss;
            ss << "/proc/self/fd/" << fd;
            std::string fdPathStr = ss.str();
            reopenFile = fopen(fdPathStr.c_str(), "r");
            return reopenFile ? OHOS::Media::MSERR_OK : OHOS::Media::MSERR_INVALID_VAL;
        }
        return OHOS::Media::MSERR_INVALID_VAL;
    }
};
} // namespace media
} // namespace ANI
#endif // FD_UTILS_H