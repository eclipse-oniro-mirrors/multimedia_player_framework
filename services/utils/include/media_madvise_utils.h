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

#ifndef MEDIA_UTILS_MADVISE_UTILS
#define MEDIA_UTILS_MADVISE_UTILS

#include <string>
#include <vector>
#include <unordered_set>
#include <limits>
#include <link.h>

namespace OHOS {
namespace Media {
class __attribute__((visibility("default"))) MadviseUtils final {
public:
    MadviseUtils() = delete;
    ~MadviseUtils() = delete;
    static bool MadviseSingleLibrary(const std::string &libName);
    static int32_t MadviseMultipleLibraries(const std::vector<std::string> &libNames);

private:
    static constexpr const char *UNKNOWN_LIB_NAME = "unknown";
    static constexpr int32_t MADVISE_SUCCESS = 0;
    struct SingleLibContext {
        int32_t successCount {0};
        int32_t failCount {0};
        std::string targetLib {};
    };
    struct MultiLibContext {
        int32_t successCount {0};
        int32_t failCount {0};
        std::unordered_set<std::string> targetLibs {};
        std::unordered_set<std::string> processedLibs;
    };
    static constexpr size_t MAX_SAFE_ADDRESS = std::numeric_limits<size_t>::max() / 2;
    static constexpr size_t MAX_SEGMENT_SIZE = 1024 * 1024 * 1024;
    static int32_t PhdrCallbackSingle(struct dl_phdr_info *info, size_t size, void *data);
    static int32_t PhdrCallbackMultiple(struct dl_phdr_info *info, size_t size, void *data);
    static bool ShouldOptimizeSegment(uint32_t phdrFlags);
    static bool ApplyMadviseAligned(void *addr, size_t len);
    static size_t PageSize();
};
} // namespace Media
} // namespace OHOS
#endif // MEDIA_UTILS_MADVISE_UTILS
