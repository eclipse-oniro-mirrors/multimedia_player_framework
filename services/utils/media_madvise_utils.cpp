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

#include <cstring>
#include <mutex>
#include <dlfcn.h>
#include <link.h>
#include <sys/mman.h>
#include <unistd.h>
#include <algorithm>
#include "common/log.h"
#include "media_log.h"
#include "media_madvise_utils.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "MediaMadviseUtils"};
}

namespace OHOS {
namespace Media {
namespace {
std::mutex gDlIteratePhdrMutex_;
} // anonymous namespace

size_t MadviseUtils::PageSize()
{
    static const size_t pageSize = static_cast<size_t>(::getpagesize());
    return pageSize;
}

bool MadviseUtils::ShouldOptimizeSegment(uint32_t flags)
{
    const bool readable = (flags & PF_R) != 0;
    const bool writable = (flags & PF_W) != 0;
    return readable && !writable;
}

bool MadviseUtils::ApplyMadviseAligned(void *addr, size_t len)
{
    if (addr == nullptr || len == 0) {
        return false;
    }
    if (len > MAX_SEGMENT_SIZE) {
        MEDIA_LOG_E("Segment size too large: %{public}zu", len);
        return false;
    }
    const size_t pageSize = PageSize();
    auto start = reinterpret_cast<uintptr_t>(addr);
    auto alignedStart = start & ~(pageSize - 1);
    if (start > MAX_SAFE_ADDRESS - len) {
        MEDIA_LOG_E("Address overflow detected");
        return false;
    }
    auto end = start + len;
    auto alignedEnd = (end + pageSize - 1) & ~(pageSize - 1);
    if (alignedEnd < alignedStart) {
        MEDIA_LOG_E("Aligned end before start");
        return false;
    }
    const size_t alignedLen = alignedEnd - alignedStart;
    if (alignedLen > MAX_SEGMENT_SIZE) {
        MEDIA_LOG_E("Aligned length too large: %{public}zu", alignedLen);
        return false;
    }
    const int32_t ret = ::madvise(reinterpret_cast<void *>(alignedStart), alignedLen, MADV_DONTNEED);
    if (ret == MADVISE_SUCCESS) {
        MEDIA_LOG_I("madvise success: len=%{public}zu", alignedLen);
        return true;
    }
    MEDIA_LOG_E("madvise failed: len=%{public}zu errno=%{public}d", alignedLen, errno);
    return false;
}

int32_t MadviseUtils::PhdrCallbackSingle(struct dl_phdr_info *info, size_t, void *data)
{
    auto *ctx = static_cast<SingleLibContext *>(data);
    CHECK_AND_RETURN_RET_LOG(info != nullptr && ctx != nullptr, 0, "info is nullptr or ctx is nullptr");
    const char *libName = info->dlpi_name;
    if (libName == nullptr || std::strlen(libName) == 0) {
        libName = UNKNOWN_LIB_NAME;
    }
    if (ctx->targetLib.empty() ||
        std::strstr(libName, ctx->targetLib.c_str()) == nullptr) {
        return 0;
    }
    MEDIA_LOG_I("Processing library: %{public}s", libName);
    for (int i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr) &phdr = info->dlpi_phdr[i];
        if (phdr.p_type != PT_LOAD || !ShouldOptimizeSegment(phdr.p_flags)) {
            continue;
        }
        if (phdr.p_memsz == 0 || phdr.p_memsz > MAX_SEGMENT_SIZE) {
            continue;
        }
        if (info->dlpi_addr > MAX_SAFE_ADDRESS - phdr.p_vaddr) {
            MEDIA_LOG_W("Address overflow in segment calculation");
            continue;
        }
        void *segmentAddr = reinterpret_cast<void *>(info->dlpi_addr + phdr.p_vaddr);
        if (ApplyMadviseAligned(segmentAddr, phdr.p_memsz)) {
            ++ctx->successCount;
        } else {
            ++ctx->failCount;
        }
    }
    return 0;
}

bool MadviseUtils::MadviseSingleLibrary(const std::string &libName)
{
    if (libName.empty()) {
        MEDIA_LOG_I("Empty library name");
        return false;
    }
    std::lock_guard<std::mutex> lock(gDlIteratePhdrMutex_);
    SingleLibContext ctx;
    ctx.targetLib.assign(libName);
    ::dl_iterate_phdr(PhdrCallbackSingle, &ctx);
    MEDIA_LOG_I("madvise_single_library done: success=%{public}d fail=%{public}d", ctx.successCount, ctx.failCount);
    return ctx.successCount > 0;
}

int32_t MadviseUtils::PhdrCallbackMultiple(struct dl_phdr_info *info, size_t, void *data)
{
    auto *ctx = static_cast<MultiLibContext *>(data);
    CHECK_AND_RETURN_RET_LOG(info != nullptr && ctx != nullptr, 0, "info is nullptr or ctx is nullptr");
    if (info->dlpi_name == nullptr || std::strlen(info->dlpi_name) == 0) {
        return 0;
    }
    const char *baseName = std::strrchr(info->dlpi_name, '/');
    baseName = (baseName == nullptr) ? info->dlpi_name : baseName + 1;
    std::string baseNameStr(baseName);
    if (ctx->targetLibs.count(baseNameStr) == 0 || ctx->processedLibs.count(baseNameStr) != 0) {
        MEDIA_LOG_I("cannot find lib in targetlibs or processedLibs, basename:%{public}s", baseName);
        return 0;
    }
    ctx->processedLibs.insert(baseNameStr);
    int32_t segmentSuccess = 0;
    for (int i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr) &phdr = info->dlpi_phdr[i];
        if (phdr.p_type != PT_LOAD || !ShouldOptimizeSegment(phdr.p_flags)) {
            MEDIA_LOG_D("skip phdr");
            continue;
        }
        if (phdr.p_memsz == 0 || phdr.p_memsz > MAX_SEGMENT_SIZE) {
            continue;
        }
        if (info->dlpi_addr > MAX_SAFE_ADDRESS - phdr.p_vaddr) {
            MEDIA_LOG_W("Address overflow in segment calculation");
            continue;
        }
        void *segmentAddr = reinterpret_cast<void *>(info->dlpi_addr + phdr.p_vaddr);
        if (ApplyMadviseAligned(segmentAddr, phdr.p_memsz)) {
            ++segmentSuccess;
            MEDIA_LOG_I("madvise %{public}s success", baseName);
        }
    }
    if (segmentSuccess > 0) {
        ++ctx->successCount;
    } else {
        ++ctx->failCount;
    }
    return 0;
}

int32_t MadviseUtils::MadviseMultipleLibraries(const std::vector<std::string> &libNames)
{
    if (libNames.empty()) {
        MEDIA_LOG_E("Library list is empty");
        return 0;
    }
    std::lock_guard<std::mutex> lock(gDlIteratePhdrMutex_);
    MultiLibContext ctx;
    ctx.targetLibs = std::unordered_set<std::string>(libNames.begin(), libNames.end());
    ::dl_iterate_phdr(PhdrCallbackMultiple, &ctx);
    MEDIA_LOG_I("madvise_multiple_libraries done: success=%{public}d fail=%{public}d", ctx.successCount, ctx.failCount);
    return ctx.successCount;
}
} // namespace Media
} // namespace OHOS