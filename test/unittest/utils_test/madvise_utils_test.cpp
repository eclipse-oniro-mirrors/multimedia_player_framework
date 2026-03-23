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

#include <sys/mman.h>
#include <link.h>
#include <cstring>
#include <memory>
#include <cstdlib>
#include "media_log.h"
#include "madvise_utils_test.h"
#include "media_madvise_utils.h"

using namespace testing::ext;
using namespace OHOS::Media;

namespace OHOS {
namespace Media {
void MadviseUtilsTest::SetUpTestCase() {}

void MadviseUtilsTest::TearDownTestCase() {}

void MadviseUtilsTest::SetUp() {}

void MadviseUtilsTest::TearDown() {}

HWTEST_F(MadviseUtilsTest, PageSizeTest_001, TestSize.Level2)
{
    size_t pageSize = MadviseUtils::PageSize();
    EXPECT_GT(pageSize, 0);
    EXPECT_EQ(pageSize % 4096, 0);
}

HWTEST_F(MadviseUtilsTest, ShouldOptimizeSegmentTest_001, TestSize.Level2)
{
    bool result = MadviseUtils::ShouldOptimizeSegment(PF_R);
    EXPECT_TRUE(result);
}

HWTEST_F(MadviseUtilsTest, ShouldOptimizeSegmentTest_002, TestSize.Level2)
{
    bool result = MadviseUtils::ShouldOptimizeSegment(PF_R | PF_X);
    EXPECT_TRUE(result);
}

HWTEST_F(MadviseUtilsTest, ShouldOptimizeSegmentTest_003, TestSize.Level2)
{
    bool result = MadviseUtils::ShouldOptimizeSegment(PF_R | PF_W);
    EXPECT_FALSE(result);
}

HWTEST_F(MadviseUtilsTest, ShouldOptimizeSegmentTest_004, TestSize.Level2)
{
    bool result = MadviseUtils::ShouldOptimizeSegment(PF_W);
    EXPECT_FALSE(result);
}

HWTEST_F(MadviseUtilsTest, ShouldOptimizeSegmentTest_005, TestSize.Level2)
{
    bool result = MadviseUtils::ShouldOptimizeSegment(PF_X);
    EXPECT_FALSE(result);
}

HWTEST_F(MadviseUtilsTest, ShouldOptimizeSegmentTest_006, TestSize.Level2)
{
    bool result = MadviseUtils::ShouldOptimizeSegment(PF_R | PF_W | PF_X);
    EXPECT_FALSE(result);
}

HWTEST_F(MadviseUtilsTest, ShouldOptimizeSegmentTest_007, TestSize.Level2)
{
    bool result = MadviseUtils::ShouldOptimizeSegment(0);
    EXPECT_FALSE(result);
}

HWTEST_F(MadviseUtilsTest, ApplyMadviseAlignedTest_001, TestSize.Level2)
{
    bool result = MadviseUtils::ApplyMadviseAligned(nullptr, 4096);
    EXPECT_FALSE(result);
}

HWTEST_F(MadviseUtilsTest, ApplyMadviseAlignedTest_002, TestSize.Level2)
{
    void *addr = malloc(4096);
    ASSERT_NE(addr, nullptr);
    bool result = MadviseUtils::ApplyMadviseAligned(addr, 0);
    EXPECT_FALSE(result);
    free(addr);
}

HWTEST_F(MadviseUtilsTest, ApplyMadviseAlignedTest_003, TestSize.Level2)
{
    void *addr = malloc(4096);
    ASSERT_NE(addr, nullptr);
    bool result = MadviseUtils::ApplyMadviseAligned(addr, 4096);
    EXPECT_TRUE(result);
    free(addr);
}

HWTEST_F(MadviseUtilsTest, ApplyMadviseAlignedTest_004, TestSize.Level2)
{
    void *addr = malloc(8192);
    ASSERT_NE(addr, nullptr);
    bool result = MadviseUtils::ApplyMadviseAligned(addr, 8192);
    EXPECT_TRUE(result);
    free(addr);
}

HWTEST_F(MadviseUtilsTest, ApplyMadviseAlignedTest_005, TestSize.Level2)
{
    void *addr = malloc(8192);
    ASSERT_NE(addr, nullptr);
    uintptr_t alignedAddr = reinterpret_cast<uintptr_t>(addr);
    alignedAddr = (alignedAddr + 4095) & ~4095ULL;
    bool result = MadviseUtils::ApplyMadviseAligned(reinterpret_cast<void*>(alignedAddr), 4096);
    EXPECT_TRUE(result);
    free(addr);
}

HWTEST_F(MadviseUtilsTest, ApplyMadviseAlignedTest_006, TestSize.Level2)
{
    void *ra = mmap(nullptr, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT_NE(ra, MAP_FAILED);
    bool result = MadviseUtils::ApplyMadviseAligned(ra, 4096);
    EXPECT_TRUE(result);
    munmap(ra, 4096);
}

HWTEST_F(MadviseUtilsTest, ApplyMadviseAlignedTest_007, TestSize.Level2)
{
    void *ra = mmap(nullptr, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT_NE(ra, MAP_FAILED);
    bool result = MadviseUtils::ApplyMadviseAligned(ra, 4096);
    EXPECT_TRUE(result);
    munmap(ra, 8192);
}

HWTEST_F(MadviseUtilsTest, PhdrCallbackSingleTest_001, TestSize.Level2)
{
    std::string targetLib = "libmedia.so";
    MadviseUtils::SingleLibContext ctx;
    ctx.targetLib = targetLib;
    ctx.successCount = 0;
    ctx.failCount = 0;

    dl_phdr_info info;
    info.dlpi_name = nullptr;
    info.dlpi_addr = 0;
    info.dlpi_phdr = nullptr;
    info.dlpi_phnum = 0;

    int32_t result = MadviseUtils::PhdrCallbackSingle(&info, 0, &ctx);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(ctx.successCount, 0);
    EXPECT_EQ(ctx.failCount, 0);
}

HWTEST_F(MadviseUtilsTest, PhdrCallbackSingleTest_002, TestSize.Level2)
{
    std::string targetLib = "libmedia.so";
    MadviseUtils::SingleLibContext ctx;
    ctx.targetLib = targetLib;
    ctx.successCount = 0;
    ctx.failCount = 0;

    dl_phdr_info info;
    info.dlpi_name = "";
    info.dlpi_addr = 0;
    info.dlpi_phdr = nullptr;
    info.dlpi_phnum = 0;

    int32_t result = MadviseUtils::PhdrCallbackSingle(&info, 0, &ctx);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(ctx.successCount, 0);
    EXPECT_EQ(ctx.failCount, 0);
}

HWTEST_F(MadviseUtilsTest, PhdrCallbackSingleTest_003, TestSize.Level2)
{
    std::string targetLib = "libmedia.so";
    MadviseUtils::SingleLibContext ctx;
    ctx.targetLib = targetLib;
    ctx.successCount = 0;
    ctx.failCount = 0;

    dl_phdr_info info;
    info.dlpi_name = "libtest.so";
    info.dlpi_addr = 0;
    info.dlpi_phdr = nullptr;
    info.dlpi_phnum = 0;

    int32_t result = MadviseUtils::PhdrCallbackSingle(&info, 0, &ctx);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(ctx.successCount, 0);
    EXPECT_EQ(ctx.failCount, 0);
}

HWTEST_F(MadviseUtilsTest, PhdrCallbackSingleTest_004, TestSize.Level2)
{
    std::string targetLib = "libmedia";
    MadviseUtils::SingleLibContext ctx;
    ctx.targetLib = targetLib;
    ctx.successCount = 0;
    ctx.failCount = 0;

    dl_phdr_info info;
    info.dlpi_name = "libmedia.so.6";
    info.dlpi_addr = 0;
    info.dlpi_phdr = nullptr;
    info.dlpi_phnum = 0;

    int32_t result = MadviseUtils::PhdrCallbackSingle(&info, 0, &ctx);
    EXPECT_EQ(result, 0);
}

HWTEST_F(MadviseUtilsTest, PhdrCallbackSingleTest_005, TestSize.Level2)
{
    std::string target = "test";
    MadviseUtils::SingleLibContext ctx;
    ctx.targetLib = target;
    ctx.successCount = 0;
    ctx.failCount = 0;

    dl_phdr_info info;
    info.dlpi_name = "test";
    info.dlpi_addr = 0x1000;
    
    ElfW(Phdr) phdr[2];
    phdr[0].p_type = PT_DYNAMIC;
    phdr[0].p_flags = PF_R;
    phdr[0].p_vaddr = 0;
    phdr[0].p_memsz = 4096;
    
    phdr[1].p_type = PT_LOAD;
    phdr[1].p_flags = PF_R | PF_W;
    phdr[1].p_vaddr = 0x1000;
    phdr[1].p_memsz = 4096;
    
    info.dlpi_phdr = phdr;
    info.dlpi_phnum = 2;

    int32_t result = MadviseUtils::PhdrCallbackSingle(&info, 0, &ctx);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(ctx.successCount, 0);
    EXPECT_EQ(ctx.failCount, 0);
}

HWTEST_F(MadviseUtilsTest, PhdrCallbackSingleTest_006, TestSize.Level2)
{
    std::string target = "test";
    MadviseUtils::SingleLibContext ctx;
    ctx.targetLib = target;
    ctx.successCount = 0;
    ctx.failCount = 0;

    dl_phdr_info info;
    info.dlpi_name = "test";
    info.dlpi_addr = 0x1000;
    
    ElfW(Phdr) phdr[1];
    phdr[0].p_type = PT_LOAD;
    phdr[0].p_flags = PF_R;
    phdr[0].p_vaddr = 0;
    phdr[0].p_memsz = 4096;
    
    info.dlpi_phdr = phdr;
    info.dlpi_phnum = 1;

    int32_t result = MadviseUtils::PhdrCallbackSingle(&info, 0, &ctx);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(ctx.successCount, 0);
}

HWTEST_F(MadviseUtilsTest, PhdrCallbackSingleTest_007, TestSize.Level2)
{
    std::string target = "test";
    MadviseUtils::SingleLibContext ctx;
    ctx.targetLib = target;
    ctx.successCount = 0;
    ctx.failCount = 0;

    dl_phdr_info info;
    info.dlpi_name = "test";
    info.dlpi_addr = 0x1000;
    
    ElfW(Phdr) phdr[2];
    phdr[0].p_type = PT_LOAD;
    phdr[0].p_flags = PF_R;
    phdr[0].p_vaddr = 0;
    phdr[0].p_memsz = 4096;
    
    phdr[1].p_type = PT_LOAD;
    phdr[1].p_flags = PF_R | PF_X;
    phdr[1].p_vaddr = 0x2000;
    phdr[1].p_memsz = 4096;
    
    info.dlpi_phdr = phdr;
    info.dlpi_phnum = 2;

    int32_t result = MadviseUtils::PhdrCallbackSingle(&info, 0, &ctx);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(ctx.successCount, 0);
}

HWTEST_F(MadviseUtilsTest, MadviseSingleLibraryTest_001, TestSize.Level2)
{
    bool result = MadviseUtils::MadviseSingleLibrary("");
    EXPECT_FALSE(result);
}

HWTEST_F(MadviseUtilsTest, MadviseSingleLibraryTest_002, TestSize.Level2)
{
    bool result = MadviseUtils::MadviseSingleLibrary("libmeida_noExistent.so");
    EXPECT_FALSE(result);
}

HWTEST_F(MadviseUtilsTest, MadviseSingleLibraryTest_003, TestSize.Level2)
{
    bool result = MadviseUtils::MadviseSingleLibrary("libmedia");
    EXPECT_TRUE(result);
}

HWTEST_F(MadviseUtilsTest, PhdrCallbackMultipleTest_001, TestSize.Level2)
{
    std::unordered_set<std::string> targetLibs = {"libmedia.so"};
    std::unordered_set<std::string> processedLibs;
    MadviseUtils::MultiLibContext ctx;
    ctx.targetLibs = targetLibs;
    ctx.successCount = 0;
    ctx.failCount = 0;
    ctx.processedLibs = processedLibs;

    dl_phdr_info info;
    info.dlpi_name = nullptr;
    info.dlpi_addr = 0;
    info.dlpi_phdr = nullptr;
    info.dlpi_phnum = 0;

    int32_t result = MadviseUtils::PhdrCallbackMultiple(&info, 0, &ctx);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(ctx.successCount, 0);
    EXPECT_EQ(ctx.failCount, 0);
}

HWTEST_F(MadviseUtilsTest, PhdrCallbackMultipleTest_002, TestSize.Level2)
{
    std::unordered_set<std::string> targetLibs = {"libmedia.so"};
    std::unordered_set<std::string> processedLibs;
    MadviseUtils::MultiLibContext ctx;
    ctx.targetLibs = targetLibs;
    ctx.successCount = 0;
    ctx.failCount = 0;
    ctx.processedLibs = processedLibs;

    dl_phdr_info info;
    info.dlpi_name = "";
    info.dlpi_addr = 0;
    info.dlpi_phdr = nullptr;
    info.dlpi_phnum = 0;

    int32_t result = MadviseUtils::PhdrCallbackMultiple(&info, 0, &ctx);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(ctx.successCount, 0);
    EXPECT_EQ(ctx.failCount, 0);
}

HWTEST_F(MadviseUtilsTest, PhdrCallbackMultipleTest_003, TestSize.Level2)
{
    std::unordered_set<std::string> targetLibs = {"libmedia.so"};
    std::unordered_set<std::string> processedLibs;
    MadviseUtils::MultiLibContext ctx;
    ctx.targetLibs = targetLibs;
    ctx.successCount = 0;
    ctx.failCount = 0;
    ctx.processedLibs = processedLibs;

    dl_phdr_info info;
    info.dlpi_name = "libtest.so";
    info.dlpi_addr = 0;
    info.dlpi_phdr = nullptr;
    info.dlpi_phnum = 0;

    int32_t result = MadviseUtils::PhdrCallbackMultiple(&info, 0, &ctx);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(ctx.successCount, 0);
    EXPECT_EQ(ctx.failCount, 0);
}

HWTEST_F(MadviseUtilsTest, PhdrCallbackMultipleTest_004, TestSize.Level2)
{
    std::unordered_set<std::string> targetLibs = {"libmedia.so"};
    std::unordered_set<std::string> processedLibs = {"libmedia.so"};
    MadviseUtils::MultiLibContext ctx;
    ctx.targetLibs = targetLibs;
    ctx.successCount = 0;
    ctx.failCount = 0;
    ctx.processedLibs = processedLibs;

    dl_phdr_info info;
    info.dlpi_name = "/usr/lib/libmedia.so";
    info.dlpi_addr = 0;
    info.dlpi_phdr = nullptr;
    info.dlpi_phnum = 0;

    int32_t result = MadviseUtils::PhdrCallbackMultiple(&info, 0, &ctx);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(ctx.successCount, 0);
    EXPECT_EQ(ctx.failCount, 0);
}

HWTEST_F(MadviseUtilsTest, PhdrCallbackMultipleTest_005, TestSize.Level2)
{
    std::unordered_set<std::string> targetLibs = {"libmedia.so"};
    std::unordered_set<std::string> processedLibs;
    MadviseUtils::MultiLibContext ctx;
    ctx.targetLibs = targetLibs;
    ctx.successCount = 0;
    ctx.failCount = 0;
    ctx.processedLibs = processedLibs;

    dl_phdr_info info;
    info.dlpi_name = "libmedia.so";
    info.dlpi_addr = 0x1000;
    
    ElfW(Phdr) phdr[1];
    phdr[0].p_type = PT_LOAD;
    phdr[0].p_flags = PF_R | PF_W;
    phdr[0].p_vaddr = 0;
    phdr[0].p_memsz = 4096;
    
    info.dlpi_phdr = phdr;
    info.dlpi_phnum = 1;

    int32_t result = MadviseUtils::PhdrCallbackMultiple(&info, 0, &ctx);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(ctx.successCount, 0);
    EXPECT_GT(ctx.failCount, 0);
}

HWTEST_F(MadviseUtilsTest, PhdrCallbackMultipleTest_006, TestSize.Level2)
{
    std::unordered_set<std::string> targetLibs = {"libmedia_service.z.so"};
    std::unordered_set<std::string> processedLibs;
    MadviseUtils::MultiLibContext ctx;
    ctx.targetLibs = targetLibs;
    ctx.successCount = 0;
    ctx.failCount = 0;
    ctx.processedLibs = processedLibs;

    dl_phdr_info info;
    info.dlpi_name = "/system/lib64/libmedia_service.z.so";
    info.dlpi_addr = 0x1000;
    
    ElfW(Phdr) phdr[1];
    phdr[0].p_type = PT_LOAD;
    phdr[0].p_flags = PF_R;
    phdr[0].p_vaddr = 0;
    phdr[0].p_memsz = 4096;
    
    info.dlpi_phdr = phdr;
    info.dlpi_phnum = 1;

    int32_t result = MadviseUtils::PhdrCallbackMultiple(&info, 0, &ctx);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(ctx.successCount, 0);
    EXPECT_GT(ctx.failCount, 0);
}

HWTEST_F(MadviseUtilsTest, PhdrCallbackMultipleTest_007, TestSize.Level2)
{
    std::unordered_set<std::string> targetLibs = {"libmedia_service.z.so"};
    std::unordered_set<std::string> processedLibs;
    MadviseUtils::MultiLibContext ctx;
    ctx.targetLibs = targetLibs;
    ctx.successCount = 0;
    ctx.failCount = 0;
    ctx.processedLibs = processedLibs;

    dl_phdr_info info;
    info.dlpi_name = "libmedia_service.z.so";
    info.dlpi_addr = 0x1000;
    
    ElfW(Phdr) phdr[1];
    phdr[0].p_type = PT_LOAD;
    phdr[0].p_flags = PF_R | PF_W;
    phdr[0].p_vaddr = 0;
    phdr[0].p_memsz = 4096;
    
    info.dlpi_phdr = phdr;
    info.dlpi_phnum = 1;

    int32_t result = MadviseUtils::PhdrCallbackMultiple(&info, 0, &ctx);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(ctx.successCount, 0);
    EXPECT_GT(ctx.failCount, 0);
}

HWTEST_F(MadviseUtilsTest, PhdrCallbackMultipleTest_008, TestSize.Level2)
{
    std::unordered_set<std::string> targetLibs = {"libmedia_service.z.so"};
    std::unordered_set<std::string> processedLibs;
    MadviseUtils::MultiLibContext ctx;
    ctx.targetLibs = targetLibs;
    ctx.successCount = 0;
    ctx.failCount = 0;
    ctx.processedLibs = processedLibs;

    dl_phdr_info info;
    info.dlpi_name = "libmedia_service.z.so";
    info.dlpi_addr = 0x1000;
    
    ElfW(Phdr) phdr[2];
    phdr[0].p_type = PT_LOAD;
    phdr[0].p_flags = PF_R;
    phdr[0].p_vaddr = 0;
    phdr[0].p_memsz = 4096;
    
    phdr[1].p_type = PT_LOAD;
    phdr[1].p_flags = PF_R | PF_X;
    phdr[1].p_vaddr = 0x2000;
    phdr[1].p_memsz = 4096;
    
    info.dlpi_phdr = phdr;
    info.dlpi_phnum = 2;

    int32_t result = MadviseUtils::PhdrCallbackMultiple(&info, 0, &ctx);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(ctx.successCount, 0);
    EXPECT_GT(ctx.failCount, 0);
}

HWTEST_F(MadviseUtilsTest, PhdrCallbackMultipleTest_009, TestSize.Level2)
{
    std::unordered_set<std::string> targetLibs = {"libmedia.so"};
    std::unordered_set<std::string> processedLibs;
    MadviseUtils::MultiLibContext ctx;
    ctx.targetLibs = targetLibs;
    ctx.successCount = 0;
    ctx.failCount = 0;
    ctx.processedLibs = processedLibs;

    dl_phdr_info info;
    info.dlpi_name = "libmedia.so";
    info.dlpi_addr = 0x1000;
    
    ElfW(Phdr) phdr[2];
    phdr[0].p_type = PT_DYNAMIC;
    phdr[0].p_flags = PF_R;
    phdr[0].p_vaddr = 0;
    phdr[0].p_memsz = 4096;
    
    phdr[1].p_type = PT_NOTE;
    phdr[1].p_flags = PF_R;
    phdr[1].p_vaddr = 0x1000;
    phdr[1].p_memsz = 4096;
    
    info.dlpi_phdr = phdr;
    info.dlpi_phnum = 2;

    int32_t result = MadviseUtils::PhdrCallbackMultiple(&info, 0, &ctx);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(ctx.successCount, 0);
    EXPECT_GT(ctx.failCount, 0);
}

HWTEST_F(MadviseUtilsTest, MadviseMultipleLibrariesTest_001, TestSize.Level2)
{
    std::vector<std::string> libNames;
    int32_t result = MadviseUtils::MadviseMultipleLibraries(libNames);
    EXPECT_EQ(result, 0);
}

HWTEST_F(MadviseUtilsTest, MadviseMultipleLibrariesTest_002, TestSize.Level2)
{
    std::vector<std::string> libNames = {"libmeida_noExistent.so"};
    int32_t result = MadviseUtils::MadviseMultipleLibraries(libNames);
    EXPECT_EQ(result, 0);
}

HWTEST_F(MadviseUtilsTest, MadviseMultipleLibrariesTest_003, TestSize.Level2)
{
    std::vector<std::string> libNames = {"libmedia.so"};
    int32_t result = MadviseUtils::MadviseMultipleLibraries(libNames);
    EXPECT_GE(result, 0);
}

HWTEST_F(MadviseUtilsTest, MadviseMultipleLibrariesTest_004, TestSize.Level2)
{
    std::vector<std::string> libNames = {"libmedia.so", "libm.so", "libpthread.so"};
    int32_t result = MadviseUtils::MadviseMultipleLibraries(libNames);
    EXPECT_GE(result, 0);
}

HWTEST_F(MadviseUtilsTest, MadviseMultipleLibrariesTest_005, TestSize.Level2)
{
    std::vector<std::string> libNames = {"libmedia.so", "libmedia.so"};
    int32_t result = MadviseUtils::MadviseMultipleLibraries(libNames);
    EXPECT_GE(result, 0);
}

HWTEST_F(MadviseUtilsTest, IntegrationTest_001, TestSize.Level2)
{
    bool result1 = MadviseUtils::MadviseSingleLibrary("libmedia");
    bool result2 = MadviseUtils::MadviseSingleLibrary("libmedia");
    EXPECT_TRUE(result1);
    EXPECT_TRUE(result2);
}

HWTEST_F(MadviseUtilsTest, IntegrationTest_002, TestSize.Level2)
{
    std::vector<std::string> libNames = {"libmedia.so"};
    int32_t result1 = MadviseUtils::MadviseMultipleLibraries(libNames);
    int32_t result2 = MadviseUtils::MadviseMultipleLibraries(libNames);
    EXPECT_GE(result1, 0);
    EXPECT_GE(result2, 0);
}
} // namespace Media
} // namespace OHOS