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

#include "dynamic_module_loader.h"
#include "media_dfx.h"
#include "media_log.h"
#include "media_errors.h"
#include <limits>
#include <cstdlib>

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "DynamicModuleLoader"};
}

namespace OHOS {
namespace Media {

const char *DynamicModuleLoader::ModuleName(DynamicModule module)
{
    switch (module) {
        case DynamicModule::SCREEN_CAPTURE:
            return "screen_capture";
        default:
            return nullptr;
    }
}

DynamicModuleLoader &DynamicModuleLoader::Instance()
{
    static DynamicModuleLoader inst;
    return inst;
}

int32_t __attribute__((no_sanitize("cfi"))) DynamicModuleLoader::DoLoad(DynamicModule module)
{
    MediaTrace trace("DynamicModuleLoader::DoLoad");
    auto it = modules_.find(module);
    if (it != modules_.end() && it->second.loaded) {
        return MSERR_OK;
    }

    const char *name = ModuleName(module);
    CHECK_AND_RETURN_RET_LOG(name != nullptr, MSERR_INVALID_VAL, "unknown module");

    std::string libName = std::string(LIB_PREFIX) + name + LIB_SUFFIX;
    std::string fullPath = std::string(LIB_DIR) + "/" + libName;

    char realPath[PATH_MAX] = {0};
    CHECK_AND_RETURN_RET_LOG(realpath(fullPath.c_str(), realPath) != nullptr, MSERR_OPEN_FILE_FAILED,
        "realpath failed for %{public}s", fullPath.c_str());

    void *handle = dlopen(realPath, RTLD_NOW | RTLD_LOCAL);
    CHECK_AND_RETURN_RET_LOG(handle != nullptr, MSERR_OPEN_FILE_FAILED, "dlopen %{public}s failed: %{public}s",
        realPath, dlerror());

    ModuleInfo info;
    info.handle = handle;
    info.fullPath = realPath;
    info.loaded = true;
    modules_[module] = info;

    MEDIA_LOGI("Module %{public}s loaded from %{public}s", name, realPath);
    return MSERR_OK;
}

void *DynamicModuleLoader::GetFactoryRaw(DynamicModule module, const std::string &symbol)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = modules_.find(module);
    if (it == modules_.end() || !it->second.loaded) {
        CHECK_AND_RETURN_RET_LOG(DoLoad(module) == MSERR_OK, nullptr, "LoadModule %{public}s failed",
            ModuleName(module));
        it = modules_.find(module);
    }
    CHECK_AND_RETURN_RET_LOG(it != modules_.end() && it->second.handle != nullptr, nullptr,
        "module %{public}s not loaded", ModuleName(module));

    void *rawFunc = dlsym(it->second.handle, symbol.c_str());
    CHECK_AND_RETURN_RET_LOG(rawFunc != nullptr, nullptr, "dlsym %{public}s failed in %{public}s: %{public}s",
        symbol.c_str(), ModuleName(module), dlerror());
    return rawFunc;
}

bool DynamicModuleLoader::IsLoaded(DynamicModule module) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = modules_.find(module);
    return it != modules_.end() && it->second.loaded;
}

} // namespace Media
} // namespace OHOS
