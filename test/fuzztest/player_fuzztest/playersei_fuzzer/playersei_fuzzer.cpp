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

#include "playersei_fuzzer.h"
#include <unistd.h>
#include <fcntl.h>
#include "fuzzer/FuzzedDataProvider.h"
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <fstream>

using namespace std;
using namespace OHOS;
using namespace OHOS::Media;

namespace OHOS {
namespace Media {
const char *DATA_PATH = "/data/test/fuzz_create.mp4";
const std::string TYPE_HEVC = "video/hevc";

PlayerSeiFuzzer::PlayerSeiFuzzer()
{
}

PlayerSeiFuzzer::~PlayerSeiFuzzer()
{
}

std::shared_ptr<AVBuffer> ReadAVBufferFromLocalFile()
{
    std::ifstream inputFile(DATA_PATH, std::ios::binary);
    if (!inputFile.is_open()) {
        return nullptr;
    }
    inputFile.seekg(0, std::ios::end);
    std::streampos fileSize = inputFile.tellg();

    inputFile.seekg(0, std::ios::beg);

    AVBufferConfig config;
    config.size = fileSize;
    config.memoryType = MemoryType::VIRTUAL_MEMORY;
    auto avBuffer = AVBuffer::CreateAVBuffer(config);
    if (avBuffer == nullptr || avBuffer->memory_ == nullptr || avBuffer->memory_->GetAddr() == nullptr) {
        return nullptr;
    }
    inputFile.read(reinterpret_cast<char *>(avBuffer->memory_->GetAddr()), fileSize);
    avBuffer->memory_->SetSize(fileSize);
    return avBuffer;
}

bool PlayerSeiFuzzer::RunFuzz(uint8_t *data, size_t size)
{
    int32_t fd = open(DATA_PATH, O_RDONLY);
    std::shared_ptr<SeiParserHelper> seiParserHelper = SeiParserHelperFactory::CreateHelper(TYPE_HEVC);
    if (seiParserHelper == nullptr) {
        return false;
    }

    auto buffer = ReadAVBufferFromLocalFile();

    FuzzedDataProvider fdp(data, size);
    seiParserHelper->SetPayloadTypeVec({ 5 });
    std::shared_ptr<SeiPayloadInfoGroup> group = std::make_shared<SeiPayloadInfoGroup>();
    seiParserHelper->ParseSeiPayload(buffer, group);
    close(fd);
    return true;
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    if (size < sizeof(int64_t)) {
        return false;
    }
    int32_t fd = open(DATA_PATH, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        return false;
    }
    int len = write(fd, data, size);
    if (len <= 0) {
        close(fd);
        return false;
    }
    close(fd);
    PlayerSeiFuzzer player;
    player.RunFuzz(data, size);
    unlink(DATA_PATH);
    return 0;
}

