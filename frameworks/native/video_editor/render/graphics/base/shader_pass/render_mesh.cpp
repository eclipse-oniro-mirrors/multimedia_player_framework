/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "render_mesh.h"

namespace OHOS {
namespace Media {
RenderMesh::RenderMesh(RenderContext* context, const std::vector<std::vector<float>>& meshData)
{
    context_ = context;
    vboIds_ = new GLuint[2];
    meshData_ = meshData;
}

RenderMesh::~RenderMesh()
{
    if (vboIds_ != nullptr) {
        const int32_t ARGS_TWO = 2;
        glDeleteBuffers(ARGS_TWO, vboIds_);
        delete[] vboIds_;
    }
    if (vaoId_) {
        glDeleteVertexArrays(1, &vaoId_);
    }
}

void RenderMesh::Bind(std::shared_ptr<RenderGeneralProgram> shader)
{
    const int32_t ARGS_TWO = 2;
    if (vaoId_ == 0) {
        glGenVertexArrays(1, &vaoId_);
        glBindVertexArray(vaoId_);
        glGenBuffers(ARGS_TWO, vboIds_);
        glBindBuffer(GL_ARRAY_BUFFER, vboIds_[0]);
        glBufferData(GL_ARRAY_BUFFER, sizeof(GLfloat) * meshData_[0].size(), meshData_[0].data(), GL_DYNAMIC_DRAW);
        int position = shader->GetAttributeLocation("aPosition");
        glEnableVertexAttribArray(position);
        glVertexAttribPointer(position, RENDERMESH_VERTEX_SIZE, GL_FLOAT, GL_FALSE,
            sizeof(GLfloat) * RENDERMESH_VERTEX_SIZE, 0);
        glBindBuffer(GL_ARRAY_BUFFER, 0);

        glBindBuffer(GL_ARRAY_BUFFER, vboIds_[1]);
        glBufferData(GL_ARRAY_BUFFER, sizeof(GLfloat) * meshData_[1].size(), meshData_[1].data(), GL_DYNAMIC_DRAW);
        int textureCoord = shader->GetAttributeLocation("aTextureCoord");
        glEnableVertexAttribArray(textureCoord);
        glVertexAttribPointer(textureCoord, RENDERMESH_TEXCOORD_SIZE, GL_FLOAT, GL_FALSE,
            sizeof(GLfloat) * RENDERMESH_TEXCOORD_SIZE, 0);
        glBindBuffer(GL_ARRAY_BUFFER, 0);
        glBindVertexArray(0);
    }
    glBindVertexArray(vaoId_);
}
}
}