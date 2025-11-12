/**
 * Josh Wallentine
 * Created 9/12/25
 * Modified 11/12/25
 *
 * Implementation of include/jwt/stream.h
 */

#include <jwt/stream.h>

#include <jwt/core.h>
#include <jwt/result.h>

#include <cstring>
#include <fstream>

namespace {

struct BufferInfo {
    char* buffer;
    size_t index;
    size_t bufferLength;
};

struct FileInfo {
    std::fstream stream;
};

struct ListInfo {

    ListInfo() : 
        list{}, 
        index(0) {

        jwtListCreate(&list, 1);
    }

    JwtList list;
    size_t index;
};

JwtResult readFile(void* impl, char* buffer, size_t charsToRead,
                 size_t* charsRead) {

    FileInfo* info = static_cast<FileInfo*>(impl);

    info->stream.read(buffer, charsToRead);
    if (charsRead) {
        *charsRead = info->stream.gcount();
    }

    return JWT_RESULT_SUCCESS;
}

JwtResult readBuffer(void* impl, char* buffer, size_t charsToRead,
                   size_t* charsRead) {

    BufferInfo* info = static_cast<BufferInfo*>(impl);
    if (info->index >= info->bufferLength) {
        *charsRead = 0;
        return JWT_RESULT_SUCCESS;
    }
    size_t readable = info->bufferLength - info->index;
    size_t toRead = std::min(readable, charsToRead);

    memcpy(buffer, info->buffer + info->index, toRead);
    info->index += toRead;

    if (charsRead) {
        *charsRead = toRead;
    }

    return JWT_RESULT_SUCCESS;
}

JwtResult writeFile(void* impl, const char* buffer, size_t charsToWrite,
                  size_t* charsWritten) {

    FileInfo* info = static_cast<FileInfo*>(impl);

    size_t startIndex = info->stream.gcount();
    info->stream.write(buffer, charsToWrite);

    if (charsWritten) {
        *charsWritten = info->stream.gcount() - startIndex;
    }

    return JWT_RESULT_SUCCESS;
}

JwtResult writeBuffer(void* impl, const char* buffer, size_t charsToWrite,
                    size_t* charsWritten) {

    BufferInfo* info = static_cast<BufferInfo*>(impl);
    if (info->index >= info->bufferLength) {
        return JWT_RESULT_SUCCESS;
    }
    size_t readable = info->bufferLength - info->index;
    size_t toWrite = std::min(readable, charsToWrite);

    memcpy(info->buffer + info->index, buffer, toWrite);
    info->index += toWrite;

    if (charsWritten) {
        *charsWritten = toWrite;
    }

    return JWT_RESULT_SUCCESS;
}

void closeBuffer(void* impl) {
    BufferInfo* info = static_cast<BufferInfo*>(impl);
    delete info;
}

void closeFile(void* impl) {
    FileInfo* info = static_cast<FileInfo*>(impl);
    info->stream.close();
    delete info;
}


JwtResult writeList(void* impl, const char* buffer, size_t charsToWrite, size_t* charsWritten) {

    ListInfo* info = static_cast<ListInfo*>(impl);
    
    void* current = jwtListPushN(&info->list, charsToWrite);
    if(current == nullptr) {
        if(charsWritten) {
            *charsWritten = JWT_RESULT_SUCCESS;
        }
        return JWT_RESULT_MEMORY_ALLOC_FAILED;
    }
    memcpy(current, buffer, charsToWrite);

    if(charsWritten) {
        *charsWritten = charsToWrite;
    }

    return JWT_RESULT_SUCCESS;
}

void closeList(void* impl) {
    ListInfo* info = static_cast<ListInfo*>(impl);
    jwtListDestroy(&info->list);
    delete info;
}

}; // namespace

JwtResult jwtReaderCreateForFile(JwtReader* reader, const char* path) {

    std::fstream stream = {};
    stream.open(path, std::ios::binary | std::ios::in);
    if (!stream.is_open()) {
        return JWT_RESULT_FILE_OPEN_FAILED;
    }

    FileInfo* info = new FileInfo();
    info->stream = std::move(stream);

    reader->impl = info;
    reader->pfnRead = readFile;
    reader->pfnClose = closeFile;
    return JWT_RESULT_SUCCESS;
}

JwtResult jwtReaderCreateForBuffer(JwtReader* reader, const void* buffer,
                                 size_t length) {
    BufferInfo* info = new BufferInfo();
    info->buffer = const_cast<char*>(static_cast<const char*>(buffer));
    info->index = 0;
    info->bufferLength = length;
    reader->impl = info;
    reader->pfnRead = readBuffer;
    reader->pfnClose = closeBuffer;
    return JWT_RESULT_SUCCESS;
}

JwtResult jwtWriterCreateForFile(JwtWriter* writer, const char* path) {

    std::fstream stream = {};
    stream.open(path, std::ios::binary | std::ios::out);
    if (!stream.is_open()) {
        return JWT_RESULT_FILE_OPEN_FAILED;
    }

    FileInfo* info = new FileInfo();
    info->stream = std::move(stream);

    writer->impl = info;
    writer->pfnWrite = writeFile;
    writer->pfnClose = closeFile;
    return JWT_RESULT_SUCCESS;
}

JwtResult jwtWriterCreateForBuffer(JwtWriter* writer, void* buffer,
                                 size_t length) {
    BufferInfo* info = new BufferInfo();
    info->buffer = static_cast<char*>(buffer);
    info->index = 0;
    info->bufferLength = length;
    writer->impl = info;
    writer->pfnWrite = writeBuffer;
    writer->pfnClose = closeBuffer;
    return JWT_RESULT_SUCCESS;
}

JwtResult jwtReaderReadAll(JwtReader reader, char* buffer, size_t charsToRead,
                         size_t* charsRead) {
    size_t totalRead = 0;
    size_t justRead;
    while (totalRead < charsToRead) {
        JwtResult result =
            reader.pfnRead(reader.impl, buffer, charsToRead, &justRead);
        if (result < 0) {
            if (charsRead) {
                *charsRead = totalRead;
            }
            return result;
        }
        if (justRead == 0) {

            if (charsRead) {
                *charsRead = totalRead;
            }
            return JWT_RESULT_EOF;
        }
        totalRead += justRead;
    }

    if (charsRead) {
        *charsRead = totalRead;
    }
    return JWT_RESULT_SUCCESS;
}

JwtResult jwtWriterWriteAll(JwtWriter writer, const char* buffer,
                          size_t charsToWrite, size_t* charsWritten) {
    size_t totalWritten = 0;
    size_t justWritten;
    while (totalWritten < charsToWrite) {
        JwtResult result =
            writer.pfnWrite(writer.impl, buffer, charsToWrite, &justWritten);
        if (result < 0) {
            if (charsWritten) {
                *charsWritten = totalWritten;
            }
            return result;
        }
        if (justWritten == 0) {

            if (charsWritten) {
                *charsWritten = totalWritten;
            }
            return JWT_RESULT_EOF;
        }
        totalWritten += justWritten;
    }

    if (charsWritten) {
        *charsWritten = totalWritten;
    }
    return JWT_RESULT_SUCCESS;
}

JwtResult jwtWriterCreateDynamic(JwtWriter* writer) {
    writer->impl = new ListInfo();
    writer->pfnClose = closeList;
    writer->pfnWrite = writeList;
    return JWT_RESULT_SUCCESS;
}

JwtList* jwtWriterExtractDynamic(JwtWriter* writer) {
    if(writer->pfnWrite != writeList) return nullptr;
    return &static_cast<ListInfo*>(writer->impl)->list;
}
