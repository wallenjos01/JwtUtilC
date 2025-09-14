/**
 * Josh Wallentine
 * Created 9/12/25
 * Modified 9/14/25
 *
 * Implementation of include/jwt/stream.h
 */

#include <jwt/stream.h>

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

int32_t readFile(void* impl, char* buffer, size_t charsToRead,
                 size_t* charsRead) {

    FileInfo* info = static_cast<FileInfo*>(impl);

    size_t startIndex = info->stream.gcount();
    info->stream.read(buffer, charsToRead);

    if (charsRead) {
        *charsRead = info->stream.gcount() - startIndex;
    }

    return 0;
}

int32_t readBuffer(void* impl, char* buffer, size_t charsToRead,
                   size_t* charsRead) {

    BufferInfo* info = static_cast<BufferInfo*>(impl);
    if (info->index >= info->bufferLength) {
        *charsRead = 0;
        return 0;
    }
    size_t readable = info->bufferLength - info->index;
    size_t toRead = std::min(readable, charsToRead);
    if (toRead == 0) {
        *charsRead = 0;
        return 0;
    }

    memcpy(buffer, info->buffer + info->index, toRead);
    info->index += toRead;

    if (charsRead) {
        *charsRead = toRead;
    }

    return 0;
}

int32_t writeFile(void* impl, const char* buffer, size_t charsToWrite,
                  size_t* charsWritten) {

    FileInfo* info = static_cast<FileInfo*>(impl);

    size_t startIndex = info->stream.gcount();
    info->stream.write(buffer, charsToWrite);

    if (charsWritten) {
        *charsWritten = info->stream.gcount() - startIndex;
    }

    return 0;
}

int32_t writeBuffer(void* impl, const char* buffer, size_t charsToWrite,
                    size_t* charsWritten) {

    BufferInfo* info = static_cast<BufferInfo*>(impl);
    if (info->index >= info->bufferLength) {
        return 0;
    }
    size_t readable = info->bufferLength - info->index;
    size_t toWrite = std::min(readable, charsToWrite);

    memcpy(info->buffer + info->index, buffer, toWrite);
    info->index += toWrite;

    if (charsWritten) {
        *charsWritten = toWrite;
    }

    return 0;
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

}; // namespace

int32_t jwtReaderCreateForFile(JwtReader* reader, const char* path) {

    std::fstream stream = {};
    stream.open(path, std::ios::binary | std::ios::in);
    if (!stream.is_open()) {
        return -1;
    }

    FileInfo* info = new FileInfo();
    info->stream = std::move(stream);

    reader->impl = info;
    reader->pfnRead = readFile;
    reader->pfnClose = closeFile;
    return 0;
}

int32_t jwtReaderCreateForBuffer(JwtReader* reader, const char* buffer,
                                 size_t length) {
    BufferInfo* info = new BufferInfo();
    info->buffer = const_cast<char*>(buffer);
    info->index = 0;
    info->bufferLength = length;
    reader->impl = info;
    reader->pfnRead = readBuffer;
    reader->pfnClose = closeBuffer;
    return 0;
}

int32_t jwtWriterCreateForFile(JwtWriter* writer, const char* path) {

    std::fstream stream = {};
    stream.open(path, std::ios::binary | std::ios::out);
    if (!stream.is_open()) {
        return -1;
    }

    FileInfo* info = new FileInfo();
    info->stream = std::move(stream);

    writer->impl = info;
    writer->pfnWrite = writeFile;
    writer->pfnClose = closeFile;
    return 0;
}

int32_t jwtWriterCreateForBuffer(JwtWriter* writer, char* buffer,
                                 size_t length) {
    BufferInfo* info = new BufferInfo();
    info->buffer = buffer;
    info->index = 0;
    info->bufferLength = length;
    writer->impl = info;
    writer->pfnWrite = writeBuffer;
    writer->pfnClose = closeBuffer;
    return 0;
}

int32_t jwtReaderReadAll(JwtReader reader, char* buffer, size_t charsToRead,
                         size_t* charsRead) {
    size_t totalRead = 0;
    size_t justRead;
    while (totalRead < charsToRead) {
        int32_t result =
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
            return 1;
        }
        totalRead += justRead;
    }

    if (charsRead) {
        *charsRead = totalRead;
    }
    return 0;
}

int32_t jwtWriterWriteAll(JwtWriter writer, const char* buffer,
                          size_t charsToWrite, size_t* charsWritten) {
    size_t totalWritten = 0;
    size_t justWritten;
    while (totalWritten < charsToWrite) {
        int32_t result =
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
            return 1;
        }
        totalWritten += justWritten;
    }

    if (charsWritten) {
        *charsWritten = totalWritten;
    }
    return 0;
}
