#ifndef JWT_STREAM_H
#define JWT_STREAM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdlib.h>

/**
 * Represents a generic reader interface.
 */
typedef struct JwtReader {
    void* impl;
    void (*pfnClose)(void* impl);
    int32_t (*pfnRead)(void* impl, char* buffer, size_t charsToRead,
                       size_t* charsRead);
} JwtReader;

/**
 * @brief Creates a reader which reads from a file.
 * @param reader The reader struct to initialize as a file reader.
 * @param path The path of the file to read from.
 * @return 0 on success, -1 on error.
 */
int32_t jwtReaderCreateForFile(JwtReader* reader, const char* path);

/**
 * @brief Creates a reader which reads from a buffer.
 * @param reader The reader struct to initialize as a buffer reader.
 * @param buffer The buffer to read from.
 * @param length The length of the buffer.
 * @return 0 on success, -1 on error.
 */
int32_t jwtReaderCreateForBuffer(JwtReader* reader, const char* buffer,
                                 size_t length);

/**
 * @brief Closes the given reader. All reads after this call will be invalid.
 * @param The reader to close.
 */
inline void jwtReaderClose(JwtReader* reader) {
    reader->pfnClose(reader->impl);
    reader->impl = nullptr;
    reader->pfnClose = nullptr;
    reader->pfnRead = nullptr;
}

/**
 * @brief Reads bytes from some source into the given buffer.
 * @param reader The source reader to read from.
 * @param buffer The buffer to read into.
 * @param charsToRead The number of characters to attempt to read.
 * @param charsRead A pointer to a variable where the number of chars
 * actually read will be stored.
 * @return 0 on success, -1 on error.
 */
inline int32_t jwtReaderRead(JwtReader reader, char* buffer, size_t charsToRead,
                             size_t* charsRead) {
    return reader.pfnRead(reader.impl, buffer, charsToRead, charsRead);
}

/**
 * @brief Reads bytes from some source into the given buffer.
 * This call ensures all requested bytes are read. If the EOF is reached before
 * that happens, an error is returned.
 * @param reader The source reader to read from.
 * @param buffer The buffer to read into.
 * @param charsToRead The number of characters to attempt to read.
 * @param charsRead A pointer to a variable where the number of chars
 * actually read will be stored.
 * @return 0 on success, -1 on error or EOF.
 */
int32_t jwtReaderReadAll(JwtReader reader, char* buffer, size_t charsToRead,
                         size_t* charsRead);

/**
 * Represents a generic writer interface.
 */
typedef struct JwtWriter {
    void* impl;
    void (*pfnClose)(void* impl);
    int32_t (*pfnWrite)(void* impl, const char* buffer, size_t charsToWrite,
                        size_t* charsWritten);
} JwtWriter;

/**
 * @brief Creates a writer which writes to a file.
 * @param reader The writer struct to initialize as a file writer.
 * @param path The path of the file to write from.
 * @return 0 on success, -1 on error.
 */
int32_t jwtWriterCreateForFile(JwtWriter* writer, const char* path);

/**
 * @brief Creates a writer which writes to a buffer.
 * @param writer The writer struct to initialize as a buffer writer.
 * @param buffer The buffer to write to.
 * @param length The length of the buffer.
 * @return 0 on success, -1 on error.
 */
int32_t jwtWriterCreateForBuffer(JwtWriter* writer, char* buffer,
                                 size_t length);

/**
 * @brief Closes the given reader. All reads after this call will be invalid.
 * @param The reader to close.
 */
inline void jwtWriterClose(JwtWriter* writer) {
    writer->pfnClose(writer->impl);
    writer->impl = nullptr;
    writer->pfnClose = nullptr;
    writer->pfnWrite = nullptr;
}

/**
 * @brief Reads bytes from some source into the given buffer.
 * @param reader The source reader to read from.
 * @param buffer The buffer to read into.
 * @param charsToRead The number of characters to attempt to read.
 * @param charsRead A pointer to a variable where the number of chars
 * actually read will be stored.
 * @return 0 on success, -1 on error.
 */
inline int32_t jwtWriterWrite(JwtWriter writer, const char* buffer,
                              size_t charsToWrite, size_t* charsWritten) {
    return writer.pfnWrite(writer.impl, buffer, charsToWrite, charsWritten);
}

/**
 * @brief Reads bytes from some source into the given buffer.
 * @param reader The source reader to read from.
 * @param buffer The buffer to read into.
 * @param charsToRead The number of characters to attempt to read.
 * @param charsRead A pointer to a variable where the number of chars
 * actually read will be stored.
 * @return 0 on success, -1 on error or end of stream.
 */
int32_t jwtWriterWriteAll(JwtWriter reader, const char* buffer,
                          size_t charsToWrite, size_t* charsWritten);

#ifdef __cplusplus
}
#endif

#endif // JWT_STREAM_H
