#ifndef JWT_STREAM_H
#define JWT_STREAM_H

#include "jwt/core.h"
#include "jwt/result.h"
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdlib.h>

/**
 * Represents a generic reader interface.
 */
typedef struct JwtReader {
    /**
     * @brief Some reader implementation
     */
    void* impl;
    /**
     * @brief A pointer to a function which closes the given reader
     * implementation.
     * @param impl The reader implementation to close.
     * Any reads after this is called are invalid.
     */
    void (*pfnClose)(void* impl);

    /**
     * @brief A pointer to a function to read from the given reader.
     * @param impl The reader implementation to read from.
     * @param buffer The buffer to read into.
     * @param charsToRead The target number of characters to read.
     * @param charsRead A pointer to a value which will contain the number of
     * characters actually read when this call returns.
     * @return 0 on success, -1 on error.
     */
    JwtResult (*pfnRead)(void* impl, char* buffer, size_t charsToRead,
                       size_t* charsRead);
} JwtReader;

/**
 * @brief Creates a reader which reads from a file.
 * @param reader The reader struct to initialize as a file reader.
 * @param path The path of the file to read from.
 * @return 0 on success, -1 on error.
 */
JwtResult jwtReaderCreateForFile(JwtReader* reader, const char* path);

/**
 * @brief Creates a reader which reads from a buffer.
 * @param reader The reader struct to initialize as a buffer reader.
 * @param buffer The buffer to read from.
 * @param length The length of the buffer.
 * @return 0 on success, -1 on error.
 */
JwtResult jwtReaderCreateForBuffer(JwtReader* reader, const void* buffer,
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
inline JwtResult jwtReaderRead(JwtReader reader, char* buffer, size_t charsToRead,
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
JwtResult jwtReaderReadAll(JwtReader reader, char* buffer, size_t charsToRead,
                         size_t* charsRead);

/**
 * Represents a generic writer interface.
 */
typedef struct JwtWriter {
    /**
     * @brief Some writer implementation
     */
    void* impl;
    /**
     * @brief A pointer to a function which closes the given writer
     * implementation.
     * @param impl The reader implementation to close.
     * Any reads after this is called are invalid.
     */
    void (*pfnClose)(void* impl);

    /**
     * @brief A pointer to a function to write to the given writer.
     * @param impl The writer implementation to write to.
     * @param buffer The buffer to write into.
     * @param charsToWrite The target number of characters to write.
     * @param charWritten A pointer to a value which will contain the number of
     * characters actually written when this call returns.
     * @return 0 on success, -1 on error.
     */
    JwtResult (*pfnWrite)(void* impl, const char* buffer, size_t charsToWrite,
                        size_t* charsWritten);
} JwtWriter;

/**
 * @brief Creates a writer which writes to a file.
 * @param reader The writer struct to initialize as a file writer.
 * @param path The path of the file to write from.
 * @return 0 on success, -1 on error.
 */
JwtResult jwtWriterCreateForFile(JwtWriter* writer, const char* path);

/**
 * @brief Creates a writer which writes to a buffer.
 * @param writer The writer struct to initialize as a buffer writer.
 * @param buffer The buffer to write to.
 * @param length The length of the buffer.
 * @return 0 on success, -1 on error.
 */
JwtResult jwtWriterCreateForBuffer(JwtWriter* writer, void* buffer,
                                 size_t length);


/**
 * @brief Creates a writer which writes to a dynamic array.
 * @param writer The writer struct to initialize as a dynamic writer.
 * @return 0 on success, -1 on error.
 */
JwtResult jwtWriterCreateDynamic(JwtWriter* writer);

/**
 * @brief Gets the dynamic array backing a dynamic writer
 * @param writer The writer to extract from.
 * @return The list backing the given writer, or 0 if the writer is not a dynamic buffer 
 */
JwtList* jwtWriterExtractDynamic(JwtWriter* writer);


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
inline JwtResult jwtWriterWrite(JwtWriter writer, const char* buffer,
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
JwtResult jwtWriterWriteAll(JwtWriter reader, const char* buffer,
                          size_t charsToWrite, size_t* charsWritten);

#ifdef __cplusplus
}
#endif

#endif // JWT_STREAM_H
