#pragma once

#include <jwt/key.h>

namespace jwt {

JwtKeyParseResult parseRsaKey(JwtKey* key, JwtJsonObject* obj);
JwtKeyParseResult parseEcKey(JwtKey* key, JwtJsonObject* obj);
JwtKeyParseResult parseOctKey(JwtKey* key, JwtJsonObject* obj);

} // namespace jwt
