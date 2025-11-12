#pragma once

#include <jwt/key.h>

namespace jwt {

JwtResult parseRsaKey(JwtKey* key, JwtJsonObject* obj);
JwtResult parseEcKey(JwtKey* key, JwtJsonObject* obj);
JwtResult parseOctKey(JwtKey* key, JwtJsonObject* obj);

} // namespace jwt
