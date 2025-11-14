#pragma once

#include <jwt/result.h>
#include <argparse/argparse.hpp>

JwtResult createToken(argparse::ArgumentParser& args);

JwtResult verifyToken(argparse::ArgumentParser& args);

JwtResult parseHeader(argparse::ArgumentParser& args);

JwtResult generateKey(argparse::ArgumentParser& args);
