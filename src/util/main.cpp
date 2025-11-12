#include <cstdint>
#include <exception>
#include <iostream>

#include <argparse/argparse.hpp>

#include <jwt/json.h>
#include <jwt/key.h>
#include <jwt/token.h>

#include "app.hpp"
#include "jwt/result.h"


int main(int argc, char** argv) { 

    argparse::ArgumentParser args("jwtutil", JWT_VERSION);
    args.set_prefix_chars("-");
    args.set_assign_chars("=");

    argparse::ArgumentParser createCommand("create", JWT_VERSION);
    createCommand.add_argument("algorithm")
        .help("The algorithm to use to protect the token")
        .nargs(1)
        .required();
    createCommand.add_argument("-k", "--key")
        .help("The path to a JSON file containing a Json Web Key (JWK)");
    createCommand.add_argument("-e", "--enc")
        .help("The encryption algorithm to use for encrypted tokens.");
    createCommand.add_argument("-p", "--payload")
        .help("A JSON object containing claims for the token payload");
    createCommand.add_argument("-h", "--header")
        .help("A JSON object containing claims for the token header");
    createCommand.add_argument("-i", "--issuer")
        .help("The token issuer");
    createCommand.add_argument("-a", "--audience")
        .help("The token's audience");
    createCommand.add_argument("-s", "--subject")
        .help("The token's subject");
    createCommand.add_argument("-j", "--id")
        .help("The token's unique ID");
    createCommand.add_argument("-x", "--expires-in")
        .help("The time, in seconds, from the time of creation until the token expires")
        .scan<'i', uint64_t>();
    createCommand.add_argument("-X", "--expires-at")
        .help("Seconds since the epoch when the token will expire")
        .scan<'i', uint64_t>();
    createCommand.add_argument("-n", "--valid-in")
        .help("The time, in seconds, from the time of creation until the token will become valid")
        .scan<'i', uint64_t>();
    createCommand.add_argument("-N", "--not-before")
        .help("Seconds since the epoch when the token will become valid")
        .scan<'i', uint64_t>();


    argparse::ArgumentParser verifyCommand("verify", JWT_VERSION);
    verifyCommand.add_argument("token")
        .help("The token to verify")
        .nargs(1);
    verifyCommand.add_argument("-k", "--key")
        .help("The path to a JSON file containing a Json Web Key (JWK)");
    verifyCommand.add_argument("-p", "--payload")
        .help("A JSON object containing claims which must be in the token payload");
    verifyCommand.add_argument("-h", "--header")
        .help("A JSON object containing claims which must be in the token header");
    verifyCommand.add_argument("-i", "--issuer")
        .help("The token's expected issuer");
    verifyCommand.add_argument("-a", "--audience")
        .help("The token's expected audience");
    verifyCommand.add_argument("-s", "--subject")
        .help("The token's expected subject");
    verifyCommand.add_argument("-j", "--id")
        .help("The token's expected unique ID");
    verifyCommand.add_argument("--allow-unprotected")
        .help("Allow successful verification of unprotected tokens")
        .flag();
    verifyCommand.add_argument("--allow-expired")
        .help("Allow successful verification of expired tokens")
        .flag();
    verifyCommand.add_argument("--allow-early")
        .help("Allow successful verification of early tokens")
        .flag();
    verifyCommand.add_argument("-o", "--output")
        .help("Output format for verify operations. One of: 'json', 'payload', 'header'")
        .choices("json", "payload", "header");

    argparse::ArgumentParser headerCommand("header", JWT_VERSION);
    headerCommand.add_argument("token")
        .help("The token to verify")
        .nargs(1);

    args.add_subparser(createCommand);
    args.add_subparser(verifyCommand);
    args.add_subparser(headerCommand);

    try {
        args.parse_args(argc, argv);
    } catch(const std::exception& ex) {
        std::cerr << args << "\n";
        return 1;
    }

    JwtResult result;

    if(args.is_subcommand_used("create")) {
        result = createToken(args.at<argparse::ArgumentParser>("create"));
    } else if(args.is_subcommand_used("verify")) {
        result = verifyToken(args.at<argparse::ArgumentParser>("verify"));
    } else if(args.is_subcommand_used("header")) {
        result = parseHeader(args.at<argparse::ArgumentParser>("header"));
    } else {
        std::cerr << args << "\n";
        return 1;
    }
    
    if(result != JWT_RESULT_SUCCESS) {
        std::cerr << "An error occurred! (" << result << ")\n";
        return 1;
    }

    return 0; 
}
