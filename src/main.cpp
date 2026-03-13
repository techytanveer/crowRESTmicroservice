#include "crow_all.h"
#include "crypto_utils.hpp"
#include <chrono>

int main() {
    crow::SimpleApp app;

    CROW_ROUTE(app, "/hash").methods(crow::HTTPMethod::POST)
    ([](const crow::request& req) {
        auto body = crow::json::load(req.body);
        if (!body || !body.has("data")) return crow::response(400);
        crow::json::wvalue res;
        res["hash"] = sha256(body["data"].s());
        return crow::response(res);
    });

    CROW_ROUTE(app, "/encrypt/aes256").methods(crow::HTTPMethod::POST)
    ([](const crow::request& req) {
        auto body = crow::json::load(req.body);
        std::string key = body["key"].s();
        auto result = encrypt_aes_256_cbc(body["data"].s(), (unsigned char*)key.c_str());
        crow::json::wvalue res;
        res["ciphertext"] = result.ciphertext_base64;
        res["iv"] = result.iv_base64;
        return crow::response(res);
    });

    CROW_ROUTE(app, "/benchmark").methods(crow::HTTPMethod::POST)
    ([](const crow::request& req) {
        auto body = crow::json::load(req.body);
        auto start = std::chrono::high_resolution_clock::now();
        sha256(body["data"].s());
        auto end = std::chrono::high_resolution_clock::now();
        auto diff = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        crow::json::wvalue res;
        res["duration_us"] = diff.count();
        return crow::response(res);
    });

    app.port(8080).multithreaded().run();
}
