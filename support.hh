#pragma once
#include <unordered_map>
#include <string>

int trifectaMain(int argc, const char* argv[]);
std::unordered_map<std::string, std::string> getCookies(const std::string& cookiestr);
std::unordered_map<std::string, std::string> getFormFields(const std::string& post);
std::string makeShortID(int64_t id);

