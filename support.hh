#pragma once
#include <unordered_map>
#include <string>

int trifectaMain(int argc, const char* argv[]);
std::unordered_map<std::string, std::string> getCookies(const std::string& cookiestr);
std::string makeShortID(int64_t id);

std::string& testrunnerPw();
