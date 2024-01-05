#pragma once
#include <unordered_map>
#include <string>


int trifectaMain(int argc, const char* argv[]);
std::unordered_map<std::string, std::string> getCookies(const std::string& cookiestr);
int64_t getRandom63();
std::string makeShortID(int64_t id);

std::string& testrunnerPw();
void sendAsciiEmailAsync(const std::string& server, const std::string& from, const std::string& to, const std::string& subject, const std::string& textBody);
