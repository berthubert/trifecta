#include <iostream>
#include <regex>

#include "cryptopp/base64.h"

#include "support.hh"

using namespace std;
// turn "abcd=1234; defgh=6934"3 into a map
static unordered_map<string,string> getGen(const std::string& cookiestr, const string& sep)
{
  std::regex cookie_regex("([^=]*=[^"+sep.substr(0,1)+"]*)");
  auto cookies_begin =
    std::sregex_iterator(cookiestr.begin(), cookiestr.end(), cookie_regex);
  auto cookies_end = std::sregex_iterator();

  unordered_map<string,string> ret;
  for(auto iter = cookies_begin; iter != cookies_end; ++iter) {
    std::regex inner("("+sep+")?([^=]*)=([^"+sep.substr(0,1)+"]*)");
    std::smatch m;
    string s = iter->str();
    std::regex_search(s, m, inner);
    if(m.size() != 4)
      continue;
    ret[m[2].str()]=m[3].str();
  }

  return ret;
}

unordered_map<string,string> getCookies(const std::string& cookiestr)
{
  return getGen(cookiestr, "; ");
}

string makeShortID(int64_t id)
{
  string encoded;
  using namespace CryptoPP;
  StringSource ss((uint8_t*)& id, sizeof(id), true,
                  new Base64URLEncoder(
                                    new StringSink(encoded)
                                    ) // Base64Encoder
                  ); // StringSource
  return encoded;
}
