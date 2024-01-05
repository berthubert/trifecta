#include <iostream>
#include <random>
#include <regex>
#include "cryptopp/base64.h"
#include "support.hh"
#include <sclasses.hh>
#include <fmt/chrono.h>

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

int64_t getRandom63()
{ // thread issue?
  static std::random_device rd;
  static std::mt19937_64 generator(rd());
  std::uniform_int_distribution<int64_t> dist(1, std::numeric_limits<int64_t>::max());
  return dist(generator);
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

// do not put UTF-8 or anything in this, it won't work. US-ASCII. 
void sendAsciiEmailAsync(const std::string& server, const std::string& from, const std::string& to, const std::string& subject, const std::string& textBody)
{
  ComboAddress mailserver(server, 25);
  Socket s(mailserver.sin4.sin_family, SOCK_STREAM);

  SocketCommunicator sc(s);
  sc.connect(mailserver);
  string line;
  auto sponge= [&](int expected) {
    while(sc.getLine(line)) {
      if(line.size() < 4)
        throw std::runtime_error("Invalid response from SMTP server: '"+line+"'");
      if(stoi(line.substr(0,3)) != expected)
        throw std::runtime_error("Unexpected response from SMTP server: '"+line+"'");
      if(line.at(3) == ' ')
        break;
    }
  };

  sponge(220);
  sc.writen("EHLO dan\r\n");
  sponge(250);

  sc.writen("MAIL From:<"+from+">\r\n");
  sponge(250);

  sc.writen("RCPT To:<"+to+">\r\n");
  sponge(250);

  sc.writen("DATA\r\n");
  sponge(354);
  sc.writen("From: "+from+"\r\n");
  sc.writen("To: "+to+"\r\n");
  sc.writen("Subject: "+subject+"\r\n");

  sc.writen(fmt::format("Message-Id: <{}@trifecta.hostname>\r\n", makeShortID(getRandom63())));
  
  //Date: Thu, 28 Dec 2023 14:31:37 +0100 (CET)
  sc.writen(fmt::format("Date: {:%a, %d %b %Y %H:%M:%S %z (%Z)}\r\n", fmt::localtime(time(0))));
  sc.writen("\r\n");


  string withCrlf;
  for(auto iter = textBody.cbegin(); iter != textBody.cend(); ++iter) {
    if(*iter=='\n' && (iter == textBody.cbegin() || *std::prev(iter)!='\r'))
      withCrlf.append(1, '\r');
    if(*iter=='.' && (iter != textBody.cbegin() && *std::prev(iter)=='\n'))
      withCrlf.append(1, '.');
        
    withCrlf.append(1, *iter);
  }
  
  sc.writen(withCrlf);
  sc.writen("\r\n.\r\n");
  sponge(250);
}

