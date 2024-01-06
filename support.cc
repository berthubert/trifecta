#include <iostream>
#include <random>
#include <regex>
#include "bcrypt.h"
#include "support.hh"
#include <sclasses.hh>
#include <fmt/chrono.h>

using namespace std;

std::string& testrunnerPw()
{
  static string testrunnerpw; // this is so the testrunner can get the newly created password
  return testrunnerpw;
}


// turn "abcd=1234; defgh=6934" into a map
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

namespace {
  //gratefully lifted from https://github.com/tobiaslocker/base64
  constexpr std::string_view base64url_chars{"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                               "abcdefghijklmnopqrstuvwxyz"
                                               "0123456789-_"};


  template<class OutputBuffer, class InputIterator>
  inline OutputBuffer encode_into(InputIterator begin, InputIterator end) {
    static_assert(std::is_same_v<std::decay_t<decltype(*begin)>, char>
                  || std::is_same_v<std::decay_t<decltype(*begin)>, unsigned char>
                  || std::is_same_v<std::decay_t<decltype(*begin)>, std::byte>);
    
    size_t counter = 0;
    uint32_t bit_stream = 0;
    size_t offset = 0;
    OutputBuffer encoded;
    encoded.reserve(static_cast<size_t>(1.5 * static_cast<double>(std::distance(begin, end))));
    while(begin != end) {
      auto const num_val = static_cast<unsigned char>(*begin);
      offset = 16 - counter % 3 * 8;
      bit_stream += num_val << offset;
      if (offset == 16) {
        encoded.push_back(base64url_chars[bit_stream >> 18 & 0x3f]);
      }
      if (offset == 8) {
        encoded.push_back(base64url_chars[bit_stream >> 12 & 0x3f]);
      }
      if (offset == 0 && counter != 3) {
        encoded.push_back(base64url_chars[bit_stream >> 6 & 0x3f]);
        encoded.push_back(base64url_chars[bit_stream & 0x3f]);
        bit_stream = 0;
      }
      ++counter;
      ++begin;
    }
    if (offset == 16) {
      encoded.push_back(base64url_chars[bit_stream >> 12 & 0x3f]);
      encoded.push_back('=');
      encoded.push_back('=');
    }
    if (offset == 8) {
      encoded.push_back(base64url_chars[bit_stream >> 6 & 0x3f]);
      encoded.push_back('=');
    }
    return encoded;
  }
  
  std::string to_base64url(std::string_view data) {
    return encode_into<std::string>(std::begin(data), std::end(data));
  }
}

string makeShortID(int64_t id)
{
  string ret = to_base64url(std::string((char*)&id, sizeof(id)));
  ret.resize(ret.size()-1); // this base64url implementation pads, somehow
  return ret;
}

// teases the session cookie from the headers
string getSessionID(const httplib::Request &req) 
{
  auto cookies = getCookies(req.get_header_value("Cookie"));
  auto siter = cookies.find("session");
  if(siter == cookies.end()) {
    throw std::runtime_error("No session cookie");
  }
  return siter->second;
}

// XXXX should only trust X-Real-IP if traffic is from a known and trusted proxy
std::string getIP(const httplib::Request& req) 
{
  if(req.has_header("X-Real-IP"))
    return req.get_header_value("X-Real-IP");
  return req.remote_addr;
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

bool Users::userHasCap(const std::string& user, const Capability& cap, const httplib::Request* req)
{
  bool ret=false;
  if(cap== Capability::IsUser) {
    auto c = d_lsqw.query("select count(1) as c from users where user=? and disabled=0", {user});
    ret = (c.size()==1 && get<int64_t>(c[0]["c"])==1);
  }
  else if(cap==Capability::Admin) {
    auto c = d_lsqw.query("select count(1) as c from users where user=? and disabled=0 and admin=1", {user});
    ret = (c.size()==1 && get<int64_t>(c[0]["c"])==1);
  } else if(cap==Capability::EmailAuthenticated && req) {
    auto c = d_lsqw.query("select count(1) as c from sessions where user=? and authenticated=1 and id=?", {user, getSessionID(*req)});
    ret = (c.size()==1 && get<int64_t>(c[0]["c"])==1);
  }
  return ret;
}

string Users::getEmail(const std::string& user)
{
  auto res = d_lsqw.query("select email from users where user=?", {user});
  if(res.size() == 1)
    return get<string>(res[0]["email"]);
  return "";
}

void Users::setEmail(const std::string& user, const std::string& email)
{
  d_lsqw.query("update users set email=? where user=?", {email, user});
}

bool Users::hasPassword(const std::string& user)
{
  auto res = d_lsqw.query("select pwhash from users where user=?", {user});
  return res.size() == 1 && !get<string>(res[0]["pwhash"]).empty();
}

bool Users::checkPassword(const std::string& user, const std::string& password) const
{
  auto res = d_lsqw.query("select pwhash, caps from users where user=? and disabled=0", {user});
  if(res.empty()) {
    return false;
  }
  return bcrypt::validatePassword(password, get<string>(res[0]["pwhash"]));
}

void Users::createUser(const std::string& user, const std::string& password, const std::string& email, bool admin)
{
  string pwhash = bcrypt::generateHash(password);
  d_lsqw.addValue({{"user", user}, {"pwhash", pwhash}, {"admin", (int)admin}, {"disabled", 0}, {"caps", ""}, {"lastLoginTstamp", 0}, {"email", email}}, "users");
  d_lsqw.addValue({{"action", "create-user"}, {"user", user}, {"ip", "xx missing xx"}, {"tstamp", time(0)}}, "log");
}

void Users::delUser(const std::string& user)
{
  d_lsqw.query("delete from users where user=?", {user});
}

// empty disables password
void Users::changePassword(const std::string& user, const std::string& password)
{
  string pwhash = password.empty() ? "" : bcrypt::generateHash(password);
  auto res = d_lsqw.query("select user from users where user=?", {user});
  if(res.size()!=1 || get<string>(res[0]["user"]) != user) {
    d_lsqw.addValue({{"action", "change-password-failure"}, {"user", user}, {"ip", "xx missing xx"}, {"meta", "no such user"}, {"tstamp", time(0)}}, "log");
    throw std::runtime_error("Tried to change password for user '"+user+"', but does not exist");
  }
  d_lsqw.query("update users set pwhash=? where user=?", {pwhash, user});
  d_lsqw.addValue({{"action", "change-password"}, {"user", user}, {"ip", "xx missing xx"}, {"tstamp", time(0)}}, "log");
}


string Sessions::getUserForSession(const std::string& sessionid, const std::string& agent, const std::string& ip) const
{
  try {
    auto ret = d_lsqw.query("select * from sessions where id=?", {sessionid});
    if(ret.size()==1) {
      time_t expire = std::get<int64_t>(ret[0]["expireTstamp"]);
      if(expire && expire < time(0)) {
        cout<<"Authenticated session expired"<<endl;
        d_lsqw.query("delete from sessions where id=?", {sessionid});
        return "";
      }
      
      d_lsqw.query("update sessions set lastUseTstamp=?, agent=?, ip=? where id=?", {time(0), agent, ip, sessionid});
      return get<string>(ret[0]["user"]);
    }
  }
  catch(std::exception&e ){ cout<<"Error: "<<e.what()<<endl;}
  return "";
}

string Sessions::getUser(const httplib::Request &req)  const
{
  string ip=getIP(req), agent= req.get_header_value("User-Agent");
  return getUserForSession(getSessionID(req), agent, ip);
}

string Sessions::createSessionForUser(const std::string& user, const std::string& agent, const std::string& ip, bool authenticated, std::optional<time_t> expire)
{
  string sessionid=makeShortID(getRandom63())+makeShortID(getRandom63());
  d_lsqw.addValue({{"id", sessionid}, {"user", user}, {"agent", agent}, {"ip", ip}, {"createTstamp", time(0)},
                   {"lastUseTstamp", 0}, {"expireTstamp", expire.value_or(0)},
                   {"authenticated", (int)authenticated}}, "sessions");
  return sessionid;
}

void Sessions::dropSession(const std::string& sessionid, std::optional<string> user)
{
  if(!user)
    d_lsqw.query("delete from sessions where id=?", {sessionid});
  else
    d_lsqw.query("delete from sessions where id=? and user=?", {sessionid, *user});
}

