#include <iostream>
#include <random>
#include <regex>
#include "bcrypt.h"
#include "support.hh"
#include <sclasses.hh>
#include <fmt/chrono.h>
#include "git_version.h"
using namespace std;

std::string& testrunnerPw()
{
  static string testrunnerpw; // this is so the testrunner can get the newly created password
  return testrunnerpw;
}


void replaceSubstring(std::string &originalString, const std::string &searchString, const std::string &replaceString) {
  size_t pos = originalString.find(searchString);
  
  while (pos != std::string::npos) {
    originalString.replace(pos, searchString.length(), replaceString);
    pos = originalString.find(searchString, pos + replaceString.length());
  }
}

string htmlEscape(const std::string& str)
{
  vector<pair<string,string>> rep{{"&", "&amp;"}, {"<", "&lt;"}, {">", "&gt;"}, {"\"", "&quot;"}, {"'", "&#39;"}};
  string ret=str;
  for(auto&& [from,to] : rep)
    replaceSubstring(ret, from, to);
  return ret;
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

uint64_t getRandom64()
{
  static std::random_device rd; // 32 bits at a time
  return ((uint64_t)rd() << 32) | rd();
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

string makeShortID(uint64_t id)
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
  const char* allowed="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_+-.@";
  if(from.find_first_not_of(allowed) != string::npos || to.find_first_not_of(allowed) != string::npos) {
    throw std::runtime_error("Illegal character in from or to address");
  }

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

  sc.writen(fmt::format("Message-Id: <{}@trifecta.hostname>\r\n", makeShortID(getRandom64())));
  
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
  string sessionid=makeShortID(getRandom64())+makeShortID(getRandom64());
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

void SimpleWebSystem::standardFunctions()
{
  wrapGet({}, "/status", [](auto &cr) {
    nlohmann::json j{{"ok", 1}};
    j["login"] = !cr.user.empty();
    j["admin"] = false;
    j["version"] = GIT_VERSION;
    if(!cr.user.empty()) {
      j["user"] = cr.user;
      j["admin"] = cr.users.userHasCap(cr.user, Capability::Admin);
      j["email"] = cr.users.getEmail(cr.user);
      j["hasPw"] = cr.users.hasPassword(cr.user);
    }
    return j;
  });

  wrapPost({}, "/login", [](auto &cr) {
    string user = cr.req.get_file_value("user").content;
    string password = cr.req.get_file_value("password").content;
    nlohmann::json j{{"ok", 0}};
    if(cr.users.checkPassword(user, password)) {
      string ip=getIP(cr.req), agent= cr.req.get_header_value("User-Agent");
      string sessionid = cr.sessions.createSessionForUser(user, agent, ip);
      cr.res.set_header("Set-Cookie",
                     "session="+sessionid+"; SameSite=Strict; Path=/; HttpOnly; Max-Age="+to_string(5*365*86400));
      cout<<"Logged in user '"<<user<<"'"<<endl;
      j["ok"]=1;
      j["message"]="welcome!";

      cr.log({{"action", "login"}, {"for", user}});
      cr.lsqw.query("update users set lastLoginTstamp=? where user=?", {time(0), user});
    }
    else {
      cout<<"Wrong user or password for user " << user <<endl;
      j["message"]="Wrong user or password";
      cr.log({{"action", "failed-login"}, {"for", user}});
    }
    return j;
  });

  wrapPost({Capability::IsUser}, "/change-my-password/?", [](auto& cr) {
    auto origpwfield = cr.req.get_file_value("password0");
    auto pwfield = cr.req.get_file_value("password1");
    if(pwfield.content.empty())
      throw std::runtime_error("Can't set an empty password");
    if(cr.users.hasPassword(cr.user) && !cr.users.checkPassword(cr.user, origpwfield.content)) {
      throw std::runtime_error("Original password not correct");
    }
    cout<<"Attemping to set password for user "<<cr.user<<endl;
    cr.users.changePassword(cr.user, pwfield.content);
    cr.log({{"action", "change-my-password"}});

    return nlohmann::json{{"ok", 1}, {"message", "Changed password"}};
  });
  
  wrapPost({}, "/join-session/(.*)", [](auto& cr) {
    string sessionid = cr.req.matches[1];
    nlohmann::json j{{"ok", 0}};

    auto c = cr.lsqw.query("select user, id from sessions where id=? and authenticated=1 and expireTstamp > ?", {sessionid, time(0)});
    if(c.size()==1) {
      string user= get<string>(c[0]["user"]);
      // delete this temporary session
      cr.sessions.dropSession(sessionid, user);
      // emailauthenticated session so it can reset your password, but no expiration
      string newsessionid = cr.sessions.createSessionForUser(user, "synth", getIP(cr.req), true);
      cr.res.set_header("Set-Cookie",
                     "session="+newsessionid+"; SameSite=Strict; Path=/; HttpOnly; Max-Age="+to_string(5*365*86400));
      cr.lsqw.query("update users set lastLoginTstamp=? where user=?", {time(0), user});
      cr.log({{"action", "join-session"}, {"sessionid", sessionid}});
      j["ok"]=1;
    }
    else
      cout<<"Could not find authenticated session "<<sessionid<<endl;
    return j;
  });

  wrapPost({Capability::IsUser}, "/change-my-email/?", [](auto& cr) {
    auto email = cr.req.get_file_value("email").content;
    cr.users.setEmail(cr.user, email);
    cr.log({{"action", "change-my-email"}, {"to", email}});
    return nlohmann::json{{"ok", 1}, {"message", "Changed email"}};
  });
  

  wrapGet({Capability::IsUser}, "/my-sessions", [](auto& cr) {
    return cr.lsqw.queryJRet("select * from sessions where user = ?", {cr.user});
  });
  
  wrapPost({Capability::IsUser}, "/kill-my-session/([^/]+)", [](auto& cr) {
    string session = cr.req.matches[1];
    cr.sessions.dropSession(session, cr.user);
    cr.log({{"action", "kill-my-session"}});
    return nlohmann::json{{"ok", 1}};
  });
  
  wrapPost({Capability::IsUser}, "/logout", [](auto& cr)  {
    cr.log({{"action", "logout"}});
    try {
      cr.sessions.dropSession(getSessionID(cr.req));
      cr.log({{"action", "logout"}});
    }
    catch(std::exception& e) {
      fmt::print("Failed to drop session from the database, perhaps there was none\n");
    }
    cr.res.set_header("Set-Cookie",
                      "session="+getSessionID(cr.req)+"; SameSite=Strict; Path=/; Max-Age=0");
    return nlohmann::json{{"ok", 1}};
  });

    
  wrapGet({Capability::Admin}, "/all-users", [](auto& cr) {
    return cr.lsqw.queryJRet("select user, email, disabled, lastLoginTstamp, admin from users");
  });
    
  wrapGet({Capability::Admin}, "/all-sessions", [](auto& cr) {
    return cr.lsqw.queryJRet("select * from sessions");
  });

  wrapPost({Capability::Admin}, "/create-user", [](auto& cr) {
    string password1 = cr.req.get_file_value("password1").content;
    string user = cr.req.get_file_value("user").content;
    string email = cr.req.get_file_value("email").content;
    nlohmann::json j;
      
    if(user.empty()) {
      j["ok"]=0;
      j["message"] = "User field empty";
    }
    else {
      cr.users.createUser(user, password1, email, false);
      cr.log({{"action", "create-user"}, {"who", user}, {"email", email}});
        
      j["ok"] = 1;
    }
    return j;
  });
    
  wrapPost({Capability::Admin}, "/change-user-disabled/([^/]+)/([01])", [](auto& cr) {
    string user = cr.req.matches[1];
    bool disabled = stoi(cr.req.matches[2]);
    cr.lsqw.query("update users set disabled = ? where user=?", {disabled, user});
    if(disabled) {
      cr.lsqw.query("delete from sessions where user=?", {user}); // XX candidate for Sessions class
    }
    cr.log({{"action", "change-user-disabled"}, {"who", user}});
    return nlohmann::json{{"ok", 1}};
  });
    
  wrapPost({Capability::Admin}, "/change-password/?", [](auto& cr) {
    auto pwfield = cr.req.get_file_value("password");
    if(pwfield.content.empty())
      throw std::runtime_error("Can't set an empty password");
      
    string user = cr.req.get_file_value("user").content;
    cout<<"Attemping to set password for user "<<user<<endl;
    cr.users.changePassword(user, pwfield.content);
    cr.log({{"action", "change-password"}});
    return nlohmann::json{{"ok", 1}};
  });

  wrapPost({Capability::Admin}, "/change-email/?", [](auto& cr) {
    auto email = cr.req.get_file_value("email").content;
    auto user = cr.req.get_file_value("user").content;
    cr.users.setEmail(user, email);
    cr.log({{"action", "change-email"}, {"to", email}});
    return nlohmann::json{{"ok", 1}, {"message", "Changed email"}};
  });

  
  wrapPost({Capability::Admin}, "/kill-session/([^/]+)", [](auto& cr) {
    string session = cr.req.matches[1];
    cr.sessions.dropSession(session);
    cr.log({{"action", "kill-session"}});
    return nlohmann::json{{"ok", 1}};
  });
    
  wrapPost({Capability::Admin}, "/del-user/([^/]+)", [](auto& cr) {
    string user = cr.req.matches[1];
    cr.users.delUser(user);
      
    // XX logging is weird, 'user' should likely be called 'subject' here
    cr.log({{"action", "del-user"}, {"who", user}});
    return nlohmann::json{{"ok", 1}};
  });

  wrapPost({Capability::IsUser, Capability::EmailAuthenticated}, "/wipe-my-password/?", [](auto& cr) {
    cr.users.changePassword(cr.user, "");
    cr.log({{"action", "wipe-my-password"}});
    return nlohmann::json{{"ok", 1}};
  });
  
  wrapPost({Capability::Admin}, "/stop" , [this](auto& cr) {
    cr.log({{"action", "stop"}});
    d_svr.stop();
    return nlohmann::json{{"ok", 1}};
  });
}

SimpleWebSystem::SimpleWebSystem(LockedSqw& lsqw) : d_lsqw(lsqw), d_users(lsqw), d_sessions(lsqw)
{
  d_svr.set_exception_handler([](const auto& req, auto& res, std::exception_ptr ep) {
    string reason;
    try {
      std::rethrow_exception(ep);
    } catch (std::exception &e) {
      reason = fmt::format("An error occurred: {}", e.what());
    } catch (...) {
      reason = "An unknown error occurred";
    }
    cout<<req.path<<": exception for "<<reason<<endl;
    nlohmann::json j{{"ok", 0}, {"message", reason}, {"reason", reason}};
    res.set_content(j.dump(), "application/json");
    res.status = 200;
  });
}
