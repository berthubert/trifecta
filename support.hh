#pragma once
#include <optional>
#include <unordered_map>
#include <string>
#include <mutex>
#include <vector>
#include "jsonhelper.hh"
#include "nlohmann/json.hpp"
#include "sqlwriter.hh"
#include "httplib.h"

struct LockedSqw
{
  LockedSqw(const LockedSqw&) = delete;

  SQLiteWriter& sqw;
  std::mutex& sqwlock;
  auto query(const std::string& query, const std::initializer_list<SQLiteWriter::var_t>& values ={})
  {
    std::lock_guard<std::mutex> l(sqwlock);
    return sqw.queryT(query, values);
  }

  void queryJ(httplib::Response &res, const std::string& q, const std::initializer_list<SQLiteWriter::var_t>& values={}) 
  {
    auto result = query(q, values);
    res.set_content(packResultsJsonStr(result), "application/json");
  }

  auto queryJRet(const std::string& q, const std::initializer_list<SQLiteWriter::var_t>& values={}) 
  {
    auto result = query(q, values);
    return packResultsJson(result);
  }
  
  void addValue(const std::initializer_list<std::pair<const char*, SQLiteWriter::var_t>>& values, const std::string& table="data")
  {
    std::lock_guard<std::mutex> l(sqwlock);
    sqw.addValue(values, table);
  }
};

int trifectaMain(int argc, const char* argv[]);
std::unordered_map<std::string, std::string> getCookies(const std::string& cookiestr);
int64_t getRandom63();
std::string makeShortID(int64_t id);
std::string getSessionID(const httplib::Request &req);
std::string& testrunnerPw();
void sendAsciiEmailAsync(const std::string& server, const std::string& from, const std::string& to, const std::string& subject, const std::string& textBody);
std::string getIP(const httplib::Request& req);

enum class Capability {IsUser=1, Admin=2, EmailAuthenticated=3};

struct Users
{
  Users(LockedSqw& lsqw) : d_lsqw(lsqw)
  {}
  bool checkPassword(const std::string& user, const std::string& password) const;
  void createUser(const std::string& user, const std::string& password, const std::string& email, bool admin);
  void changePassword(const std::string& user, const std::string& password);
  std::string getEmail(const std::string& user);
  void setEmail(const std::string& user, const std::string& email);
  void delUser(const std::string& user);
  bool userHasCap(const std::string& user, const Capability& cap, const httplib::Request* req=0);
  bool hasPassword(const std::string& user);
  LockedSqw& d_lsqw;
};

class Sessions
{
public:
  Sessions(LockedSqw& lsqw) : d_lsqw(lsqw)
  {}

  std::string getUserForSession(const std::string& sessionid, const std::string& agent, const std::string& ip) const;
  std::string createSessionForUser(const std::string& user, const std::string& agent, const std::string& ip, bool authenticated=false, std::optional<time_t> expire={});

  void dropSession(const std::string& sessionid, std::optional<std::string> user={});
  std::string getUser(const httplib::Request &req)  const;

private:
  LockedSqw& d_lsqw;
};

