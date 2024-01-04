#define CPPHTTPLIB_USE_POLL
#include <exception>
#include <iostream>
#include <mutex>
#include <random>
#include <stdexcept>
#include <string>

#include "argparse/argparse.hpp"
#include "bcrypt.h"
#include "fmt/core.h"
#include "httplib.h"
#include "jsonhelper.hh"
#include "nlohmann/json.hpp"
#include "sqlwriter.hh"

#include "support.hh"
using namespace std;

/*
Todo:
  Configuration items in database
  if a user is disabled, do images/posts turn into 404s?

  opengraph data for previews, how? iframe?

  how do we deal with errors?  500? or a JSON thing?
    authentication/authorization error?
    impossible requests?
      "trying to delete an image that does not exist"
*/

std::string& testrunnerPw()
{
  static string testrunnerpw; // this is so the testrunner can get the newly created password
  return testrunnerpw;
}

// helper that makes sure only 1 thread uses the sqlitewriter at a time, plus some glue to emit answers as json
struct LockedSqw
{
  LockedSqw(const LockedSqw&) = delete;

  SQLiteWriter& sqw;
  std::mutex& sqwlock;
  vector<unordered_map<string, MiniSQLite::outvar_t>> query(const std::string& query, const std::initializer_list<SQLiteWriter::var_t>& values ={})
  {
    std::lock_guard<mutex> l(sqwlock);
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
    std::lock_guard<mutex> l(sqwlock);
    sqw.addValue(values, table);
  }
};

static int64_t getRandom63()
{
  static std::random_device rd;
  static std::mt19937_64 generator(rd());
  std::uniform_int_distribution<int64_t> dist(1, std::numeric_limits<int64_t>::max());
  return dist(generator);
}

enum class Capability {IsUser=1, Admin=2, EmailAuthenticated=3};

string getSessionID(const httplib::Request &req) 
{
  auto cookies = getCookies(req.get_header_value("Cookie"));
  auto siter = cookies.find("session");
  if(siter == cookies.end()) {
    throw std::runtime_error("No session cookie");
  }
  return siter->second;
}


struct Users
{
  Users(LockedSqw& lsqw) : d_lsqw(lsqw)
  {}
  bool checkPassword(const std::string& user, const std::string& password) const;
  void createUser(const std::string& user, const std::string& password, const std::string& email, bool admin);
  void changePassword(const std::string& user, const std::string& password);
  string getEmail(const std::string& user);
  void delUser(const std::string& user);
  bool hasPassword(const std::string& user);
  bool userHasCap(const std::string& user, const Capability& cap, const httplib::Request* req=0)
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
  LockedSqw& d_lsqw;
};

string Users::getEmail(const std::string& user)
{
  string ret;
  auto res = d_lsqw.query("select email from users where user=?", {user});
  if(res.size() == 1)
    ret = get<string>(res[0]["email"]);
  return ret;
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
    cout<<"No such user '"<< user << "'" <<endl;
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


// XXXX should only trust X-Real-IP if traffic is from a known and trusted proxy
string getIP(const httplib::Request& req) 
{
  if(req.has_header("X-Real-IP"))
    return req.get_header_value("X-Real-IP");
  return req.remote_addr;
}

class Sessions
{
public:
  Sessions(LockedSqw& lsqw) : d_lsqw(lsqw)
  {}

  string getUserForSession(const std::string& sessionid, const std::string& agent, const std::string& ip) const
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

  string createSessionForUser(const std::string& user, const std::string& agent, const std::string& ip, bool authenticated=false, std::optional<time_t> expire={})
  {
    string sessionid=makeShortID(getRandom63())+makeShortID(getRandom63());
    d_lsqw.addValue({{"id", sessionid}, {"user", user}, {"agent", agent}, {"ip", ip}, {"createTstamp", time(0)},
                     {"lastUseTstamp", 0}, {"expireTstamp", expire.value_or(0)},
                     {"authenticated", (int)authenticated}}, "sessions");
    return sessionid;
  }

  void dropSession(const std::string& sessionid)
  {
    d_lsqw.query("delete from sessions where id=?", {sessionid});
  }

  string getUser(const httplib::Request &req)  const
  {
    string ip=getIP(req), agent= req.get_header_value("User-Agent");
    return getUserForSession(getSessionID(req), agent, ip);
  }

private:
  LockedSqw& d_lsqw;
};

void checkImageOwnership(LockedSqw& lsqw, Users& u, const std::string& user, const std::string& imgid)
{
  if(!u.userHasCap(user, Capability::Admin)) {
    auto check = lsqw.query("select user from images, posts where images.postId = posts.id and images.id=? and user=?", {imgid, user});
    if(check.empty())
      throw std::runtime_error("Can't touch image from post that is not yours (user '"+user+"')");
  }
}

bool checkImageOwnershipBool(LockedSqw& lsqw, Users& u, std::string& user, std::string& imgid)
{
  try {    checkImageOwnership(lsqw, u, user, imgid);  }
  catch(std::exception& e) {
    cout<<e.what()<<endl;
    return false;
  }
  return true;
}

bool canTouchPost(LockedSqw& lsqw, Users& u, const std::string& user, const std::string& postid)
{
  if(u.userHasCap(user, Capability::Admin))
    return true;
  auto check = lsqw.query("select user from posts where id=?", {postid});
  if(check.size() != 1)
    return false;
  return get<string>(check[0]["user"]) == user;
}

bool shouldShow(Users& u, const std::string& user, unordered_map<string, MiniSQLite::outvar_t> row)
{
  // admin and owner can always see a post
  if(get<string>(row["user"]) == user || u.userHasCap(user, Capability::Admin))
    return true;

  if(!get<int64_t>(row["public"]))
    return false;

  time_t pubUntil = get<int64_t>(row["publicUntilTstamp"]);
  return (!pubUntil || time(0) < pubUntil);
}

int trifectaMain(int argc, const char**argv)
{
  argparse::ArgumentParser args("serv");

  args.add_argument("db-file").help("file to read database from").default_value("trifecta.sqlite");
  args.add_argument("--html-dir").help("directory with our HTML files").default_value("./html/");
  args.add_argument("--rnd-admin-password").help("Create admin user if necessary, and set a random password").flag();
  args.add_argument("-p", "--port").help("port number to listen on").default_value(3456).scan<'i', int>();
  args.add_argument("--local-address", "-l").help("address to listen on").default_value("0.0.0.0");

  try {
    args.parse_args(argc, argv);
  }
  catch (const std::runtime_error& err) {
    std::cout << err.what() << std::endl;
    std::cout << args;
    std::exit(1);
  }
  fmt::print("Database is in {}\n", args.get<string>("db-file"));
  SQLiteWriter sqw(args.get<string>("db-file"),
                   {
                     {"users", {{"user", "PRIMARY KEY"}}},
                     {"posts", {{"id", "PRIMARY KEY"}, {"user", "NOT NULL REFERENCES users(user) ON DELETE CASCADE"}}},
                     {"images", {{"id", "PRIMARY KEY"}, {"postId", "NOT NULL REFERENCES posts(id) ON DELETE CASCADE"}}},
                     {"sessions", {{"id", "PRIMARY KEY"}, {"user", "NOT NULL REFERENCES users(user) ON DELETE CASCADE"}}}
                   });
  std::mutex sqwlock;
  LockedSqw lsqw{sqw, sqwlock};
  Users u(lsqw);

  if(args["--rnd-admin-password"] == true) {
    bool changed=false;
    string pw = makeShortID(getRandom63());

    testrunnerPw() = pw;     // for the testrunner

    try {
      if(u.userHasCap("admin", Capability::Admin)) {
        cout<<"Admin user existed already, updating password to: "<< pw << endl;
        u.changePassword("admin", pw);
        changed=true;
      }
    }
    catch(...) {
    }

    if(!changed) {
      fmt::print("Creating user admin with password: {}\n", pw);
      u.createUser("admin", pw, "", true);
    }
  }

  try {
    auto admins=lsqw.query("select user from users where admin=1");
    if(admins.empty())
      fmt::print("WARNING: No admin users are defined, try --rnd-admin-password\n");
    else {
      fmt::print("Admin users: ");
      for(auto& a: admins)
        fmt::print("{} ", get<string>(a["user"]));
      fmt::print("\n");
    }
  }
  catch(...) {
    fmt::print("WARNING: No admin users are defined, try --rnd-admin-password\n");
  }

  httplib::Server svr;

  svr.set_exception_handler([](const auto& req, auto& res, std::exception_ptr ep) {
    string reason;
    try {
      std::rethrow_exception(ep);
    } catch (std::exception &e) {
      reason = fmt::format("An error occurred: {}", e.what());
    } catch (...) {
      reason = "An unknown error occurred";
    }
    cout<<req.path<<": exception for "<<reason<<endl;
    nlohmann::json j;
    j["ok"]=0;
    j["message"]=reason;
    j["reason"]=reason;
    res.set_content(j.dump(), "application/json");
                  
    res.status = 500;
  });

  svr.set_mount_point("/", args.get<string>("html-dir"));

  Sessions sessions(lsqw);
  auto wrapGetOrPost = [&svr, &sessions, &u](bool getOrPost, const set<Capability>& caps, const std::string& pattern, auto f) {
    cout<< (getOrPost ? "GET " : "POST") <<" caps";
    if(caps.empty())
      cout<<"  NONE ";
    if(caps.count(Capability::IsUser))
      cout<<" IsUser";
    if(caps.count(Capability::Admin))
      cout<<" Admin ";
    cout<<" pattern "<<pattern<<endl;
        
    auto func = [f, &sessions, caps, &u](const httplib::Request &req, httplib::Response &res) {
      string user;
      try {
        user = sessions.getUser(req);
      }
      catch(exception& e) {
        cout<<"Error getting user from session: "<<e.what()<<endl;
      }
      for(const auto& c: caps) {
        if(!u.userHasCap(user, c, &req))
          throw std::runtime_error(fmt::format("Lacked a capability ({})", (int)c));
      }
      auto output = f(req, res, user);
      if constexpr (std::is_same_v<decltype(output), std::pair<string, string>>) {
        res.set_content(output.first, output.second);
      }
      else {
        res.set_content(output.dump(), "application/json");
      }
    };
    if(getOrPost)
      svr.Get(pattern, func);
    else
      svr.Post(pattern, func);
  };
  auto wrapGet = [&wrapGetOrPost](const set<Capability>& caps, const std::string& pattern, auto f) { wrapGetOrPost(true, caps, pattern, f); };
  auto wrapPost = [&wrapGetOrPost](const set<Capability>& caps, const std::string& pattern, auto f) {
    wrapGetOrPost(false, caps, pattern, f);
  };
 
  wrapGet({}, "/status", [&u](const auto &req, httplib::Response &res, const std::string& user) {
    nlohmann::json j;
    j["login"] = !user.empty();
    j["admin"] = false;
    if(!user.empty()) {
      j["user"] = user;
      j["admin"] = u.userHasCap(user, Capability::Admin);
      j["email"] = u.getEmail(user);
      j["hasPw"] = u.hasPassword(user);
    }
    return j;
  });

  wrapPost({}, "/login", [&lsqw, &sessions, &u](const auto &req, httplib::Response &res, const std::string& ign) {
    string user = req.get_file_value("user").content;
    string password = req.get_file_value("password").content;
    nlohmann::json j;
    j["ok"]=0;
    if(u.checkPassword(user, password)) {
      string ip=getIP(req), agent= req.get_header_value("User-Agent");
      string sessionid = sessions.createSessionForUser(user, agent, ip);
      res.set_header("Set-Cookie",
                     "session="+sessionid+"; SameSite=Strict; Path=/; Max-Age="+to_string(5*365*86400));
      cout<<"Logged in user "<<user<<endl;
      j["ok"]=1;
      j["message"]="welcome!";
      lsqw.addValue({{"action", "login"}, {"user", user}, {"ip", getIP(req)}, {"tstamp", time(0)}}, "log");
      lsqw.query("update users set lastLoginTstamp=? where user=?", {time(0), user});
    }
    else {
      cout<<"Wrong user or password for user " << user <<endl;
      j["message"]="Wrong user or password";
      lsqw.addValue({{"action", "failed-login"}, {"user", user}, {"ip", getIP(req)}, {"tstamp", time(0)}}, "log");
    }
    return j;
  });

  wrapPost({}, "/join-session/(.*)", [&lsqw, &u, &sessions](const auto& req, auto& res, const string&) {
    string sessionid = req.matches[1];
    nlohmann::json j;
    j["ok"]=0;

    auto c = lsqw.query("select user, id from sessions where id=? and authenticated=1 and expireTstamp > ?", {sessionid, time(0)});
    if(c.size()==1) {
      // delete this temporary session
      string user= get<string>(c[0]["user"]);
      lsqw.query("delete from sessions where id=? and user=?", {sessionid, user});
      // emailauthenticated session so it can reset your password, but no expiration
      string newsessionid = sessions.createSessionForUser(user, "synth", getIP(req), true);
      res.set_header("Set-Cookie",
                     "session="+newsessionid+"; SameSite=Strict; Path=/; Max-Age="+to_string(5*365*86400));
      lsqw.query("update users set lastLoginTstamp=? where user=?", {time(0), user});
      j["ok"]=1;
    }
    else
      cout<<"Could not find authenticated session "<<sessionid<<endl;
    return j;
  });

  wrapPost({}, "/get-signin-email", [&lsqw, &sessions, &u](const auto &req, httplib::Response &res, const std::string& ign) {
    string user = req.get_file_value("user").content;
    string email = u.getEmail(user); // CHECK FOR DISABLED USER!!
    fmt::print("User '{}', email '{}'\n", user, email);
    nlohmann::json j;
    j["message"] = "If this user exists and has an email address, a message was sent";
    j["ok"]=1;
    if(!email.empty()) {
      // valid for 1 day
      string session = sessions.createSessionForUser(user, "Change password session", getIP(req), true, time(0)+86400); // authenticated session
      string dest="http://127.0.0.1:1234/";
      sendAsciiEmailAsync("bert@hubertnet.nl", email, "Trifecta sign-in link", "Going to this link will allow you to reset your password or sign you in directly: "+dest+"reset.html?session="+session+"\nEnjoy!");
      cout<<"Sent email pointing user at "<<dest<<"/reset.html?session="<<session<<endl;
    }
    else
      cout<<"Had no email address for user "<<user<<endl;
    
    return j;
  });

  
  wrapGet({}, "/getPost/:postid", [&lsqw, &u](const auto& req, auto& res, const std::string& user) {
    string postid = req.path_params.at("postid");

    nlohmann::json j;

    auto post = lsqw.query("select user, public, title, publicUntilTstamp from posts where id=?", {postid});
    if(post.size() != 1) {
      j["images"] = nlohmann::json::array();
    }
    else if(shouldShow(u, user, post[0])) {
      auto images = lsqw.query("select images.id as id, caption from images,posts where postId = ? and images.postId = posts.id", {postid});

      j["images"]=packResultsJson(images);
      j["title"]=get<string>(post[0]["title"]);
      j["public"]=get<int64_t>(post[0]["public"]);
      time_t until = get<int64_t>(post[0]["publicUntilTstamp"]);
      j["publicUntil"]=until;
      if(!user.empty())
        j["can_touch_post"] = canTouchPost(lsqw, u, user, postid) ? 1 : 0;
      else
        j["can_touch_post"] = 0;
      j["publicUntilExpired"] = until && (time(0) < until);
    }
    return j;
  });

  wrapGet({}, "/i/:imgid", [&lsqw, &u](const auto& req, auto& res, const string& user) {
    string imgid = req.path_params.at("imgid");
    res.status = 404;

    auto results = lsqw.query("select image,public,content_type, posts.publicUntilTstamp, posts.user from images,posts where images.id=? and posts.id = images.postId ", {imgid});

    if(results.size() != 1) {
      lsqw.addValue({{"action", "view-failed"} , {"user", user}, {"imageId", imgid}, {"ip", getIP(req)}, {"tstamp", time(0)}, {"meta", "no such image"}}, "log");
      return pair<string,string>("No such file", "text/html");
    }

    if(!shouldShow(u, user, results[0])) {
      lsqw.addValue({{"action", "view-failed"} , {"user", user}, {"imageId", imgid}, {"ip", getIP(req)}, {"tstamp", time(0)}}, "log");
      return pair<string,string>("No such file", "text/html");
    }

    auto img = get<vector<uint8_t>>(results[0]["image"]);
    string s((char*)&img[0], img.size());
    res.status = 200;

    lsqw.addValue({{"action", "view"} , {"user", user}, {"imageId", imgid}, {"ip", getIP(req)}, {"tstamp", time(0)}}, "log");
    return make_pair(s, get<string>(results[0]["content_type"]));
  });

  wrapPost({Capability::IsUser}, "/upload", [&lsqw, &u](const auto& req, auto& res, const std::string& user) {
    time_t tstamp = time(0);
    string postId = req.get_file_value("postId").content;
    if(postId.empty()) {
      postId = makeShortID(getRandom63());
      lsqw.addValue({{"id", postId}, {"user", user}, {"stamp", tstamp}, {"public", 1}, {"publicUntilTstamp", 0}, {"title", ""}}, "posts");
    }
    else if(!u.userHasCap(user, Capability::Admin)) {
      auto access=lsqw.query("select id from posts where id=? and user=?", {postId, user});
      if(access.empty())
        throw std::runtime_error("Attempt to upload to post that's not ours!");
      }
    
    nlohmann::json j; // if you upload multiple files in one go, this does the wrong thing
    for(auto&& [name, f] : req.files) {
      fmt::print("name {}, filename {}, content_type {}, size {}, postid {}\n", f.name, f.filename, f.content_type, f.content.size(), postId);
      if(f.content_type.substr(0,6) != "image/" || f.filename.empty()) {
        cout<<"Skipping non-image or non-file (type " << f.content_type<<", filename '"<<f.filename<<"'"<<endl;
        continue;
      }
      vector<uint8_t> content(f.content.c_str(), f.content.c_str() + f.content.size());
      auto imgid=makeShortID(getRandom63());
      lsqw.addValue({{"id", imgid},
                     {"ip", getIP(req)},
                     {"tstamp", tstamp},
                     {"image", content},
                     {"content_type", f.content_type},
                     {"postId", postId},
                     {"caption", ""}
        }, "images");
      
      j["id"]=imgid;
      j["postId"] = postId;
      
      auto row = lsqw.query("select public, publicUntilTstamp from posts where id=?", {postId});
      if(!row.empty()) {
        j["public"] = get<int64_t>(row[0]["public"]);
        j["publicUntil"] = get<int64_t>(row[0]["publicUntilTstamp"]);;
      }
      lsqw.addValue({{"action", "upload"} , {"user", user}, {"imageId", imgid}, {"ip", getIP(req)}, {"tstamp", tstamp}}, "log");
      
    }
    return j;
  });
  
  wrapPost({Capability::IsUser}, "/delete-image/(.+)", [&lsqw, &u](const auto& req, auto& res, const std::string& user) {
    string imgid = req.matches[1];
    
    cout<<"Attemping to delete image "<<imgid<<" for user " << user << endl;
    checkImageOwnership(lsqw, u, user, imgid);
    
    lsqw.query("delete from images where id=?", {imgid});
    lsqw.addValue({{"action", "delete-image"}, {"ip", getIP(req)}, {"user", user}, {"imageId", imgid}, {"tstamp", time(0)}}, "log");
    return nlohmann::json();
  });
  
  wrapPost({Capability::IsUser}, "/delete-post/(.+)", [&lsqw, &u](const auto& req, auto& res, const string& user) {
    string postid = req.matches[1];
    nlohmann::json j;
    j["ok"]=0;
    if(canTouchPost(lsqw, u, user, postid)) {
      lsqw.query("delete from posts where id=?", {postid});
      j["ok"]=1;
    }
    else {
      cout<<"Tried to delete post "<<postid<<" but user "<<user<<" had no rights"<<endl;
    }
    return j;
  });
  
  wrapPost({Capability::IsUser}, "/set-post-title/(.+)", [&lsqw, &u](const auto& req, auto& res, const string& user) {
    
    string postid = req.matches[1];
    
    string title = req.get_file_value("title").content;
    cout<<"Attemping to set title for post "<< postid<<" for user " << user <<" to " << title << endl;
    auto rows = lsqw.query("select user from posts where id=?", {postid});
    if(rows.size() != 1)
      throw std::runtime_error("Attempting to change title for post that does not exist");
    
    if(get<string>(rows[0]["user"]) != user && !u.userHasCap(user, Capability::Admin))
      throw std::runtime_error("Attempting to change title for post that is not yours and you are not admin");
    
    lsqw.query("update posts set title=? where user=? and id=?", {title, user, postid});
    lsqw.addValue({{"action", "set-post-title"}, {"ip", getIP(req)}, {"user", user}, {"postId", postid}, {"tstamp", time(0)}}, "log");
    return nlohmann::json();
  });
  
  wrapPost({Capability::IsUser}, "/set-image-caption/(.+)", [&lsqw, &u](const auto& req, auto& res, const string& user) {
    string imgid = req.matches[1];
    string caption = req.get_file_value("caption").content;
    
    checkImageOwnership(lsqw, u, user, imgid);
    lsqw.query("update images set caption=? where id=?", {caption, imgid});
    lsqw.addValue({{"action", "set-image-caption"}, {"ip", getIP(req)}, {"user", user}, {"imageId", imgid}, {"tstamp", time(0)}}, "log");
    return nlohmann::json();
  });

  wrapPost({Capability::IsUser, Capability::EmailAuthenticated}, "/wipe-my-password/?", [&lsqw, &u](const auto& req, auto& res, const string& user) {
    u.changePassword(user, "");
    nlohmann::json j; 
    j["ok"]=1;
    return j;
  });
  
  wrapPost({Capability::IsUser}, "/change-my-password/?", [&lsqw, &u](const auto& req, auto& res, const string& user) {
    auto origpwfield = req.get_file_value("password0");
    auto pwfield = req.get_file_value("password1");
    if(pwfield.content.empty())
      throw std::runtime_error("Can't set an empty password");
    if(u.hasPassword(user) && !u.checkPassword(user, origpwfield.content)) {
      throw std::runtime_error("Original password not correct");
    }
    cout<<"Attemping to set password for user "<<user<<endl;
    u.changePassword(user, pwfield.content);
    nlohmann::json j;
    j["ok"]=1;
    j["message"]="Changed password";
    return j;
  });

  wrapPost({Capability::IsUser}, "/change-my-email/?", [&lsqw, &u](const auto& req, auto& res, const string& user) {
    auto email = req.get_file_value("email").content;
    auto ret= lsqw.queryJRet("update users set email=? where user=?", {email, user});
    nlohmann::json j;
    j["ok"]=1;
    j["message"]="Changed email";
    return j;
  });

  wrapPost({Capability::IsUser}, "/set-post-public/([^/]+)/([01])/?([0-9]*)", [&lsqw, &u](const auto& req, auto& res, const string& user) {
    string postid = req.matches[1];
    bool pub = stoi(req.matches[2]);
    time_t until=0;
    
    if(!canTouchPost(lsqw, u, user, postid))
      throw std::runtime_error("Attempt to change public status of post you can't touch");
    if(req.matches.size() > 3) {
      string untilStr = req.matches[3];
      if(!untilStr.empty())
        until = stoi(untilStr);
    }
    cout<<"postid: "<< postid << ", new state: "<<pub<<", until: "<<until <<", matches "<< req.matches.size()<<endl;
    if(!pub && until)
      throw std::runtime_error("Attempting to set nonsensical combination for public");
    
    if(until)
      lsqw.query("update posts set public = ?, publicUntilTstamp=? where id=?", {pub, until, postid});
    else
      lsqw.query("update posts set public =? where id=?", {pub, postid});
    lsqw.addValue({{"action", "change-post-public"}, {"ip", getIP(req)}, {"user", user}, {"postId", postid}, {"pub", pub}, {"tstamp", time(0)}}, "log");
    return nlohmann::json();
  });
    
  wrapGet({Capability::IsUser}, "/my-images", [&lsqw](const auto &req, auto &res, const string& user) {
    return lsqw.queryJRet("select images.id as id, postid, images.tstamp, content_type,length(image) as size, public, posts.publicUntilTstamp,title,caption from images,posts where postId = posts.id and user=?", {user});
    });

  wrapGet({Capability::IsUser}, "/my-sessions", [&lsqw](const auto&req, auto &res, const string& user) {
    return lsqw.queryJRet("select * from sessions where user = ?", {user});
  });

  wrapPost({Capability::IsUser}, "/kill-my-session/([^/]+)", [&lsqw](const auto& req, auto& res, const string& user) {
    string session = req.matches[1];
    lsqw.query("delete from sessions where id=? and user=?", {session, user});
    lsqw.addValue({{"action", "kill-my-session"}, {"user", user}, {"ip", getIP(req)}, {"session", session}, {"tstamp", time(0)}}, "log");
    return nlohmann::json();
  });

  
  wrapPost({Capability::IsUser}, "/logout", [&lsqw, &sessions](const auto &req, auto &res, const string& user)  {
    lsqw.addValue({{"action", "logout"}, {"user", user}, {"ip", getIP(req)}, {"tstamp", time(0)}}, "log");
    try {
      sessions.dropSession(getSessionID(req));
    }
    catch(std::exception& e) {
      fmt::print("Failed to drop session from the database, perhaps there was none\n");
    }
    res.set_header("Set-Cookie",
                   "session="+getSessionID(req)+"; SameSite=Strict; Path=/; Max-Age=0");
    
    return nlohmann::json();
  });

  wrapGet({Capability::Admin}, "/all-images", [&lsqw](const auto &req, auto &res, const string& user) {
    return lsqw.queryJRet("select images.id as id, postId, user,tstamp,content_type,length(image) as size, posts.public, ip from images,posts where posts.id=images.postId");
  });
    
  wrapGet({Capability::Admin}, "/all-users", [&lsqw](const auto &req, auto &res, const string& ) {
    return lsqw.queryJRet("select user, email, disabled, lastLoginTstamp, admin from users");
  });
    
  wrapGet({Capability::Admin}, "/all-sessions", [&lsqw](const auto&req, auto &res, const string& user) {
    return lsqw.queryJRet("select * from sessions");
  });
    
  wrapPost({Capability::Admin}, "/create-user", [&u](const auto &req, auto &res, const string& ) {
    string password1 = req.get_file_value("password1").content;
    string user = req.get_file_value("user").content;
    string email = req.get_file_value("email").content;
    nlohmann::json j;
      
    if(user.empty()) {
      j["ok"]=false;
      j["message"] = "User field empty";
    }
    else {
      u.createUser(user, password1, email, false);
      j["ok"] = true;
    }
    return j;
  });
    
  wrapPost({Capability::Admin}, "/change-user-disabled/([^/]+)/([01])", [&lsqw](const auto& req, auto& res, const string& ) {
    string user = req.matches[1];
    bool disabled = stoi(req.matches[2]);
    lsqw.query("update users set disabled = ? where user=?", {disabled, user});
    if(disabled) {
      lsqw.query("delete from sessions where user=?", {user});
    }
    lsqw.addValue({{"action", "change-user-disabled"}, {"user", user}, {"ip", getIP(req)}, {"disabled", disabled}, {"tstamp", time(0)}}, "log");
    return nlohmann::json();
  });
    
  wrapPost({Capability::Admin}, "/change-password/?", [&lsqw, &u](const auto& req, auto& res, const string&) {
    auto pwfield = req.get_file_value("password");
    if(pwfield.content.empty())
      throw std::runtime_error("Can't set an empty password");
      
    string user = req.get_file_value("user").content;
    cout<<"Attemping to set password for user "<<user<<endl;
    u.changePassword(user, pwfield.content);
    return nlohmann::json();
  });
    
  wrapPost({Capability::Admin}, "/kill-session/([^/]+)", [&lsqw](const auto& req, auto& res, const string& ign) {
    string session = req.matches[1];
    lsqw.query("delete from sessions where id=?", {session});
    lsqw.addValue({{"action", "kill-session"}, {"ip", getIP(req)}, {"session", session}, {"tstamp", time(0)}}, "log");
    return nlohmann::json();
  });
    
  wrapPost({Capability::Admin}, "/del-user/([^/]+)", [&lsqw, &u](const auto& req, auto& res, const string&) {
    string user = req.matches[1];
    u.delUser(user);
      
    // XX logging is weird, 'user' should likely be called 'subject' here
    lsqw.addValue({{"action", "del-user"}, {"ip", getIP(req)}, {"user", user}, {"tstamp", time(0)}}, "log");
    return nlohmann::json();
  });
    
  wrapPost({Capability::Admin}, "/stop" , [&lsqw, &svr](const auto& req, auto& res, const string& wuser) {
    lsqw.addValue({{"action", "stop"}, {"ip", getIP(req)}, {"user", wuser}, {"tstamp", time(0)}}, "log");
    svr.stop();
    return nlohmann::json();
  });
  
  string laddr = args.get<string>("local-address");
  cout<<"Will listen on http://"<< laddr <<":"<<args.get<int>("port")<<endl;

  svr.set_socket_options([](socket_t sock) {
   int yes = 1;
   setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
                reinterpret_cast<const void *>(&yes), sizeof(yes));
  });

  if(!svr.listen(laddr, args.get<int>("port"))) {
    cout<<"Error launching server: "<<strerror(errno)<<endl;
    return EXIT_FAILURE;
  }
  cout<<"Stopping"<<endl;
  return 0;
}
