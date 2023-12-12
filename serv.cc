#define CPPHTTPLIB_USE_POLL
#include "httplib.h"
#include "sqlwriter.hh"
#include "nlohmann/json.hpp"
#include "bcrypt.h"
#include <iostream>
#include <mutex>
#include "jsonhelper.hh"
#include "support.hh"
#include <fmt/core.h>
#include <stdexcept>
#include "argparse/argparse.hpp" 
#include <random>
using namespace std;

/*
Todo:
  Enable password reset
  Enable _actual_ thumbnails
  expiry
  UI
*/
      
struct LockedSqw
{
  SQLiteWriter& sqw;
  std::mutex& sqwlock;
  vector<unordered_map<string, MiniSQLite::outvar_t>> query(const std::string& query, const std::initializer_list<SQLiteWriter::var_t>& values)
  {
    std::lock_guard<mutex> l(sqwlock);
    return sqw.queryT(query, values);
  }

  void queryJ(httplib::Response &res, const std::string& q, const std::initializer_list<SQLiteWriter::var_t>& values) 
    try
      {
        auto result = query(q, values);
        res.set_content(packResultsJsonStr(result), "application/json");
      }
    catch(exception& e) {
      cerr<<"Error: "<<e.what()<<endl;
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

struct Users
{
  Users(LockedSqw& lsqw) : d_lsqw(lsqw)
  {}
  bool checkPassword(const std::string& user, const std::string& password) const;
  void createUser(const std::string& user, const std::string& password, const std::string& email, bool admin);
  set<string> getCaps(const std::string& user) const;
  bool userHasCap(const std::string& user, const std::string& cap)
  {
    bool ret=false;
    if(cap=="valid-user") {
      auto c = d_lsqw.query("select count(1) as c from users where useruser=? and disabled=0", {user});
      ret = (c.size()==1 && get<int64_t>(c[0]["c"])==1);
    }
    else if(cap=="admin") {
      auto c = d_lsqw.query("select count(1) as c from users where useruser=? and disabled=0 and admin=1", {user});
      ret = (c.size()==1 && get<int64_t>(c[0]["c"])==1);
    }
    return ret;
  }
  LockedSqw& d_lsqw;
};

bool Users::checkPassword(const std::string& user, const std::string& password) const
{
  auto res = d_lsqw.query("select pwhash, caps from users where useruser=? and disabled=0", {user});
  if(res.empty())
    return false;
  return bcrypt::validatePassword(password, get<string>(res[0]["pwhash"]));
}

void Users::createUser(const std::string& user, const std::string& password, const std::string& email, bool admin)
{
  string pwhash = bcrypt::generateHash(password);
  cout<<"Going to add user '"<<user<<"'"<<endl;
  d_lsqw.addValue({{"useruser", user}, {"pwhash", pwhash}, {"admin", (int)admin}, {"disabled", 0}, {"caps", ""}, {"lastLoginTstamp", 0}, {"email", email}}, "users");
}

class Sessions
{
public:
  Sessions(LockedSqw& lsqw) : d_lsqw(lsqw)
  {}

  string getUserForSession(const std::string& sessionid)
  {
    try {
      auto ret = d_lsqw.query("select * from sessions where sessionid=?", {sessionid});
      if(ret.size()==1)
        return get<string>(ret[0]["user"]);
    }
    catch(...){}
    return "";
  }
  string createSessionForUser(const std::string& user)
  {
    string sessionid=to_string(getRandom63())+to_string(getRandom63());
    d_lsqw.addValue({{"sessionid", sessionid}, {"user", user}, {"createTstamp", time(0)}}, "sessions");
    return sessionid;
  }

  void dropSession(const std::string& sessionid)
  {
    d_lsqw.query("delete from sessions where sessionid=?", {sessionid});
  }
private:
  LockedSqw& d_lsqw;
};

struct AuthReqs
{
  AuthReqs(Sessions& sessions, Users& users) : d_sessions(sessions), d_users(users)
  {}

  set<string> auths;

  string getSessionID(const httplib::Request &req) const
  {
    auto cookies = getCookies(req.get_header_value("Cookie"));
    auto siter = cookies.find("session");
    if(siter == cookies.end()) {
      throw std::runtime_error("No session cookie");
    }
    return siter->second;
  }
  bool check(const httplib::Request &req) const
  {
    string user = getUser(req);
    for(const auto& a : auths) {
      if(!d_users.userHasCap(user, a)) {
        cout<<"User '"<<user<<"' lacked capability '"<<a<<"'"<<endl;
        return false;
      }
    }
    return true;
  }

  void dropSession(const httplib::Request &req) 
  {
    d_sessions.dropSession(getSessionID(req));
  }

  string getUser(const httplib::Request &req)  const
  {
    return d_sessions.getUserForSession(getSessionID(req));
  }
  
  Sessions& d_sessions;
  Users& d_users;
};

struct AuthSentinel
{
  AuthSentinel(AuthReqs& ar, string auth) : d_ar(ar), d_auth(auth)
  {
    d_ar.auths.insert(d_auth);
  }
  ~AuthSentinel()
  {
    d_ar.auths.erase(d_auth);
  }

  AuthReqs& d_ar;
  string d_auth;
};


int main(int argc, char**argv)
{
  argparse::ArgumentParser args("serv");

  args.add_argument("db-file").help("file to read database from").default_value("trifecta.sqlite");
  args.add_argument("--html-dir").help("directory with our HTML files").default_value("./html/");
  args.add_argument("--admin-password").help("If set, create admin user with this password");
  args.add_argument("-p", "--port").help("port number to listen on").default_value(3456).scan<'i', int>();
  
  try {
    args.parse_args(argc, argv);
  }
  catch (const std::runtime_error& err) {
    std::cerr << err.what() << std::endl;
    std::cerr << args;
    std::exit(1);
  }

  SQLiteWriter sqw(args.get<string>("db-file"), {{"useruser", "UNIQUE"}});
  std::mutex sqwlock;
  LockedSqw lsqw{sqw, sqwlock};
  Users u(lsqw);
  
  if(auto fn = args.present("--admin-password")) {
    u.createUser("admin", *fn, "", true);
  }
  
  httplib::Server svr;
  
  svr.set_exception_handler([](const auto& req, auto& res, std::exception_ptr ep) {
    string reason;
    try {
      std::rethrow_exception(ep);
    } catch (std::exception &e) {
      reason = fmt::format("An error occurred: {}", e.what());
    } catch (...) { // See the following NOTE
      reason = "An unknown error occurred";
    }
    cout<<req.path<<": " 500 created for "<<reason<<endl;
    string html = fmt::format("<html><body><h1>Error</h1>{}</body></html>", reason);
    res.set_content(html, "text/html");
    res.status = 500;
  });
  
  svr.set_mount_point("/", args.get<string>("html-dir"));
  
  Sessions sessions(lsqw);
  AuthReqs a(sessions, u);

  // anyone can do this

  svr.Post("/login", [&lsqw, &sessions, &u](const httplib::Request &req, httplib::Response &res) {
    auto fields=getFormFields(req.body);
    for(const auto& f : fields) {
      fmt::print("'{}'\t'{}'\n", f.first, f.second);
    }

    string user = fields["user"];
    string password = fields["password"];
    nlohmann::json j;
    j["ok"]=0;
    if(u.checkPassword(user, password)) { 
      string sessionid = sessions.createSessionForUser(user);
      res.set_header("Set-Cookie",
                     "session="+sessionid+"; SameSite=Strict; Path=/; Max-Age="+to_string(5*365*86400));
      cout<<"Logged in user "<<user<<endl;
      j["ok"]=1;
      j["message"]="welcome!";
      lsqw.addValue({{"action", "login"}, {"user", user}, {"ip", req.remote_addr}, {"tstamp", time(0)}}, "log");
      lsqw.query("update users set lastLoginTstamp=? where useruser=?", {time(0), user});
              
    }
    else {
      j["message"]="Wrong user or password";
      lsqw.addValue({{"action", "failed-login"}, {"user", user}, {"ip", req.remote_addr}, {"tstamp", time(0)}}, "log");
    }
    
    res.set_content(j.dump(), "application/json");
  });

  svr.Get("/join-session/:sessionid", [&lsqw, a](const auto& req, auto& res) {
    string sessionid = req.path_params.at("sessionid");
    
    res.set_header("Set-Cookie",
                   "session="+sessionid+"; SameSite=Strict; Path=/; Max-Age="+to_string(5*365*86400));
    res.set_header("Location", "../");
    res.status = 303;
    
  });
  
  svr.Get("/i/:imgid", [&lsqw, a](const auto& req, auto& res) {
    string imgid = req.path_params.at("imgid");
    string user;
    res.status = 404;
    
    try {
      user = a.getUser(req);
    }catch(...){}
    
    auto results = lsqw.query("select image,publicUntilTstamp,user from images where id=? and (public=1 or user=?) ", {imgid, user});

    if(results.size() != 1) {
      return;
    }

    // if not owned by user, need to check publicUntilTstamp
    if(get<string>(results[0]["user"]) != user) {
      if(auto ptr = get_if<int64_t>(&results[0]["publicUntilTstamp"]) ) {
        if(*ptr && *ptr < time(0))
          return;
      }
    }
    
    auto img = get<vector<uint8_t>>(results[0]["image"]);
    string s((char*)&img[0], img.size());
    res.set_content(s, "image/png");
    res.status = 200;
  });

  svr.Get("/status", [&lsqw, a](const httplib::Request &req, httplib::Response &res) {
    nlohmann::json j;
    string user;
    try {
      user = a.getUser(req);
    }
    catch(exception& e) {
      cout<<"On /status, could not find a session"<<endl;
    }
      
    j["login"] = !user.empty();
    if(!user.empty())
      j["user"] = user;
    
    res.set_content(j.dump(), "application/json");
  });
  

  {
    AuthSentinel as(a, "valid-user");

    svr.Post("/upload", [&lsqw, a](const auto& req, auto& res) {
      if(!a.check(req))
        throw std::runtime_error("Can't upload if not logged in");
      time_t tstamp = time(0);
      for(auto&& [name, f] : req.files) {
        fmt::print("name {}, filename {}, content_type {}, size {}\n", f.name, f.filename, f.content_type, f.content.size());
        vector<uint8_t> content(f.content.c_str(), f.content.c_str() + f.content.size());
        auto imgid=makeShortID(getRandom63());
        lsqw.addValue({{"id", imgid}, {"public", 1},
                       {"ip", req.remote_addr},
                       {"user", a.getUser(req)},
                       {"timestamp", tstamp},
                       {"image", content},
                       {"content_type", f.content_type},
                       {"publicUntilTstamp", 0}}, "images");
        nlohmann::json j;
        j["id"]=imgid;
        res.set_content(j.dump(), "application/json");
        lsqw.addValue({{"action", "upload"} , {"image_id", imgid}, {"tstamp", tstamp}}, "log");
        break;
      }
      
    });

    svr.Post("/delete-image/(.+)", [&lsqw, a](const auto& req, auto& res) {
      if(!a.check(req))
        throw std::runtime_error("Can't delete if not logged in");
      string imgid = req.matches[1];

      string user = a.getUser(req);
      cout<<"Attemping to delete image "<<imgid<<" for user " << user << endl;
      lsqw.query("delete from images where id=? and user=?", {imgid, user});
      lsqw.addValue({{"action", "delete-image"}, {"user", user}, {"image_id", imgid}, {"tstamp", time(0)}}, "log");
    });

    svr.Post("/set-image-public/([^/]+)/([01])", [&lsqw, a](const auto& req, auto& res) {
      cout<<"change image public called"<<endl;

      if(!a.check(req))
        throw std::runtime_error("Can't delete if not logged in");
      string imgid = req.matches[1];
      bool pub = stoi(req.matches[2]);
      cout<<"imgid: "<<imgid<<", new state: "<<pub<<endl;
      string user = a.getUser(req);
      // XXX admin should be able to do this for everyone
      lsqw.query("update images set public =? where id=? and user=?", {pub, imgid, a.getUser(req)});
      lsqw.addValue({{"action", "change-image-public"}, {"user", user}, {"image_id", imgid}, {"pub", pub}, {"tstamp", time(0)}}, "log");
    });

    
    svr.Get("/can_touch_image/:imgid", [&lsqw, a](const httplib::Request &req, httplib::Response &res) {
      nlohmann::json j;
      string imgid = req.path_params.at("imgid");

      j["can_touch_image"]=0;
      
      try {
        if(a.check(req)) {
          string user = a.getUser(req);
          auto sqres = lsqw.query("select count(1) as c from images where id=? and user=?", {imgid, user});
          if(get<int64_t>(sqres[0]["c"]))
            j["can_touch_image"]=1;
        }
      }
      catch(exception&e) { cout<<"No session for checking access rights: "<<e.what()<<"\n";}
      // now check if user is admin, and then also set to 1 XXX
      res.set_content(j.dump(), "application/json");
    });

    
    svr.Get("/myimages", [&lsqw, a](const httplib::Request &req, httplib::Response &res) {
      if(!a.check(req)) {
        throw std::runtime_error("Not admin");
      }
      lsqw.queryJ(res, "select id, timestamp,content_type,length(image) as size, public, publicUntilTstamp from images where user=?", {a.getUser(req)});
    });  

    svr.Post("/logout", [&lsqw, a](const httplib::Request &req, httplib::Response &res) mutable {
      if(a.check(req)) {
        lsqw.addValue({{"action", "logout"}, {"user", a.getUser(req)}, {"ip", req.remote_addr}, {"tstamp", time(0)}}, "log");
        a.dropSession(req);
        res.set_header("Set-Cookie",
                       "session="+a.getSessionID(req)+"; SameSite=Strict; Path=/; Max-Age=0");

      }
    });
    
    {
      AuthSentinel as(a, "admin");
      svr.Get("/images", [&lsqw, a](const httplib::Request &req, httplib::Response &res) {
        if(!a.check(req)) {
          throw std::runtime_error("Not admin");
        }
        lsqw.queryJ(res, "select id, user,timestamp,content_type,length(image) as size, public,ip from images", {});
      });

      svr.Post("/create-user", [&lsqw, &sessions, &u](const httplib::Request &req, httplib::Response &res) {
        auto fields=getFormFields(req.body);
        for(const auto& f : fields) {
          fmt::print("'{}'\t'{}'\n", f.first, f.second);
        }
        
      });
      
    }


    
  }
  
  cout<<"Will listen on http://127.0.0.1:"<<args.get<int>("port")<<endl;
  svr.listen("0.0.0.0", args.get<int>("port"));
}
