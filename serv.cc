#define CPPHTTPLIB_USE_POLL
#include <exception>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>
#include "argparse/argparse.hpp"
#include "fmt/core.h"
#include "support.hh"
#include "git_version.h"
using namespace std;

/*
Todo:
  if a user is disabled, do images/posts turn into 404s?
  opengraph data for previews, how? iframe?

  how do we deal with errors?  500? or a JSON thing?
    plan: never do 500, always set an 'ok' field 
*/

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

  if(!get<int64_t>(row["public"])) // not public, no show
    return false;

  time_t pubUntil = get<int64_t>(row["publicUntilTstamp"]);
  return (!pubUntil || time(0) < pubUntil);
}

int trifectaMain(int argc, const char**argv)
{
  argparse::ArgumentParser args("serv", GIT_VERSION);

  args.add_argument("db-file").help("file to read database from").default_value("trifecta.sqlite");
  args.add_argument("--html-dir").help("directory with our HTML files").default_value("./html/");
  args.add_argument("--rnd-admin-password").help("Create admin user if necessary, and set a random password").default_value(string(""));
  args.add_argument("-p", "--port").help("port number to listen on").default_value(3456).scan<'i', int>();
  args.add_argument("--local-address", "-l").help("address to listen on").default_value("127.0.0.1");
  args.add_argument("--smtp-server", "-s").help("SMTP server to use").default_value("127.0.0.1:25");
  args.add_argument("--smtp-from", "-f").help("Origin/from email address to use").default_value("changeme@example.com");
  args.add_argument("--canonical-url", "-c").help("Canonical URL of service").default_value("");

  string canURL;
  try {
    args.parse_args(argc, argv);
    canURL=args.get<string>("canonical-url");
    if(canURL.empty()) {
      canURL="http://"+args.get<string>("local-address")+":"+to_string(args.get<int>("port"));
    }
  }
  catch (const std::runtime_error& err) {
    std::cout << err.what() << std::endl << args;
    std::exit(1);
  }
  fmt::print("Database is in {}, canonical URL is {}\n", args.get<string>("db-file"), canURL);
  SQLiteWriter sqw(args.get<string>("db-file"),
                   {
                     {"users", {{"user", "PRIMARY KEY"}}},
                     {"posts", {{"id", "PRIMARY KEY"}, {"user", "NOT NULL REFERENCES users(user) ON DELETE CASCADE"}}},
                     {"images", {{"id", "PRIMARY KEY"}, {"postId", "NOT NULL REFERENCES posts(id) ON DELETE CASCADE"}}},
                     {"sessions", {{"id", "PRIMARY KEY"}, {"user", "NOT NULL REFERENCES users(user) ON DELETE CASCADE"}}}
                   });
  std::mutex sqwlock;
  LockedSqw lsqw{sqw, sqwlock};
  SimpleWebSystem sws(lsqw);
  sws.standardFunctions();
  if(args.is_used("--rnd-admin-password")) {
    bool changed=false;
    string pw = makeShortID(getRandom63());

    testrunnerPw() = pw;     // for the testrunner

    try {
      if(sws.d_users.userHasCap("admin", Capability::Admin)) {
        cout<<"Admin user existed already, updating password to: "<< pw << endl;
        sws.d_users.changePassword("admin", pw);
        changed=true;
      }
    }
    catch(...) {
    }

    if(!changed) {
      fmt::print("Creating user admin with password: {}\n", pw);
      sws.d_users.createUser("admin", pw, "", true);
    }
    if(args.get<string>("rnd-admin-password") != "continue")
      return EXIT_SUCCESS;
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

  sws.d_svr.set_mount_point("/", args.get<string>("html-dir"));
   
  sws.wrapGet({}, "/getPost/:postid", [&sws](const auto& req, auto& res, const std::string& user) {
    string postid = req.path_params.at("postid");
    nlohmann::json j;

    auto post = sws.d_lsqw.query("select user, public, title, publicUntilTstamp from posts where id=?", {postid});
    if(post.size() != 1) {
      j["images"] = nlohmann::json::array();
    }
    else if(shouldShow(sws.d_users, user, post[0])) {
      auto images = sws.d_lsqw.query("select images.id as id, caption from images,posts where postId = ? and images.postId = posts.id", {postid});

      j["images"]=packResultsJson(images);
      j["title"]=get<string>(post[0]["title"]);
      j["public"]=get<int64_t>(post[0]["public"]);
      time_t until = get<int64_t>(post[0]["publicUntilTstamp"]);
      j["publicUntil"]=until;
      if(!user.empty())
        j["can_touch_post"] = canTouchPost(sws.d_lsqw, sws.d_users, user, postid) ? 1 : 0;
      else
        j["can_touch_post"] = 0;
      j["publicUntilExpired"] = until && (time(0) < until);
    }
    return j;
  });

  sws.wrapGet({}, "/i/:imgid", [&sws](const auto& req, auto& res, const string& user) {
    string imgid = req.path_params.at("imgid");
    res.status = 404;

    auto results = sws.d_lsqw.query("select image,public,content_type, posts.publicUntilTstamp, posts.user from images,posts where images.id=? and posts.id = images.postId ", {imgid});

    if(results.size() != 1) {
      sws.d_lsqw.addValue({{"action", "view-failed"} , {"user", user}, {"imageId", imgid}, {"ip", getIP(req)}, {"tstamp", time(0)}, {"meta", "no such image"}}, "log");
      return pair<string,string>("No such file", "text/html");
    }

    if(!shouldShow(sws.d_users, user, results[0])) {
      sws.d_lsqw.addValue({{"action", "view-failed"} , {"user", user}, {"imageId", imgid}, {"ip", getIP(req)}, {"tstamp", time(0)}}, "log");
      return pair<string,string>("No such file", "text/html");
    }

    auto img = get<vector<uint8_t>>(results[0]["image"]);
    string s((char*)&img[0], img.size());
    res.status = 200;

    sws.d_lsqw.addValue({{"action", "view"} , {"user", user}, {"imageId", imgid}, {"ip", getIP(req)}, {"tstamp", time(0)}}, "log");
    return make_pair(s, get<string>(results[0]["content_type"]));
  });

  sws.wrapPost({Capability::IsUser}, "/upload", [&sws](const auto& req, auto& res, const std::string& user) {
    time_t tstamp = time(0);
    string postId = req.get_file_value("postId").content;
    if(postId.empty()) {
      postId = makeShortID(getRandom63());
      sws.d_lsqw.addValue({{"id", postId}, {"user", user}, {"stamp", tstamp}, {"public", 1}, {"publicUntilTstamp", 0}, {"title", ""}}, "posts");
    }
    else if(!sws.d_users.userHasCap(user, Capability::Admin)) {
      auto access=sws.d_lsqw.query("select id from posts where id=? and user=?", {postId, user});
      if(access.empty())
        throw std::runtime_error("Attempt to upload to post that's not ours!");
    }
    
    nlohmann::json j; // if you upload multiple files in one go, this does the wrong thing
    for(auto&& [name, f] : req.files) {
      fmt::print("name {}, filename {}, content_type {}, size {}, postid {}\n", f.name, f.filename, f.content_type, f.content.size(), postId);
      if(f.content_type.substr(0,6) != "image/" || f.filename.empty()) {
        cout<<"Skipping non-image or non-file (type " << f.content_type<<", filename '"<<f.filename<<"')"<<endl;
        continue;
      }
      vector<uint8_t> content(f.content.c_str(), f.content.c_str() + f.content.size());
      auto imgid=makeShortID(getRandom63());
      sws.d_lsqw.addValue({{"id", imgid},
                     {"ip", getIP(req)},
                     {"tstamp", tstamp},
                     {"image", content},
                     {"content_type", f.content_type},
                     {"postId", postId},
                     {"caption", ""}
        }, "images");
      
      j["id"]=imgid;
      j["postId"] = postId;
      
      auto row = sws.d_lsqw.query("select public, publicUntilTstamp from posts where id=?", {postId});
      if(!row.empty()) {
        j["public"] = get<int64_t>(row[0]["public"]);
        j["publicUntil"] = get<int64_t>(row[0]["publicUntilTstamp"]);;
      }
      sws.d_lsqw.addValue({{"action", "upload"} , {"user", user}, {"imageId", imgid}, {"ip", getIP(req)}, {"tstamp", tstamp}}, "log");
    }
    return j;
  });
  
  sws.wrapPost({Capability::IsUser}, "/delete-image/(.+)", [&sws](const auto& req, auto& res, const std::string& user) {
    string imgid = req.matches[1];
    checkImageOwnership(sws.d_lsqw, sws.d_users, user, imgid);
    
    sws.d_lsqw.query("delete from images where id=?", {imgid});
    sws.d_lsqw.addValue({{"action", "delete-image"}, {"ip", getIP(req)}, {"user", user}, {"imageId", imgid}, {"tstamp", time(0)}}, "log");
    return nlohmann::json{{"ok", 1}};
  });
  
  sws.wrapPost({Capability::IsUser}, "/delete-post/(.+)", [&sws](const auto& req, auto& res, const string& user) {
    string postid = req.matches[1];
    nlohmann::json j{{"ok", 0}};
    if(canTouchPost(sws.d_lsqw, sws.d_users, user, postid)) {
      sws.d_lsqw.query("delete from posts where id=?", {postid});
      j["ok"]=1;
    }
    else {
      cout<<"Tried to delete post "<<postid<<" but user "<<user<<" had no rights"<<endl;
    }
    return j;
  });
  
  sws.wrapPost({Capability::IsUser}, "/set-post-title/(.+)", [&sws](const auto& req, auto& res, const string& user) {
    string postid = req.matches[1];
    string title = req.get_file_value("title").content;
    
    auto rows = sws.d_lsqw.query("select user from posts where id=?", {postid});
    if(rows.size() != 1)
      throw std::runtime_error("Attempting to change title for post that does not exist");
    
    if(get<string>(rows[0]["user"]) != user && !sws.d_users.userHasCap(user, Capability::Admin))
      throw std::runtime_error("Attempting to change title for post that is not yours and you are not admin");
    
    sws.d_lsqw.query("update posts set title=? where user=? and id=?", {title, user, postid});
    sws.d_lsqw.addValue({{"action", "set-post-title"}, {"ip", getIP(req)}, {"user", user}, {"postId", postid}, {"tstamp", time(0)}}, "log");
    return nlohmann::json{{"ok", 1}};
  });
  
  sws.wrapPost({Capability::IsUser}, "/set-image-caption/(.+)", [&sws](const auto& req, auto& res, const string& user) {
    string imgid = req.matches[1];
    string caption = req.get_file_value("caption").content;
    
    checkImageOwnership(sws.d_lsqw, sws.d_users, user, imgid);
    sws.d_lsqw.query("update images set caption=? where id=?", {caption, imgid});
    sws.d_lsqw.addValue({{"action", "set-image-caption"}, {"ip", getIP(req)}, {"user", user}, {"imageId", imgid}, {"tstamp", time(0)}}, "log");
    return nlohmann::json{{"ok", 1}};
  });
  
  sws.wrapPost({Capability::IsUser}, "/set-post-public/([^/]+)/([01])/?([0-9]*)", [&sws](const auto& req, auto& res, const string& user) {
    string postid = req.matches[1];
    bool pub = stoi(req.matches[2]);
    time_t until=0;
    
    if(!canTouchPost(sws.d_lsqw, sws.d_users, user, postid))
      throw std::runtime_error("Attempt to change public status of post you can't touch");
    if(req.matches.size() > 3) {
      string untilStr = req.matches[3];
      if(!untilStr.empty())
        until = stoi(untilStr);
    }

    if(!pub && until)
      throw std::runtime_error("Attempting to set nonsensical combination for public");
    
    if(until)
      sws.d_lsqw.query("update posts set public = ?, publicUntilTstamp=? where id=?", {pub, until, postid});
    else
      sws.d_lsqw.query("update posts set public =? where id=?", {pub, postid});
    sws.d_lsqw.addValue({{"action", "change-post-public"}, {"ip", getIP(req)}, {"user", user}, {"postId", postid}, {"pub", pub}, {"tstamp", time(0)}}, "log");
    return nlohmann::json{{"ok", 1}};
  });
    
  sws.wrapGet({Capability::IsUser}, "/my-images", [&sws](const auto &req, auto &res, const string& user) {
    return sws.d_lsqw.queryJRet("select images.id as id, postid, images.tstamp, content_type,length(image) as size, public, posts.publicUntilTstamp,title,caption from images,posts where postId = posts.id and user=?", {user});
    });

  sws.wrapGet({Capability::Admin}, "/all-images", [&sws](const auto &req, auto &res, const string& user) {
    return sws.d_lsqw.queryJRet("select images.id as id, postId, user,tstamp,content_type,length(image) as size, posts.public, ip from images,posts where posts.id=images.postId");
  });

  sws.wrapPost({}, "/get-signin-email", [&sws, &args, canURL](const auto &req, httplib::Response &res, const std::string& ign) {
    string user = req.get_file_value("user").content;
    string email = sws.d_users.getEmail(user); // CHECK FOR DISABLED USER!!
    fmt::print("User '{}', email '{}'\n", user, email);
    nlohmann::json j;
    j["message"] = "If this user exists and has an email address, a message was sent";
    j["ok"]=1;
    if(!email.empty()) {
      // valid for 1 day
      string session = sws.d_sessions.createSessionForUser(user, "Change password session", getIP(req), true, time(0)+86400); // authenticated session
      string dest=canURL;
      if(dest.empty() || *dest.rbegin()!='/')
        dest += '/';
      dest += "reset.html?session="+session;
      sendAsciiEmailAsync(args.get<string>("smtp-server"), args.get<string>("smtp-from"), email, "Trifecta sign-in link",
                          "Going to this link will allow you to reset your password or sign you in directly: "+dest+"\nEnjoy!");
      cout<<"Sent email pointing user at "<<dest<<endl;
    }
    else
      cout<<"Had no email address for user "<<user<<endl;
    
    return j;
  });

  
  string laddr = args.get<string>("local-address");
  cout<<"Will listen on http://"<< laddr <<":"<<args.get<int>("port")<<endl;

  sws.d_svr.set_socket_options([](socket_t sock) {
   int yes = 1;
   setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
                reinterpret_cast<const void *>(&yes), sizeof(yes));
  });

  if(!sws.d_svr.listen(laddr, args.get<int>("port"))) {
    cout<<"Error launching server: "<<strerror(errno)<<endl;
    return EXIT_FAILURE;
  }
  cout<<"Stopping"<<endl;
  return 0;
}
