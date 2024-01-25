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

  if(u.isUserDisabled(get<string>(row["user"])))
    return false;
  
  time_t pubUntil = get<int64_t>(row["publicUntilTstamp"]);
  return (!pubUntil || time(0) < pubUntil);
}

static string getEnvOr(const std::string& envname, const std::string& def)
{
  auto ptr = getenv(envname.c_str());
  return ptr ? string(ptr) : def;
}

int trifectaMain(int argc, const char**argv)
{
  argparse::ArgumentParser args("trifecta", GIT_VERSION);

  args.add_argument("--db-file").help("file to read database from").default_value(getEnvOr("TRIFECTA_DB", "trifecta.sqlite"));
  args.add_argument("--html-dir").help("directory with our HTML files").default_value(getEnvOr("TRIFECTA_HTML_DIR", "./html/"));
  args.add_argument("--rnd-admin-password").help("Create admin user if necessary, and set a random password").default_value(string(""));
  args.add_argument("-p", "--port").help("port number to listen on").default_value(std::stoi(getEnvOr("TRIFECTA_PORT", "3456"))).scan<'i', int>();
  args.add_argument("--local-address", "-l").help("address to listen on").default_value(getEnvOr("TRIFECTA_LOCAL", "127.0.0.1"));
  args.add_argument("--smtp-server", "-s").help("SMTP server to use").default_value(getEnvOr("TRIFECTA_SMTP_SERVER", "127.0.0.1:25"));
  args.add_argument("--smtp-from", "-f").help("Origin/from email address to use").default_value(getEnvOr("TRIFECTA_MAIL_FROM", "changeme@example.com"));
  args.add_argument("--canonical-url", "-c").help("Canonical URL of service").default_value(getEnvOr("TRIFECTA_CAN_URL", ""));
  args.add_argument("--real-ip-header", "-r").help("HTTP header containing the real IP of visitor").default_value(getEnvOr("TRIFECTA_REAL_IP_HEADER", "X-Real-IP"));
  args.add_argument("--trusted-proxy","-t").default_value<std::vector<std::string>>({ getEnvOr("TRIFECTA_TRUSTED_PROXY", "127.0.0.1") })
    .append().help("IP address of a trusted proxy");

  string canURL;
  try {
    args.parse_args(argc, argv);
    canURL=args.get<string>("canonical-url");
    if(canURL.empty()) {
      canURL="http://"+args.get<string>("local-address")+":"+to_string(args.get<int>("port"));
    }
    if(canURL.empty() || *canURL.rbegin()!='/')
        canURL += '/';

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
  sws.setTrustedProxies(args.get<vector<string>>("trusted-proxy"), args.get<string>("real-ip-header"));
  sws.standardFunctions();
  if(args.is_used("--rnd-admin-password")) {
    bool changed=false;
    string pw = makeShortID(getRandom64());

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

  // this is here to insert opengraph tags into the HTML, because crawlers won't execute javascript for us
  sws.d_svr.set_file_request_handler([&sws, &canURL](const httplib::Request& req, httplib::Response& res) {
    if(req.path=="/") {
      string searchString="<!-- opengraph -->";
      size_t pos = res.body.find(searchString);
      if(pos == string::npos)
        return;
      auto iter = req.params.find("p");
      if(iter == req.params.end())
        return;

      string rep;
      auto rows = sws.d_lsqw.query("select images.id as iid, posts.id as pid, user, title, content_type, caption, public, publicUntilTstamp from posts,images where posts.id=? and posts.id = images.postId", {iter->second});
      if(rows.empty())
        return;

      string user;
      try { user = sws.d_sessions.getUser(req, sws.getIP(req)); } catch(...){}

      if(!shouldShow(sws.d_users, user, rows[0]))
        return;

      rep += fmt::format(R"(<meta property="og:title" content="{}" />)", htmlEscape(get<string>(rows[0]["title"])));
      rep += fmt::format(R"(<meta property="og:description" content="{}" />)", htmlEscape(get<string>(rows[0]["caption"])));
      rep += fmt::format(R"(<meta property="og:url" content="{}">)", htmlEscape(canURL+"?p="+get<string>(rows[0]["pid"])));
      rep += R"(<meta property="og:site_name" content="Trifecta"><meta property="og:type" content="article">)";
      for(auto& row : rows) {
        rep += "\n";
        rep += fmt::format(R"(<meta property="og:image" content="{}" />)", canURL+"i/"+htmlEscape(get<string>(row["iid"])))+"\n";
        rep += fmt::format(R"(<meta property="og:image:type" content="{}" />)", htmlEscape(get<string>(row["content_type"])))+"\n";
        rep += fmt::format(R"(<meta property="og:image:alt" content="{}" />)", htmlEscape(get<string>(row["caption"])))+"\n";
      }
      /*
<meta property='article:published_time' content='2023-12-30T10:56:56&#43;01:00'/><meta property='article:modified_time' content='2023-12-30T10:56:56&#43;01:00'/>
      */
      
      res.body.replace(pos, searchString.length(), rep);
    }
  });
  
  sws.d_svr.set_mount_point("/", args.get<string>("html-dir"));
  
  sws.wrapGet({}, "/getPost/:postid", [](auto& cr) {
    string postid = cr.req.path_params.at("postid");
    nlohmann::json j;
    j["ok"]=0;
    auto post = cr.lsqw.query("select user, public, title, publicUntilTstamp from posts where id=?", {postid});
    if(post.size() != 1) {
      j["images"] = nlohmann::json::array();
    }
    else if(shouldShow(cr.users, cr.user, post[0])) {
      auto images = cr.lsqw.query("select images.id as id, caption from images,posts where postId = ? and images.postId = posts.id", {postid});

      j["images"]=packResultsJson(images);
      j["title"]=get<string>(post[0]["title"]);
      j["public"]=get<int64_t>(post[0]["public"]);
      time_t until = get<int64_t>(post[0]["publicUntilTstamp"]);
      j["publicUntil"]=until;
      if(!cr.user.empty())
        j["can_touch_post"] = canTouchPost(cr.lsqw, cr.users, cr.user, postid) ? 1 : 0;
      else
        j["can_touch_post"] = 0;
      j["publicUntilExpired"] = until && (time(0) < until);
      j["ok"]=1;
    }
    return j;
  });

  sws.wrapGet({}, "/i/:imgid", [](auto& cr) {
    string imgid = cr.req.path_params.at("imgid");
    cr.res.status = 404;

    auto results = cr.lsqw.query("select image,public,content_type, posts.publicUntilTstamp, posts.user from images,posts where images.id=? and posts.id = images.postId ", {imgid});

    if(results.size() != 1) {
      cr.log({{"action", "view-failed"} , {"imageId", imgid}, {"meta", "no such image"}});
      return pair<string,string>("No such file", "text/html");
    }

    if(!shouldShow(cr.users, cr.user, results[0])) {
      cr.log({{"action", "view-failed"} , {"imageId", imgid}});
      return pair<string,string>("No such file", "text/html");
    }

    auto img = get<vector<uint8_t>>(results[0]["image"]);
    string s((char*)&img[0], img.size());
    cr.res.status = 200;

    cr.log({{"action", "view"}, {"imageId", imgid}});
    // this is needed for SVG which can contain embedded JavaScript (yes) and iframes
    cr.res.set_header("Content-Security-Policy", "script-src 'none'; frame-src 'none';");
    // this prevents browsers from loading scripts/stylesheets through us
    cr.res.set_header("X-Content-Type-Options", "nosniff");
    return make_pair(s, get<string>(results[0]["content_type"]));
  });

  sws.wrapPost({Capability::IsUser}, "/upload", [](auto& cr) {
    time_t tstamp = time(0);
    string postId = cr.req.get_file_value("postId").content;
    if(postId.empty()) {
      postId = makeShortID(getRandom64());
      cr.lsqw.addValue({{"id", postId}, {"user", cr.user}, {"stamp", tstamp}, {"public", 1}, {"publicUntilTstamp", 0}, {"title", ""}}, "posts");
    }
    else if(!cr.users.userHasCap(cr.user, Capability::Admin)) {
      auto access=cr.lsqw.query("select id from posts where id=? and user=?", {postId, cr.user});
      if(access.empty())
        throw std::runtime_error("Attempt to upload to post that's not ours!");
    }
    
    nlohmann::json j; // if you upload multiple files in one go, this does the wrong thing
    for(auto&& [name, f] : cr.req.files) {
      fmt::print("upload name {}, filename {}, content_type {}, size {}, postid {}\n", f.name, f.filename, f.content_type, f.content.size(), postId);
      if(f.content_type.substr(0,6) != "image/" || f.content_type.find_first_of(" \t\n\r") != string::npos
         || f.filename.empty()) {
        cout<<"Skipping non-image or non-file (type " << f.content_type<<", filename '"<<f.filename<<"')"<<endl;
        continue;
      }
      vector<uint8_t> content(f.content.c_str(), f.content.c_str() + f.content.size());
      auto imgid=makeShortID(getRandom64());
      cr.lsqw.addValue({{"id", imgid},
                     {"ip", cr.getIP()},
                     {"tstamp", tstamp},
                     {"image", content},
                     {"content_type", f.content_type},
                     {"postId", postId},
                     {"caption", ""}
        }, "images");
      
      j["id"]=imgid;
      j["postId"] = postId;
      
      auto row = cr.lsqw.query("select public, publicUntilTstamp from posts where id=?", {postId});
      if(!row.empty()) {
        j["public"] = get<int64_t>(row[0]["public"]);
        j["publicUntil"] = get<int64_t>(row[0]["publicUntilTstamp"]);;
      }
      cr.log({{"action", "upload"} , {"imageId", imgid}});
    }
    return j;
  });
  
  sws.wrapPost({Capability::IsUser}, "/delete-image/(.+)", [](auto& cr) {
    string imgid = cr.req.matches[1];
    checkImageOwnership(cr.lsqw, cr.users, cr.user, imgid);
    
    cr.lsqw.query("delete from images where id=?", {imgid});
    cr.log({{"action", "delete-image"}, {"imageId", imgid}});
    return nlohmann::json{{"ok", 1}};
  });
  
  sws.wrapPost({Capability::IsUser}, "/delete-post/(.+)", [](auto& cr) {
    string postid = cr.req.matches[1];
    nlohmann::json j{{"ok", 0}};
    if(canTouchPost(cr.lsqw, cr.users, cr.user, postid)) {
      cr.lsqw.query("delete from posts where id=?", {postid});
      j["ok"]=1;
    }
    else {
      cout<<"Tried to delete post "<<postid<<" but user "<<cr.user<<" had no rights"<<endl;
    }
    return j;
  });
  
  sws.wrapPost({Capability::IsUser}, "/set-post-title/(.+)", [](auto& cr) {
    string postid = cr.req.matches[1];
    string title = cr.req.get_file_value("title").content;
    
    auto rows = cr.lsqw.query("select user from posts where id=?", {postid});
    if(rows.size() != 1)
      throw std::runtime_error("Attempting to change title for post that does not exist");
    
    if(get<string>(rows[0]["user"]) != cr.user && !cr.users.userHasCap(cr.user, Capability::Admin))
      throw std::runtime_error("Attempting to change title for post that is not yours and you are not admin");
    
    cr.lsqw.query("update posts set title=? where user=? and id=?", {title, cr.user, postid});
    cr.log({{"action", "set-post-title"}, {"title", title}});
    return nlohmann::json{{"ok", 1}};
  });
  
  sws.wrapPost({Capability::IsUser}, "/set-image-caption/(.+)", [](auto& cr) {
    string imgid = cr.req.matches[1];
    string caption = cr.req.get_file_value("caption").content;
    
    checkImageOwnership(cr.lsqw, cr.users, cr.user, imgid);
    cr.lsqw.query("update images set caption=? where id=?", {caption, imgid});
    cr.log({{"action", "set-image-caption"}, {"imageId", imgid}});
    return nlohmann::json{{"ok", 1}};
  });
  
  sws.wrapPost({Capability::IsUser}, "/set-post-public/([^/]+)/([01])/?([0-9]*)", [](auto& cr) {
    string postid = cr.req.matches[1];
    bool pub = stoi(cr.req.matches[2]);
    time_t until=0;
    
    if(!canTouchPost(cr.lsqw, cr.users, cr.user, postid))
      throw std::runtime_error("Attempt to change public status of post you can't touch");
    if(cr.req.matches.size() > 3) {
      string untilStr = cr.req.matches[3];
      if(!untilStr.empty())
        until = stoi(untilStr);
    }

    if(!pub && until)
      throw std::runtime_error("Attempting to set nonsensical combination for public");
    
    if(until)
      cr.lsqw.query("update posts set public = ?, publicUntilTstamp=? where id=?", {pub, until, postid});
    else
      cr.lsqw.query("update posts set public =? where id=?", {pub, postid});
    cr.log({{"action", "change-post-public"}, {"postId", postid}, {"pub", pub}});
    return nlohmann::json{{"ok", 1}};
  });
    
  sws.wrapGet({Capability::IsUser}, "/my-images", [](auto& cr) {
    return cr.lsqw.queryJRet("select images.id as id, postid, images.tstamp, content_type,length(image) as size, public, posts.publicUntilTstamp,title,caption from images,posts where postId = posts.id and user=?", {cr.user});
    });

  sws.wrapGet({Capability::Admin}, "/all-images", [](auto& cr) {
    return cr.lsqw.queryJRet("select images.id as id, postId, user,tstamp,content_type,length(image) as size, posts.public, ip from images,posts where posts.id=images.postId");
  });

  sws.wrapPost({}, "/get-signin-email", [&sws, &args, canURL](auto& cr) {
    string user = cr.req.get_file_value("user").content;
    string email = cr.users.getEmail(user); // CHECK FOR DISABLED USER!!
    fmt::print("User '{}', email '{}'\n", user, email);
    nlohmann::json j;
    j["message"] = "If this user exists and has an email address, a message was sent";
    j["ok"]=1;
    if(!email.empty()) {
      // valid for 1 day
      string session = cr.sessions.createSessionForUser(user, "Change password session", cr.getIP(), true, time(0)+86400); // authenticated session
      string dest=canURL;
      dest += "reset.html?session="+session;
      sendAsciiEmailAsync(args.get<string>("smtp-server"), args.get<string>("smtp-from"), email, "Trifecta sign-in link",
                          "Going to this link will allow you to reset your password or sign you in directly: "+dest+"\nNOTE! This will only work ONCE! Otherwise request a new email. Enjoy!");
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
