#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <algorithm> // std::move() and friends
#include <stdexcept>
#include <string>
#include <thread>
#include <unistd.h> //unlink(), usleep()
#include <unordered_map>
#include "doctest.h"
#include "httplib.h"
#include "nlohmann/json.hpp"

#include "support.hh"

using namespace std;

TEST_CASE("cookie test") {
  auto res = getCookies("test=1235; test2=9876");
  CHECK(res.size() == 2);
  CHECK(res["test"]=="1235");
  CHECK(res["test2"]=="9876");

  res = getCookies("user=ahu");
  CHECK(res.size() == 1);
  CHECK(res["user"]=="ahu");

  res = getCookies("test=1235; test2=9876; boeh=bah");
  CHECK(res.size() == 3);
  CHECK(res["test"]=="1235");
  CHECK(res["test2"]=="9876");
  CHECK(res["boeh"]=="bah");
}


TEST_CASE("base64url id") {
  CHECK(makeShortID((1ULL<<62) - 132430)== "svr9_____z8");
  CHECK(makeShortID( 4529558240454539472)== "0Hi8lzg53D4");
  CHECK(makeShortID(2984614381840956837) == "pf0mlfd6ayk");
  CHECK(makeShortID(1) == "AQAAAAAAAAA");
}

TEST_CASE("random test") {
  std::unordered_map<uint64_t, int> c;
  for(unsigned int n = 0 ; n < 500000;++n)
    c[getRandom64()]++;

  int dups=0;
  for(auto&& [key, val] : c)
    if(val>1) dups++;
  CHECK(dups == 0);
}


namespace {
  struct TrifectaServer
  {
    TrifectaServer() {
      std::thread t1([]() {
        unlink("testrunner.sqlite");
        const char* argv[] = {"./trifecta", "--db-file=testrunner.sqlite", "-p", "9999",
          "--rnd-admin-password=continue",
          "--local-address=127.0.0.1"};
        trifectaMain(6, argv);
      });
      d_t = std::move(t1);
      d_t.detach(); // now we wait for the server to be active
      usleep(250000); // bit sad, should have a semaphore
    }

    httplib::Headers doLogin(const string& user = "admin", const string& password="")
    {
      string rpassword=password;
      if(user == "admin" && rpassword.empty()) {
        rpassword = testrunnerPw();
      }
      httplib::Client cli("127.0.0.1", 9999);
      httplib::MultipartFormDataItems items = {
        { "user", user, "user"},
        { "password", rpassword, "password"},
      };

      auto res = cli.Post("/login", items);
      if(res == nullptr)
        throw std::runtime_error("Can't connect for login");

      nlohmann::json j= nlohmann::json::parse(res->body);

      if(j["ok"] != 1)
        throw std::runtime_error("Can't login user "+user+" with password '"+rpassword+"'");

      string cookieline= res->get_header_value("Set-Cookie");
      //session=c7XaOYsDOhYei09WzN_9hA; SameSite=Strict; Path=/; Max-Age=157680000
      auto pos = cookieline.find('=');
      if(pos == string::npos)
        throw std::runtime_error("Can't parse cookie line");
      auto pos2 = cookieline.find(';', pos);
      if(pos2 == string::npos)
        throw std::runtime_error("Can't parse cookie line 2");

      pos++;
      string session = cookieline.substr(pos, pos2-pos);
      //      cout<<"session is '"<<session<<"'\n";
      httplib::Headers headers = {
      { "Cookie", "trifecta_session="+session }
      };

      return headers;
    }

    ~TrifectaServer()
    {
      usleep(1100000); // so the sqlite stuff get synched
      /*
      cout<<"Destructor called"<<endl;

      auto headers = doLogin();
      httplib::Client cli("127.0.0.1", 9999);
      auto res = cli.Post("/stop", headers);
      cli.stop();
      */
    }
    std::thread d_t;
  };
  auto& getTFS()
  {
    static TrifectaServer tfs;
    return tfs;
  }
}

TEST_CASE("basic web tests") {

  httplib::Client cli("127.0.0.1", 9999);

  auto headers = getTFS().doLogin();
  
  auto res = cli.Get("/status", headers);
  REQUIRE(res != 0);
  nlohmann::json j = nlohmann::json::parse(res->body);
  CHECK(j["admin"]==true);
  CHECK(j["user"]=="admin");
  CHECK(j["login"]==true);

  /////////////////////

  httplib::MultipartFormDataItems items = {
    { "file", "test content", "hello.png", "image/png" }
  };

  res = cli.Post("/upload", headers, items);
  REQUIRE(res != 0);

  j = nlohmann::json::parse(res->body);
  CHECK(j["postId"] != "");

  string upload1 = j["id"];
  string postId = j["postId"];

  ///////////

  httplib::MultipartFormDataItems items2 = {
    { "file", "test content extra", "hello2.png", "image/png" },
    { "postId", postId, "postId"}
  };

  res = cli.Post("/upload", headers, items2);
  REQUIRE(res != 0);

  j = nlohmann::json::parse(res->body);
  CHECK(j["postId"]==postId);
  string upload2 = j["id"];

  ///////////

  res = cli.Post("/set-post-title/"+postId, headers,
                 httplib::MultipartFormDataItems({{"title", "this is the title", "title"}}));

  REQUIRE(res);
  REQUIRE(res->status == 200);
  CHECK(nlohmann::json::parse(res->body)["ok"] == 1);

  ///////////

  res = cli.Post("/set-image-caption/"+upload1, headers,
                 httplib::MultipartFormDataItems({{"caption", "this is a caption", "caption"}}));

  REQUIRE(res);
  REQUIRE(res->status == 200);
  CHECK(nlohmann::json::parse(res->body)["ok"] == 1);
  ///////////

  res = cli.Post("/set-image-caption/"+upload2, headers,
                 httplib::MultipartFormDataItems({{"caption", "this is a second caption", "caption"}}));

  REQUIRE(res);
  REQUIRE(res->status == 200);
  CHECK(nlohmann::json::parse(res->body)["ok"] == 1);

  ////
  res = cli.Get("/getPost/"+postId);
  REQUIRE(res);
  j = nlohmann::json::parse(res->body);
  CHECK(j["images"].size() == 2);

  CHECK(j["title"] == "this is the title");
  CHECK(j["public"] == 1);
  CHECK(j["can_touch_post"] == 0);
  CHECK(j["publicUntil"] == 0);

  CHECK(j["images"][0]["id"]==upload1);
  CHECK(j["images"][0]["caption"] == "this is a caption");

  CHECK(j["images"][1]["id"]==upload2);
  CHECK(j["images"][1]["caption"] == "this is a second caption");

  ///////////

  ////
  res = cli.Get("/getPost/"+postId, headers);
  REQUIRE(res);
  j = nlohmann::json::parse(res->body);
  CHECK(j["can_touch_post"] == 1); //  as admin

  ///
  

  res = cli.Post("/logout", headers);
  REQUIRE(res != 0);

  string cookieline = res->get_header_value("Set-Cookie");
  CHECK(cookieline.find("Max-Age=0") != string::npos);

  //////////////
  res = cli.Get("/status", headers);
  REQUIRE(res != 0);
  cout<< res->body << endl;
  cout<< res->status << endl;

  j = nlohmann::json::parse(res->body);
  CHECK(j["login"]==false);
}

auto createAndLoginUser(httplib::Client& cli, const httplib::Headers& adminSession, const std::string& user, const std::string& password)
{
  httplib::MultipartFormDataItems items = {
    { "user", user, "user" },
    { "password1", password, "password1" }
  };

  auto res = cli.Post("/create-user", adminSession, items);
  if(!res || res->status != 200 || nlohmann::json::parse(res->body)["ok"] != 1)
    throw std::runtime_error("Client call to create-user failed");

  return getTFS().doLogin(user, password);
}

TEST_CASE("post deletion tests") {
  httplib::Client cli("127.0.0.1", 9999);

  auto adminSession = getTFS().doLogin();
  auto janSession = createAndLoginUser(cli, adminSession, "jan", "jan1234");
  auto henkSession = createAndLoginUser(cli, adminSession, "henk", "henk1234");

  httplib::MultipartFormDataItems items = {
    { "file", "test content 123", "hello2.png", "image/png" }
  };

  auto res = cli.Post("/upload", janSession, items);
  REQUIRE(res != 0);
  nlohmann::json j = nlohmann::json::parse(res->body);
  CHECK(j["postId"] != "");

  string upload1 = j["id"];
  string postId = j["postId"];

  res = cli.Post("/delete-post/"+postId, henkSession);
  REQUIRE(res != 0);
  REQUIRE(res->status == 200);
  j = nlohmann::json::parse(res->body);
  CHECK(j["ok"]==0);

  res = cli.Post("/delete-post/"+postId, janSession);
  REQUIRE(res != 0);
  REQUIRE(res->status == 200);
  j = nlohmann::json::parse(res->body);
  CHECK(j["ok"]==1);
}

TEST_CASE("web visibility tests") {
  httplib::Client cli("127.0.0.1", 9999);

  auto adminSession = getTFS().doLogin();

  // create user piet
  httplib::MultipartFormDataItems items2 = {
    { "user", "piet", "user" },
    { "password1", "piet123piet", "password1" }
  };

  auto res = cli.Post("/create-user", adminSession, items2);
  REQUIRE(res != 0);

  auto pietSession = getTFS().doLogin("piet", "piet123piet");
  res = cli.Get("/status", pietSession);
  REQUIRE(res != 0);

  nlohmann::json j = nlohmann::json::parse(res->body);
  CHECK(j["admin"]==false);
  CHECK(j["user"]=="piet");
  CHECK(j["login"]==true);

  // create user karel
  httplib::MultipartFormDataItems items3 = {
    { "user", "karel", "user" },
    { "password1", "karel123karel", "password1" }
  };

  res = cli.Post("/create-user", adminSession, items3);
  REQUIRE(res != 0);

  auto karelSession = getTFS().doLogin("karel", "karel123karel");
  res = cli.Get("/status", pietSession);
  REQUIRE(res != 0);

  httplib::MultipartFormDataItems items = {
    { "file", "test content 123", "hello2.png", "image/png" }
  };

  res = cli.Post("/upload", pietSession, items);
  REQUIRE(res != 0);
  j = nlohmann::json::parse(res->body);
  CHECK(j["postId"] != "");

  string upload1 = j["id"];
  string postId = j["postId"];

  res = cli.Get("/i/"+upload1); // anon access
  REQUIRE(res != 0); CHECK(res->body ==items[0].content);

  res = cli.Get("/i/"+upload1, pietSession); // with cookie
  REQUIRE(res != 0); CHECK(res->body ==items[0].content);

  res = cli.Get("/i/"+upload1, adminSession); // with admin cookie
  REQUIRE(res != 0); CHECK(res->body ==items[0].content);

  // make post non-public
  res = cli.Post("/set-post-public/"+postId+"/0", pietSession);
  REQUIRE(res != 0);

  res = cli.Get("/getPost/"+postId, adminSession); // with admin cookie
  REQUIRE(res != 0);
  j = nlohmann::json::parse(res->body);
  cout<<"dump: " << j.dump()<<endl;
  REQUIRE(j["images"].size() == 1);
  CHECK(j["images"][0]["id"] == upload1);
  CHECK(j["can_touch_post"] == 1);

  res = cli.Get("/i/"+upload1); // no cookie
  REQUIRE(res != 0); CHECK(res->status == 404);

  res = cli.Get("/i/"+upload1, pietSession); // with cookie
  REQUIRE(res != 0);
  CHECK(res->body ==items[0].content);

  res = cli.Get("/i/"+upload1, adminSession); // admin
  REQUIRE(res != 0); CHECK(res->body == items[0].content);


  // admin makes post public
  res = cli.Post("/set-post-public/"+postId+"/1", adminSession);
  REQUIRE(res != 0);

  res = cli.Get("/i/"+upload1); // no cookie
  REQUIRE(res != 0); CHECK(res->body == items[0].content);

  // admin makes post public until one minute ago
  res = cli.Post("/set-post-public/"+postId+"/1/" + to_string(time(0)-60), adminSession);
  REQUIRE(res != 0);

  // should be 404 for anon user
  res = cli.Get("/i/"+upload1); // no cookie
  REQUIRE(res != 0); CHECK(res->status == 404);

  res = cli.Get("/i/"+upload1, adminSession); // as admin, should work
  REQUIRE(res != 0); CHECK(res->body == items[0].content);

  // admin makes post public for one minute
  time_t newTime = time(0)+60;
  res = cli.Post("/set-post-public/"+postId+"/1/" + to_string(newTime), adminSession);
  REQUIRE(res != 0);

  res = cli.Get("/i/"+upload1); // no cookie, should work
  REQUIRE(res != 0); CHECK(res->body == items[0].content);

  res = cli.Get("/getPost/"+postId);
  REQUIRE(res != 0);
  j = nlohmann::json::parse(res->body);
  CHECK(j["images"].size()==1);
  CHECK(j["publicUntil"]==newTime);
  CHECK(j["can_touch_post"]==0);

  // admin makes post non-public, but confusingly tries to also set a time limit
  res = cli.Post("/set-post-public/"+postId+"/0/" + to_string(time(0)+60), adminSession);
  REQUIRE(res != 0);
  CHECK(res->status == 200);
  CHECK(nlohmann::json::parse(res->body)["ok"] == 0);

  // non-admin tries to make post public
  res = cli.Post("/set-post-public/"+postId+"/1/", karelSession);
  REQUIRE(res != 0);
  CHECK(nlohmann::json::parse(res->body)["ok"] == 0);

  // anony,ous tries to make post public
  res = cli.Post("/set-post-public/"+postId+"/1/");
  REQUIRE(res != 0);
  CHECK(nlohmann::json::parse(res->body)["ok"] == 0);
}


TEST_CASE("web abuse tests") {
  httplib::Client cli("127.0.0.1", 9999);

  auto adminSession = getTFS().doLogin();

  // create user john
  httplib::MultipartFormDataItems items1 = {
    { "user", "john", "user" },
    { "password1", "john123john", "password1" }
  };

  auto res = cli.Post("/create-user", adminSession, items1);
  REQUIRE(res != 0);

  auto johnSession = getTFS().doLogin(items1[0].content, items1[1].content);

  // create user barak
  httplib::MultipartFormDataItems items2 = {
    { "user", "barak", "user" },
    { "password1", "barak123barak", "password1" }
  };

  res = cli.Post("/create-user", adminSession, items2);
  REQUIRE(res != 0);

  auto barakSession = getTFS().doLogin(items2[0].content, items2[1].content);

  // user john is going to upload a photo
  httplib::MultipartFormDataItems items3 = {
    { "file", "test content 123", "hello2.png", "image/png" }
  };

  res = cli.Post("/upload", johnSession, items3);
  REQUIRE(res != 0);
  nlohmann::json j = nlohmann::json::parse(res->body);
  CHECK(j["postId"] != "");

  string upload1 = j["id"];
  string postId = j["postId"];

  // Now barak is going to try to add something to john's post

  httplib::MultipartFormDataItems items4 = {
    { "file", "123 test content", "hello2.png", "image/png" },
    {"postId", postId, "postId"}
  };

  res = cli.Post("/upload", barakSession, items4);
  REQUIRE(res != 0);
  CHECK(nlohmann::json::parse(res->body)["ok"] == 0);

  // now barak is going to set the title of john's post

  res = cli.Post("/set-post-title/"+postId, barakSession,
                 httplib::MultipartFormDataItems({{"title", "this is the title", "title"}}));

  REQUIRE(res);
  CHECK(nlohmann::json::parse(res->body)["ok"] == 0);

 
  // now barak is going to set the caption of john's image

  res = cli.Post("/set-image-caption/"+upload1, barakSession,
                 httplib::MultipartFormDataItems({{"caption", "this is the caption", "caption"}}));

  REQUIRE(res);
  CHECK(nlohmann::json::parse(res->body)["ok"] == 0);

  // now barak is going to delete john's image

  res = cli.Post("/delete-image/"+upload1, barakSession);

  REQUIRE(res);
  CHECK(nlohmann::json::parse(res->body)["ok"] == 0);
}

TEST_CASE("web admin tests") {
  httplib::Client cli("127.0.0.1", 9999);

  auto adminSession = getTFS().doLogin();

  httplib::MultipartFormDataItems items = {
    { "file", "test content 123213213", "hello3.png", "image/png" }
  };

  auto res = cli.Post("/upload", adminSession, items);
  REQUIRE(res != 0);
  nlohmann::json j = nlohmann::json::parse(res->body);
  CHECK(j["postId"] != "");
  string upload1 = j["id"];

  res = cli.Get("/all-images", adminSession);
  REQUIRE(res != 0);

  j = nlohmann::json::parse(res->body);

  CHECK(j.size() > 0);
  bool found=false;
  for(const auto& item : j) {
    if(item["id"]==upload1)
      found=true;
  }
  CHECK(found == true);
}

TEST_CASE("disable user test") {
  httplib::Client cli("127.0.0.1", 9999);
  
  auto adminSession = getTFS().doLogin();
  auto katySession = createAndLoginUser(cli, adminSession, "katy", "katy123");

  httplib::MultipartFormDataItems items = {
    { "file", "123 test content", "hello2.png", "image/png" }
  };
  auto res = cli.Post("/upload", katySession, items);
  REQUIRE(res != 0);
  nlohmann::json j = nlohmann::json::parse(res->body);
  CHECK(j["postId"] != "");

  cout<<j<<endl;
  string id = j["id"];
  string postid= j["postId"];

  res = cli.Get("/i/"+id); // no cookie, should work
  REQUIRE(res != 0); CHECK(res->body == items[0].content);

  res = cli.Post("/change-user-disabled/katy/1", adminSession);
  REQUIRE(res != 0); CHECK(nlohmann::json::parse(res->body)["ok"] == 1);

  res = cli.Get("/i/"+id); // should no longer work
  REQUIRE(res != 0); CHECK(res->body != items[0].content);

  res = cli.Get("/i/"+id, katySession); // should no longer work
  REQUIRE(res != 0); CHECK(res->body != items[0].content);
  
  res = cli.Get("/i/"+id, adminSession); // should still work
  REQUIRE(res != 0); CHECK(res->body == items[0].content);

  res = cli.Get("/getPost/"+postid, adminSession); // should still work
  REQUIRE(res != 0); CHECK(nlohmann::json::parse(res->body)["ok"] == 1);

  res = cli.Get("/getPost/"+postid); // anon
  REQUIRE(res != 0); CHECK(nlohmann::json::parse(res->body)["ok"] == 0);

  res = cli.Get("/getPost/"+postid, katySession); // katy
  REQUIRE(res != 0); CHECK(nlohmann::json::parse(res->body)["ok"] == 0);

  auto stuff = [&]() {
    getTFS().doLogin("katy", "katy123");
  };
  CHECK_THROWS_AS(stuff(), const std::exception&);

  res = cli.Post("/change-user-disabled/katy/0", adminSession);
  REQUIRE(res != 0); CHECK(nlohmann::json::parse(res->body)["ok"] == 1);

  katySession = getTFS().doLogin("katy", "katy123");

  res = cli.Get("/i/"+id, katySession); // retry
  REQUIRE(res != 0); CHECK(res->body == items[0].content);

  res = cli.Get("/i/"+id); // anon
  REQUIRE(res != 0); CHECK(res->body == items[0].content);

  res = cli.Get("/getPost/"+postid, katySession); // katy
  REQUIRE(res != 0); CHECK(nlohmann::json::parse(res->body)["ok"] == 1);

  res = cli.Get("/getPost/"+postid); // anon
  REQUIRE(res != 0); CHECK(nlohmann::json::parse(res->body)["ok"] == 1);
}

TEST_CASE("change my password") {
  httplib::Client cli("127.0.0.1", 9999);

  auto adminSession = getTFS().doLogin();
  auto harrySession = createAndLoginUser(cli, adminSession, "harry", "harrypw");

  httplib::MultipartFormDataItems items = {
    { "password0", "harrypw", "password0"}, 
    { "password1", "newharrypw", "password1"}
  };
  
  
  cli.Post("/change-my-password", harrySession, items);

  auto newHarrySession = getTFS().doLogin("harry", "newharrypw");

  auto res = cli.Get("/status", newHarrySession);
  REQUIRE(res != 0);

  nlohmann::json j = nlohmann::json::parse(res->body);
  CHECK(j["admin"]==false);
  CHECK(j["user"]=="harry");
  CHECK(j["login"]==true);
}

TEST_CASE("email address change test") {
  httplib::Client cli("127.0.0.1", 9999);

  auto adminSession = getTFS().doLogin();
  auto j0hnSession = createAndLoginUser(cli, adminSession, "j0hn", "j0hnpw");
  
  auto res = cli.Get("/status", j0hnSession);
  REQUIRE(res != 0);

  nlohmann::json j = nlohmann::json::parse(res->body);
  CHECK(j["email"]=="");

  httplib::MultipartFormDataItems items = {
    { "email", "j0hn-243243@gmail.com", "email"}
  };

  res = cli.Post("/change-my-email", j0hnSession, items);
  REQUIRE(res != 0);
  j = nlohmann::json::parse(res->body);
  CHECK(j["ok"]==1);

  res = cli.Get("/status", j0hnSession);
  REQUIRE(res != 0);

  j = nlohmann::json::parse(res->body);
  CHECK(j["email"]=="j0hn-243243@gmail.com");


  httplib::MultipartFormDataItems items2 = {
    { "email", "j0hn-blah-243243@gmail.com", "email"},
    { "user", "j0hn", "user"}
  };

  // and now using the admin interface
  res = cli.Post("/change-email", adminSession, items2);
  REQUIRE(res != 0);
  j = nlohmann::json::parse(res->body);
  CHECK(j["ok"]==1);

  res = cli.Get("/status", j0hnSession);
  REQUIRE(res != 0);

  j = nlohmann::json::parse(res->body);
  
  CHECK(j["email"]=="j0hn-blah-243243@gmail.com");

  // and now using the admin interface, but not as admin
  res = cli.Post("/change-email", j0hnSession, items2);

  REQUIRE(res != 0);
  j = nlohmann::json::parse(res->body);
  CHECK(j["ok"]==0);
}

TEST_CASE("email test" * doctest::skip(true)) {
  sendAsciiEmailAsync("10.0.0.2:25", "bert@hubertnet.nl", "bert@hubertnet.nl", "Le Sujet",
                 R"(Hallo,

Dit is een test van meerdere regels.

.

Nog een paragraaf!
)");

}

TEST_CASE("user without password") {
  httplib::Client cli("127.0.0.1", 9999);

  auto adminSession = getTFS().doLogin();

  // create user pieter
  httplib::MultipartFormDataItems items2 = {
    { "user", "pieter", "user" },
    { "password1", "", "password1" }
  };

  auto res = cli.Post("/create-user", adminSession, items2);
  REQUIRE(res != 0);

  auto stuff = [&]() {
    auto pietSession = getTFS().doLogin("pieter", "");
  };
  CHECK_THROWS_AS(stuff(), const std::exception&);
}
