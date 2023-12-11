#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
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

TEST_CASE("form parse test") {
  auto res = getFormFields("user=ahu&password=Super123Secret");
  CHECK(res.size() == 2);
  CHECK(res["user"]=="ahu");
  CHECK(res["password"]=="Super123Secret");
}

TEST_CASE("base64url id") {
  CHECK(makeShortID((1ULL<<62) - 132430)== "svr9_____z8");
  CHECK(makeShortID( 4529558240454539472)== "0Hi8lzg53D4");
  CHECK(makeShortID(2984614381840956837) == "pf0mlfd6ayk");
  CHECK(makeShortID(1) == "AQAAAAAAAAA");
}

