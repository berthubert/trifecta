#include "support.hh"
using namespace std;
int main(int argc, char* argv[])
try
{
  return trifectaMain(argc, (const char**)argv);
}
catch(std::exception& e) {
  cerr<<"Error: "<<e.what()<<endl;
  return EXIT_FAILURE;
}
