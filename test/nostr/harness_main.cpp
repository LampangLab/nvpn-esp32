#include "NostrBoard_check.cpp"
#include <iostream>
int main() {
  setup();
  onWs(WStype_CONNECTED, nullptr, 0);
  std::string line;
  while (std::getline(std::cin, line)) { onWs(WStype_TEXT, (uint8_t *)line.data(), line.size()); }
  return 0;
}
