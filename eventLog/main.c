#include <stdio.h>
#include "loging.c"

int main() {

    // 0 - info, 1 - notice, 2 - error
    makeLog(0, "Vsechno jede. Hura....");

    makeLog(2, "Neco se posralo.");

    return 1;
}
