#define LOG_ENABLED

#ifdef _WIN32
    #ifndef UNICODE
        #define UNICODE
    #endif
    #include <windows.h>
    #include <stdio.h>

    #pragma comment(lib, "advapi32.lib")
    #define PROVIDER_NAME L"Remsig"
#endif

#ifdef __linux__
    #include <syslog.h>
#endif

#ifdef _WIN32
LPWSTR toUni(const char* string) {

    LPWSTR output;

    int lenW = MultiByteToWideChar(CP_ACP, 0, string, strlen(string), 0, 0);

    if (lenW > 0) {
      // Check whether conversion was successful
      output = malloc((lenW + 1) * sizeof(LPWSTR));
      MultiByteToWideChar(CP_ACP, 0, string, strlen(string), output, lenW);
      output[lenW] = 0;
    }
    else
    {
      puts("Error during log convertion.");
      return 0;
    }

    return output;
}
#endif


void makeLog(int priority, const char* msg) {

    #ifndef LOG_ENABLED
        if(priority == 0) {
            printf("INFO LOG: %s\n", msg);
        }
        else if(priority == 1) {
            printf("NOTICE LOG: %s\n", msg);
        }
        else if(priority == 2) {
            printf("ERROR LOG: %s\n", msg);
        }
        else {
            puts(msg);
        }
        return;
    #endif

    // Log part
    #ifdef __linux__

        openlog( "Remsig", LOG_NDELAY | LOG_PID , LOG_USER);

        if(priority == 0) {
            syslog(LOG_INFO, msg);
        }
        if(priority == 1) {
            syslog(LOG_NOTICE, msg);
        }
        if(priority == 2) {
            syslog(LOG_ERR, msg);
        }

        puts("ok");

        closelog();
        return;

    #endif

    #ifdef _WIN32
        HANDLE hEventLog = NULL;
        LPWSTR pInsertStrings[2] = {NULL, NULL};
        WORD type;

        hEventLog = RegisterEventSource(NULL, PROVIDER_NAME);

        if (hEventLog == NULL) {
            wprintf(L"RegisterEventSource failed with 0x%x.\n", GetLastError());
            goto cleanup;
        }

        if(priority == 0) {
            pInsertStrings[0] = toUni("Info log:");
            type = EVENTLOG_SUCCESS;
        }
        else if(priority == 1) {
            pInsertStrings[0] = toUni("Notice log:");
            type = EVENTLOG_SUCCESS;
        }
        else if(priority == 2) {
            pInsertStrings[0] = toUni("Error log:");
            type = EVENTLOG_ERROR_TYPE;
        }
        else {
            printf("Unknown log type.\n");
            goto cleanup;
        }
        pInsertStrings[1] = toUni(msg);
        if (!ReportEvent(hEventLog, type, 0, 0, NULL, 2, 0, (LPCWSTR*)pInsertStrings, NULL)) {
            wprintf(L"ReportEvent failed with 0x%x for event 0x%x.\n", GetLastError(), 10);
            goto cleanup;
        }

        puts("Ok");
        return;

        cleanup:
        if (hEventLog) {
            DeregisterEventSource(hEventLog);
        }
        return;
    #endif
}
