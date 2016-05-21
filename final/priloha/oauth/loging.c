/*
 * The MIT License
 *
 * Copyright (c) 2016 Institute of Computer Science, Masaryk University.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdio.h>

#ifdef _WIN32
    #ifndef UNICODE
        #define UNICODE
    #endif
    #include <windows.h>

    #define PROVIDER_NAME L"Remsig"
#endif

#ifdef __linux__
    #include <syslog.h>
#endif

/**
  * For debug purposes disable LOG_ENABLED
  * when disabled - standard output
  * When enabled - output goes to log
  */
//#define LOG_ENABLED

#ifdef _WIN32
/**
 * @brief This function converts LPWSTR string to Unicode
 * @param string to be converted
 * @return converted string on success, '\0' otherwise
 */
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

/**
 * @brief This function is used for os logs. Windows default is EvenViewer, Linux uses syslog
 * @param priority - priority of message, 0 - info log, 1 - notice log, 2 - error log
 * @param msg - log string
 */
void makeLog(int priority, const char* msg, ...) {

    // standard output
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

    // Logs fow linux
    #ifdef __linux__

        // opens syslog
        openlog( "Remsig", LOG_NDELAY | LOG_PID , LOG_USER);

        // logs message
        if(priority == 0) {
            syslog(LOG_INFO, msg);
        }
        else if(priority == 1) {
            syslog(LOG_NOTICE, msg);
        }
        else if(priority == 2) {
            syslog(LOG_ERR, msg);
        }
        else {
            syslog(LOG_ERR, msg);
        }

        // closes log
        closelog();
        return;

    #endif

    // logs for windows
    #ifdef _WIN32
        HANDLE hEventLog = NULL;
        LPWSTR pInsertStrings[2] = {NULL, NULL};
        WORD type;

        // open logs
        hEventLog = RegisterEventSource(NULL, PROVIDER_NAME);

        if (hEventLog == NULL) {
            wprintf(L"RegisterEventSource failed with 0x%x.\n", GetLastError());
            goto cleanup;
        }

        // adds log priority
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
        // adds log message
        pInsertStrings[1] = toUni(msg);
        if (!ReportEvent(hEventLog, type, 0, 0, NULL, 2, 0, (LPCWSTR*)pInsertStrings, NULL)) {
            wprintf(L"ReportEvent failed with 0x%x for event 0x%x.\n", GetLastError(), 10);
            goto cleanup;
        }

        //puts("Ok");
        return;

        // error cleanup
        cleanup:
        if (hEventLog) {
            DeregisterEventSource(hEventLog);
        }
        return;
    #endif
}
