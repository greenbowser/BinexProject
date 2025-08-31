#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/limits.h>

#define MAX_LOGS 8
#define CONTENT_SIZE_MAX 256
const char *LOGBOOK_PATH = "/tmp/sLogs";

int credits = 10;

typedef struct
{
    char name[32];
    long len;
    FILE *log_file_ptr;
    char *content_buffer;
} Log;

Log *g_logbook[MAX_LOGS];

// Due to repeated hacking attempts, we are forced to take antihacking measures.
void anti_hacking(int idx)
{
    if (*((int *)((char *)g_logbook[idx]->log_file_ptr - 0x8)) != 0x1e1)
    {
        puts("Hacking attempt detected! CEASE ALL HACKING ACTIVITIES IMMEDIATELY!");
        *((int *)((char *)g_logbook[idx]->log_file_ptr - 0x8)) = 0x1e1;
    }
}

void read_stdin(char *text, char *buf, int size)
{
    printf("Please input %s:\n", text);
    fgets(buf, size, stdin);
    for (char *p = buf + strlen(buf) - 1; p >= buf && *p == '\n'; --p)
        *p = 0;
}

int read_int(char *prompt)
{
    printf("%s\n", prompt);
    char buf[8] = {0};
    read(0, buf, 7);
    return atoi(buf);
}

int validate_path(const char *path)
{
    char resolved_path[PATH_MAX];
    realpath(path, resolved_path);
    if (strncmp(resolved_path, LOGBOOK_PATH, strlen(LOGBOOK_PATH)) == 0)
    {
        return 1; // Valid path
    }
    return 0; // Invalid path
}

void add_log()
{
    int idx = -1;
    for (int i = 0; i < MAX_LOGS; i++)
    {
        if (g_logbook[i] == NULL)
        {
            idx = i;
            break;
        }
    }
    if (idx == -1)
    {
        puts("Logbook is full.");
        return;
    }
    g_logbook[idx] = (Log *)calloc(1, sizeof(Log));
    if (!g_logbook[idx])
    {
        puts("The machine is too tired to create a new log... (calloc failed)");
        return;
    }
    g_logbook[idx]->len = read_int("Enter Size (1-256): ");
    if (g_logbook[idx]->len <= 0 || g_logbook[idx]->len > CONTENT_SIZE_MAX)
    {
        puts("Invalid size. Must be between 1 and 256 bytes.");
        free(g_logbook[idx]);
        g_logbook[idx] = NULL;
        return;
    }
    printf("Enter log name (1-32): ");
    for (int i = 0; i <= 32; i++)
    {
        char c = getchar();
        if (c == '\n' || c == EOF)
        {
            g_logbook[idx]->name[i] = '\0';
            if (i == 0)
            {
                puts("Log name cannot be empty.");
                free(g_logbook[idx]);
                g_logbook[idx] = NULL;
                return;
            }
            break;
        }
        g_logbook[idx]->name[i] = c;
    }

    char file_path[64];
    snprintf(file_path, 63, "/tmp/sLogs/%s.log", g_logbook[idx]->name);
    if (!validate_path(file_path))
    {
        puts("Invalid file path. Log creation aborted.");
        free(g_logbook[idx]);
        g_logbook[idx] = NULL;
        return;
    }

    g_logbook[idx]->content_buffer = (char *)calloc(1, g_logbook[idx]->len < CONTENT_SIZE_MAX ? g_logbook[idx]->len : CONTENT_SIZE_MAX);
    if (!g_logbook[idx]->content_buffer)
    {
        puts("Computer says no... (calloc failed)");
        free(g_logbook[idx]);
        g_logbook[idx] = NULL;
        return;
    }

    g_logbook[idx]->log_file_ptr = fopen(file_path, "w");
    if (!g_logbook[idx]->log_file_ptr)
    {
        puts("Computer says no... (fopen failed)");
        free(g_logbook[idx]->content_buffer);
        free(g_logbook[idx]);
        g_logbook[idx]->content_buffer = NULL;
        g_logbook[idx] = NULL;
        return;
    }

    printf("Enter log content (up to %ld bytes):\n", g_logbook[idx]->len < CONTENT_SIZE_MAX ? g_logbook[idx]->len - 1 : CONTENT_SIZE_MAX - 1);

    ssize_t bytes_read = read(0, g_logbook[idx]->content_buffer, g_logbook[idx]->len - 1);
    if (bytes_read > 0)
    {
        g_logbook[idx]->content_buffer[bytes_read - 1] = '\0'; // Remove newline
    }

    printf("Log '%s' created with ID %d.\n", g_logbook[idx]->name, idx);
}

void read_log()
{
    int idx = read_int("Enter Log ID (0-7): ");
    if (idx < 0 || idx >= MAX_LOGS || g_logbook[idx] == NULL)
    {
        puts("Invalid Log ID.");
        return;
    }

    printf("\n--- Log ID: %d | Name: %s ---\n", idx, g_logbook[idx]->name);
    puts("--- Start of Log ---");
    write(1, g_logbook[idx]->content_buffer, g_logbook[idx]->len - 1);
    puts("\n--- End of Log ---");
}

void delete_log()
{

    int idx = read_int("Enter Log ID (0-7): ");
    if (idx < 0 || idx >= MAX_LOGS || g_logbook[idx] == NULL)
    {
        puts("Invalid Log ID.");
        return;
    }
    anti_hacking(idx);
    fclose(g_logbook[idx]->log_file_ptr);
    free(g_logbook[idx]->content_buffer);
    free(g_logbook[idx]);
    g_logbook[idx] = NULL;

    puts("Log entry cast into the void.");
}

void flush_log()
{
    int idx = read_int("Enter Log ID (0-7): ");
    if (idx < 0 || idx >= MAX_LOGS || g_logbook[idx] == NULL)
    {
        puts("Invalid Log ID.");
        return;
    }
    anti_hacking(idx);
    fwrite(g_logbook[idx]->content_buffer, 1, g_logbook[idx]->len - 1, g_logbook[idx]->log_file_ptr);
    fclose(g_logbook[idx]->log_file_ptr);
    g_logbook[idx]->log_file_ptr = NULL;
    free(g_logbook[idx]->content_buffer);
    free(g_logbook[idx]);
    g_logbook[idx] = NULL;

    puts("Log entry has been sealed to disk.");
}

void print_banner()
{
    int leak = 0x1337;
    puts("========================================");
    puts("=        Logging as a Service          =");
    puts("=        Your logs are secure          =");
    puts("========================================");
    printf("Today's special: %p\n", &leak);
}

void print_menu()
{
    puts("\nAvailable commands:");
    puts("add - Create a new log entry");
    puts("read - Read a log entry");
    puts("delete - Delete a log entry");
    puts("flush - Flush log to disk");
    puts("exit - Exit the program");
}

int main()
{

    setbuf(stdout, NULL);
    print_banner();
    char cmd[0x20];

    while (1)
    {
        printf("You have %d credits.\n", credits);
        if (credits <= 0)
        {
            puts("You have no credits left. Buy more at our store!");
            puts("1 Credit = 13.37 Euros");
            puts("10 Credits = 133.7 Euros");
            puts("100 Credits = 420.69 Euros (our best deal!)");
            exit(0);
        }
        print_menu();
        read_stdin("a command", cmd, sizeof(cmd));

        if (strcmp(cmd, "add") == 0)
        {
            add_log();
        }
        else if (strcmp(cmd, "read") == 0)
        {
            read_log();
        }
        else if (strcmp(cmd, "delete") == 0)
        {
            delete_log();
        }
        else if (strcmp(cmd, "flush") == 0)
        {
            flush_log();
        }
        else if (strcmp(cmd, "exit") == 0)
        {
            exit(0);
        }
        else
        {
            printf("bro input a valid command 💀\n");
        }
        credits--;
    }
}