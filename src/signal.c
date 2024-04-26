/*
** EPITECH PROJECT, 2024
** signal.c
** File description:
** signal.c.
*/
#include <unistd.h>
#include <signal.h>

static void write_signal_1(int signal)
{
    switch (signal) {
        case SIGHUP:
            return (void)write(1, "SIGHUP", 6);
        case SIGINT:
            return (void)write(1, "SIGINT", 6);
        case SIGQUIT:
            return (void)write(1, "SIGQUIT", 7);
        case SIGILL:
            return (void)write(1, "SIGILL", 6);
        case SIGABRT:
            return (void)write(1, "SIGABRT", 7);
        case 7:
            return (void)write(1, "SIGEMT", 6);
        case SIGFPE:
            return (void)write(1, "SIGFPE", 6);
        case SIGKILL:
            return (void)write(1, "SIGKILL", 7);
    }
}

static void write_signal_2(int signal)
{
    switch (signal) {
        case SIGSEGV:
            return (void)write(1, "SIGSEGV", 7);
        case SIGSYS:
            return (void)write(1, "SIGSYS", 6);
        case SIGPIPE:
            return (void)write(1, "SIGPIPE", 7);
        case SIGALRM:
            return (void)write(1, "SIGALRM", 7);
        case SIGTERM:
            return (void)write(1, "SIGTERM", 7);
        case SIGUSR1:
            return (void)write(1, "SIGUSR1", 7);
        case SIGUSR2:
            return (void)write(1, "SIGUSR2", 7);
        case SIGCHLD:
            return (void)write(1, "SIGCHLD", 7);
        case SIGPWR:
            return (void)write(1, "SIGPWR", 7);
    }
}

static void write_signal_3(int signal)
{
    switch (signal) {
        case SIGWINCH:
            return (void)write(1, "SIGWINCH", 8);
        case SIGURG:
            return (void)write(1, "SIGURG", 6);
        case SIGPOLL:
            return (void)write(1, "SIGPOLL", 7);
        case SIGSTOP:
            return (void)write(1, "SIGSTOP", 7);
        case SIGTSTP:
            return (void)write(1, "SIGTSTP", 7);
        case SIGCONT:
            return (void)write(1, "SIGCONT", 7);
        case SIGTTIN:
            return (void)write(1, "SIGTTIN", 7);
        case SIGTTOU:
            return (void)write(1, "SIGTTOU", 7);
        case SIGVTALRM:
            return (void)write(1, "SIGVTALRM", 9);
    }
}

static void write_signal_4(int signal)
{
    switch (signal) {
        case SIGPROF:
            return (void)write(1, "SIGPROF", 7);
        case SIGXCPU:
            return (void)write(1, "SIGXCPU", 7);
        case SIGXFSZ:
            return (void)write(1, "SIGXFSZ", 7);
        case 32:
            return (void)write(1, "SIGWAITING", 10);
        case 33:
            return (void)write(1, "SIGLWP", 6);
        case 34:
            return (void)write(1, "SIGAIO", 6);
        default:
            return;
    }
}

void write_signal(int signal)
{
    switch (signal) {
        case SIGHUP ... SIGKILL:
            return write_signal_1(signal);
        case SIGSEGV:
        case SIGSYS:
        case SIGPIPE ... SIGTERM:
        case SIGUSR1:
        case SIGUSR2:
        case SIGCHLD:
        case SIGPWR:
            return write_signal_2(signal);
        case SIGWINCH:
        case SIGURG:
        case SIGPOLL:
        case SIGCONT ... SIGTTOU:
        case SIGVTALRM:
            return write_signal_3(signal);
        default:
            return write_signal_4(signal);
    }
}
