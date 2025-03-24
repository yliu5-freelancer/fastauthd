#ifndef _FASTAUTHD_DEBUG_H
#define _FASTAUTHD_DEBUG_H

#ifdef DEBUG
#define DEBUGPRINT(...) fprintf(stderr, __VA_ARGS__)
#else
#define DEBUGPRINT(...) do { } while(0)
#endif

#endif