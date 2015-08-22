
#pragma once
#include <Windows.h>

#define INITIALIZE_LIST_HEAD(le)    (void)((le)->Flink = (le)->Blink = (le))
#define INSERT_HEAD_LIST(le,e)      do { PLIST_ENTRY f = (le)->Flink; (e)->Flink = f; (e)->Blink = (le); f->Blink = (e); (le)->Flink = (e); } while (0)
#define INSERT_TAIL_LIST(le,e)      do { PLIST_ENTRY b = (le)->Blink; (e)->Flink = (le); (e)->Blink = b; b->Flink = (e); (le)->Blink = (e); } while (0)
#define REMOVE_ENTRY_LIST(e)        do { PLIST_ENTRY f = (e)->Flink, b = (e)->Blink; f->Blink = b; b->Flink = f; (e)->Flink = (e)->Blink = NULL; } while (0)
#define IS_LIST_EMPTY(le)           ((le)->Flink == (le))

