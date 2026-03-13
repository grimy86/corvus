#ifndef API_CONFIG_H
#define API_CONFIG_H

#ifdef MUNINN_EXPORTS
#warning "MUNINN_EXPORTS is defined"
#define MUNINN_API __declspec(dllexport)
#else
#warning "MUNINN_EXPORTS is undefined"
#define MUNINN_API __declspec(dllimport)
#endif

#define MUNINN_CALL __fastcall

#ifndef _In_
#define _In_
#endif // !_In_

#ifndef _Out_
#define _Out_
#endif // !_Out_

#ifndef _Out_writes_
#define _Out_writes_(size)
#endif // !_Out_writes_

#ifndef _Out_opt_
#define _Out_opt_
#endif // !_Out_opt_
#endif // !API_CONFIG_H