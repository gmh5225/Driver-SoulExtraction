#pragma once

//#define usedbg

#ifdef usedbg

#    define pr_debug DbgPrint
#    define pr_devel DbgPrint
#    define pr_err DbgPrint
#    define pr_warn DbgPrint
#    define printk DbgPrint

#else

#    define pr_debug
#    define pr_devel
#    define pr_err
#    define pr_warn
#    define printk

#endif // usedbg
