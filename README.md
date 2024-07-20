# usermode_edr
A poc (proof-of-concept) EDR implemented completely in user-mode. It utilizes LdrRegisterDllNotification() to look for dll loads and utilizes my custom hooking engine to place hooks in the target dlls.
