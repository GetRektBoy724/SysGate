# SysGate
SysGate is a program that will help you to "guess" a Syscall ID by the location of the syscall stub in memory and make a "gate" to the NT function you want to use. Basically the syscall stub that has the lowest position on the memory have the lowest number of Syscall ID and the syscall stub that has the highest position on the memory have the highest number of Syscall ID. So by having that in mind, we can just get all NT functions from EAT, sort them by the addresses, and "guess" the syscall by the position of the address (still doesnt understand? then check [this](https://www.crummie5.club/freshycalls/#first-detection-the-number-extraction) out). But there is a flaw on this idea, AVs can potentially implant a modded-NTDLL where the Syscall ID doesnt correspond with the position of the syscall stub on memory, hence breaking this technique, but fortunetely, it seems for now there isnt any AVs that doing this.

# Usage Example
You can take a look at the [source code](https://github.com/GetRektBoy724/SysGate/blob/main/SysGate.cs#L661). For compilation, dont forget to add `unsafe` parameter ;)

# Sources
- https://www.crummie5.club/freshycalls/
- https://github.com/crummie5/FreshyCalls
- https://github.com/jthuraisamy/SysWhispers2
- https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/
